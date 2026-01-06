#!/usr/bin/env python3
"""
GitHub Actions Self-Hosted Runner Controller

This script replaces config.sh, run.sh, and run-helper.sh with a unified Python implementation.
Designed for containerized (Docker) environments with Rocky Linux 10+.

ALGORITHM:
==========

1. COMMON INITIALIZATION (all modes):
   - Verify not running as root (unless RUNNER_ALLOW_RUNASROOT is set)
   - Set up directory paths (RUNNER_HOME, RUNNER_ROOT)
   - Validate Runner.Listener binary exists

2. CONFIGURE MODE (./runner.py configure):
   - Create .env file with environment variables (LANG, JAVA_HOME, ANT_HOME, etc.)
   - Create .path file with current PATH
   - Fetch registration token (GITHUB_TOKEN or via GITHUB_PAT API call)
   - Execute: bin/Runner.Listener configure --unattended --token <token> --url <url> 
              --name <name> --labels <labels> --work <work> [--runnergroup <group>]
              [--disableupdate] (if RUNNER_DISABLE_UPDATE is set)

3. RUN MODE (./runner.py run or ./runner.py):
   - Set up signal handlers (SIGINT, SIGTERM) for graceful shutdown
   - Main run loop:
     a. Execute: bin/Runner.Listener run [arguments]
     b. Handle return codes:
        - 0: Normal exit, stop service
        - 1: Terminated error, stop service
        - 2: Retryable error, sleep 5 seconds and restart
        - 3/4: Update requested, exit (container should be rebuilt with new runner)
        - 5: Session conflict, stop service
        - Other: Unknown error, stop service
     c. If interrupted by signal, exit gracefully
     d. Loop until exit condition met

4. REMOVE/DELETE MODE (./runner.py remove or ./runner.py delete):
   - Fetch removal token (GITHUB_TOKEN or via GITHUB_PAT API call)
   - Execute: bin/Runner.Listener remove --token <token>

USAGE:
======
  ./runner.py configure  - Configure and register runner
  ./runner.py run        - Run the runner listener (default)
  ./runner.py            - Same as 'run'
  ./runner.py remove     - Remove/unregister runner
  ./runner.py delete     - Alias for 'remove'

ENVIRONMENT VARIABLES:
======================
  RUNNER_HOME              - Runner home directory (default: /home/runner)
  RUNNER_ROOT              - Runner installation root (default: /usr/local/runner)
  RUNNER_ALLOW_RUNASROOT   - Allow running as root (set to any value)
  RUNNER_DISABLE_UPDATE    - Disable runner self-updates (recommended for containers)
  
  # Configuration
  GITHUB_URL               - GitHub instance URL (required)
  GITHUB_TOKEN             - Pre-generated registration/removal token (priority 1)
  GITHUB_PAT               - Personal Access Token for token generation (priority 2)
  RUNNER_NAME              - Runner name (default: github-actions-runner-<hostname>)
  RUNNER_GROUP             - Runner group (default: Default)
  RUNNER_LABELS            - Runner labels (default: self-hosted,linux,x64)
  RUNNER_WORKSPACE         - Working directory (default: _work)

UPDATE PREVENTION:
==================
  For containerized runners, self-updates are prevented by:
  1. RUNNER_DISABLE_UPDATE environment variable (adds --disableupdate flag)
  2. Exit on update return codes (3, 4) instead of restarting
  3. Runner version baked into Docker image
  4. Updates handled by rebuilding container image with new runner version
"""

import argparse
from collections import deque
import functools
import json
import logging
import os
import platform
import random
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import List, Optional, Any, Set
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

__version__ = "1.0.0"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("runner-ctl")

class SignalHandler:
    """
    Context manager for handling system signals (SIGINT, SIGTERM).
    Restores original handlers upon exit.
    """
    def __init__(self):
        self.shutdown_requested = False
        self._original_sigint = None
        self._original_sigterm = None

    def __enter__(self):
        # Save original signal handlers for restoration on exit
        self._original_sigint = signal.getsignal(signal.SIGINT)
        self._original_sigterm = signal.getsignal(signal.SIGTERM)

        # Install custom signal handlers
        signal.signal(signal.SIGINT, self._handler)
        signal.signal(signal.SIGTERM, self._handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original signal handlers
        signal.signal(signal.SIGINT, self._original_sigint)
        signal.signal(signal.SIGTERM, self._original_sigterm)

    def _handler(self, signum: int, frame: Any):
        try:
            name = signal.Signals(signum).name
        except ValueError:
            name = str(signum)
        logger.info(f"Received signal {name}. Shutting down...")

        self.shutdown_requested = True

# --- Constants & Enums ---
class RunnerExitCode(IntEnum):
    """Exit codes returned by the Runner.Listener binary."""
    SUCCESS = 0
    TERMINATED_ERROR = 1
    RETRYABLE_ERROR = 2
    UPDATE_REQUIRED = 3
    EPHEMERAL_UPDATE_REQUIRED = 4
    SESSION_CONFLICT = 5

class RunnerError(Exception):
    """Base exception for runner controller errors."""
    pass

# --- Configuration ---
@dataclass
class Config:
    """
    Holds configuration derived from environment variables.
    Responsible for validating inputs and providing paths.
    """
    runner_home: Path = field(default_factory=lambda: Path(os.getenv("RUNNER_HOME", "/home/runner")))
    runner_root: Path = field(default_factory=lambda: Path(os.getenv("RUNNER_ROOT", "/usr/local/runner")))

    github_url: Optional[str] = field(default_factory=lambda: os.getenv("GITHUB_URL"))
    github_token: Optional[str] = field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))
    github_pat: Optional[str] = field(default_factory=lambda: os.getenv("GITHUB_PAT"))

    api_retries: int = int(os.getenv("GITHUB_API_RETRIES", "3"))
    api_backoff: float = float(os.getenv("GITHUB_API_BACKOFF", "1.5"))

    runner_name: str = os.getenv("RUNNER_NAME") or f"github-actions-runner-{socket.gethostname()}"
    runner_group: str = os.getenv("RUNNER_GROUP", "Default")
    runner_labels: str = os.getenv("RUNNER_LABELS", "self-hosted,linux,x64")
    runner_work_dir: str = os.getenv("RUNNER_WORKSPACE", "_work")

    allow_root: bool = bool(os.getenv("RUNNER_ALLOW_RUNASROOT"))
    disable_update: bool = bool(os.getenv("RUNNER_DISABLE_UPDATE"))

    # Timeouts
    # Timeout for setup operations (configure/remove).
    # Default: 60 seconds (Fail fast approach).
    setup_timeout: int = int(os.getenv("RUNNER_SETUP_TIMEOUT", "60"))

    @property
    def listener_bin(self) -> Path:
        return self.runner_root / "bin" / "Runner.Listener"

    def validate(self):
        """Validates critical configuration presence."""
        if not self.github_url:
            raise RunnerError("GITHUB_URL environment variable is required.")
        if not self.github_token and not self.github_pat:
            raise RunnerError("Either GITHUB_TOKEN or GITHUB_PAT must be provided.")

# --- Components ---
class FileSystemManager:
    """
    Handles file operations, environment setup, and persistence logic.
    """

    ENV_VARS: List[str] = [
        'LANG',
        'JAVA_HOME',
        'ANT_HOME',
        'M2_HOME',
        'ANDROID_HOME',
        'ANDROID_SDK_ROOT',
        'GRADLE_HOME',
        'NVM_BIN',
        'NVM_PATH',
        'LD_LIBRARY_PATH',
        'PERL5LIB'
    ]

    CONFIG_FILES: List[str] = [
        '.runner',
        '.runner_migrated',
        '.credentials',
        '.credentials_migrated',
        '.credentials_rsaparams',
        '.service',
        '.credential_store',
        '.certificates',
        '.options',
        '.setup_info',
        '.telemetry',
    ]

    def __init__(self, config: Config):
        self.config = config

    def check_user_permissions(self):
        """Ensures the script is not run as root unless allowed."""
        if os.geteuid() == 0 and not self.config.allow_root:
            raise RunnerError("Must not run as root. Set RUNNER_ALLOW_RUNASROOT=1 to override.")

    def create_env_files(self):
        """Generates .env and .path files for the runner."""
        env_file: Path = self.config.runner_home / ".env"
        path_file: Path = self.config.runner_home / ".path"

        # Generate .env file with environment variables
        existing_vars: Set[str] = set()
        if env_file.exists():
            with env_file.open('r') as f:
                existing_vars = {line.split('=')[0] for line in f if '=' in line}

        with env_file.open('a') as f:
            for var_name in self.ENV_VARS:
                if var_name not in existing_vars and (value := os.getenv(var_name)):
                    f.write(f"{var_name}={value}\n")
                    logger.debug(f"Added {var_name} to .env")

        # Generate .path file with current PATH
        path_file.write_text(os.getenv("PATH", ""))
        logger.info(f"Environment initialized: {env_file}, {path_file}")

    def persist_config(self):
        """Moves configuration files from ephemeral install dir to persistent volume."""
        for filename in self.CONFIG_FILES:
            install_path: Path = self.config.runner_root / filename
            volume_path: Path = self.config.runner_home / filename

            if install_path.exists() and not install_path.is_symlink():
                if volume_path.exists():
                    if volume_path.is_dir():
                        shutil.rmtree(volume_path)
                    else:
                        volume_path.unlink()

                shutil.move(str(install_path), str(volume_path))
                logger.debug(f"Persisted {filename} to volume.")

        self.restore_config_links()

    def restore_config_links(self):
        """Creates symlinks from install dir to persistent volume."""
        for filename in self.CONFIG_FILES:
            install_path: Path = self.config.runner_root / filename
            volume_path: Path = self.config.runner_home / filename

            if volume_path.exists():
                if install_path.exists() or install_path.is_symlink():
                    install_path.unlink(missing_ok=True)

                install_path.symlink_to(volume_path)
                logger.info(f"Linked {install_path} -> {volume_path}")
            else:
                logger.debug(f"Config file {filename} not found on volume, skipping symlink")

class RetryPolicy:
    """
    Class-based decorator for network resilience.
    It inspects the instance ('self') to find configuration.
    """

    def __init__(self, exceptions=(URLError, HTTPError)):
        self.exceptions = exceptions

    def __call__(self, func):
        @functools.wraps(func)
        def wrapper(obj, *args, **kwargs):
            # Extract configuration from the decorated method's instance
            # The 'obj' parameter represents 'self' from the instance method

            config = getattr(obj, 'config', None)

            # Use instance configuration if available, otherwise apply default values
            if config and hasattr(config, 'api_retries'):
                max_retries = config.api_retries
                backoff_factor = config.api_backoff
            else:
                max_retries = 3
                backoff_factor = 1.5

            delay = 1.0
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    # Call the instance method: func(self, *args)
                    return func(obj, *args, **kwargs)
                except self.exceptions as e:
                    last_exception = e

                    # Fail fast on 4xx client errors (do not retry)
                    if isinstance(e, HTTPError) and 400 <= e.code < 500:
                        raise e

                    if attempt < max_retries:
                        # Apply jitter to prevent thundering herd problem
                        sleep_time = delay * (1 + random.random() * 0.1)
                        logger.warning(f"Network error: {e}. Retrying in {sleep_time:.2f}s (Attempt {attempt + 1}/{max_retries})...")

                        time.sleep(sleep_time)
                        delay *= backoff_factor

            # Reaching here means all retry attempts have been exhausted without success
            if last_exception:
                logger.error(f"Operation failed after {max_retries} retries: {last_exception}")
                raise last_exception

            # Safeguard for edge cases (should not occur if max_retries >= 0)
            raise RunnerError("Operation failed with unknown error.")

        return wrapper

class GitHubClient:
    """
    Handles interaction with GitHub API to retrieve tokens.
    """

    def __init__(self, config: Config):
        self.config = config

    def _get_api_url(self, action: str) -> str:
        parsed = urlparse(self.config.github_url)
        parts: List[str] = [p for p in parsed.path.split('/') if p]

        scope: str = ""
        if len(parts) == 1:
            scope = f"orgs/{parts[0]}"
        elif len(parts) >= 2:
            scope = f"repos/{parts[0]}/{parts[1]}"
        else:
            raise RunnerError(f"Invalid GITHUB_URL format: {self.config.github_url}")

        api_base: str
        if parsed.hostname == "github.com":
            api_base = "https://api.github.com"
        else:
            api_base = f"{parsed.scheme}://{parsed.netloc}/api/v3"

        return f"{api_base}/{scope}/actions/runners/{action}-token"

    # Network operation helper method decorated with retry logic
    # The RetryPolicy decorator intercepts URLError/HTTPError exceptions and performs automatic retries
    @RetryPolicy()
    def _send_request(self, req: Request) -> bytes:
        with urlopen(req, timeout=30) as resp:
            return resp.read()

    def get_token(self, action: str) -> str:
        """
        Retrieves a token with the following priority:
        1. Use explicit GITHUB_TOKEN environment variable if provided
        2. Generate token via GitHub API using GITHUB_PAT
        """
        if self.config.github_token:
            logger.info(f"Using provided GITHUB_TOKEN for {action}.")
            return self.config.github_token

        if not self.config.github_pat:
            raise RunnerError(f"No GITHUB_TOKEN or GITHUB_PAT available for {action}.")

        api_url: str = self._get_api_url(action)
        logger.info(f"Requesting {action} token via API...")

        req = Request(api_url, method="POST")
        req.add_header("Authorization", f"Bearer {self.config.github_pat}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")

        user_agent = f"RunnerController/{__version__} (Python {platform.python_version()}; {platform.system()})"
        req.add_header("User-Agent", user_agent)

        try:
            raw_response = self._send_request(req)

            data = json.loads(raw_response.decode())
            return data["token"]
        except HTTPError as e:
            if e.code == 401:
                raise RunnerError("Invalid GITHUB_PAT (401 Unauthorized).")
            elif e.code == 404:
                raise RunnerError("Repo/Org not found or PAT missing permissions (404).")
            raise RunnerError(f"GitHub API Error: {e.code} {e.reason}")
        except URLError as e:
            raise RunnerError(f"Token fetch failed: {str(e)}")
        except (KeyError, json.JSONDecodeError) as e:
            raise RunnerError(f"Invalid API response: {str(e)}")

class RunnerService:
    """
    Orchestrates the runner lifecycle (Configure -> Run -> Remove).
    """
    IO_POLL_INTERVAL = 1.0
    ERROR_LOG_SIZE = 50
    TERMINATION_TIMEOUT = 5.0

    def __init__(self, config: Config, fman: FileSystemManager, gh_client: GitHubClient):
        self.config = config
        self.fman = fman
        self.github = gh_client
        self._shutdown_requested: bool = False

    def _terminate_process(self, process: subprocess.Popen) -> None:
        """
        Terminate subprocess gracefully, escalating to force kill if needed.
        
        Args:
            process: The subprocess to terminate.
        """
        if process is None or process.poll() is not None:
            return

        try:
            # Attempt graceful shutdown first (SIGTERM)
            process.terminate()
            process.wait(timeout=self.TERMINATION_TIMEOUT)
        except subprocess.TimeoutExpired:
            # Force kill if graceful termination fails (SIGKILL)
            process.kill()
            try:
                process.wait(timeout=self.TERMINATION_TIMEOUT)
            except subprocess.TimeoutExpired:
                # Process is stuck, will become zombie - OS will eventually clean up
                pass

    def _exec(self, args: List[str], timeout: Optional[int] = None) -> int:
        """
        Helper to execute subprocess command.
        
        Args:
            args: Command arguments as list.
            timeout: Max execution time in seconds (None for infinite).
        """
        start_time = time.time()
        binary_name = args[0]

        captured_lines = deque(maxlen=self.ERROR_LOG_SIZE)
        process = None

        try:
            with subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr and stdout into single stream
                text=True,
                cwd=self.config.runner_home,
                bufsize=1  # Line buffered
            ) as proc:
                # Lazy initialization pattern
                process = proc

                while True:
                    run_time = time.time() - start_time
                    if timeout:
                        if run_time > timeout:
                            # Timeout exceeded before entering wait state
                            raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)
                        wait_time = timeout - run_time
                    else:
                        # No timeout specified (run mode): use heartbeat interval
                        # to periodically check for OS signals and prevent indefinite blocking
                        wait_time = self.IO_POLL_INTERVAL

                    # Pass precise wait time to select() for I/O monitoring
                    rlist = [process.stdout.fileno()]
                    rready, _, _ = select.select(rlist, [], [], wait_time)

                    # If select() returned empty list (poll interval elapsed with no data)
                    if not rready:
                        # No data available. Check if process has terminated.
                        # https://docs.python.org/3/library/subprocess.html#subprocess.Popen.poll
                        if process.poll() is not None:
                            break
                        # Process still alive, no data ready. Continue to next iteration
                        # to check timeout at start of loop
                        continue

                    # https://docs.python.org/3/library/subprocess.html#subprocess.Popen.stdout
                    line = process.stdout.readline()

                    # Process terminated, no more output available
                    if not line:
                        break

                    sys.stdout.write(line)
                    sys.stdout.flush()

                    captured_lines.append(line)

            return_code = process.poll()

            if return_code != 0:
                # Convert deque to string for error reporting
                error_context = "".join(captured_lines).strip()
                raise RunnerError(f"Command failed (Code {return_code}).\nLast output:\n{error_context}")

            return return_code

        except subprocess.TimeoutExpired:
            self._terminate_process(process)

            # Extract accumulated log from deque
            error_context = "".join(captured_lines).strip()
            stderr_info = f"\nLast output:\n{error_context}" if error_context else ""

            logger.error(f"Command timed out after {timeout}s: {' '.join(args)}{stderr_info}")

            # Return terminated error exit code
            return RunnerExitCode.TERMINATED_ERROR
        except FileNotFoundError:
            raise RunnerError(f"Binary not found: {binary_name}")
        except Exception as e:
            self._terminate_process(process)

            # If already RunnerError (from non-zero return code), re-raise unchanged
            if isinstance(e, RunnerError):
                raise e
            # Handle unexpected errors
            raise RunnerError(f"Unexpected error executing {binary_name}: {e}")

    def configure(self):
        """Configure and register the runner"""
        logger.info("Configuring runner...")

        # Create environment files
        self.fman.create_env_files()

        # Fetch registration token
        token: str = self.github.get_token("registration")

        # Build command
        cmd: List[str] = [
            str(self.config.listener_bin), "configure",
            "--unattended",
            "--token", token,
            "--url", str(self.config.github_url),
            "--name", self.config.runner_name,
            "--labels", self.config.runner_labels,
            "--work", self.config.runner_work_dir,
            "--replace"
        ]

        # Add optional runner group
        if self.config.runner_group:
            cmd.extend(["--runnergroup", self.config.runner_group])

        # Disable self-updates (recommended for containerized runners)
        if self.config.disable_update:
            cmd.append("--disableupdate")
            logger.info("Self-updates disabled")

        logger.info(f"Configuring runner: {self.config.runner_name} (Timeout: {self.config.setup_timeout}s)")
        logger.info(f"Labels: {self.config.runner_labels}")

        # Execute with timeout
        if (returncode := self._exec(cmd, timeout=self.config.setup_timeout)) == 0:
            logger.info("Runner configured successfully.")
            self.fman.persist_config()
        else:
            raise RunnerError(f"Configuration failed with code {returncode}")

    def run(self):
        """Run the runner listener with auto-restart logic"""
        logger.info("Starting runner...")

        # Persist any orphaned configs and restore symlinks before starting
        self.fman.persist_config()

        with SignalHandler() as handler:
            try:
                # Main run loop
                while not handler.shutdown_requested:
                    logger.info("Starting Runner.Listener...")

                    cmd: List[str] = [str(self.config.listener_bin), "run"]
                    return_code: int = self._exec(cmd)

                    # Check shutdown flag immediately after subprocess completes
                    # Signal may have arrived while waiting for process termination
                    if handler.shutdown_requested:
                        logger.info("Shutdown detected during execution loop.")
                        break

                    # Map raw int to Enum for readability
                    try:
                        exit_status = RunnerExitCode(return_code)
                    except ValueError:
                        logger.warning(f"Unknown exit code: {return_code}")
                        break

                    logger.info(f"Runner.Listener exited with code {return_code}")

                    if exit_status == RunnerExitCode.SUCCESS:
                        logger.info("Runner exited normally.")
                        break
                    elif exit_status == RunnerExitCode.TERMINATED_ERROR:
                        logger.error("Runner terminated with error.")
                        break
                    elif exit_status == RunnerExitCode.RETRYABLE_ERROR:
                        logger.warning("Retryable error. Restarting in 5s...")
                        time.sleep(5)
                        continue
                    elif exit_status in (RunnerExitCode.UPDATE_REQUIRED, RunnerExitCode.EPHEMERAL_UPDATE_REQUIRED):
                        logger.info(f"Update requested (Code {return_code}). Exiting container for rebuild.")
                        break
                    elif exit_status == RunnerExitCode.SESSION_CONFLICT:
                        logger.error("Session conflict detected.")
                        break
                    else:
                        logger.warning(f"Unexpected exit code: {return_code}")
                        break
            finally:
                # Guaranteed state persistence on exit
                # Preserves .credentials during updates, interrupts, errors, and all exit scenarios
                logger.info("Persisting runner state and restoring symlinks before exit...")
                self.fman.persist_config()

        logger.info("Runner service stopped.")

    def remove(self):
        """Remove and unregister the runner"""
        logger.info("Removing runner...")

        # Restore configuration symlinks before unregistration
        self.fman.restore_config_links()

        # Fetch removal token
        token: str = self.github.get_token("remove")

        # Build command
        cmd: List[str] = [
            str(self.config.listener_bin),
            "remove",
            "--token", token
        ]

        # Execute with timeout
        if (returncode := self._exec(cmd, timeout=self.config.setup_timeout)) == 0:
            logger.info("Runner removed successfully")
        else:
            raise RunnerError(f"Removal failed with code {returncode}")

def main():
    """Main entry point"""

    # Use argparse for better CLI handling
    parser = argparse.ArgumentParser(description="GitHub Actions Runner Controller")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Subcommands
    subparsers.add_parser("configure", help="Configure the runner")
    subparsers.add_parser("run", help="Start the runner listener")
    subparsers.add_parser("remove", help="Unregister the runner")
    subparsers.add_parser("delete", help="Alias for remove")

    args = parser.parse_args()

    # Default to 'run' if no args provided
    command = args.command or "run"

    try:
        # Initialize Dependency Injection
        config = Config()
        config.validate()

        fman = FileSystemManager(config)
        fman.check_user_permissions()

        # Initialize controller
        github = GitHubClient(config)
        service = RunnerService(config, fman, github)

        # Execute
        if command == "configure":
            service.configure()
        elif command == "run":
            service.run()
        elif command in ("remove", "delete"):
            service.remove()
    except RunnerError as e:
        logger.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(0)
    except Exception:
        logger.exception("Unexpected error occurred.")
        sys.exit(1)

if __name__ == "__main__":
    main()