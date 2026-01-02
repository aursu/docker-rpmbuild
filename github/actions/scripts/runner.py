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
import json
import logging
import os
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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("runner-ctl")

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

    github_url: Optional[str] = os.getenv("GITHUB_URL")
    github_token: Optional[str] = os.getenv("GITHUB_TOKEN")
    github_pat: Optional[str] = os.getenv("GITHUB_PAT")

    runner_name: str = os.getenv("RUNNER_NAME") or f"github-actions-runner-{socket.gethostname()}"
    runner_group: str = os.getenv("RUNNER_GROUP", "Default")
    runner_labels: str = os.getenv("RUNNER_LABELS", "self-hosted,linux,x64")
    runner_work_dir: str = os.getenv("RUNNER_WORKSPACE", "_work")

    allow_root: bool = bool(os.getenv("RUNNER_ALLOW_RUNASROOT"))
    disable_update: bool = bool(os.getenv("RUNNER_DISABLE_UPDATE"))

    @property
    def listener_bin(self) -> Path:
        return self.runner_root / "bin" / "Runner.Listener"

    def validate(self):
        """Validates critical configuration presence."""
        if not self.github_url:
            raise RunnerError("GITHUB_URL environment variable is required.")
        if not self.github_token and not self.github_pat:
            raise RunnerError("Either GITHUB_TOKEN or GITHUB_PAT must be provided.")

class RunnerService:
    """Unified GitHub Actions Runner Controller"""

    # Environment variables to capture in .env file (from env.sh)
    ENV_VARS: List[str] = [
        'LANG', 'JAVA_HOME', 'ANT_HOME', 'M2_HOME',
        'ANDROID_HOME', 'ANDROID_SDK_ROOT', 'GRADLE_HOME',
        'NVM_BIN', 'NVM_PATH', 'LD_LIBRARY_PATH', 'PERL5LIB'
    ]

    # Runner configuration files to persist on volume
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

    def __init__(self):
        self.runner_home: Path = Path(os.getenv("RUNNER_HOME", "/home/runner"))
        self.runner_root: Path = Path(os.getenv("RUNNER_ROOT", "/usr/local/runner"))

        self.listener_bin: Path = self.runner_root / "bin" / "Runner.Listener"

        # GitHub configuration
        self.github_url: Optional[str] = os.getenv("GITHUB_URL")
        self.github_token: Optional[str] = os.getenv("GITHUB_TOKEN")
        self.github_pat: Optional[str] = os.getenv("GITHUB_PAT")

        # Runner configuration
        self.runner_name: str = os.getenv("RUNNER_NAME") or f"github-actions-runner-{socket.gethostname()}"
        self.runner_group: str = os.getenv("RUNNER_GROUP", "Default")
        self.runner_labels: str = os.getenv("RUNNER_LABELS", "self-hosted,linux,x64")
        self.runner_workspace: str = os.getenv("RUNNER_WORKSPACE", "_work")

        # Runtime flags
        self.allow_root: Optional[str] = os.getenv("RUNNER_ALLOW_RUNASROOT")
        self.disable_update: Optional[str] = os.getenv("RUNNER_DISABLE_UPDATE")

        # Shutdown flag for signal handling
        self.shutdown_requested: bool = False

    def check_not_root(self):
        """Verify not running as root unless explicitly allowed"""
        if os.geteuid() == 0 and not self.allow_root:
            logger.error("Must not run as root. Set RUNNER_ALLOW_RUNASROOT to override.")
            sys.exit(1)

    def create_env_files(self):
        """Create .env and .path files (from env.sh)"""
        env_file: Path = self.runner_home / ".env"
        path_file: Path = self.runner_home / ".path"

        # Read existing .env content if it exists
        existing_vars: Set[str] = set()
        if env_file.exists():
            with open(env_file, 'r') as f:
                for line in f:
                    if '=' in line:
                        var_name = line.split('=')[0]
                        existing_vars.add(var_name)

        # Append new variables that don't exist
        with open(env_file, 'a') as f:
            for var_name in self.ENV_VARS:
                if var_name not in existing_vars:
                    value = os.getenv(var_name)
                    if value:
                        f.write(f"{var_name}={value}\n")
                        logger.debug(f"Added {var_name} to .env")

        # Write PATH to .path file
        with open(path_file, 'w') as f:
            f.write(os.getenv("PATH", ""))

        logger.info(f"Created/updated environment files: {env_file}, {path_file}")

    def get_api_url(self, action: str = "registration") -> str:
        """Generate GitHub API URL for token generation"""
        if not self.github_url:
            logger.error("GITHUB_URL environment variable is required")
            sys.exit(1)

        parsed = urlparse(self.github_url)
        # Type hint for parts helps understand it's a list of strings
        parts: List[str] = [p for p in parsed.path.split('/') if p]

        scope_path: str = ""
        if len(parts) == 1:
            # Organization scope
            scope_path = f"orgs/{parts[0]}"
        elif len(parts) >= 2:
            # Repository scope
            scope_path = f"repos/{parts[0]}/{parts[1]}"
        else:
            raise ValueError(f"Invalid GITHUB_URL format: {self.github_url}")

        # Determine API base URL
        api_base: str
        if parsed.hostname == "github.com":
            api_base = "https://api.github.com"
        else:
            # GitHub Enterprise Server
            api_base = f"{parsed.scheme}://{parsed.netloc}/api/v3"

        return f"{api_base}/{scope_path}/actions/runners/{action}-token"

    def fetch_token(self, action: str = "registration") -> str:
        """
        Fetches the runner token with the following priority:
        Priority 1: GITHUB_TOKEN (direct registration/removal token).
        Priority 2: Generated via GITHUB_PAT (Personal Access Token).
        """
        if self.github_token:
            logger.info(f"Using pre-provisioned GITHUB_TOKEN for {action}, skipping API call")
            return self.github_token

        if not self.github_pat:
            logger.error(f"Error: Neither GITHUB_TOKEN nor GITHUB_PAT provided for {action}.")
            sys.exit(1)

        api_url: str = self.get_api_url(action)
        logger.info(f"Fetching {action} token from GitHub API using GITHUB_PAT...")

        req = Request(api_url, method="POST")
        req.add_header("Authorization", f"Bearer {self.github_pat}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")

        try:
            with urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                token: str = data["token"]
                logger.info(f"Successfully fetched {action} token")
                return token
        except HTTPError as e:
            logger.error(f"GitHub API error: {e.code} - {e.reason}")
            if e.code == 401:
                logger.error("Invalid or expired GITHUB_PAT")
            elif e.code == 404:
                logger.error("Resource not found or insufficient permissions")
            sys.exit(1)
        except URLError as e:
            logger.error(f"Network error: {e.reason}")
            sys.exit(1)
        except (KeyError, json.JSONDecodeError) as e:
            logger.error(f"Invalid API response: {e}")
            sys.exit(1)

    def signal_handler(self, signum: int, frame: Any):
        """Handle shutdown signals"""
        try:
            sig_name = signal.Signals(signum).name
        except ValueError:
            sig_name = str(signum)
        logger.info(f"Received {sig_name}, shutting down gracefully...")
        self.shutdown_requested = True

    def _persist_config(self):
        """
        Move newly created runner configuration files to volume-mounted storage.
        """
        for filename in self.CONFIG_FILES:
            install_path: Path = self.runner_root / filename
            volume_path: Path = self.runner_home / filename

            # Move newly created config file/directory from install directory to volume
            if install_path.exists() and not install_path.is_symlink():
                logger.info(f"Persisting {filename} to volume...")
                # Remove existing file/directory on volume if present
                if volume_path.exists():
                    if volume_path.is_dir():
                        shutil.rmtree(volume_path)
                    else:
                        volume_path.unlink()  # Handles both files and symlinks

                # Move to volume
                shutil.move(str(install_path), str(volume_path))
                logger.info(f"Moved {filename} to volume")

        self._restore_config_links()

    def _restore_config_links(self):
        """
        Restore symlinks from installation directory to volume-mounted storage.
        """
        for filename in self.CONFIG_FILES:
            install_path: Path = self.runner_root / filename
            volume_path: Path = self.runner_home / filename

            # Create symlink from install directory to volume
            if volume_path.exists():
                # Remove existing file or symlink at install location
                if install_path.exists() or install_path.is_symlink():
                    install_path.unlink(missing_ok=True)

                install_path.symlink_to(volume_path)
                logger.info(f"Linked {install_path} -> {volume_path}")
            else:
                logger.debug(f"Config file {filename} not found on volume, skipping symlink")

    def configure(self):
        """Configure and register the runner"""
        logger.info("Configuring runner...")

        # Create environment files
        self.create_env_files()

        # Fetch registration token
        token: str = self.fetch_token("registration")

        # Build command
        cmd: List[str] = [
            str(self.listener_bin),
            "configure",
            "--unattended",
            "--token", token,
            "--url", str(self.github_url),
            "--name", self.runner_name,
            "--labels", self.runner_labels,
            "--work", self.runner_workspace,
        ]

        # Add optional runner group
        if self.runner_group:
            cmd.extend(["--runnergroup", self.runner_group])

        # Add replace flag to allow re-registration
        cmd.append("--replace")

        # Disable self-updates (recommended for containerized runners)
        if self.disable_update:
            cmd.append("--disableupdate")
            logger.info("Self-updates disabled")

        logger.info(f"Configuring runner: {self.runner_name}")
        logger.info(f"Labels: {self.runner_labels}")

        # Execute
        result = subprocess.run(cmd, cwd=self.runner_home)

        if result.returncode == 0:
            logger.info("Runner configured successfully")
            self._persist_config()
        else:
            logger.error(f"Configuration failed with code {result.returncode}")
            sys.exit(result.returncode)

    def run(self):
        """Run the runner listener with auto-restart logic"""
        logger.info("Starting runner...")

        # Persist any orphaned configs and restore symlinks before starting
        self._persist_config()

        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # Main run loop
        while not self.shutdown_requested:
            logger.info("Starting Runner.Listener...")

            cmd: List[str] = [str(self.listener_bin), "run"]

            # Run the listener
            result = subprocess.run(cmd, cwd=self.runner_home)
            return_code: int = result.returncode

            logger.info(f"Runner.Listener exited with code {return_code}")

            # Handle return codes
            if return_code == 0:
                logger.info("Runner listener exit with 0 return code, stop the service, no retry needed.")
                break

            elif return_code == 1:
                logger.info("Runner listener exit with terminated error, stop the service, no retry needed.")
                break

            elif return_code == 2:
                logger.info("Runner listener exit with retryable error, re-launch runner in 5 seconds.")
                time.sleep(5)
                # Check for broken symlinks before restart
                self._persist_config()
                continue

            elif return_code in (3, 4):
                update_type = "Runner update" if return_code == 3 else "Ephemeral runner update"
                logger.info(f"{update_type} requested, but updates are disabled in container. Exiting.")
                logger.info("To update: rebuild Docker image with new runner version")
                break

            elif return_code == 5:
                logger.info("Runner listener exit with Session Conflict error, stop the service, no retry needed.")
                break

            else:
                logger.warning(f"Exiting with unknown error code: {return_code}")
                break

        if self.shutdown_requested:
            logger.info("Shutdown completed")
        else:
            logger.info("Runner stopped")

    def remove(self):
        """Remove and unregister the runner"""
        logger.info("Removing runner...")

        # IMPORTANT: Restore symlinks before removal
        self._restore_config_links()

        # Fetch removal token
        token: str = self.fetch_token("remove")

        # Build command
        cmd: List[str] = [
            str(self.listener_bin),
            "remove",
            "--token", token
        ]

        # Execute
        result = subprocess.run(cmd, cwd=self.runner_home)

        if result.returncode == 0:
            logger.info("Runner removed successfully")
        else:
            logger.error(f"Removal failed with code {result.returncode}")
            sys.exit(result.returncode)

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

        # Initialize controller
        service = RunnerService()

        # Common checks
        service.check_not_root()

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