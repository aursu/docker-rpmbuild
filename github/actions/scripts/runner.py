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

import os
import sys
import subprocess
import json
import logging
import time
import signal
import socket
import shutil
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("runner-ctl")


class RunnerController:
    """Unified GitHub Actions Runner Controller"""

    # Environment variables to capture in .env file (from env.sh)
    ENV_VARS = [
        'LANG', 'JAVA_HOME', 'ANT_HOME', 'M2_HOME',
        'ANDROID_HOME', 'ANDROID_SDK_ROOT', 'GRADLE_HOME',
        'NVM_BIN', 'NVM_PATH', 'LD_LIBRARY_PATH', 'PERL5LIB'
    ]

    def __init__(self):
        self.runner_home = Path(os.getenv("RUNNER_HOME", "/home/runner"))
        self.runner_root = Path(os.getenv("RUNNER_ROOT", "/usr/local/runner"))

        self.listener_bin = self.runner_root / "bin" / "Runner.Listener"

        # GitHub configuration
        self.github_url = os.getenv("GITHUB_URL")
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.github_pat = os.getenv("GITHUB_PAT")

        # Runner configuration
        self.runner_name = os.getenv("RUNNER_NAME") or f"github-actions-runner-{socket.gethostname()}"
        self.runner_group = os.getenv("RUNNER_GROUP", "Default")
        self.runner_labels = os.getenv("RUNNER_LABELS", "self-hosted,linux,x64")
        self.runner_workspace = os.getenv("RUNNER_WORKSPACE", "_work")

        # Runtime flags
        self.allow_root = os.getenv("RUNNER_ALLOW_RUNASROOT")
        self.disable_update = os.getenv("RUNNER_DISABLE_UPDATE")

        # Shutdown flag for signal handling
        self.shutdown_requested = False

    def check_not_root(self):
        """Verify not running as root unless explicitly allowed"""
        if os.geteuid() == 0 and not self.allow_root:
            logger.error("Must not run as root. Set RUNNER_ALLOW_RUNASROOT to override.")
            sys.exit(1)

    def create_env_files(self):
        """Create .env and .path files (from env.sh)"""
        env_file = self.runner_home / ".env"
        path_file = self.runner_home / ".path"

        # Read existing .env content if it exists
        existing_vars = set()
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

    def get_api_url(self, action="registration"):
        """Generate GitHub API URL for token generation"""
        if not self.github_url:
            logger.error("GITHUB_URL environment variable is required")
            sys.exit(1)

        parsed = urlparse(self.github_url)
        parts = [p for p in parsed.path.split('/') if p]

        if len(parts) == 1:
            # Organization scope
            scope_path = f"orgs/{parts[0]}"
        elif len(parts) >= 2:
            # Repository scope
            scope_path = f"repos/{parts[0]}/{parts[1]}"
        else:
            raise ValueError(f"Invalid GITHUB_URL format: {self.github_url}")

        # Determine API base URL
        if parsed.hostname == "github.com":
            api_base = "https://api.github.com"
        else:
            # GitHub Enterprise Server
            api_base = f"{parsed.scheme}://{parsed.netloc}/api/v3"

        return f"{api_base}/{scope_path}/actions/runners/{action}-token"

    def fetch_token(self, action="registration"):
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

        api_url = self.get_api_url(action)
        logger.info(f"Fetching {action} token from GitHub API using GITHUB_PAT...")

        req = Request(api_url, method="POST")
        req.add_header("Authorization", f"Bearer {self.github_pat}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")

        try:
            with urlopen(req) as resp:
                token = json.loads(resp.read().decode())["token"]
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

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name}, shutting down gracefully...")
        self.shutdown_requested = True

    def _persist_config(self):
        """
        Persist runner configuration files to volume-mounted storage.
        
        Moves configuration files from the ephemeral installation directory 
        to the persistent home directory (volume) and creates symlinks back 
        to ensure configuration survives container restarts.
        """
        well_known_config_files = [
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

        for filename in well_known_config_files:
            install_path = self.runner_root / filename  # /usr/local/runner/.runner
            volume_path = self.runner_home / filename   # /home/runner/.runner

            # Step 1: Move newly created config file/directory from install directory to volume
            if install_path.exists() and not install_path.is_symlink():
                logger.info(f"Persisting {filename} to volume...")
                # Remove existing file/directory on volume if present
                if volume_path.exists():
                    if volume_path.is_dir():
                        shutil.rmtree(volume_path)
                    else:
                        volume_path.unlink()  # Handles both files and symlinks

                # Move physical file/directory to volume
                install_path.replace(volume_path)

            # Step 2: Create symlink from install directory to volume
            # Runner reads from install_path but accesses volume_path
            if volume_path.exists():
                if install_path.exists() or install_path.is_symlink():
                    install_path.unlink(missing_ok=True)

                install_path.symlink_to(volume_path)
                logger.info(f"Linked {install_path} -> {volume_path}")

    def configure(self):
        """Configure and register the runner"""
        logger.info("Configuring runner...")

        # Create environment files
        self.create_env_files()

        # Fetch registration token
        token = self.fetch_token("registration")

        # Build command
        cmd = [
            str(self.listener_bin),
            "configure",
            "--unattended",
            "--token", token,
            "--url", self.github_url,
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

        self._persist_config()

        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # Main run loop (from run.sh and run-helper.sh)
        while not self.shutdown_requested:
            logger.info("Starting Runner.Listener...")

            cmd = [str(self.listener_bin), "run"]

            # Run the listener
            result = subprocess.run(cmd, cwd=self.runner_home)
            return_code = result.returncode

            logger.info(f"Runner.Listener exited with code {return_code}")

            # Handle return codes (from run-helper.sh)
            if return_code == 0:
                logger.info("Runner listener exit with 0 return code, stop the service, no retry needed.")
                break

            elif return_code == 1:
                logger.info("Runner listener exit with terminated error, stop the service, no retry needed.")
                break

            elif return_code == 2:
                logger.info("Runner listener exit with retryable error, re-launch runner in 5 seconds.")
                time.sleep(5)
                continue

            elif return_code in (3, 4):
                # Runner update requested - exit instead of updating
                # In containerized environments, updates should be handled by rebuilding the image
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

        # Fetch removal token
        token = self.fetch_token("remove")

        # Build command
        cmd = [
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
    # Determine mode from command line
    mode = "run"  # default
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ("configure", "config"):
            mode = "configure"
        elif arg in ("remove", "delete", "unregister"):
            mode = "remove"
        elif arg in ("run", "start"):
            mode = "run"
        elif arg in ("-h", "--help", "help"):
            print(__doc__)
            sys.exit(0)
        else:
            print(f"Unknown command: {sys.argv[1]}")
            print("Usage: runner.py [configure|run|remove|delete]")
            sys.exit(1)

    # Initialize controller
    controller = RunnerController()

    # Common checks
    controller.check_not_root()

    # Execute mode
    if mode == "configure":
        controller.configure()
    elif mode == "run":
        controller.run()
    elif mode == "remove":
        controller.remove()

if __name__ == "__main__":
    main()
