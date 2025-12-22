import os
import sys
import subprocess
import json
import logging
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("runner-config")

class RunnerConfigurator:
    def __init__(self):
        self.runner_home = Path(os.getenv("RUNNER_HOME", "/home/runner"))
        self.runner_root = Path(os.getenv("RUNNER_ROOT", "/usr/local/runner"))
        self.binary = self.runner_root / "bin" / "Runner.Listener"

        self.pat = os.getenv("GITHUB_PAT")
        self.org_name = os.getenv("ORG_NAME")
        self.github_url = os.getenv("GITHUB_URL")

        # Configuration parameters for Runner.Listener
        self.config_args = {
            "--url": os.getenv("GITHUB_URL"),
            "--name": f"{os.getenv('RUNNER_NAME')}-{os.gethostname()}",
            "--runnergroup": os.getenv("RUNNER_GROUP", "Default"),
            "--labels": os.getenv("RUNNER_LABELS", "self-hosted,linux,x64"),
            "--work": os.getenv("RUNNER_WORKSPACE", "_work"),
        }

    def _get_api_info(self, action="registration"):
        """Determines the API URL based on GITHUB_URL (Organization vs Repository scope)."""
        parsed = urlparse(self.github_url)
        parts = [p for p in parsed.path.split('/') if p]

        if len(parts) == 1:
            # Organization level scope
            scope_path = f"orgs/{parts[0]}"
        elif len(parts) >= 2:
            # Repository level scope
            scope_path = f"repos/{parts[0]}/{parts[1]}"
        else:
            raise ValueError(f"Invalid GITHUB_URL: {self.github_url}")

        return f"https://api.github.com/{scope_path}/actions/runners/{action}-token"

    def _fetch_token(self, action="registration"):
        """
        Fetches the runner token with the following priority:
        Priority 1: GITHUB_TOKEN (direct registration/removal token).
        Priority 2: Generated via GITHUB_PAT (Personal Access Token).
        """
        # Check for direct token availability (highest priority)
        runner_token = os.getenv("GITHUB_TOKEN")
        if runner_token:
            logger.info(f"Using provided GITHUB_TOKEN for {action} (Priority: High)")
            return runner_token

        # If no direct token is provided, check for PAT to call GitHub API
        if not self.pat:
            logger.error(f"Error: Neither GITHUB_TOKEN nor GITHUB_PAT provided for {action}.")
            sys.exit(1)

        api_url = self._get_api_info(action)
        logger.info(f"Fetching {action} token from GitHub API using GITHUB_PAT...")

        req = Request(api_url, method="POST")
        req.add_header("Authorization", f"Bearer {self.pat}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")

        try:
            with urlopen(req) as resp:
                return json.loads(resp.read().decode())["token"]
        except Exception as e:
            logger.error(f"Failed to fetch {action} token via API: {e}")
            sys.exit(1)

    def get_token(self, token_type="registration"):
        """Retrieves runner token (Registration/Remove) via GitHub REST API."""
        if not self.pat:
            logger.error("GITHUB_PAT environment variable is not set")
            sys.exit(1)
        if not self.org_name:
            logger.error("ORG_NAME environment variable is not set")
            sys.exit(1)

        url = f"https://api.github.com/orgs/{self.org_name}/actions/runners/{token_type}-token"
        headers = {
            "Authorization": f"Bearer {self.pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        try:
            req = Request(url, headers=headers, method="POST")
            with urlopen(req) as resp:
                return json.loads(resp.read().decode())["token"]
        except HTTPError as e:
            logger.error(f"GitHub API error: {e.code} - {e.reason}")
            if e.code == 401:
                logger.error("Invalid or expired GitHub PAT token")
            elif e.code == 404:
                logger.error(f"Organization '{self.org_name}' not found or no access")
            sys.exit(1)
        except URLError as e:
            logger.error(f"Network error: {e.reason}")
            sys.exit(1)
        except (KeyError, json.JSONDecodeError) as e:
            logger.error(f"Invalid response from GitHub API: {e}")
            sys.exit(1)

    def run_listener(self, mode="configure"):
        """Executes the Runner.Listener binary with specified configuration mode."""
        listener_bin = self.runner_root / "bin" / "Runner.Listener"

        if not listener_bin.exists():
            logger.error(f"Binary not found: {listener_bin}")
            sys.exit(1)

        # Validate required parameters for configure mode
        if mode == "configure":
            if not self.config_args.get("--url"):
                logger.error("GITHUB_URL environment variable is required")
                sys.exit(1)

        # Prepare command-line arguments
        token = self.get_token("registration" if mode == "configure" else "remove")

        cmd = [str(listener_bin), mode, "--unattended", "--token", token]

        if mode == "configure":
            cmd.append("--replace")
            for key, value in self.config_args.items():
                cmd.extend([key, value])

        logger.info(f"Executing: {' '.join(cmd)}")

        # Note: Runner.Listener expects environment variables from env.sh
        # These can be passed via the env parameter
        current_env = os.environ.copy()
        # Add any specific variables from env.sh here if required

        result = subprocess.run(cmd, cwd=self.runner_home, env=current_env)
        if result.returncode != 0:
            logger.error(f"Listener failed with code {result.returncode}")
            sys.exit(result.returncode)

if __name__ == "__main__":
    configurator = RunnerConfigurator()

    # Operation mode: configure (default) or remove
    mode = "remove" if len(sys.argv) > 1 and sys.argv[1] == "remove" else "configure"
    configurator.run_listener(mode)