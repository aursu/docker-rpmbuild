import os
import sys
import subprocess
import json
import logging
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("runner-config")

class RunnerConfigurator:
    def __init__(self):
        self.runner_home = Path(os.getenv("RUNNER_HOME", os.getcwd()))
        self.root_dir = Path("/usr/local/runner")
        self.pat = os.getenv("GITHUB_PAT")
        self.org_name = os.getenv("ORG_NAME")

        # Параметры для передачи в Listener
        self.config_args = {
            "--url": os.getenv("GITHUB_URL"),
            "--name": f"{os.getenv('RUNNER_NAME')}-{os.gethostname()}",
            "--runnergroup": os.getenv("RUNNER_GROUP", "Default"),
            "--labels": os.getenv("RUNNER_LABELS", "self-hosted,linux,x64"),
            "--work": os.getenv("RUNNER_WORKSPACE", "_work"),
        }

    def check_dependencies(self):
        """Реализация проверок из вашего config.sh"""
        logger.info("Checking dependencies for .NET Core 6.0...")

        # 1. Проверка на root
        if os.getuid() == 0 and not os.getenv("RUNNER_ALLOW_RUNASROOT"):
            logger.error("Must not run with sudo / root")
            sys.exit(1)

        # 2. Проверка критических библиотек (аналог ldd | grep 'not found')
        libs_to_check = [
            "libcoreclr.so",
            "libSystem.Security.Cryptography.Native.OpenSsl.so",
            "libSystem.IO.Compression.Native.so"
        ]

        for lib in libs_to_check:
            lib_path = self.root_dir / "bin" / lib
            try:
                result = subprocess.run(["ldd", str(lib_path)], capture_output=True, text=True, check=True)
                if "not found" in result.stdout:
                    logger.error(f"Dependency missing for {lib}:\n{result.stdout}")
                    sys.exit(1)
            except subprocess.CalledProcessError:
                logger.error(f"Could not run ldd on {lib_path}")
                sys.exit(1)

        logger.info("All dependencies found.")

    def get_token(self, token_type="registration"):
        """Получение токена (Registration/Remove) через GitHub API"""
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
        """Прямой вызов бинарного файла Runner.Listener"""
        listener_bin = self.root_dir / "bin" / "Runner.Listener"

        if not listener_bin.exists():
            logger.error(f"Binary not found: {listener_bin}")
            sys.exit(1)

        # Валидация обязательных параметров для configure
        if mode == "configure":
            if not self.config_args.get("--url"):
                logger.error("GITHUB_URL environment variable is required")
                sys.exit(1)

        # Подготовка аргументов
        token = self.get_token("registration" if mode == "configure" else "remove")

        cmd = [str(listener_bin), mode, "--unattended", "--token", token]

        if mode == "configure":
            cmd.append("--replace")
            for key, value in self.config_args.items():
                cmd.extend([key, value])

        logger.info(f"Executing: {' '.join(cmd)}")

        # Важно: Runner.Listener ожидает переменные из env.sh
        # Мы можем передать их через env параметр
        current_env = os.environ.copy()
        # Если в env.sh есть специфические переменные, добавляем их тут

        result = subprocess.run(cmd, cwd=self.runner_home, env=current_env)
        if result.returncode != 0:
            logger.error(f"Listener failed with code {result.returncode}")
            sys.exit(result.returncode)

if __name__ == "__main__":
    configurator = RunnerConfigurator()
    configurator.check_dependencies()

    # Режим работы: configure (по умолчанию) или remove
    mode = "remove" if len(sys.argv) > 1 and sys.argv[1] == "remove" else "configure"
    configurator.run_listener(mode)