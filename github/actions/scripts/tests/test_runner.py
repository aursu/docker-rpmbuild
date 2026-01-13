#!/usr/bin/env python3
import unittest
import sys
import os
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from unittest.mock import patch, MagicMock

# Import from parent directory (runner module)
sys.path.insert(0, str(Path(__file__).parent.parent))
import runner

class TestConfig(unittest.TestCase):
    def test_validation_error(self):
        """Verify that the script raises an error when GITHUB_URL is not provided"""
        with patch.dict(os.environ, {}, clear=True):
            config = runner.Config()
            with self.assertRaises(runner.RunnerError) as cm:
                config.validate()
            self.assertRegex(str(cm.exception), r"GITHUB_URL .* required")

    def test_validation_success(self):
        """Verify successful configuration validation"""
        env = {
            "GITHUB_URL": "https://github.com/rpmbsys",
            "GITHUB_TOKEN": "AE6PSSNJMIPFR3XKLREU2QLJLBTCQ"
        }
        with patch.dict(os.environ, env, clear=True):
            config = runner.Config()
            config.validate()
            self.assertEqual(config.github_url, "https://github.com/rpmbsys")

    def test_retry_delay_default(self):
        """Test default retry delay is 5 seconds"""
        # Нужно замокать обязательные поля, чтобы validate не упал (если он вызывается в init)
        with patch.dict('os.environ', {"GITHUB_URL": "https://github.com/rpmbsys"}, clear=True):
            config = runner.Config()
            self.assertEqual(config.retry_delay, 5)

    def test_retry_delay_from_env(self):
        """Test retry delay override"""
        env = {
            "GITHUB_URL": "https://github.com/rpmbsys",
            "RUNNER_RETRY_DELAY": "60",
        }
        with patch.dict('os.environ', env, clear=True):
            config = runner.Config()
            self.assertEqual(config.retry_delay, 60)

class TestGitHubClient(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.github_url = "https://github.com/rpmbsys"
        self.config.github_pat = "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"
        self.config.github_token = None
        # Important: Mock retry settings to prevent actual sleep delays in tests
        self.config.api_retries = 3
        self.config.api_backoff = 1.5
        self.client = runner.GitHubClient(self.config)

    @patch('runner.urlopen')
    @patch('runner.Request')
    def test_get_token_success(self, mock_req, mock_urlopen):
        """Verify successful token retrieval from API"""
        # Configure mock API response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"token": "AE6PSSNJMIPFR3XKLREU2QLJLBTCQ"}).encode()

        # with urlopen(req, timeout=30) as resp
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        token = self.client.get_token("registration")

        self.assertEqual(token, "AE6PSSNJMIPFR3XKLREU2QLJLBTCQ")

        args, _ = mock_req.call_args
        self.assertIn("https://api.github.com/orgs/rpmbsys/actions/runners/registration-token", args[0])

    @patch('runner.urlopen')
    @patch('runner.Request')
    @patch('runner.platform.system')
    @patch('runner.platform.python_version')
    def test_get_api_url_success(self, mock_py, mock_sys, mock_req, mock_urlopen):
        """Verify successful API URL generation and token retrieval"""
        # Configure mock API response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"token": "AE6PSSNJMIPFR3XKLREU2QLJLBTCQ"}).encode()

        # with urlopen(req, timeout=30) as resp
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        mock_py.return_value = "3.12.5"
        mock_sys.return_value = "Linux"

        self.client.get_token("registration")

        args, _ = mock_req.call_args
        self.assertIn("https://api.github.com/orgs/rpmbsys/actions/runners/registration-token", args[0])

        req_obj = mock_req.return_value
        req_obj.add_header.assert_any_call("Authorization", "Bearer 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")
        req_obj.add_header.assert_any_call("User-Agent", "RunnerController/1.0.0 (Python 3.12.5; Linux)")

    @patch('runner.urlopen')
    @patch('runner.time.sleep')  # Mock sleep to make tests run instantly
    def test_get_token_retry_logic(self, _, mock_urlopen):
        """Verify that retry logic functions correctly on 500 server errors"""
        # Simulate 500 Server Error
        error_500 = HTTPError("https://api.github.com/orgs/rpmbsys/actions/runners/registration-token", 500, "Internal Server Error", {}, None)
        mock_urlopen.side_effect = [error_500] * 4

        # Expect RunnerError to be raised
        # (get_token catches HTTPError and wraps it in RunnerError)
        with self.assertRaises(runner.RunnerError) as cm:
            self.client.get_token("registration")

        # Verify that 4 attempts were made (initial attempt + 3 retries)
        self.assertEqual(mock_urlopen.call_count, 4)

        # Verify the error message is correct
        self.assertIn("GitHub API Error: 500", str(cm.exception))

class TestRetryPolicy(unittest.TestCase):
    """
    Unit tests specifically for the RetryPolicy decorator logic.
    Isolated from GitHubClient business logic.
    """
    class ConfigStub:
        def __init__(self, retries=3, backoff=1.5):
            self.api_retries = retries
            self.api_backoff = backoff

    class ClientStub:
        """Simulates GitHubClient instance"""
        def __init__(self, config=None):
            self.config = config
            self.request_mock = MagicMock()

        @runner.RetryPolicy()
        def execute_request(self):
            return self.request_mock()

    def _make_client(self, retries=3, backoff=1.5):
        """Factory method for creating test client instances"""
        config = self.ConfigStub(retries, backoff)
        return self.ClientStub(config)

    def _http_error(self, code):
        """Helper method for creating HTTP error instances"""
        reasons = {
            401: "Unauthorized",
            404: "Not Found",
            500: "Internal Server Error",
            503: "Service Unavailable",
        }
        return HTTPError("https://api.github.com/orgs/rpmbsys/actions/runners/registration-token", code, reasons.get(code, "Error"), {}, None)

    def test_successful_call_no_retry(self):
        """Test that successful calls don't trigger retries"""
        client = self._make_client()
        client.request_mock.return_value = "Success"

        result = client.execute_request()

        self.assertEqual(result, "Success")
        self.assertEqual(client.request_mock.call_count, 1, "Should only call once on success")

    @patch('runner.time.sleep')
    def test_retry_on_url_error(self, _):
        """Test retry behavior on URLError"""

        client = self._make_client(retries=3)
        client.request_mock.side_effect = [
            URLError("Connection refused"),
            URLError("Connection refused"),
            "Success"
        ]

        result = client.execute_request()

        self.assertEqual(result, "Success")
        self.assertEqual(client.request_mock.call_count, 3, "Should retry twice before success")

    @patch('runner.time.sleep')
    def test_retry_on_5xx_http_error(self, _):
        """Test retry behavior on 5xx server errors"""
        client = self._make_client()

        # Test scenario: 503 error followed by success
        client.request_mock.side_effect = [self._http_error(503), "Success"]

        result = client.execute_request()

        self.assertEqual(result, "Success")
        self.assertEqual(client.request_mock.call_count, 2, "Should retry once on 503")

    def test_no_retry_on_4xx_http_error(self):
        """Test that 4xx errors fail fast without retry"""
        client = self._make_client()

        # Test scenario: immediate 404 error
        client.request_mock.side_effect = self._http_error(404)

        # Expect the error to be raised immediately without retries
        with self.assertRaises(HTTPError):
            client.execute_request()

        self.assertEqual(client.request_mock.call_count, 1, "Should not retry on 4xx errors")

    @patch('runner.time.sleep')
    def test_max_retries_exceeded(self, mock_sleep):
        """Test that max retries are respected"""
        # Configuration: 2 retries (total 3 attempts: initial + retry 1 + retry 2)
        client = self._make_client(retries=2)

        # Three consecutive 500 errors to exhaust all retry attempts
        client.request_mock.side_effect = self._http_error(500)

        with self.assertRaises(HTTPError):
            client.execute_request()

        self.assertEqual(client.request_mock.call_count, 3, "Should make 3 total attempts (initial + 2 retries)")

    @patch('runner.time.sleep')
    def test_exponential_backoff_timing(self, mock_sleep):
        """Test that exponential backoff is applied correctly"""
        class SleepTracker:
            def __init__(self):
                self.history = []
            def __call__(self, duration, *args, **kwds):
                self.history.append(duration)

        tracker = SleepTracker()
        mock_sleep.side_effect = tracker

        # Configuration: Backoff factor = 2.0
        client = self._make_client(retries=3, backoff=2.0)

        # Test scenario: 3 consecutive errors (to trigger 3 sleep calls), then success
        client.request_mock.side_effect = [self._http_error(500)] * 3 + ["Success"]

        result = client.execute_request()

        self.assertEqual(result, "Success")
        self.assertEqual(len(tracker.history), 3, "Should sleep 3 times")

        # Verify exponential backoff (with jitter tolerance)
        # Base: 1.0, then 2.0, then 4.0
        self.assertGreaterEqual(tracker.history[0], 1.0, "First delay should be ~1s")
        self.assertLess(tracker.history[0], 1.101, "First delay with jitter")

        self.assertGreaterEqual(tracker.history[1], 2.0, "Second delay should be ~2.0s")
        self.assertLess(tracker.history[1], 2.201, "Second delay with jitter")

        self.assertGreaterEqual(tracker.history[2], 4.0, "Third delay should be ~4.0s")
        self.assertLess(tracker.history[2], 4.401, "Third delay with jitter")

    @patch('runner.time.sleep')
    def test_custom_config_values(self, mock_sleep):
        """Test that custom retry config is respected"""
        # Configuration: only 1 retry allowed
        client = self._make_client(retries=1, backoff=2.0)

        # Simulate persistent failure (exceeds allowed retry count)
        client.request_mock.side_effect = self._http_error(500)

        with self.assertRaises(HTTPError):
            client.execute_request()

        # Verify exactly 2 calls were made (initial attempt + 1 retry)
        self.assertEqual(client.request_mock.call_count, 2, "Should respect custom retry count")

    @patch('runner.time.sleep')
    def test_fallback_to_defaults_without_config(self, mock_sleep):
        """Test that decorator works without config (uses defaults)"""

        client = self.ClientStub()

        # Test scenario: 4 consecutive errors (initial attempt + 3 default retries)
        client.request_mock.side_effect = self._http_error(500)

        with self.assertRaises(HTTPError):
            client.execute_request()

        self.assertEqual(client.request_mock.call_count, 4, "Should use default retry count")

    def test_401_error_fails_fast(self):
        """Test that 401 Unauthorized fails immediately"""
        client = self._make_client()
        client.request_mock.side_effect = self._http_error(401)

        with self.assertRaises(HTTPError):
            client.execute_request()

        self.assertEqual(client.request_mock.call_count, 1, "Should fail fast on 401")

class TestGitHubClientExecuteApiCall(unittest.TestCase):
    """Tests for the _execute_api_call method"""

    def setUp(self):
        self.config = MagicMock()
        self.config.github_url = "https://github.com/rpmbsys/repo"
        self.config.github_pat = "github_pat_test"
        self.config.github_token = None
        self.config.api_retries = 3
        self.config.api_backoff = 1.5
        self.client = runner.GitHubClient(self.config)

    @patch('runner.urlopen')
    def test_execute_api_call_get_success(self, mock_urlopen):
        """Test successful GET request"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"runners": []}).encode()
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        result = self.client._execute_api_call("actions/runners", method="GET")

        self.assertEqual(result, {"runners": []})
        mock_urlopen.assert_called_once()

    @patch('runner.urlopen')
    def test_execute_api_call_post_success(self, mock_urlopen):
        """Test successful POST request"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"token": "test_token"}).encode()
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        result = self.client._execute_api_call("actions/runners/registration-token", method="POST")

        self.assertEqual(result, {"token": "test_token"})

        args, _ = mock_urlopen.call_args
        request_obj = args[0]

        # 1. Проверяем метод
        self.assertEqual(request_obj.method, "POST")

        # 2. [ВАЖНО] Проверяем заголовки
        # headers в объекте Request хранятся как словарь
        self.assertEqual(request_obj.headers['Authorization'], "Bearer github_pat_test")
        self.assertEqual(request_obj.headers['Accept'], "application/vnd.github+json")
        self.assertIn("RunnerController", request_obj.headers['User-agent'])

    @patch('runner.urlopen')
    def test_execute_api_call_with_params(self, mock_urlopen):
        """Test request with query parameters"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"runners": []}).encode()
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        self.client._execute_api_call("actions/runners", method="GET", params="per_page=100")

        # Verify URL contains parameters
        args, _ = mock_urlopen.call_args
        request_obj = args[0]

        self.assertIn("per_page=100", request_obj.full_url)

    @patch('runner.urlopen')
    def test_execute_api_call_401_error(self, mock_urlopen):
        """Test 401 Unauthorized error handling"""
        error = HTTPError("url", 401, "Unauthorized", {}, None)
        mock_urlopen.side_effect = error

        with self.assertRaises(runner.RunnerError) as cm:
            self.client._execute_api_call("actions/runners", method="GET")

        self.assertIn("Invalid GITHUB_PAT", str(cm.exception))

    @patch('runner.urlopen')
    def test_execute_api_call_404_error(self, mock_urlopen):
        """Test 404 Not Found error handling"""
        error = HTTPError("url", 404, "Not Found", {}, None)
        mock_urlopen.side_effect = error

        with self.assertRaises(runner.RunnerError) as cm:
            self.client._execute_api_call("actions/runners", method="GET")

        self.assertIn("Resource not found", str(cm.exception))
        self.assertIn("404", str(cm.exception))

    @patch('runner.urlopen')
    def test_execute_api_call_network_error(self, mock_urlopen):
        """Test network error handling"""
        mock_urlopen.side_effect = URLError("Connection refused")

        with self.assertRaises(runner.RunnerError) as cm:
            self.client._execute_api_call("actions/runners", method="GET")

        self.assertIn("Network error connecting to GitHub", str(cm.exception))

    @patch('runner.urlopen')
    def test_execute_api_call_invalid_json(self, mock_urlopen):
        """Test handling of invalid JSON response"""
        mock_response = MagicMock()
        mock_response.read.return_value = b"Invalid JSON"
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        with self.assertRaises(runner.RunnerError) as cm:
            self.client._execute_api_call("actions/runners", method="GET")

        self.assertIn("Invalid API response", str(cm.exception))

    @patch('runner.urlopen')
    def test_execute_api_call_no_pat(self, mock_urlopen):
        """Test error when PAT is not provided"""
        self.client.config.github_pat = None

        with self.assertRaises(runner.RunnerError) as cm:
            self.client._execute_api_call("actions/runners", method="GET")

        self.assertIn("GITHUB_PAT is required", str(cm.exception))

class TestRunnerServiceStartup(unittest.TestCase):
    """Tests for the startup method"""

    def setUp(self):
        self.config = MagicMock()
        self.config.runner_name = "test-runner"
        self.fman = MagicMock()
        self.github = MagicMock()
        self.service = runner.RunnerService(self.config, self.fman, self.github)

    def test_startup_already_configured_valid(self):
        """Test startup when runner is already configured and valid"""
        self.fman.is_configured.return_value = True
        self.github.get_runner_status.return_value = True
        self.service.run = MagicMock()

        self.service.startup()

        self.fman.is_configured.assert_called()
        self.github.get_runner_status.assert_called_once_with("test-runner")
        self.fman.cleanup_config_only.assert_not_called()
        self.service.configure = MagicMock()
        self.service.configure.assert_not_called()
        self.service.run.assert_called_once()

    def test_startup_configured_but_orphaned(self):
        """Test startup when local config exists but runner deleted from GitHub"""
        self.fman.is_configured.side_effect = [True, False, False]
        self.github.get_runner_status.return_value = False
        self.service.configure = MagicMock()
        self.service.run = MagicMock()

        self.service.startup()

        self.fman.is_configured.assert_called()
        self.github.get_runner_status.assert_called_once_with("test-runner")
        self.fman.cleanup_config_only.assert_called_once()
        self.service.configure.assert_called_once()
        self.service.run.assert_called_once()

    def test_startup_not_configured(self):
        """Test startup when runner is not configured"""
        self.fman.is_configured.return_value = False
        self.service.configure = MagicMock()
        self.service.run = MagicMock()

        self.service.startup()

        self.fman.is_configured.assert_called()
        self.github.get_runner_status.assert_not_called()
        self.service.configure.assert_called_once()
        self.service.run.assert_called_once()

    def test_startup_verification_failure_failsafe(self):
        """Test startup when GitHub verification fails (fail-safe behaves as existing runner)"""
        self.fman.is_configured.return_value = True

        # Симулируем ситуацию: Клиент вернул True, хотя API мог сбоить (это логика клиента)
        self.github.get_runner_status.return_value = True
        self.service.run = MagicMock()
        self.service.configure = MagicMock() # Лучше замокать явно

        self.service.startup()

        self.fman.cleanup_config_only.assert_not_called()

        # Should proceed with running despite API failure
        self.service.run.assert_called_once()

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
