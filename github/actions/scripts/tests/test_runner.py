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
        req_obj.add_header.assert_any_call("User-Agent", "RunnerController/1.1.0 (Python 3.12.5; Linux)")

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

        url = self.client._build_endpoint("actions/runners")
        result = self.client._execute_api_call(url, method="GET")

        self.assertEqual(result, {"runners": []})
        mock_urlopen.assert_called_once()

    @patch('runner.urlopen')
    def test_execute_api_call_post_success(self, mock_urlopen):
        """Test successful POST request"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"token": "test_token"}).encode()
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        url = self.client._build_endpoint("actions/runners/registration-token")
        result = self.client._execute_api_call(url, method="POST")

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

        url = self.client._build_endpoint("actions/runners")
        self.client._execute_api_call(url, method="GET", params="per_page=100")

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
            url = self.client._build_endpoint("actions/runners")
            self.client._execute_api_call(url, method="GET")

        self.assertIn("Invalid GITHUB_PAT", str(cm.exception))

    @patch('runner.urlopen')
    def test_execute_api_call_404_error(self, mock_urlopen):
        """Test 404 Not Found error handling"""
        error = HTTPError("url", 404, "Not Found", {}, None)
        mock_urlopen.side_effect = error

        with self.assertRaises(runner.RunnerError) as cm:
            url = self.client._build_endpoint("actions/runners")
            self.client._execute_api_call(url, method="GET")

        self.assertIn("Resource not found", str(cm.exception))
        self.assertIn("404", str(cm.exception))

    @patch('runner.time.sleep')
    @patch('runner.urlopen')
    def test_execute_api_call_network_error(self, mock_urlopen, _):
        """Test network error handling"""
        mock_urlopen.side_effect = URLError("Connection refused")

        with self.assertRaises(runner.RunnerError) as cm:
            url = self.client._build_endpoint("actions/runners")
            self.client._execute_api_call(url, method="GET")

        self.assertIn("Network error connecting to GitHub", str(cm.exception))

    @patch('runner.urlopen')
    def test_execute_api_call_invalid_json(self, mock_urlopen):
        """Test handling of invalid JSON response"""
        mock_response = MagicMock()
        mock_response.read.return_value = b"Invalid JSON"
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        with self.assertRaises(runner.RunnerError) as cm:
            url = self.client._build_endpoint("actions/runners")
            self.client._execute_api_call(url, method="GET")

        self.assertIn("Invalid API response", str(cm.exception))

    @patch('runner.urlopen')
    def test_execute_api_call_no_pat(self, mock_urlopen):
        """Test error when PAT is not provided"""
        self.client.config.github_pat = None

        with self.assertRaises(runner.RunnerError) as cm:
            url = self.client._build_endpoint("actions/runners")
            self.client._execute_api_call(url, method="GET")

        self.assertIn("PAT missing, App Auth not used", str(cm.exception))


class TestGitHubClientAppAuth(unittest.TestCase):
    """Tests for GitHub App Authentication functionality"""

    def setUp(self):
        self.config = MagicMock()
        self.config.github_url = "https://github.com/rpmbsys"
        self.config.github_pat = None
        self.config.github_token = None
        self.config.api_retries = 3
        self.config.api_backoff = 1.5
        self.client = runner.GitHubClient(self.config)

    @patch('runner.urlopen')
    def test_get_app_installation_token_org_success(self, mock_urlopen):
        """
        Verify the complete GitHub App authentication handshake for an Organization scope,
        validating network requests at the transport layer.
        """
        # 1. Configuration: Isolate and mock the App Authentication component
        # to simulate valid JWT generation for this specific test case.
        self.client.app_auth = MagicMock()
        self.client.app_auth.is_available = True
        self.client.app_auth.generate_jwt.return_value = "jwt.test.token"

        # 2. Network Simulation: Configure mock responses for the sequential API calls.

        # Response 1: Installation Lookup (GET). Returns the Installation ID.
        resp_inst = MagicMock()
        resp_inst.read.return_value = json.dumps({"id": 12345}).encode()
        cm_inst = MagicMock()
        cm_inst.__enter__.return_value = resp_inst

        # Response 2: Token Exchange (POST). Returns the ephemeral Access Token.
        resp_token = MagicMock()
        resp_token.read.return_value = json.dumps({"token": "ghs_final_token"}).encode()
        cm_token = MagicMock()
        cm_token.__enter__.return_value = resp_token

        # Define the sequence of side effects for the mocked urlopen callable.
        mock_urlopen.side_effect = [cm_inst, cm_token]

        # 3. Execution: Initiate the token retrieval workflow.
        token = self.client._get_app_installation_token()

        # 4. Assertion: Validate the returned token matches the expected Access Token.
        self.assertEqual(token, "ghs_final_token")

        # 5. Low-Level Verification: Assert exactly two network requests occurred
        # and unpack the call arguments for detailed inspection.
        self.assertEqual(mock_urlopen.call_count, 2)
        call_install, call_token = mock_urlopen.call_args_list

        # Inspection: First Request (Installation Lookup)
        # Extract the urllib.request.Request object from the call arguments.
        req_install = call_install.args[0]
        self.assertEqual(req_install.method, "GET")
        self.assertIn("/orgs/rpmbsys/installation", req_install.full_url)
        # Critical: Ensure the JWT is used for authentication.
        self.assertEqual(req_install.headers['Authorization'], "Bearer jwt.test.token")

        # Inspection: Second Request (Access Token Exchange)
        req_token = call_token.args[0]
        self.assertEqual(req_token.method, "POST")
        self.assertIn("/app/installations/12345/access_tokens", req_token.full_url)
        # Critical: Ensure the JWT is maintained for the second step.
        self.assertEqual(req_token.headers['Authorization'], "Bearer jwt.test.token")

    @patch('runner.urlopen')
    def test_get_app_installation_token_repo_success(self, mock_urlopen):
        """
        Verify the complete GitHub App authentication handshake for a Repository scope,
        validating network requests at the transport layer.
        """
        # 1. Configuration: Configure the client to target a specific repository scope.
        # This dictates the discovery endpoint logic (switching from /orgs/ to /repos/).
        self.config.github_url = "https://github.com/rpmbsys/docker-rpmbuild"

        # Isolate and mock the App Authentication component to simulate valid JWT generation.
        self.client.app_auth = MagicMock()
        self.client.app_auth.is_available = True
        self.client.app_auth.generate_jwt.return_value = "jwt.repo.token"

        # 2. Network Simulation: Configure mock responses for the sequential API calls.

        # Response 1: Installation Lookup (GET).
        # Returns the Installation ID associated with the specific repository.
        resp_inst = MagicMock()
        resp_inst.read.return_value = json.dumps({"id": 67890}).encode()
        cm_inst = MagicMock()
        cm_inst.__enter__.return_value = resp_inst

        # Response 2: Token Exchange (POST).
        # Returns the ephemeral Access Token.
        resp_token = MagicMock()
        resp_token.read.return_value = json.dumps({"token": "ghs_repo_token_abc"}).encode()
        cm_token = MagicMock()
        cm_token.__enter__.return_value = resp_token

        # Define the sequence of side effects for the mocked urlopen callable.
        mock_urlopen.side_effect = [cm_inst, cm_token]

        # 3. Execution: Initiate the token retrieval workflow.
        token = self.client._get_app_installation_token()

        # 4. Assertion: Validate the returned token matches the expected Access Token.
        self.assertEqual(token, "ghs_repo_token_abc")

        # 5. Low-Level Verification: Assert exactly two network requests occurred
        # and unpack the call arguments for detailed inspection.
        self.assertEqual(mock_urlopen.call_count, 2)
        call_install, call_token = mock_urlopen.call_args_list

        # Inspection: First Request (Installation Lookup)
        req_install = call_install.args[0]
        self.assertEqual(req_install.method, "GET")

        # Validation: Verify that the URL logic correctly identified the 'Repository' scope
        # (targeting /repos/... instead of /orgs/...).
        self.assertIn("/repos/rpmbsys/docker-rpmbuild/installation", req_install.full_url)
        # Critical: Ensure the JWT is used for authentication.
        self.assertEqual(req_install.headers['Authorization'], "Bearer jwt.repo.token")

        # Inspection: Second Request (Access Token Exchange)
        req_token = call_token.args[0]
        self.assertEqual(req_token.method, "POST")
        # Validation: Ensure the Installation ID from the first response is incorporated into the URL.
        self.assertIn("/app/installations/67890/access_tokens", req_token.full_url)
        # Critical: Ensure the JWT is maintained for the second step.
        self.assertEqual(req_token.headers['Authorization'], "Bearer jwt.repo.token")

    @patch('runner.urlopen')
    def test_get_app_installation_token_org_fallback_to_user(self, mock_urlopen):
        """
        Verify the installation lookup fallback mechanism: if the Organization-level 
        lookup fails (HTTP 404), the client must automatically attempt a User-level 
        lookup before proceeding to token exchange.
        """
        # 1. Configuration: Isolate and mock App Auth to provide a valid JWT.
        self.client.app_auth = MagicMock()
        self.client.app_auth.is_available = True
        self.client.app_auth.generate_jwt.return_value = "jwt.fallback.token"

        # 2. Network Simulation: Define the response sequence.

        # Response 1: Simulate an HTTP 404 Not Found error for the Organization installation lookup.
        # This triggers the exception handling logic in `_get_app_installation_token`.
        error_404 = HTTPError(
            url="http://gh/orgs/rpmbsys/installation",
            code=404, msg="Not Found", hdrs={}, fp=None
        )

        # Response 2: Simulate a successful response for the User installation lookup (Fallback target).
        resp_user = MagicMock()
        resp_user.read.return_value = json.dumps({"id": 11111}).encode()

        cm_user = MagicMock()
        cm_user.__enter__.return_value = resp_user

        # Response 3: Simulate a successful Token Exchange using the ID retrieved in step 2.
        resp_token = MagicMock()
        resp_token.read.return_value = json.dumps({"token": "ghs_user_final"}).encode()

        cm_token = MagicMock()
        cm_token.__enter__.return_value = resp_token

        # Define the sequence of network behaviors: Failure -> Success (Fallback) -> Success (Token).
        mock_urlopen.side_effect = [error_404, cm_user, cm_token]

        # 3. Execution: Initiate the token retrieval workflow.
        token = self.client._get_app_installation_token()

        # 4. Assertion: Verify the final token matches the result of the successful exchange.
        self.assertEqual(token, "ghs_user_final")

        # 5. Low-Level Verification: Confirm the exact sequence of 3 network calls occurred.
        self.assertEqual(mock_urlopen.call_count, 3)

        # Unpack the call history to inspect specific request parameters.
        call_fail, call_success, call_token = mock_urlopen.call_args_list

        # Inspection: First Request (Failed Org Lookup).
        # Ensure it targeted the Organization endpoint.
        req_fail = call_fail.args[0]
        self.assertIn("/orgs/rpmbsys/installation", req_fail.full_url)

        # Inspection: Second Request (Successful User Lookup).
        # Verify the fallback logic retargeted the URL to the User endpoint.
        req_success = call_success.args[0]
        self.assertIn("/users/rpmbsys/installation", req_success.full_url)
        # Ensure the JWT persisted correctly during the retry.
        self.assertEqual(req_success.headers['Authorization'], "Bearer jwt.fallback.token")

        # Inspection: Third Request (Token Exchange).
        # Verify it used the ID (11111) returned by the user lookup.
        req_token = call_token.args[0]
        self.assertIn("/app/installations/11111/access_tokens", req_token.full_url)

    @patch('runner.urlopen')
    def test_get_app_installation_token_repo_no_fallback(self, mock_urlopen):
        """
        Verify that a Repository-scoped configuration adheres to a 'Fail-Fast' strategy.
        If the installation lookup returns HTTP 404, the client must raise an error immediately
        without attempting fallback to User scope (which is only valid for Organization URLs).
        """
        # 1. Configuration: Configure the client with a Repository URL.
        # This constrains the logic to look exclusively in /repos/ path.
        self.config.github_url = "https://github.com/rpmbsys/docker-rpmbuild"

        # Mock the App Authentication to provide a valid JWT.
        self.client.app_auth = MagicMock()
        self.client.app_auth.is_available = True
        self.client.app_auth.generate_jwt.return_value = "jwt.repo.token"

        # 2. Network Simulation: Simulate an HTTP 404 Not Found error.
        # This represents the scenario where the GitHub App is not installed on the target repository.
        error_404 = HTTPError(
            url="http://gh/repos/rpmbsys/docker-rpmbuild/installation",
            code=404, msg="Not Found", hdrs={}, fp=None
        )
        mock_urlopen.side_effect = error_404

        # 3. Execution & Assertion:
        # Verify that the HTTP error triggers a RunnerError exception, halting execution.
        with self.assertRaises(runner.RunnerError):
            self.client._get_app_installation_token()

        # 4. Logic Verification: Assert that exactly one network request was made.
        # If the call count is > 1, it implies the client incorrectly attempted a fallback,
        # which would violate the fail-fast requirement for repository scopes.
        self.assertEqual(mock_urlopen.call_count, 1)

        # 5. Request Inspection: Verify the single request targeted the repository endpoint.
        single_call_args = mock_urlopen.call_args
        req = single_call_args.args[0]

        self.assertIn("/repos/rpmbsys/docker-rpmbuild/installation", req.full_url)

    @patch('runner.urlopen')
    @patch.object(runner.GitHubClient, '_get_app_installation_token')
    def test_get_token_uses_app_auth_when_available(self, mock_get_app_token, mock_urlopen):
        """
        Verify that `get_token` prioritizes GitHub App Authentication when available.
        It must retrieve an installation token via the helper method and inject it 
        into the HTTP Authorization header for the final API request.
        """
        # 1. Configuration: Enable App Authentication state.
        self.client.app_auth = MagicMock()
        self.client.app_auth.is_available = True

        # Mock the internal helper method `_get_app_installation_token`.
        # We assume the complex handshake logic (tested separately) succeeds and returns
        # a valid intermediate installation token.
        mock_get_app_token.return_value = "ghs_intermediate_token"

        # 2. Network Simulation: Configure the mock response for the final API call
        # (fetching the Registration Token).
        resp = MagicMock()
        resp.read.return_value = json.dumps({"token": "FINAL_REG_TOKEN"}).encode()

        cm = MagicMock()
        cm.__enter__.return_value = resp
        mock_urlopen.return_value = cm

        # 3. Execution: Invoke the token retrieval method.
        token = self.client.get_token("registration")

        # 4. Assertion: Validate the returned token matches the mocked network response.
        self.assertEqual(token, "FINAL_REG_TOKEN")

        # Verify dependency interaction: Ensure the installation token retrieval method was invoked.
        mock_get_app_token.assert_called_once()

        # 5. Low-Level Verification: Inspect the outgoing `urllib.request.Request`.
        self.assertEqual(mock_urlopen.call_count, 1)
        (req, ), _ = mock_urlopen.call_args

        # Validation: Verify the endpoint targets the registration token API.
        self.assertIn("/actions/runners/registration-token", req.full_url)

        # CRITICAL: Verify that the 'Authorization' header carries the Installation Token
        # (returned by the helper), confirming that the App Auth flow was utilized instead of a PAT.
        self.assertEqual(req.headers['Authorization'], "Bearer ghs_intermediate_token")

    @patch('runner.urlopen')
    def test_get_token_fallback_to_pat_low_level(self, mock_urlopen):
        """
        Verify that `get_token` correctly falls back to using the Personal Access Token (PAT)
        in HTTP headers when GitHub App Authentication is unavailable.
        """
        # 1. Configuration: Disable App Auth and ensure PAT availability.
        self.config.github_pat = "ghp_pat_token_xyz"

        # Explicitly mock the app_auth dependency to simulate an unavailable state,
        # ensuring the fallback logic is triggered.
        self.client.app_auth = MagicMock()
        self.client.app_auth.is_available = False

        # 2. Network Simulation: Mock the HTTP response lifecycle.
        resp = MagicMock()
        resp.read.return_value = json.dumps({"token": "REAL_REMOVAL_TOKEN"}).encode()

        cm = MagicMock()
        cm.__enter__.return_value = resp
        mock_urlopen.return_value = cm

        # 3. Execution: Invoke the token retrieval method.
        # CORRECTION: The argument must be "remove" to match the API endpoint /remove-token
        token = self.client.get_token("remove")

        # 4. Assertion: Verify the returned token matches the mocked response.
        self.assertEqual(token, "REAL_REMOVAL_TOKEN")

        # 5. Low-Level Verification: Inspect the `urllib.request.Request` object.
        # Ensure that exactly one network request was initiated.
        self.assertEqual(mock_urlopen.call_count, 1)
        (req, ), _ = mock_urlopen.call_args

        # Validation: Ensure the URL targets the correct 'remove-token' endpoint.
        self.assertIn("/actions/runners/remove-token", req.full_url)

        # CRITICAL: Verify that the 'Authorization' header was constructed using
        # the Personal Access Token (PAT) and not an App token or None.
        self.assertEqual(req.headers['Authorization'], "Bearer ghp_pat_token_xyz")

    @patch('runner.logger')
    def test_get_token_no_auth_configured(self, mock_logger):
        """
        Verify that `get_token` raises a `RunnerError` when no valid authentication
        mechanism (neither GitHub App nor Personal Access Token) is configured.
        """
        # 1. Configuration: Ensure both App Auth and PAT are explicitly disabled.
        self.client.app_auth = MagicMock()
        self.client.app_auth.is_available = False
        self.config.github_pat = None

        # 2. Execution & Assertion: Verify that the operation fails with the expected exception.
        with self.assertRaises(runner.RunnerError) as cm:
            self.client.get_token("registration")

        # 3. Validation: specific error message indicates the missing configuration.
        self.assertIn("Authentication not configured", str(cm.exception))

    @patch('runner.logger')
    def test_get_token_uses_github_token_directly(self, mock_logger):
        """
        Verify that `get_token` returns the pre-configured `GITHUB_TOKEN` immediately,
        bypassing any API interaction or authentication handshake.
        """
        # 1. Configuration: Inject a static registration token into the configuration.
        self.config.github_token = "direct_token_abc"

        # 2. Execution: Invoke the token retrieval method.
        token = self.client.get_token("registration")

        # 3. Assertion: Confirm that the returned token matches the configuration value exactly.
        self.assertEqual(token, "direct_token_abc")

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
        self.fman.cleanup_runner_state.assert_not_called()
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
        self.fman.cleanup_runner_state.assert_called_once()
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

        self.fman.cleanup_runner_state.assert_not_called()

        # Should proceed with running despite API failure
        self.service.run.assert_called_once()

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
