# Tests

Unit tests for the GitHub Actions Runner Controller.

## Running Tests

From the `scripts` directory:

```bash
# Run all tests with verbose output
python3 -m unittest discover tests/ -v

# Run specific test file
python3 tests/test_runner.py -v

# Run without verbose output
python3 -m unittest discover tests/
```

## Test Coverage

### TestConfig (in test_runner.py)
Configuration validation and environment variable handling tests:
- Validation error handling when required environment variables are missing
- Successful configuration validation with valid environment variables
- Input validation for runner names, groups, and labels (via regex patterns)
- Retry delay default value verification
- Retry delay configuration from RUNNER_RETRY_DELAY environment variable

### TestGitHubClient (in test_runner.py)
Integration tests for GitHubClient API interactions:
- Successful token retrieval from GitHub API
- API URL generation with proper authentication headers and user agent
- Retry logic on 500 server errors with exponential backoff

### TestRetryPolicy (in test_runner.py)
Comprehensive unit tests for the RetryPolicy decorator:
- Successful calls without retry
- Retry behavior on network errors (URLError)
- Retry behavior on 5xx server errors (500, 503)
- Fail fast on 4xx client errors (401, 404)
- Maximum retry count enforcement
- Exponential backoff with jitter verification
- Custom configuration support (retries, backoff factor)
- Default fallback behavior when config is not provided

### TestRunnerServiceExecIntegration (in test_service_exec.py)
Integration tests for RunnerService._exec() method with real subprocess execution:
- Successful command execution with real /bin/echo and output capture
- FileNotFoundError handling for non-existent binary
- Silent command execution with /usr/bin/true (no output)
- Run loop integration test with configurable retry delay (verifies RUNNER_RETRY_DELAY is used)

### TestRunnerServiceExec (in test_service_exec.py)
Unit tests for RunnerService._exec() subprocess execution method with mocked processes:
- Successful command execution with output capture (mocked)
- Command failure with error context capture
- Timeout handling with process termination
- Timeout with captured error output in logs
- Bounded error context (last 50 lines) for large outputs
- Silent command execution (no output, mocked)
- IO poll interval usage for heartbeat checking
- Process termination helper (_terminate_process):
  - Escalation to SIGKILL on timeout

### TestSignalHandler (in test_signal_handler.py)
Unit tests for the SignalHandler context manager (in test_signal_handler.py):
- Context manager lifecycle (enter/exit behavior)
- Signal handler installation and restoration
- SIGINT and SIGTERM signal handling with shutdown flag management
- Multiple signal handling scenarios
- Unknown signal number graceful handling
- Nested context manager behavior
- Exception safety (handlers restored even on errors)
- Shutdown flag persistence after context exit
- Real signal delivery testing

### TestSignalHandlerIntegration
Integration test for SignalHandler in realistic usage patterns (in test_signal_handler.py):
- Typical run loop pattern with signal interruption and proper shutdown flag checking

### TestSecuritySanitization (in test_security.py)
Unit and integration tests for credential sanitization and log security:
- Token masking in _sanitize_args for runner configuration commands
- Multiple sensitive flags handling (--token, --pat)
- Robustness with malformed commands (flag without value)
- Normal commands pass through unchanged
- Integration test verifying sanitized logging during timeout errors

## Total Test Count

**44 tests** across 6 test classes ensuring comprehensive coverage of:
- Configuration validation and input sanitization
- API integration and retry logic
- Subprocess execution and timeout handling
- Signal management
- Security and credential protection
