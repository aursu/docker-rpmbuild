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

### TestConfig
Configuration validation tests:
- Validation error handling when required environment variables are missing
- Successful configuration validation with valid environment variables

### TestGitHubClient
Integration tests for GitHubClient API interactions:
- Successful token retrieval from GitHub API
- API URL generation with proper authentication headers and user agent
- Retry logic on 500 server errors with exponential backoff

### TestRetryPolicy
Comprehensive unit tests for the RetryPolicy decorator:
- Successful calls without retry
- Retry behavior on network errors (URLError)
- Retry behavior on 5xx server errors (500, 503)
- Fail fast on 4xx client errors (401, 404)
- Maximum retry count enforcement
- Exponential backoff with jitter verification
- Custom configuration support (retries, backoff factor)
- Default fallback behavior when config is not provided

### TestSignalHandler
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
