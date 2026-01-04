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

## Test Implementation Details

All tests use `unittest.mock` to isolate functionality and prevent actual network calls. The RetryPolicy tests use a `ClientStub` pattern to test the decorator in isolation from GitHubClient business logic.

Configuration for retry behavior can be controlled via:
- `GITHUB_API_RETRIES` environment variable (default: 3)
- `GITHUB_API_BACKOFF` environment variable (default: 1.5)
