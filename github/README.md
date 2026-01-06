# GitHub Actions Self-Hosted Runner

This directory contains Docker configuration for running a self-hosted GitHub Actions runner in a container.

## Prerequisites

1. **Environment Configuration**: Create `secrets/github.env` with required variables:
   ```bash
   GITHUB_URL=https://github.com/your-org/your-repo
   GITHUB_PAT=your_personal_access_token_here
   # OR use GITHUB_TOKEN for one-time registration token
   # GITHUB_TOKEN=your_registration_token_here
   RUNNER_NAME=my-runner-name
   RUNNER_LABELS=self-hosted,linux,x64
   ```

2. **Docker and Docker Compose**: Ensure Docker and Docker Compose are installed and running.

## Usage

### 1. Build the Runner Image

Build the base image with GitHub Actions Runner installed:

```bash
docker compose -f github/docker-compose.yml build
```

This creates an image with the GitHub Actions Runner binaries and the runner controller script.

### 2. Configure the Runner (First Time Setup)

Register the runner with GitHub:

```bash
docker compose -f github/docker-compose.yml run --rm githubrunnerconfig
```

This command:
- Connects to GitHub using the provided token
- Registers the runner with your repository or organization
- Stores configuration in the `githubrunner` volume
- Exits after configuration is complete

**Note**: You need valid GitHub credentials. Choose one:

**Option 1 (Recommended): Personal Access Token (PAT)**
- Generate from: GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
- Required scopes: `repo` (full control) or `admin:org` (read and write for organization runners)
- Does not expire (unless you set expiration)
- Set as `GITHUB_PAT` in `secrets/github.env`

**Option 2: Registration Token**
- Get from: Repository/Organization Settings → Actions → Runners → New self-hosted runner
- Expires after 1 hour
- Set as `GITHUB_TOKEN` in `secrets/github.env`
- Must regenerate for each registration

### 3. Start the Runner

Start the runner as a background service:

```bash
docker compose -f github/docker-compose.yml up -d githubrunner
```

The runner will:
- Start listening for jobs from GitHub Actions
- Run in detached mode (background)
- Automatically restart on failure
- Use the configuration from step 2

### 4. Check Runner Status

View runner logs:

```bash
docker compose -f github/docker-compose.yml logs -f githubrunner
```

Check if the runner is running:

```bash
docker compose -f github/docker-compose.yml ps
```

### 5. Stop the Runner

Stop the running runner service:

```bash
docker compose -f github/docker-compose.yml down
```

This stops the container but preserves the runner configuration in the volume.

### 6. Remove/Unregister the Runner

Unregister the runner from GitHub (cleanup):

```bash
docker compose -f github/docker-compose.yml run --rm githubrunnerdelete
```

This command:
- Connects to GitHub
- Removes the runner registration
- Cleans up configuration files
- Exits after removal is complete

**Important**: Run this before deleting the runner permanently or when decommissioning.

## Complete Workflow Example

Full lifecycle from setup to teardown:

```bash
# 1. Build the image
docker compose -f github/docker-compose.yml build

# 2. Register the runner
docker compose -f github/docker-compose.yml run --rm githubrunnerconfig

# 3. Start the runner service
docker compose -f github/docker-compose.yml up -d githubrunner

# 4. View logs
docker compose -f github/docker-compose.yml logs -f githubrunner

# 5. Stop the runner (when needed)
docker compose -f github/docker-compose.yml down

# 6. Unregister from GitHub (when decommissioning)
docker compose -f github/docker-compose.yml run --rm githubrunnerdelete
```

## Configuration Options

### Environment Variables

Configure the runner behavior through `secrets/github.env`:

**Required:**
- `GITHUB_URL`: Repository or organization URL (e.g., `https://github.com/owner/repo`)
- `GITHUB_PAT`: Personal Access Token (recommended) - Generate from GitHub Settings → Developer settings → Personal access tokens
  - Required scopes: `repo` (for private repos) or `public_repo` (for public repos)
  - Or use `GITHUB_TOKEN`: One-time registration token from GitHub Actions Runner settings (expires in 1 hour)

**Optional:**
- `RUNNER_NAME`: Custom runner name (default: `github-actions-runner-<hostname>`)
- `RUNNER_GROUP`: Runner group name (default: `Default`)
- `RUNNER_LABELS`: Comma-separated labels (default: `self-hosted,linux,x64`)
- `RUNNER_WORKSPACE`: Working directory for jobs (default: `_work`)
- `RUNNER_ALLOW_RUNASROOT`: Allow running as root (default: disabled)

**Timeouts and Retry:**
- `RUNNER_SETUP_TIMEOUT`: Timeout for configure/remove operations in seconds (default: `60`)
- `RUNNER_RETRY_DELAY`: Delay between retries on retryable errors in seconds (default: `5`)

**API Configuration:**
- `GITHUB_API_RETRIES`: Number of API retry attempts (default: `3`)
- `GITHUB_API_BACKOFF`: Backoff multiplier for retries (default: `1.5`)

### Docker Volumes

- `githubrunner`: Persistent volume storing runner configuration and credentials
  - Preserves runner state between container restarts
  - Must be cleaned manually if corrupted: `docker volume rm githubrunner`

### Security Notes

1. **Token Security**:
   - `GITHUB_PAT`: Store securely, never commit to git. Use GitHub Secrets or secure vault.
   - `GITHUB_TOKEN`: Registration tokens expire after 1 hour. Generate fresh token for each registration.
2. **Credential Storage**: Runner credentials are stored in the `githubrunner` volume with appropriate permissions.
3. **Input Validation**: All environment variables are validated to prevent shell injection attacks.
4. **Log Sanitization**: Sensitive tokens (`--token`, `--pat`) are automatically masked in logs (`***`).

## Troubleshooting

### Runner fails to start

Check logs for errors:
```bash
docker compose -f github/docker-compose.yml logs githubrunner
```

Common issues:
- Expired or invalid token:
  - `GITHUB_TOKEN`: Regenerate from GitHub (expires in 1 hour)
  - `GITHUB_PAT`: Verify token has not been revoked and has correct scopes
- Invalid `GITHUB_URL` format
- Network connectivity issues
- Runner already registered with the same name

### Configuration issues

Remove existing configuration and reconfigure:
```bash
docker compose -f github/docker-compose.yml run --rm githubrunnerdelete
docker volume rm githubrunner
docker compose -f github/docker-compose.yml run --rm githubrunnerconfig
```

### Runner not appearing in GitHub

1. Check if configuration succeeded: `docker compose logs githubrunnerconfig`
2. Verify the runner is running: `docker compose ps`
3. Check GitHub UI: Settings → Actions → Runners
4. Ensure the token has not expired

### Permission errors

Ensure the runner has appropriate permissions:
- Docker socket access for Docker-in-Docker operations
- Volume permissions for `/home/runner`

## Architecture

The runner setup consists of:

1. **Base Image** (`githubrunnerbase`): Rocky Linux with GitHub Actions Runner binaries
2. **Configuration Service** (`githubrunnerconfig`): One-time registration with GitHub
3. **Runner Service** (`githubrunner`): Long-running listener for GitHub Actions jobs
4. **Removal Service** (`githubrunnerdelete`): Cleanup and unregistration

All services use the same base image but with different commands and lifecycle patterns.

## Development

For development and debugging:

```bash
# Run interactive shell in runner container
docker compose -f github/docker-compose.yml run --rm githubrunner bash

# View runner script details
docker compose -f github/docker-compose.yml run --rm githubrunner /usr/local/runner/runner.py --help

# Test configuration without starting
docker compose -f github/docker-compose.yml run --rm githubrunnerconfig
```

## Additional Resources

- [GitHub Actions Runner Documentation](https://docs.github.com/en/actions/concepts/runners/self-hosted-runners)
- [Self-Hosted Runner Security](https://docs.github.com/en/actions/concepts/runners/self-hosted-runners#self-hosted-runner-security)
- Runner Controller Script: `actions/scripts/runner.py`
