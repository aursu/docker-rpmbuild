# [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

## Supported runners and hardware resources

### Standard GitHub-hosted runners for public repositories

### Standard GitHub-hosted runners for private repositories

### Limitations for arm64 macOS runners

### Single-CPU runners

#### Usage limits

### Larger runners

## Administrative privileges

## IP addresses

## Communication requirements for GitHub-hosted runners

## File systems

### Файловая система Docker-контейнера (Docker container filesystem)

Действия (actions), которые запускаются в Docker-контейнерах, имеют статические директории (static directories) по пути `/github`. Однако мы настоятельно рекомендуем использовать **переменные окружения по умолчанию (default environment variables)** для построения путей к файлам в Docker-контейнерах.

**GitHub** резервирует префикс пути `/github` и создает три директории для действий:

* `/github/home`
* `/github/workspace` — **Примечание (Note):** **GitHub Actions** должны запускаться пользователем Docker по умолчанию (**root**). Убедитесь, что ваш **Dockerfile** не содержит инструкцию `USER`, иначе вы не сможете получить доступ к директории, на которую указывает переменная **GITHUB_WORKSPACE**.
* `/github/workflow`
