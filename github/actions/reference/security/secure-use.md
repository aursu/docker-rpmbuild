# Справочное руководство по безопасному использованию (Secure use reference)

**Практики безопасности** для написания рабочих процессов (workflows) и использования функций GitHub Actions.

## В этой статье

Найдите информацию о лучших практиках безопасности (security best practices) при написании рабочих процессов (workflows) и использовании функций безопасности GitHub Actions.

## Написание рабочих процессов (Writing workflows)

### Используйте секреты для конфиденциальной информации

Поскольку существует множество способов преобразования значения **секрета** (secret), автоматическое **скрытие** (redaction) не гарантируется. Придерживайтесь следующих лучших практик, чтобы ограничить риски, связанные с секретами.

- **Принцип наименьших привилегий** (Principle of least privilege)
    - Любой пользователь с доступом на запись (write access) в ваш репозиторий (repository) имеет доступ на чтение ко всем секретам, настроенным в вашем репозитории. Поэтому вы должны убедиться, что учетные данные (credentials), используемые в рабочих процессах, обладают минимальными привилегиями, необходимыми для выполнения задач.

    - GitHub Actions могут использовать токен `GITHUB_TOKEN`, обращаясь к нему через контекст `github.token` (github.token context). Для получения дополнительной информации см. «[Справочник по контекстам](https://docs.github.com/en/actions/learn-github-actions/contexts#github-context)» (Contexts reference). Таким образом, вам следует убедиться, что токену `GITHUB_TOKEN` предоставлены минимально необходимые разрешения (permissions).
    С точки зрения безопасности хорошей практикой считается установка разрешений по умолчанию для `GITHUB_TOKEN` только на «чтение содержимого репозитория» (read access only for repository contents). Затем эти разрешения могут быть расширены по мере необходимости для отдельных заданий (jobs) внутри файла рабочего процесса (workflow file). Для получения дополнительной информации см. раздел «[Использование GITHUB_TOKEN для аутентификации в рабочих процессах](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)» (Use GITHUB_TOKEN for authentication in workflows).

- **Маскирование конфиденциальных данных** (Mask sensitive data)
    - Конфиденциальные данные никогда не должны храниться в виде простого текста (plaintext) в файлах рабочих процессов (workflow files). Маскируйте всю конфиденциальную информацию, которая не является секретом GitHub (GitHub secret), используя команду `::add-mask::VALUE`. Это приведет к тому, что значение будет обрабатываться как секрет и скрываться (redacted) из логов. Для получения дополнительной информации о маскировании данных см. раздел «[Команды рабочих процессов для GitHub Actions](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#masking-a-value-in-a-log)» (Workflow commands for GitHub Actions).

- **Удаление и ротация скомпрометированных секретов** (Delete and rotate exposed secrets)
    - Маскирование секретов (redacting of secrets) выполняется вашими исполнителями сценариев автоматизации (workflow runners). Это означает, что секрет будет замаскирован только в том случае, если он использовался в рамках задания (job) и был доступен исполнителю (runner). Если немаскированный секрет (unredacted secret) попадает в журнал выполнения сценария автоматизации (workflow run log), вам следует удалить этот журнал и выполнить ротацию секрета (rotate the secret). Для получения информации об удалении журналов см. раздел «[Использование журналов выполнения сценариев автоматизации](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/using-workflow-run-logs#deleting-logs) (Using workflow run logs)».

- **Никогда не используйте структурированные данные в качестве секретов** (Never use structured data as a secret)
    - Использование структурированных данных может привести к сбою скрытия секретов в логах, так как этот процесс во многом опирается на поиск точного соответствия конкретному значению секрета. Например, не используйте блоки `JSON`, `XML` или `YAML` (или аналогичные) для инкапсуляции значения секрета, так как это значительно снижает вероятность того, что секреты будут надлежащим образом скрыты. Вместо этого создавайте отдельные секреты для каждого конфиденциального значения.

- **Регистрируйте все секреты, используемые в рабочих процессах** (Register all secrets used within workflows)
    - Если секрет используется для генерации другого конфиденциального значения внутри рабочего процесса, это сгенерированное значение должно быть официально [зарегистрировано как секрет](https://github.com/actions/toolkit/tree/main/packages/core#setting-a-secret) (registered as a secret), чтобы оно было скрыто в случае появления в логах. Например, если вы используете закрытый ключ (private key) для генерации подписанного `JWT` (signed JWT) для доступа к веб-интерфейсу программирования приложений (web API), обязательно зарегистрируйте этот JWT как секрет, иначе он не будет скрыт при попадании в вывод логов.
    - Регистрация секретов также относится к любому виду трансформации или кодирования. Если ваш секрет каким-либо образом преобразуется (например, `Base64` или `URL-кодирование`), обязательно зарегистрируйте новое значение как секрет.

- **Проводите аудит обработки секретов** (Audit how secrets are handled)
    - Проверяйте, как используются секреты, чтобы убедиться, что они обрабатываются должным образом. Вы можете сделать это, просмотрев исходный код (source code) репозитория, выполняющего рабочий процесс, и проверив любые действия (actions), используемые в нем. Например, убедитесь, что они не отправляются на непредусмотренные хосты (hosts) и не выводятся явно в логи.

    - Просматривайте логи выполнения вашего рабочего процесса после тестирования валидных и невалидных входных данных (inputs) и проверяйте, что секреты надлежащим образом скрыты или не отображаются. Не всегда очевидно, как вызываемая вами команда или инструмент будут отправлять ошибки в потоки `STDOUT` и `STDERR`, вследствие чего секреты могут оказаться в логах ошибок. Поэтому хорошей практикой является ручная проверка логов рабочего процесса после тестирования различных входных данных. Информацию о том, как очистить логи рабочих процессов, которые могут непреднамеренно содержать конфиденциальные данные, см. в разделе «[Использование логов выполнения рабочих процессов](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/using-workflow-run-logs#deleting-logs)» (Using workflow run logs).

- **Аудит и ротация зарегистрированных секретов** (Audit and rotate registered secrets)
    - Периодически проверяйте зарегистрированные секреты, чтобы подтвердить их актуальность. Удаляйте те, которые больше не нужны.
    - Регулярно проводите ротацию секретов (rotate secrets), чтобы сократить период времени, в течение которого скомпрометированный секрет остается действительным.

- **Рассмотрите возможность обязательного подтверждения доступа к секретам** (Consider requiring review for access to secrets)
    - Вы можете использовать обязательных рецензентов (required reviewers) для защиты секретов окружения (environment secrets). Задание рабочего процесса не сможет получить доступ к секретам окружения до тех пор, пока не будет получено одобрение от рецензента. Для получения дополнительной информации о хранении секретов в окружениях (environments) или требовании проверки для окружений см. разделы «[Использование секретов в GitHub Actions](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions)» (Using secrets in GitHub Actions) и «[Управление окружениями для развертывания](https://docs.github.com/en/actions/deployment/targeting-different-environments/managing-environments-for-deployment)» (Managing environments for deployment).

### Рекомендации по предотвращению атак типа «инъекция скрипта» (Good practices for mitigating script injection attacks)

Рекомендуемые подходы для предотвращения рисков **инъекций скриптов** (script injection) в ваших рабочих процессах (workflows):

#### Используйте действие вместо встроенного скрипта (Use an action instead of an inline script)

Рекомендуемый подход заключается в создании действия на JavaScript (JavaScript action), которое обрабатывает значение контекста (context value) как аргумент (argument). Этот подход исключает возможность атаки типа «инъекция» (injection attack), так как значение контекста не используется для генерации скрипта командной оболочки (shell script), а передается в действие в качестве аргумента.

```
uses: fakeaction/checktitle@v3
with:
  title: ${{ github.event.pull_request.title }}
```

#### Используйте промежуточную переменную окружения (Use an intermediate environment variable)

Для встроенных скриптов (inline scripts) предпочтительным подходом к обработке ненадежных входных данных (untrusted input) является присвоение значения выражения промежуточной переменной окружения (intermediate environment variable). В следующем примере используется **Bash** для обработки значения `github.event.pull_request.title` в качестве переменной окружения:

```
      - name: Check PR title
        env:
          TITLE: ${{ github.event.pull_request.title }}
        run: |
          if [[ "$TITLE" =~ ^octocat ]]; then
          echo "PR title starts with 'octocat'"
          exit 0
          else
          echo "PR title did not start with 'octocat'"
          exit 1
          fi
```

В этом примере попытка инъекции скрипта (script injection) оказывается неудачной, что отражено в следующих строках лога (log):

```
   env:
     TITLE: a"; ls $GITHUB_WORKSPACE"
PR title did not start with 'octocat'
```

При таком подходе значение выражения `${{ github.event.pull_request.title }}` сохраняется в памяти и используется как переменная, не взаимодействуя с процессом генерации скрипта. Кроме того, рекомендуется использовать переменные оболочки (shell variables) в двойных кавычках, чтобы избежать [разбиения по словам](https://github.com/koalaman/shellcheck/wiki/SC2086) (word splitting); это является [одной из многих](https://mywiki.wooledge.org/BashPitfalls) общих рекомендаций по написанию скриптов оболочки (shell scripts) и не относится исключительно к GitHub Actions.

#### Использование шаблонов рабочих процессов для сканирования кода (Using workflow templates for code scanning)

Сканирование кода (Code scanning) позволяет находить уязвимости в системе безопасности (security vulnerabilities) до того, как они попадут в производственную среду (production). GitHub предоставляет шаблоны сценариев автоматизации (workflow templates) для сканирования кода (code scanning). Вы можете использовать эти предложенные сценарии автоматизации (workflows) для создания собственных сценариев автоматизации сканирования кода (code scanning workflows) вместо того, чтобы начинать всё с нуля.

Сценарий автоматизации GitHub (GitHub's workflow) — сценарий анализа CodeQL (CodeQL analysis workflow) — работает на базе технологии CodeQL. Также доступны шаблоны сценариев автоматизации от сторонних разработчиков (third-party workflow templates).

Для получения дополнительной информации см. разделы «[О сканировании кода](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning) (About code scanning)» и «[Настройка расширенных параметров сканирования кода](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/configuring-advanced-setup-for-code-scanning#configuring-code-scanning-using-third-party-actions) (Configuring advanced setup for code scanning)».

#### Ограничение разрешений для токенов (Restricting permissions for tokens)

Чтобы снизить риски, связанные с **компрометацией токена** (exposed token), рассмотрите возможность ограничения назначенных ему разрешений (permissions). Для получения дополнительной информации см. раздел «[Использование `GITHUB_TOKEN` для аутентификации в рабочих процессах](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token)» (Use GITHUB_TOKEN for authentication in workflows).

## Использование сторонних действий (Using third-party actions)

Отдельные задания (jobs) в рабочем процессе могут взаимодействовать с другими заданиями (и компрометировать их). Например, задание может запрашивать переменные окружения (environment variables), используемые последующим заданием, записывать файлы в общую директорию (shared directory), которую обрабатывает последующее задание, или даже более непосредственно — взаимодействовать с сокетом **Docker** (Docker socket), инспектируя другие запущенные контейнеры и выполняя в них команды.

Это означает, что **компрометация одного действия** (action) внутри рабочего процесса может иметь серьезные последствия, поскольку это скомпрометированное действие получит доступ ко всем секретам (secrets), настроенным в вашем репозитории, и сможет использовать `GITHUB_TOKEN` для записи в репозиторий. Следовательно, существует значительный риск при использовании действий из сторонних репозиториев на GitHub. Информацию о шагах, которые может предпринять злоумышленник, см. в «[Справочном руководстве по безопасному использованию](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#potential-impact-of-a-compromised-runner)» (Secure use reference).

Вы можете помочь в предотвращении этого риска, следуя этим рекомендациям:

- **Фиксация действий по полному хэшу коммита** (Pin actions to a full-length commit SHA)
  Фиксация **действия (action)** по полному **SHA хэшу коммита (full-length commit SHA)** в настоящее время является единственным способом использовать действие как **неизменяемый релиз (immutable release)**.
  Фиксация по конкретному **SHA** помогает снизить риск того, что **злоумышленник (bad actor)** добавит **бэкдор (backdoor)** в репозиторий действия, так как ему потребовалось бы создать **коллизию SHA-1 (SHA-1 collision)** для валидной **полезной нагрузки объекта Git (valid Git object payload)**. При выборе **SHA** вам следует убедиться, что он взят из репозитория самого действия, а не из **ответвления репозитория (repository fork)**.

  Пример использования полного SHA коммита в рабочем процессе см. в разделе «[Использование готовых строительных блоков в вашем рабочем процессе](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/find-and-customize-actions#using-shas)» (Using pre-written building blocks in your workflow).

  GitHub предлагает политики на уровне репозитория и организации, требующие фиксации действий по полному SHA коммита:

  - Чтобы настроить политику на уровне репозитория, см. «[Управление настройками GitHub Actions для репозитория](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#managing-github-actions-permissions-for-your-repository)» (Managing GitHub Actions settings for a repository).

  - Чтобы настроить политику на уровне организации, см. «[Отключение или ограничение GitHub Actions для вашей организации](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#managing-github-actions-permissions-for-your-organization)» (Disabling or limiting GitHub Actions for your organization).

- **Проводите аудит исходного кода действия** (Audit the source code of the action)

  Убедитесь, что действие обрабатывает содержимое вашего репозитория и секреты должным образом. Например, проверьте, что секреты не отправляются на непредусмотренные хосты (hosts) и не записываются непреднамеренно в логи.

- **Привязывайте действия к конкретному тегу только при условии полного доверия к их автору** (Pin actions to a tag only if you trust the creator)

  Хотя фиксация по SHA коммита является наиболее безопасным вариантом, указание **тега** (tag) более удобно и широко используется. Если вы хотите указать тег, убедитесь, что вы доверяете создателям действия. Значок **«Проверенный создатель»** (Verified creator) на GitHub Marketplace является полезным сигналом, так как он указывает на то, что действие было написано командой, чья личность была подтверждена GitHub. Обратите внимание, что этот подход сопряжен с риском, даже если вы доверяете автору, поскольку тег может быть перемещен или удален, если злоумышленник получит доступ к репозиторию, в котором хранится действие.

### Повторное использование сторонних сценариев автоматизации (Reusing third-party workflows)

Те же принципы, описанные выше для использования **сторонних действий (third-party actions)**, применимы и к использованию **сторонних сценариев автоматизации (third-party workflows)**. Вы можете помочь снизить риски, связанные с повторным использованием **сценариев автоматизации (workflows)**, следуя тем же передовым практикам (good practices), изложенным выше.
Для получения дополнительной информации см. раздел **«[Повторное использование сценариев автоматизации](https://docs.github.com/en/actions/using-workflows/reusing-workflows) (Reuse workflows)»**.

## Функции безопасности GitHub (GitHub's security features)

GitHub предоставляет множество функций, позволяющих сделать ваш код более защищенным. Вы можете использовать встроенные возможности GitHub, чтобы лучше понимать, от каких действий (actions) зависят ваши сценарии автоматизации (workflows), гарантировать получение уведомлений об уязвимостях (vulnerabilities) в используемых вами действиях или автоматизировать процесс поддержания действий в ваших сценариях автоматизации в актуальном состоянии. Если вы публикуете и поддерживаете действия (actions), вы можете использовать GitHub для взаимодействия со своим сообществом по вопросам обнаруженных уязвимостей и способов их устранения. Для получения дополнительной информации о функциях безопасности, которые предлагает GitHub, см. раздел «[Функции безопасности GitHub](https://docs.github.com/en/code-security/getting-started/github-security-features#about-githubs-security-features) (GitHub security features)».

### Использование `CODEOWNERS` для мониторинга изменений (Using CODEOWNERS to monitor changes)

Вы можете использовать функцию **«Владельцы кода» (CODEOWNERS)** для контроля того, как вносятся изменения в ваши **файлы сценариев автоматизации (workflow files)**. Например, если все ваши файлы сценариев автоматизации хранятся в директории `.github/workflows`, вы можете добавить эту директорию в **список владельцев кода (code owners list)**. Таким образом, любые предлагаемые изменения в этих файлах потребуют предварительного **одобрения (approval)** от **назначенного рецензента (designated reviewer)**.

Для получения дополнительной информации см. раздел «[О владельцах кода](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)» (About code owners).

### Использование OpenID Connect для доступа к облачным ресурсам (Using OpenID Connect to access cloud resources)

Если вашим рабочим процессам GitHub Actions требуется доступ к ресурсам **облачного провайдера** (cloud provider), поддерживающего **OpenID Connect** (OIDC), вы можете настроить свои рабочие процессы для прямой аутентификации у этого провайдера. Это позволит вам отказаться от хранения учетных данных (credentials) в виде долгоживущих секретов (long-lived secrets) и обеспечит другие преимущества в области безопасности. Для получения дополнительной информации см. раздел [OpenID Connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect).

> **Примечание:**
>
> Поддержка настраиваемых утверждений (custom claims) для OIDC недоступна в AWS.

### Использование обновлений версий Dependabot для поддержания действий в актуальном состоянии (Using Dependabot version updates to keep actions up to date)

Вы можете использовать **Dependabot**, чтобы гарантировать, что ссылки на **действия (actions)** и **повторно используемые сценарии автоматизации (reusable workflows)**, используемые в вашем **репозитории (repository)**, поддерживаются в актуальном состоянии.
**Действия (actions)** часто обновляются: в них вносятся **исправления ошибок (bug fixes)** и добавляются новые функции, что делает **автоматизированные процессы (automated processes)** более быстрыми, безопасными и надежными. **Dependabot** избавляет вас от необходимости вручную поддерживать ваши **зависимости (dependencies)**, выполняя это автоматически.
Для получения дополнительной информации см. разделы «[Поддержание ваших действий в актуальном состоянии с помощью Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot)» (Keeping your actions up to date with **Dependabot**) и «[Об обновлениях безопасности **Dependabot**](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates)» (About **Dependabot** security updates).

### Предотвращение создания или одобрения запросов на слияние через GitHub Actions (Preventing GitHub Actions from creating or approving pull requests)

Вы можете разрешить или запретить рабочим процессам GitHub Actions создавать или одобрять запросы на слияние (pull requests). Разрешение рабочим процессам или любой другой автоматизации создавать или одобрять запросы на слияние может представлять **риск для безопасности**, если запрос на слияние будет слит (merged) без надлежащего контроля.

Для получения дополнительной информации о том, как настроить этот параметр, см. разделы «[Отключение или ограничение GitHub Actions для вашей организации](https://docs.github.com/en/github/setting-up-and-managing-organizations-and-teams/disabling-or-limiting-github-actions-for-your-organization#preventing-github-actions-from-creating-or-approving-pull-requests)» (Disabling or limiting GitHub Actions for your organization) и «[Управление настройками GitHub Actions для репозитория](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests)» (Managing GitHub Actions settings for a repository).

### Использование сканирования кода для защиты рабочих процессов (Using code scanning to secure workflows)

**Сканирование кода** (code scanning) может автоматически обнаруживать и предлагать улучшения для распространенных **уязвимых паттернов** (vulnerable patterns), используемых в рабочих процессах GitHub Actions. Для получения дополнительной информации о том, как включить сканирование кода, см. «[Настройка конфигурации по умолчанию для сканирования кода](https://docs.github.com/en/code-security/code-scanning/enabling-code-scanning/configuring-default-setup-for-code-scanning)» (Configuring default setup for code scanning).

### Использование OpenSSF Scorecards для защиты зависимостей сценариев автоматизации (Using OpenSSF Scorecards to secure workflow dependencies)

**[Scorecards](https://github.com/ossf/scorecard)** — это автоматизированный инструмент безопасности, который помечает рискованные практики в цепочке поставок (supply chain practices). Вы можете использовать [действие **Scorecards**](https://github.com/marketplace/actions/ossf-scorecard-action) (Scorecards action) и [шаблон рабочего процесса](https://github.com/actions/starter-workflows) (workflow template) для соблюдения лучших практик безопасности. После настройки действие Scorecards запускается автоматически при изменениях в репозитории и предупреждает разработчиков о рискованных практиках в цепочке поставок, используя встроенный интерфейс сканирования кода. Проект Scorecards выполняет ряд проверок, включая атаки типа «инъекция скрипта» (script injection attacks), разрешения токенов (token permissions) и фиксацию действий (pinned actions).

### Укрепление защиты агентов выполнения, размещаемых на GitHub (Hardening for GitHub-hosted runners)

**Исполнители, размещаемые на GitHub** (GitHub-hosted runners), принимают меры для предотвращения рисков безопасности.

#### Проверка цепочки поставок для агентов выполнения, размещаемых на GitHub (Reviewing the supply chain for GitHub-hosted runners)

Для агентов выполнения, размещаемых на GitHub и созданных на основе образов (images), поддерживаемых GitHub, вы можете просмотреть **спецификацию программного обеспечения** (Software Bill of Materials, SBOM), чтобы увидеть, какое ПО было предустановлено на исполнителе (runner). Вы можете предоставить SBOM своим пользователям, чтобы они могли запустить сканер уязвимостей (vulnerability scanner) для проверки продукта. Если вы создаете артефакты (artifacts), вы можете включить этот SBOM в свою спецификацию для получения полного списка всего, что было использовано при создании вашего ПО.

SBOM доступны для образов агентов выполнения на базе **Ubuntu**, **Windows** и **macOS**, поддерживаемых GitHub. Вы можете найти SBOM для вашей сборки в активах релиза (release assets) по адресу `https://github.com/actions/runner-images/releases`. Файл SBOM с именем в формате `sbom.IMAGE-NAME.json.zip` находится в приложениях к каждому релизу.

Для сторонних образов, таких как образы исполнителей на базе **ARM** (ARM-powered runners), подробную информацию о ПО, включенном в образ, можно найти в [репозитории `actions/partner-runner-images`](https://github.com/actions/partner-runner-images).

#### Запрет доступа к хостам (Denying access to hosts)

Исполнители, размещаемые на GitHub, поставляются с файлом `etc/hosts`, который блокирует сетевой доступ к различным пулам для майнинга криптовалют и вредоносным сайтам. Такие хосты, как `MiningMadness.com` и `cpu-pool.com`, перенаправляются на `localhost`, чтобы они не представляли значительного риска безопасности. Для получения дополнительной информации см. раздел «[Исполнители, размещаемые на GitHub](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners)» (GitHub-hosted runners).

### Укрепление защиты собственных исполнителей (Hardening for self-hosted runners)

**Исполнители, размещаемые на GitHub**, выполняют код внутри **эфемерных** (ephemeral) и чистых изолированных виртуальных машин. Это означает, что не существует способа перманентно скомпрометировать эту среду или иным образом получить доступ к большему объему информации, чем тот, который был помещен в эту среду в процессе начальной загрузки (bootstrap process).

**Собственные исполнители** (self-hosted runners) для GitHub не имеют гарантий работы в эфемерных чистых виртуальных машинах и могут быть перманентно скомпрометированы ненадежным кодом (untrusted code) в рабочем процессе.

В результате **собственные исполнители (self-hosted runners)** почти **[никогда не должны использоваться для публичных репозиториев](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) (public repositories)** на GitHub, так как любой пользователь может создать **запрос на слияние (pull request)** к репозиторию и скомпрометировать среду. Точно так же следует проявлять осторожность при использовании собственных исполнителей в **приватных (private)** или **внутренних репозиториях (internal repositories)**, поскольку любой, кто может создать **форк (fork)** репозитория и открыть запрос на слияние (как правило, это те, у кого есть **доступом на чтение (read access)** к репозиторию), способен скомпрометировать среду собственного исполнителя. Это включает получение доступа к **секретам (secrets)** и токену **`GITHUB_TOKEN`**, который, в зависимости от его настроек, может предоставлять **доступ на запись (write access)** в репозиторий. Хотя **сценарии автоматизации (workflows)** могут контролировать доступ к секретам сред с помощью использования **сред (environments)** и **обязательных проверок (required reviews)**, эти сценарии не запускаются в **изолированной среде (isolated environment)** и по-прежнему подвержены тем же рискам при запуске на собственном исполнителе.

Владельцы организации (Organization owners) могут выбирать, каким репозиториям разрешено создавать собственные исполнители уровня репозитория (repository-level self-hosted runners).

Для получения дополнительной информации см. «[Отключение или ограничение GitHub Actions для вашей организации](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#limiting-the-use-of-self-hosted-runners)» (Disabling or limiting GitHub Actions for your organization).

Когда собственный исполнитель определен на уровне организации или предприятия (enterprise), GitHub может распределять рабочие процессы из нескольких репозиториев на один и тот же исполнитель. Следовательно, компрометация безопасности такой среды может иметь широкие последствия. Чтобы уменьшить масштаб компрометации, вы можете создать границы, распределив собственные исполнители по отдельным группам (groups). Вы можете ограничить список организаций и репозиториев, имеющих доступ к группам исполнителей. Для получения дополнительной информации см. раздел «[Управление доступом к собственным исполнителям с помощью групп](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups)» (Managing access to self-hosted runners using groups).

Вам также следует учитывать окружение машин с собственными агентами выполнения:

- Какая конфиденциальная информация находится на машине, настроенной как собственный исполнитель? Например, закрытые ключи SSH (private SSH keys), токены доступа к API (API access tokens) и другие.

- Имеет ли машина сетевой доступ к чувствительным сервисам? Например, к сервисам метаданных Azure или AWS. Объем конфиденциальной информации в этой среде должен быть сведен к минимуму, и вы всегда должны помнить, что любой пользователь, способный вызывать рабочие процессы, имеет доступ к этой среде.

Некоторые клиенты могут пытаться частично предотвратить эти риски, внедряя системы, которые автоматически уничтожают собственный исполнитель после каждого выполнения задания. Однако этот подход может быть не таким эффективным, как ожидалось, поскольку нет способа гарантировать, что собственный исполнитель выполнит только одно задание. Некоторые задания используют секреты в качестве аргументов командной строки, которые могут быть видны другому заданию, запущенному на том же исполнителе (например, через команду `ps x -w`). Это может привести к **утечке секретов** (secret leaks).

### Использование исполнителей, создаваемых по запросу (Using just-in-time runners)

Для повышения безопасности регистрации **исполнителей (runners)** вы можете использовать **REST API (REST API)** для создания эфемерных **исполнителей, создаваемых по запросу (just-in-time (JIT) runners)**. Эти **собственные исполнители (self-hosted runners)** выполняют не более одного **задания (job)**, после чего автоматически удаляются из **репозитория (repository)**, **организации (organization)** или **предприятия (enterprise)**. Для получения дополнительной информации о настройке **исполнителей, создаваемых по запросу (JIT runners)** см. раздел «[Конечные точки REST API для собственных исполнителей](https://docs.github.com/en/rest/actions/self-hosted-runners#create-configuration-for-a-just-in-time-runner-for-an-organization) (REST API endpoints for self-hosted runners)».

> **Примечание:**
>
> Повторное использование оборудования (hardware) для хостинга JIT-исполнителей может привести к риску раскрытия информации из окружения. Используйте автоматизацию, чтобы гарантировать использование JIT-исполнителем чистой среды. Для получения дополнительной информации см. «[Справочник по собственным исполнителям](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/autoscaling-with-self-hosted-runners#using-ephemeral-runners-for-autoscaling)» (Self-hosted runners reference).

После получения конфигурационного файла из ответа REST API вы можете передать его агенту выполнения при запуске.

```
./run.sh --jitconfig ${encoded_jit_config}
```

#### Планирование стратегии управления собственными агентами выполнения (Planning your management strategy for self-hosted runners)

**Собственный агент выполнения** (self-hosted runner) может быть добавлен на различных уровнях иерархии GitHub: на уровне предприятия (enterprise), организации (organization) или репозитория (repository). Это размещение определяет, кто сможет управлять исполнителем:

**Централизованное управление** (Centralized management):

- Если вы планируете, что собственными агентами выполнения будет владеть централизованная команда, рекомендуется добавлять исполнителей на самом высоком общем уровне организации или предприятия. Это даст вашей команде единое место для просмотра и управления агентами выполнения.

- Если у вас только одна организация, добавление исполнителей на уровне организации фактически будет тем же подходом, однако вы можете столкнуться с трудностями, если добавите еще одну организацию в будущем.

**Децентрализованное управление** (Decentralized management):

- Если каждая команда будет самостоятельно управлять своими собственными агентами выполнения, рекомендуется добавлять их на самом высоком уровне владения командой. Например, если каждая команда владеет своей организацией, проще всего будет добавить исполнителей также на уровне организации.

- Вы также можете добавлять исполнителей на уровне репозитория (repository level), но это увеличит накладные расходы на управление (management overhead), а также количество необходимых исполнителей, поскольку вы не сможете совместно использовать их между репозиториями.

#### Аутентификация у вашего облачного провайдера (Authenticating to your cloud provider)

Если вы используете GitHub Actions для развертывания (deployment) у облачного провайдера или планируете использовать **HashiCorp Vault** для управления секретами, рекомендуется рассмотреть использование **OpenID Connect** (OIDC) для создания **краткосрочных токенов доступа с четко ограниченной областью действия** (short-lived, well-scoped access tokens) для ваших запусков рабочих процессов. Для получения дополнительной информации см. раздел [OpenID Connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect).

### Аудит событий GitHub Actions (Auditing GitHub Actions events)

Вы можете использовать **журнал безопасности** (security log) для мониторинга активности вашей учетной записи пользователя и **журнал аудита** (audit log) для мониторинга активности в вашей организации. В журналах безопасности и аудита фиксируется тип действия (action), время его выполнения и персональная учетная запись (personal account), выполнившая это действие.

Например, вы можете использовать журнал аудита для отслеживания события `org.update_actions_secret`, которое фиксирует изменения в секретах организации.

Для получения полного списка **событий (events)**, которые вы можете найти в **журнале аудита (audit log)** для каждого **типа учетной записи (account type)**, см. следующие статьи:

* **[События журнала безопасности](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events) (Security log events)**
* **[События журнала аудита для вашей организации](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization) (Audit log events for your organization)**

### Понимание зависимостей в ваших сценариях автоматизации (Understanding dependencies in your workflows)

Вы можете использовать **граф зависимостей (dependency graph)**, чтобы изучить **действия (actions)**, которые используют **сценарии автоматизации (workflows)** в вашем **репозитории (repository)**. Граф зависимостей представляет собой сводку файлов **манифеста (manifest)** и **лок-файлов (lock files)**, хранящихся в репозитории. Он также распознает файлы в директории `./github/workflows/` как манифесты, что означает, что любые действия (actions) или сценарии автоматизации (workflows), на которые ссылаются с помощью синтаксиса `jobs[*].steps[*].uses` или `jobs.<job_id>.uses`, будут проанализированы как **зависимости (dependencies)**.

Граф зависимостей (dependency graph) отображает следующую информацию о действиях (actions), используемых в сценариях автоматизации (workflows):
* Учетная запись или **организация (organization)**, владеющая действием.
* Файл сценария автоматизации (workflow file), который ссылается на действие.
* Версия или **SHA**, к которым привязано действие.

В графе зависимостей зависимости автоматически сортируются по **степени серьезности уязвимости (vulnerability severity)**. Если для каких-либо из используемых вами действий существуют **бюллетени по безопасности (security advisories)**, они будут отображаться в верхней части списка. Вы можете перейти к бюллетеню из графа зависимостей и получить доступ к инструкциям по устранению **уязвимости (vulnerability)**.

Граф зависимостей (dependency graph) включен для **публичных репозиториев (public repositories)**, также вы можете включить его для **приватных репозиториев (private repositories)**. Для получения дополнительной информации об использовании графа зависимостей см. раздел «[Изучение зависимостей репозитория](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exploring-the-dependencies-of-a-repository) (Exploring the dependencies of a repository)».

### Осведомленность об уязвимостях в безопасности в используемых вами действиях (Being aware of security vulnerabilities in actions you use)

Для **действий (actions)**, доступных в **маркетплейсе (marketplace)**, **GitHub** проверяет соответствующие **бюллетени по безопасности (security advisories)** и добавляет их в **базу данных консультаций по безопасности GitHub (GitHub Advisory Database)**. Вы можете искать в этой базе данных используемые вами действия, чтобы найти информацию о существующих **уязвимостях (vulnerabilities)** и инструкции по их устранению. Чтобы упростить поиск, используйте фильтр **GitHub Actions** в **[GitHub Advisory Database](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aactions)**.

Вы можете настроить свои **репозитории (repositories)** так, чтобы:

- **Получать оповещения (alerts)**, когда для действий, используемых в ваших **сценариях автоматизации (workflows)**, поступает отчет об уязвимости. Для получения дополнительной информации см. раздел «[Мониторинг действий в ваших сценариях автоматизации](https://docs.github.com/en/actions/reference/security/secure-use#monitoring-the-actions-in-your-workflows) (Monitoring the actions in your workflows)».

- **Получать предупреждения** о существующих бюллетенях (advisories) при добавлении или обновлении действия в сценарии автоматизации. Для получения дополнительной информации см. раздел «[Проверка действий на наличие уязвимостей в новых или обновленных сценариях автоматизации](https://docs.github.com/en/actions/reference/security/secure-use#screening-actions-for-vulnerabilities-in-new-or-updated-workflows) (Screening actions for vulnerabilities in new or updated workflows)».

#### Мониторинг действий в ваших сценариях автоматизации (Monitoring the actions in your workflows)

Вы можете использовать Dependabot для мониторинга действий (actions) в ваших сценариях автоматизации (workflows) и включить оповещения Dependabot (Dependabot alerts), чтобы получать уведомления, когда в используемом вами действии обнаруживается уязвимость. Dependabot выполняет сканирование ветки по умолчанию (default branch) репозиториев, где он включен, для обнаружения небезопасных зависимостей (insecure dependencies).
Dependabot генерирует оповещения, когда в базу данных консультаций по безопасности GitHub (GitHub Advisory Database) добавляется новый бюллетень (advisory) или когда обновляется используемое вами действие.

> **Примечание (Note)**
>
> Dependabot создает оповещения только для уязвимых действий, которые используют семантическое версионирование (semantic versioning), и не будет создавать оповещения для действий, зафиксированных по значениям SHA (pinned to SHA values).

Вы можете включить оповещения Dependabot (Dependabot alerts) для своего личного аккаунта (personal account), для конкретного репозитория (repository) или для всей организации (organization). Для получения дополнительной информации см. «[Настройка оповещений Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/configuring-dependabot-alerts) (Configuring Dependabot alerts)».

Вы можете просматривать все открытые и закрытые оповещения, а также соответствующие обновления безопасности Dependabot (Dependabot security updates) на вкладке оповещений Dependabot (Dependabot alerts tab) вашего репозитория. Для получения дополнительной информации см. «[Просмотр и обновление оповещений Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts) (Viewing and updating Dependabot alerts)».

#### Проверка действий на наличие уязвимостей в новых или обновленных сценариях автоматизации (Screening actions for vulnerabilities in new or updated workflows)

Когда вы открываете запросы на слияние (pull requests) для обновления ваших сценариев автоматизации (workflows), хорошей практикой считается использование отзыва зависимостей (dependency review), чтобы понять, как внесенные изменения в используемые вами действия (actions) влияют на безопасность.
Отзыв зависимостей (dependency review) помогает оценить изменения в зависимостях и их влияние на безопасность (security impact) при каждом запросе на слияние. Он предоставляет легко понятную визуализацию изменений зависимостей с подробной разницей (diff) на вкладке «Измененные файлы» (Files Changed tab) запроса на слияние.
Отзыв зависимостей (dependency review) информирует вас о следующем:

- Какие зависимости были добавлены, удалены или обновлены, а также даты их выпуска.

- Сколько проектов используют эти компоненты.

- Данные об уязвимостях (vulnerability data) для этих зависимостей.

Если какие-либо изменения, внесенные вами в сценарии автоматизации, будут помечены как уязвимые, вы сможете избежать их добавления в свой проект или обновить их до безопасной версии.

Для получения дополнительной информации см. раздел «[Об отзыве зависимостей](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review) (About dependency review)».

Термин «действие по отзыву зависимостей» (dependency review action) относится к конкретному действию, которое может сообщать о различиях в запросе на слияние в контексте GitHub Actions. См. [`dependency-review-action`](https://github.com/actions/dependency-review-action)

Вы можете использовать dependency-review-action в своем репозитории для принудительного выполнения отзывов зависимостей в ваших запросах на слияние. Это действие сканирует на наличие уязвимых версий зависимостей, вносимых изменениями версий пакетов в запросах на слияние, и предупреждает вас о связанных с ними уязвимостях в безопасности (security vulnerabilities).

Это дает вам лучшую видимость того, что именно меняется в запросе на слияние, и помогает предотвратить добавление уязвимостей в ваш репозиторий.

### Поддержание безопасности и актуальности действий в ваших сценариях автоматизации (Keeping the actions in your workflows secure and up to date)

Вы можете использовать **Dependabot**, чтобы гарантировать, что ссылки на **действия (actions)** и **повторно используемые сценарии автоматизации (reusable workflows)**, используемые в вашем **репозитории (repository)**, поддерживаются в актуальном состоянии. **Действия (actions)** часто обновляются с целью **исправления ошибок (bug fixes)** и добавления новых функций, чтобы сделать **автоматизированные процессы (automated processes)** более быстрыми, безопасными и надежными. **Dependabot** берет на себя заботу о поддержании ваших **зависимостей (dependencies)**, выполняя это за вас автоматически.

Для получения дополнительной информации см. разделы «[Поддержание ваших действий в актуальном состоянии с помощью **Dependabot**](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot) (Keeping your actions up to date with **Dependabot**)» и «[Об обновлениях безопасности **Dependabot**](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates) (About **Dependabot** security updates)».

Следующие функции могут автоматически обновлять действия в ваших сценариях автоматизации:
- **Обновления версий Dependabot (Dependabot version updates)** открывают **запросы на слияние (pull requests)** для обновления действий до последней версии при выходе новой версии.
- **Обновления безопасности Dependabot (Dependabot security updates)** открывают **запросы на слияние (pull requests)** для обновления действий с обнаруженными уязвимостями до минимальной **версии с исправлением (patched version)**.

> **Примечание (Note)**
>
> - **Dependabot** поддерживает обновления для **GitHub Actions** только с использованием синтаксиса репозитория **GitHub**, такого как `actions/checkout@v5` или `actions/checkout@<commit>`. **Dependabot** будет игнорировать действия или повторно используемые сценарии автоматизации, на которые ведут локальные ссылки (например, `./.github/actions/foo.yml`).
> - **Dependabot** обновляет документацию версий **GitHub Actions**, когда комментарий находится на той же строке, например `actions/checkout@<commit> #<tag or link>` или `actions/checkout@<tag> #<tag or link>`.
> - Если используемый вами **коммит (commit)** не связан ни с каким **тегом (tag)**, **Dependabot** обновит **GitHub Actions** до последнего коммита (который может отличаться от последнего релиза).
> - **URL-адреса реестров контейнеров Docker Hub и GitHub Packages (Docker Hub and GitHub Packages Container registry URLs)** в настоящее время не поддерживаются. Например, ссылки на действия в Docker-контейнерах с использованием синтаксиса `docker://` не поддерживаются.
> - **Dependabot** поддерживает как публичные, так и приватные репозитории для **GitHub Actions**. Информацию о параметрах конфигурации приватных реестров см. в разделе «`git`» справочника параметров **[Dependabot (Dependabot options reference)](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#git)**.

Для получения информации о том, как настроить обновления версий **Dependabot**, см. «[Настройка обновлений версий **Dependabot**](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates) (Configuring **Dependabot** version updates)».
Для получения информации о том, как настроить обновления безопасности **Dependabot**, см. «[Настройка обновлений безопасности **Dependabot**](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates) (Configuring **Dependabot** security updates)».

### Защита созданных вами действий (Protecting actions you've created)

**GitHub** способствует сотрудничеству между людьми, которые публикуют и поддерживают **действия (actions)**, и теми, кто сообщает об уязвимостях (**vulnerability reporters**), в целях продвижения безопасного программирования (**secure coding**). **Бюллетени по безопасности репозитория (Repository security advisories)** позволяют сопровождающим (**maintainers**) публичных репозиториев (**public repositories**) конфиденциально обсуждать и исправлять **уязвимости безопасности (security vulnerabilities)** в проекте. После совместной работы над исправлением сопровождающие репозитория могут опубликовать бюллетень по безопасности, чтобы публично раскрыть уязвимость сообществу проекта. Публикуя бюллетени по безопасности, сопровождающие репозитория упрощают своему сообществу процесс обновления **зависимостей пакетов (package dependencies)** и изучения влияния уязвимостей.

Если вы являетесь тем, кто поддерживает **действие (action)**, используемое в других проектах, вы можете использовать следующие функции **GitHub** для повышения безопасности опубликованных вами действий:

- Используйте представление **зависимых проектов (dependants view)** в **графе зависимостей (Dependency graph)**, чтобы увидеть, какие проекты зависят от вашего кода. Если вы получите отчет об уязвимости, это даст вам представление о том, с кем вам нужно связаться по поводу уязвимости и как её исправить. Для получения дополнительной информации см. «[Изучение зависимостей репозитория](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exploring-the-dependencies-of-a-repository#dependents-view) (Exploring the dependencies of a repository)».

- Используйте **бюллетени по безопасности репозитория (repository security advisories)**, чтобы создать бюллетень, конфиденциально сотрудничать для исправления уязвимости во временном **приватном ответвлении (temporary private fork)** и опубликовать бюллетень по безопасности, чтобы предупредить своё сообщество об уязвимости после выпуска **исправления (patch)**. Для получения дополнительной информации см. «[Настройка приватных сообщений об уязвимостях для репозитория](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository) (Configuring private vulnerability reporting for a repository)» и «[Создание бюллетеня по безопасности репозитория](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/creating-a-repository-security-advisory) (Creating a repository security advisory)».
