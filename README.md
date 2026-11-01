# scanner-triage

CLI-утилита для триажа результатов сканеров: приводит отчёты **Trivy** (JSON) и
**Semgrep** (SARIF) к одной модели, убирает дубликаты, строит Markdown-отчёт и
заводит задачи в GitLab Issues.

## Зачем

После подключения нескольких сканеров в CI разработчик получает сотни строк
вывода на трёх разных языках. Рутина — свести их в один список, отфильтровать
шум, разложить по severity и завести задачи — хорошо автоматизируется. Утилита
решает именно её и годится как шаг пайплайна: отчёт уходит в артефакты, а
сборка падает по порогу severity.

## Возможности

- парсинг Trivy JSON (`Results[].Vulnerabilities`, `Results[].Misconfigurations`,
  `Results[].Secrets`);
- парсинг Semgrep SARIF (`runs[].results[]`);
- нормализация severity (`error` → `HIGH`, `warning` → `MEDIUM`, `moderate` → `MEDIUM`);
- дедупликация по стабильному fingerprint (source + rule + target + line + package);
- Markdown-отчёт со сводкой по severity и деталями;
- фильтр `--min-severity` и CI-гейт `--fail-on`;
- создание issues в GitLab через REST API: таймауты, retry с экспоненциальным
  backoff, обработка ошибок, токен только из переменной окружения.

## Запуск

```bash
python -m triage trivy.json semgrep.sarif -o security-report.md
python -m triage trivy.json --fail-on HIGH --min-severity MEDIUM
```

Создание задач (токен не попадает в лог и не хранится в коде):

```bash
export GITLAB_TOKEN=...        # personal/project access token, scope api
python -m triage trivy.json \
  --create-issues \
  --gitlab-url https://gitlab.example \
  --project-id 123
```

Коды возврата: `0` — успех, `1` — findings выше порога или ошибка GitLab API,
`2` — некорректный ввод (нет файла, неизвестный формат, нет токена).

## Тесты

```bash
python -m pytest
```

Покрыты парсинг обоих форматов, нормализация severity, дедупликация, рендер,
CLI-коды возврата и клиент GitLab (retry на 5xx/429, отсутствие retry на 4xx,
отсутствие токена в тексте ошибки) — HTTP замокан, сеть не нужна.

## Решения по безопасности

| Риск | Решение |
| --- | --- |
| Токен утекает в лог | токен читается из `GITLAB_TOKEN`, в сообщения не подставляется |
| URL с неожиданной схемой (`file://`) | `base_url` проверяется: только абсолютный `http(s)` |
| Подвисший HTTP-запрос | `timeout` на каждый запрос (по умолчанию 10 с) |
| Временные 5xx/429 | до 3 повторов с экспоненциальным backoff |
| Некорректный отчёт | явная ошибка `UnsupportedReport`, код возврата 2 |
| Утечка значения секрета в отчёт | поля `Match`/`Code` от Trivy не используются: в отчёт попадают только правило, файл и строка |
| Дубли задач | fingerprint в теле issue и дедупликация до создания |
| Инъекция в Markdown | экранирование `|` и переносов строк в таблицах |

## Ограничения

- GitLab API не ищет по телу issue, поэтому повторный запуск создаст дубликат:
  в проде нужен поиск по label + fingerprint или состояние в БД;
- не поддерживаются HTML-отчёты и SARIF от других инструментов (добавляется
  отдельным парсером);
- CVSS/EPSS-обогащение не реализовано — следующий шаг.
