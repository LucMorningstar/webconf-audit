# Отчет о большом тестировании на публичных real-world конфигурациях

Дата: 2026-05-15
Репозиторий: `webconf-audit`
Режим: безопасный локальный анализ конфигураций без сетевого probing

## Краткое заключение

Был проведен большой безопасный прогон проекта на корпусе реальных публичных конфигураций веб-серверов, скачанных из открытых GitHub-репозиториев. Проверялись локальные анализаторы `analyze-nginx`, `analyze-apache`, `analyze-lighttpd` и `analyze-iis`. Внешние цели не сканировались, HTTP/TLS probing не выполнялся, `include_shell` в Lighttpd не исполнялся.

Финальный corpus-run обработал 245 файлов: 35 Nginx, 80 Apache, 60 Lighttpd и 70 IIS. После исправлений все 245 файлов были обработаны без необработанных исключений: `crashes = 0`. Анализаторы вернули 4682 finding'а по политикам безопасности и 45 файлов с error-level diagnostic issues. Эти error-level issues были классифицированы: оставшиеся случаи в основном связаны с отсутствующими системными include-файлами, Markdown/template/snippet-файлами, shell-generated фрагментами или действительно некорректными публичными конфигами. Новых crash-дефектов после исправлений не осталось.

В ходе работы были найдены и исправлены реальные проблемы проекта:

- Nginx false negatives в Gixy-style паттернах: неполное taint-распознавание переменных, named captures, SSRF в `proxy_pass`, CRLF/response splitting через tainted значения и Host spoofing через `proxy_set_header Host`.
- Lighttpd parser gap: валидные compact-формы `$HTTP[...] { directive = "" }` и `} else $HTTP[...] {` раньше давали `lighttpd_parse_error`.
- API inconsistency: `analyze_nginx_config`, `analyze_apache_config` и `analyze_iis_config` падали при передаче `PathLike`, хотя `analyze_lighttpd_config` уже это поддерживал.

После исправлений прошли targeted analyzer tests, полный non-live unit/static набор, Ruff и CLI smoke на реальных файлах корпуса.

## Цель тестирования

Целью было проверить проект на реальных публичных конфигурациях, а не только на синтетических unit fixtures:

- найти crash-сценарии и необработанные исключения;
- проверить устойчивость парсеров к реальному синтаксису, шаблонам, include'ам, backup-файлам и документационным snippets;
- оценить шум и диагностические ошибки;
- выявить false negatives в правилах;
- исправить воспроизводимые дефекты и закрыть их regression-тестами;
- сохранить воспроизводимые артефакты большого прогона.

## Границы безопасности

Тестирование было выполнено только как local static analysis:

- не выполнялся `analyze-external`;
- не выполнялись live HTTP/TLS-запросы к доменам из конфигов;
- не выполнялся external probing неизвестных host'ов;
- Lighttpd `include_shell` оставался в безопасном режиме и не исполнялся;
- IIS TLS registry enrichment был отключен для corpus-run через `use_tls_registry=False`, чтобы не зависеть от локального Windows registry;
- скачанные конфиги анализировались как локальные файлы в `.tmp/public-config-corpus-2026-05-15`.

## Корпус публичных конфигураций

Корпус был собран из публичных GitHub-репозиториев. Использовались GitHub code search queries и скачивание raw/blob содержимого в локальную временную директорию. GitHub code search частично уперся в rate limit, поэтому корпус является крупной репрезентативной выборкой, но не буквальным "всем интернетом". Это ожидаемое ограничение: полный перебор всех публичных конфигураций в интернете технически и юридически не является реалистичной задачей для одного безопасного локального прогона.

Итоговый состав корпуса:

| Тип | Количество | Типичные файлы |
| --- | ---: | --- |
| Nginx | 35 | `nginx.conf`, `*.conf`, `*.conf.prod`, `*.conf.dev`, `*.md`, `*.sigil`, `*.ctmpl`, backup/config snippets |
| Apache | 80 | `httpd.conf`, vhost configs, `ssl.conf`, `.htaccess`, `.htaccess.dist`, examples/backups |
| Lighttpd | 60 | `lighttpd.conf`, distro samples, embedded configs, `*.j2`, `*.tpl`, `*.dist`, include-heavy configs |
| IIS | 70 | `web.config`, `Web.config`, `applicationHost.config`, `*.txt`, `*.md`, `.bak`, `.org` |

Примеры источников из корпуса:

- Nginx: [nginx/nginx-quic-qns `nginx.conf.http3`](https://github.com/nginx/nginx-quic-qns/blob/e74a9c596e763365d9591163ba701a7f643a8cce/nginx.conf.http3), [allisterb/Alpheus `Examples/nginx.conf.2`](https://github.com/allisterb/Alpheus/blob/214e56b3b31013f293cb81e95deec027f2b30c27/Examples/nginx.conf.2), [caktus/django-project-template `nginx.conf.sigil`](https://github.com/caktus/django-project-template/blob/644148f7327a7bb54e52d3de8a7fe3c03c674b20/nginx.conf.sigil).
- Apache: [92TheBrilliant/heac `apache.conf`](https://github.com/92TheBrilliant/heac/blob/9f5c9e2ac8469d913236723981d42af2eb5fcb54/apache.conf), [beepnl/BEEP `apache/webapp-vhost.conf`](https://github.com/beepnl/BEEP/blob/79842d0b11c0561b8ca2f666ea04df4f6294e393/apache/webapp-vhost.conf), [openshift/basic-authentication-provider-example `ssl.conf`](https://github.com/openshift/basic-authentication-provider-example/blob/bc3073deaa2cc5901b92ffaada3cb6ada49f47a5/ssl.conf).
- Lighttpd: [bastienwirtz/homer `lighttpd.conf`](https://github.com/bastienwirtz/homer/blob/59f6c3c313a712ff6c3a53e47457e4078cb317b3/lighttpd.conf), [AllskyTeam/allsky `config_repo/lighttpd.conf.repo`](https://github.com/AllskyTeam/allsky/blob/a7b32445b9689969af3c757e4888a2db90e1a86e/config_repo/lighttpd.conf.repo), [AaltoSciComp/ansible-role-lgw-quota `templates/lighttpd.conf.j2`](https://github.com/AaltoSciComp/ansible-role-lgw-quota/blob/31c937d3312b8d5ed37e760f7e80e3817d971088/templates/lighttpd.conf.j2).
- IIS: [microsoft/nav-docker `generic/Run/web.config`](https://github.com/microsoft/nav-docker/blob/cd6627134a6a51a7e16b8c02a64712d4d825dd33/generic/Run/web.config), [steffest/BassoonTracker `api/web.config`](https://github.com/steffest/BassoonTracker/blob/805cf5f7801a178013255ea1f5c567a6afde4d07/api/web.config), [AppertaFoundation/Apperta-GLNRegistryApp-Angular `src/Web.Config`](https://github.com/AppertaFoundation/Apperta-GLNRegistryApp-Angular/blob/1615d14c125dc3d29428a9d75e098317da93dce6/src/Web.Config).

Локальные артефакты:

- `.tmp/public-config-corpus-2026-05-15/manifest.json` - список скачанных файлов и ссылок на источники.
- `.tmp/public-config-corpus-2026-05-15/analysis-results-final.json` - полный результат анализа.
- `.tmp/public-config-corpus-2026-05-15/analysis-summary-final.json` - агрегированная сводка.
- `.tmp/public-config-corpus-2026-05-15/analysis-error-issues-final.json` - файлы с error-level diagnostic issues.
- `.tmp/public-config-corpus-2026-05-15/analysis-crashes-final.json` - необработанные исключения; финально пустой массив.

## Методика

1. Был сделан snapshot состояния рабочей директории и доступных тестовых команд.
2. Был собран корпус публичных конфигов по типам серверов.
3. Каждый файл был прогнан соответствующим локальным анализатором:
   - Nginx: `analyze_nginx_config(path)`;
   - Apache: `analyze_apache_config(path)`;
   - Lighttpd: `analyze_lighttpd_config(path)`;
   - IIS: `analyze_iis_config(path, use_tls_registry=False)`.
4. Для каждого файла сохранялись:
   - тип сервера;
   - repo/path/blob URL;
   - локальный путь;
   - количество findings;
   - список diagnostic issues;
   - crash traceback, если возникло необработанное исключение.
5. После первичной классификации были исправлены воспроизводимые дефекты.
6. Corpus-run был повторен после исправлений.
7. Дополнительно были выполнены targeted tests, полный non-live pytest, Ruff и CLI smoke.

## Финальные результаты corpus-run

Финальная сводка:

| Метрика | Значение |
| --- | ---: |
| Всего файлов | 245 |
| Nginx | 35 |
| Apache | 80 |
| Lighttpd | 60 |
| IIS | 70 |
| Необработанные исключения | 0 |
| Файлов с error-level diagnostic issues | 45 |
| Всего findings | 4682 |

Распределение findings по severity:

| Severity | Количество |
| --- | ---: |
| High | 18 |
| Medium | 1393 |
| Low | 3194 |
| Info | 77 |

Важно: findings - это результаты правил безопасности на публичных конфигурациях. Они не являются ошибками проекта сами по себе. Ошибкой проекта считались crash, parser gap, false negative или некорректная обработка API/входа.

## Наиболее частые findings

На публичном корпусе ожидаемо доминируют baseline-hardening правила: отсутствующие security headers, request limits, log policy, TLS/HTTP hardening, доступ к backup/generated/VCS files и общие listen/interface checks.

Частые группы по серверам:

- Nginx:
  - `nginx.missing_backup_file_deny`;
  - `nginx.missing_content_security_policy`;
  - `nginx.missing_hidden_files_deny`;
  - `nginx.missing_limit_conn`;
  - `nginx.missing_limit_req`;
  - `nginx.proxy_missing_source_ip_headers`.
- Apache:
  - `apache.timeout_keepalive_default_policy`;
  - `apache.allowoverride_not_none`;
  - `apache.server_tokens_not_prod`;
  - `apache.trace_enable_not_off`;
  - `apache.backup_temp_files_not_restricted`;
  - `apache.ht_files_not_restricted`;
  - `apache.default_vhost_not_rejecting_unknown_hosts`.
- Lighttpd:
  - `lighttpd.max_request_size_missing`;
  - `lighttpd.missing_strict_transport_security`;
  - `lighttpd.server_tag_not_blank`;
  - `lighttpd.url_access_deny_missing`;
  - `lighttpd.missing_http_method_restrictions`;
  - universal header/listen findings.
- IIS:
  - `iis.request_filtering_allow_high_bit`;
  - `iis.file_extensions_allow_unlisted`;
  - `iis.request_filtering_remove_server_header_disabled`;
  - `iis.max_allowed_content_length_missing`;
  - `iis.missing_hsts_header`;
  - `iis.http_runtime_version_header_enabled`;
  - `iis.authorization_policy_missing`.

## Diagnostic issues и их классификация

Финальные diagnostic issue counts:

| Level | Code | Count | Классификация |
| --- | --- | ---: | --- |
| warning | `iis_physical_path_not_found` | 72 | Ожидаемо при анализе скачанного `applicationHost.config`: физические пути сайтов не существуют локально |
| warning | `lighttpd_include_shell_skipped` | 18 | Ожидаемая безопасная политика: `include_shell` не исполнялся |
| error | `iis_parse_error` | 15 | В основном Markdown/snippet/malformed XML, не crash анализатора |
| error | `nginx_include_not_found` | 9 | Ожидаемо при isolated configs: `mime.types`, `fastcgi_params`, `uwsgi_params`, `conf/mime.types` не были скачаны рядом |
| error | `lighttpd_include_not_found` | 7 | Ожидаемо при isolated configs: локальные/system include paths отсутствуют |
| error | `nginx_parse_error` | 6 | В основном template/Markdown/non-raw config files (`.md`, `.sigil`, `.ctmpl`, `.js`) |
| error | `apache_include_not_found` | 4 | Ожидаемо при isolated configs: Bitnami/system include paths отсутствуют |
| warning | `lighttpd_undefined_variable` | 4 | Ожидаемо для шаблонов или фрагментов без полного окружения |
| error | `apache_parse_error` | 3 | Некорректные публичные файлы: merge conflict markers или незакрытые кавычки |
| error | `lighttpd_parse_error` | 3 | Остались shell/template-generated файлы, не raw Lighttpd syntax |

Примеры:

- `apache_include_not_found`: [beepnl/BEEP](https://github.com/beepnl/BEEP/blob/79842d0b11c0561b8ca2f666ea04df4f6294e393/apache/webapp-vhost.conf) с `/opt/bitnami/apps/BEEP/apache/beep-public.conf`.
- `apache_parse_error`: [c57fr/Site-Internet `o.htaccess`](https://github.com/c57fr/Site-Internet/blob/a08887bdb3575b921d0c3a298087f9249c8d7cf5/o.htaccess) содержит merge conflict markers.
- `iis_parse_error`: [flukehan/MixERP `web.config.md`](https://github.com/flukehan/MixERP/blob/bb756c5092fc63f420b173a18975d9ec6e3f702c/docs/configs/web.config.md) является Markdown-документом, а не чистым XML.
- `lighttpd_parse_error`: [AaltoSciComp/ansible-role-lgw-quota `lighttpd.conf.j2`](https://github.com/AaltoSciComp/ansible-role-lgw-quota/blob/31c937d3312b8d5ed37e760f7e80e3817d971088/templates/lighttpd.conf.j2) содержит Jinja placeholders.
- `nginx_parse_error`: [caktus/django-project-template `nginx.conf.sigil`](https://github.com/caktus/django-project-template/blob/644148f7327a7bb54e52d3de8a7fe3c03c674b20/nginx.conf.sigil) содержит Sigil/template syntax.

Вывод по diagnostic issues: текущая модель корректно возвращает structured `AnalysisIssue`, а не падает. Оставшиеся ошибки не требуют срочного исправления парсеров, потому что большая часть входов не является чистыми конфигами или требует файловой среды оригинального приложения. Потенциальное улучшение на будущее - отдельный template/documentation preprocessing mode, но это уже новая функциональность, а не bugfix.

## Найденные дефекты проекта и исправления

### 1. Nginx false negatives в Gixy-style паттернах

До основного финального corpus-run были проверены Gixy-style fixtures и похожие паттерны. Они выявили несколько false negatives в Nginx правилах:

- user-controlled destination в `proxy_pass`, включая host-position interpolation;
- `$host`, `$uri`, `$document_uri` в host position для `proxy_pass`;
- taint через `set` и `map`;
- named regex captures из `location` вроде `(?<proxy_host>...)`;
- CRLF/response splitting через tainted values в `return` и `add_header`;
- Host spoofing через `proxy_set_header Host $http_host` или named capture.

Исправления:

- Расширен taint-анализ в `src/webconf_audit/local/nginx/rules/_variable_taint_utils.py`:
  - добавлены request-controlled named captures;
  - добавлена обработка host-position контекста для `proxy_pass`;
  - учтены `$host`, `$uri`, `$document_uri` в опасном контексте;
  - сохранена безопасная обработка циклов и scoped definitions.
- Добавлено правило `nginx.proxy_set_header_host_spoofing` в `src/webconf_audit/local/nginx/rules/proxy_set_header_host_spoofing.py`.
- Добавлены regression-тесты:
  - `tests/test_nginx_proxy_pass_ssrf.py`;
  - `tests/test_nginx_crlf_response_splitting.py`;
  - `tests/test_nginx_variable_taint.py`;
  - `tests/test_nginx_host_spoofing.py`.

Результат: ранее пропущенные Gixy-class паттерны теперь детектируются targeted tests.

### 2. Lighttpd parser gap: compact condition blocks

Реальные публичные Lighttpd configs показали валидный синтаксис, который парсер не принимал:

```lighttpd
$HTTP["remote-ip"] == "127.0.0.1" { accesslog.filename = "" }
} else $HTTP["url"] =~ "^/overlay/config/" {
```

Такие формы встретились, например, в [bastienwirtz/homer `lighttpd.conf`](https://github.com/bastienwirtz/homer/blob/59f6c3c313a712ff6c3a53e47457e4078cb317b3/lighttpd.conf) и [AllskyTeam/allsky `lighttpd.conf.repo`](https://github.com/AllskyTeam/allsky/blob/a7b32445b9689969af3c757e4888a2db90e1a86e/config_repo/lighttpd.conf.repo).

До исправления parser выдавал `lighttpd_parse_error: Unsupported inline brace usage`. Это был настоящий parser coverage bug: конфиг валиден, но анализатор не мог его разобрать.

Исправление:

- В `src/webconf_audit/local/lighttpd/parser/parser.py` добавлено разбиение физической строки на логические segments по unquoted `{` и `}`.
- Разбиение сохраняет кавычки и source line, не ломает multiline values и не интерпретирует braces внутри строк.
- Добавлены regression-тесты:
  - `test_parse_lighttpd_inline_condition_block`;
  - `test_parse_lighttpd_closing_brace_and_else_if_on_same_line`.

Эффект:

- до исправления: `lighttpd_parse_error` на corpus-run был 8;
- после исправления: `lighttpd_parse_error` снизился до 3;
- оставшиеся 3 случая являются shell/template-generated файлами, а не чистыми Lighttpd configs.

### 3. PathLike API inconsistency в local analyzers

При повторном corpus-run harness намеренно передавал `Path` objects в анализаторы. Это выявило API inconsistency:

- `analyze_lighttpd_config` уже принимал `str | PathLike`;
- `analyze_nginx_config`, `analyze_apache_config`, `analyze_iis_config` типизированы как `str` и в некоторых ветках возвращали `AnalysisResult(target=Path(...))`;
- Pydantic model требовал `target: str`, из-за чего возникал `ValidationError`, если библиотечный API вызывался напрямую с `Path`.

Исправление:

- `analyze_nginx_config`, `analyze_apache_config`, `analyze_iis_config` теперь принимают `str | PathLike[str]`;
- вход нормализуется один раз через `config_path_str = str(config_path)`;
- `AnalysisResult.target`, `SourceLocation.file_path` и сообщения об ошибках используют строковое представление;
- добавлены regression-тесты:
  - `test_analyze_nginx_config_accepts_pathlike_config_path`;
  - `test_analyze_apache_config_accepts_pathlike_config_path`;
  - `test_analyze_iis_config_accepts_pathlike_config_path`.

Результат: прямой библиотечный вызов с `Path` теперь работает для всех local analyzers.

## Что не исправлялось как bug

Некоторые diagnostic issues были оставлены как корректное поведение:

- `include_not_found` для `mime.types`, `fastcgi_params`, `/etc/...`, Bitnami paths и других файлов, которые не были частью isolated download. Это ожидаемый результат анализа одиночного конфигурационного файла без полной файловой среды исходного проекта.
- `iis_physical_path_not_found` для `applicationHost.config`, где физические пути сайтов указывают на локальные Windows directories исходного приложения.
- `lighttpd_include_shell_skipped`, потому что безопасный режим специально не исполняет shell directives.
- Parse errors на Markdown, Sigil, Consul Template, Jinja, `.tpl`, `.js`, `.txt` snippets и файлах с merge conflict markers. Эти входы полезны для robustness testing, но не являются чистым синтаксисом соответствующего сервера.

## Верификация после исправлений

Были выполнены следующие проверки:

| Проверка | Результат |
| --- | --- |
| Targeted analyzer tests: `tests/test_local_lighttpd.py`, `tests/test_local_nginx.py`, `tests/test_local_apache.py`, `tests/test_local_iis.py` | `143 passed` |
| Full non-live pytest: `pytest -q --ignore=tests\integration_external --ignore=tests\integration_local --ignore=tests\integration_optional_external` | `3071 passed, 1 skipped` |
| Ruff | `All checks passed!` |
| CLI smoke на 4 публичных файлах корпуса (`analyze-nginx/apache/lighttpd/iis --format json`) | Все exit `0`, JSON успешно parsed |
| Финальный corpus-run на 245 файлах | `crashes = 0` |

Ruff дополнительно вывел warning `Отказано в доступе. (os error 5)` по уже существующей директории `tmpkd_ok9wt/`, но завершился с exit code 0 и `All checks passed!`.

## Ограничения тестирования

Ограничения, которые важно учитывать:

- Корпус большой и реальный, но не исчерпывает весь интернет. Сбор через GitHub code search ограничен rate limit и релевантностью поисковых запросов.
- Анализ isolated config files не всегда эквивалентен анализу полного проекта с include tree, generated templates, environment variables и реальными filesystem paths.
- Template-aware режим не реализовывался: Jinja/Sigil/Consul Template/PHP/JS-generated config files анализировались как raw server config. Это намеренно выявляет robustness, но часть parse errors в таком режиме ожидаема.
- Live integration/external probing намеренно не выполнялись, потому что задача была безопасной и локальной.

## Рекомендации на будущее

1. Добавить регулярный `real-config-corpus` smoke job, который берет сохраненный manifest и прогоняет corpus локально без сети.
2. Расширить corpus за счет pinned raw URLs и небольшого curated набора известных конфигов, чтобы не зависеть от GitHub search rate limit.
3. Добавить optional template preprocessing mode для `.j2`, `.tpl`, `.ctmpl`, `.sigil` и Markdown fenced blocks. Это снизит parse noise и позволит анализировать больше документационных конфигов.
4. Рассмотреть отдельную классификацию `include_not_found` для стандартных include-файлов (`mime.types`, `fastcgi_params`, `uwsgi_params`) как expected isolated-corpus diagnostic, чтобы отчеты по real-world корпусу были менее шумными.
5. Сохранить Gixy-style regression pack как обязательный targeted suite для Nginx правил, потому что именно он эффективно ловит false negatives в taint-sensitive правилах.

## Итоговое заключение

Проект показал хорошую устойчивость на публичных real-world конфигурациях: после исправлений все 245 файлов корпуса обработаны без crashes. Найденные security findings соответствуют ожидаемому профилю публичных конфигов: много baseline-hardening замечаний, отсутствующих headers/limits/logging policy, открытых defaults и server-specific policy gaps. Эти findings подтверждают, что правила активно срабатывают на реальных данных, а не только на синтетических fixtures.

Критически важная часть тестирования - не количество findings, а поведение анализаторов на грязных реальных входах. Здесь были найдены настоящие проблемы качества: Nginx false negatives в taint-sensitive сценариях, Lighttpd parser gap на валидном compact syntax и inconsistency API при `PathLike` input. Все эти проблемы были исправлены, покрыты regression-тестами и повторно проверены полным corpus-run.

Оставшиеся error-level diagnostic issues после исправлений не являются необработанными исключениями и не указывают на системную нестабильность проекта. Они объясняются ограничениями isolated local analysis: отсутствующие include-файлы, системные пути исходных окружений, template syntax, Markdown/snippet files и несколько действительно поврежденных публичных файлов. Анализаторы в этих случаях возвращают structured issues, что является корректным и безопасным поведением.

Итог: большой real-world тест подтвердил работоспособность проекта на разнородных публичных конфигурациях, помог закрыть несколько реальных дефектов и оставил понятный список дальнейших улучшений для снижения шума на template/include-heavy корпусах.
