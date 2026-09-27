# testdata/fixtures

Мини-шаблоны (single/multi-репо) для offline-тестов tplater (file:// репозитории,
без сети). Содержат примеры для движка рендера (`internal/engine`) —
generic-шаблоны с `.Settings`, `is`/`has`, `__if_group__`/`__if_group=value__`-
каталогами, files-правилами и т.п., используемые юнит- и e2e-тестами
engine/repo/scaffolding связанных компонентов.

Ни один фикстурный шаблон не является настоящим Go-проектом — это текстовые
файлы, единственная цель которых — упражнять механики движка/резолвера.

## single-basic/

Одиночный шаблон-репозиторий (`template.manifest.yaml` в корне +
`files/`) для тестов `internal/engine`:

- `database` (select: none|postgres, вложенный toggle `migrations` при
  postgres) и `brokers` (multiselect: kafka|rabbitmq) — настройки.
- `files/README.md.tmpl` — `is`/`has` в контенте.
- `files/__if_database=postgres__/db/schema.sql.tmpl` — условный путь по
  значению select-группы.
- `files/__if_brokers__/brokers-enabled.txt` — условный путь по
  «истинности» multiselect-группы (непустой список).
- `files/extra/postgres-only.txt.tmpl` + `files/integrations/common.txt` —
  files-правила манифеста (`paths`/composite `remove`).
- `files/dashboards/board.json.tmpl` — `copyWithoutRender` (сохраняет
  `{{ __rate_interval }}`) + `postReplace` (`__PROJECT_SLUG__` →
  `Project.Slug`).
- `files/config/__slug__.env.tmpl` — плейсхолдер `__slug__` в имени файла.
- `files/main.txt.tmpl` + `partials/greeting.tmpl` — ассоциированные
  шаблоны (`Options.Partials`).
- `NOTES.tmpl`, `README.md` — вне `files/` (metadata.notes/docs), не
  рендерятся движком напрямую — материал для генерации и тестов.

## multi/

Мульти-шаблонный репозиторий (`repo.manifest.yaml`, ) с двумя
предельно маленькими шаблонами — `alpha/` (toggle-настройка) и `beta/`
(string-настройка) — достаточными, чтобы упражнять выбор шаблона в
репозитории без повторного тестирования самого движка (это делает
single-basic).
