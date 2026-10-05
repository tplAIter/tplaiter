# testdata/fixtures

Mini-templates (single/multi-repo) for offline tplaiter tests (file:// repositories,
no network). Contain examples for the rendering engine (`internal/engine`) —
generic templates with `.Settings`, `is`/`has`, `__if_group__`/`__if_group=value__`
directories, file rules, etc., used by unit and e2e tests of
engine/repo/scaffolding-related components.

No fixture template is a real Go project — these are text files whose sole purpose
is to exercise engine/resolver mechanics.

## single-basic/

Single template repository (`template.manifest.yaml` at root +
`files/`) for `internal/engine` tests:

- `database` (select: none|postgres, nested toggle `migrations` with
  postgres) and `brokers` (multiselect: kafka|rabbitmq) — settings.
- `files/README.md.tmpl` — `is`/`has` in content.
- `files/__if_database=postgres__/db/schema.sql.tmpl` — conditional path based on
  select-group value.
- `files/__if_brokers__/brokers-enabled.txt` — conditional path based on
  multiselect-group truthiness (non-empty list).
- `files/extra/postgres-only.txt.tmpl` + `files/integrations/common.txt` —
  file rules in manifest (`paths`/composite `remove`).
- `files/dashboards/board.json.tmpl` — `copyWithoutRender` (preserves
  `{{ __rate_interval }}`) + `postReplace` (`__PROJECT_SLUG__` →
  `Project.Slug`).
- `files/config/__slug__.env.tmpl` — placeholder `__slug__` in filename.
- `files/main.txt.tmpl` + `partials/greeting.tmpl` — associated
  templates (`Options.Partials`).
- `NOTES.tmpl`, `README.md` — outside `files/` (metadata.notes/docs), not
  rendered directly by the engine — material for generation and tests.

## multi/

Multi-template repository (`repo.manifest.yaml`) with two
minimal templates — `alpha/` (toggle setting) and `beta/`
(string setting) — sufficient to exercise template selection in the
repository without re-testing the engine itself (that is done by
single-basic).

## nested-provider/

Provider-shaped repository without `repo.manifest.yaml`: a root template
(`provider-base`) plus nested templates discovered recursively —
`bootstrap/template-repository/templates/service` (`service`, the
template-base bootstrap shape) and `templates/worker` (`worker`). Used by
repository discovery tests (`internal/repo`, `internal/inittemplate`, and the
`tests/` e2e `TestNestedTemplates`). The root template keeps un-namespaced
tags (`v0.1.0`); nested templates use namespaced tags (`service/v0.1.0`).
