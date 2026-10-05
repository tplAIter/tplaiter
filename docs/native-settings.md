# Bounded native settings

The installed binary exposes a bounded, trust-gated settings sidecar for an
existing native project. It reads the authenticated project context, its exact
registered root, the sealed project state, and the signed template pinned by
that state. It does not use a mutable checkout or a caller-provided template as
settings authority.

## CLI

List the authenticated settings:

```sh
tplaiter settings list \
  --project-context <context-key> \
  --dir /absolute/canonical/project/root \
  --json
```

`settings show` is an alias for `settings list`. The command reports the
resolved values in the `settings.show` result operation. `--project-context`
selects an authenticated installed context; when omitted, the registration's
default context is used. `--dir` is a locator and must match that context's
registered project root.

Set one or more groups with `group=value` pairs:

```sh
tplaiter settings set database=postgres label=beta \
  --project-context <context-key> \
  --dir /absolute/canonical/project/root \
  --yes --json
```

The native plan resolves the answers against the signed manifest, renders the
current pinned template version, and applies the resulting file and settings
changes in one native transaction. `--dry-run` reports the signed plan without
publication or a transaction. Without `--dry-run`, interactive CLI use asks
before `settings set` applies the plan; `--yes` skips that confirmation.

Edit one group either interactively or with an explicit value:

```sh
tplaiter settings edit label --value=beta \
  --project-context <context-key> \
  --dir /absolute/canonical/project/root \
  --dry-run --json
```

`settings edit [group]` reanswers the selected signed manifest group. A
terminal can answer it interactively; a non-interactive invocation must provide
`--value`. It uses the same native plan and transaction path as `settings set`.
`--dry-run` keeps the edit read-only. All three commands support the global
`--json` result output.

The settings plan uses the registered project as its source and target
context, both resolved from the same signed current template version. A caller
cannot substitute a different source or target selection. Invalid group/value
pairs, a mismatched directory or context, and unauthenticated or changed
project state are rejected before publication.

## Conditional files and conflicts

Conditional file changes preserve local edits according to the native settings
policy. For example, selecting `database=none` deletes a clean conditional
`schema.sql`. A locally modified conditional `seed.sql` is retained byte for
byte and produces the warning diagnostic
`TPL-W-NATIVE-SETTINGS-LOCAL-EDITS`.

Owned bounded UTF-8 text files use the native line-based three-way merge. When
both the local project and the signed target change the same owned text, the
published bytes contain the deterministic markers `<<<<<<< ours`, `=======`,
and `>>>>>>> template`.

The committed result has `status: "conflicted"`, includes the real transaction
ID and the published changes, and the installed CLI exits with status `2` after
the commit. A dry run reports the proposed conflict without writing or creating
a transaction. MCP `settings_set` and `settings_edit` return the same result
envelope; a committed conflict is returned with `isError: true` while retaining
the result details.

Binary, invalid-UTF-8, oversized, unsafe-mode, symlink, foreign, and other
unowned conflict cases remain refusal cases. A conflict marker is published
only for an authenticated owned text merge reconstructed by the native plan.

## MCP

The MCP surface has three tools:

* `settings_list` requires `dir` and accepts `projectContext`.
* `settings_set` requires `dir` and `values` (`group` to `value`), accepts
  `projectContext` and `dryRun`, and applies without confirmation.
* `settings_edit` requires `dir`, `group`, and `value`, accepts
  `projectContext` and `dryRun`, and maps to the `settings.reanswer` result
  operation.

MCP `projectContext` has the same exact authenticated-context meaning as the
CLI flag. `dryRun` plans without publication. The tools return the CLI's
structured `result/v1` data, including changes, diagnostics, transaction ID
when committed, and conflict status.

## Limits

This page documents the bounded native settings sidecar. It does not claim full
U07 acceptance, workspace settings operations, executable actions, hooks,
environment setup, or general lifecycle recovery. The native settings path
also does not provide a settings recovery or continuation command; unresolved
transaction or trust failures must remain under maintainer investigation.
