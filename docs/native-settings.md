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

## Recorded answers and ancestry

An explicit `settings set` pair or `settings edit --value` records a `user`
answer even when its value equals the signed default or its previous value.
Untouched answers retain their recorded source (`user`, `legacy`, `migration`,
or `default`). Except for declared deprecated values described below, default-origin answers are resolved from the current signed
manifest defaults and requirements; a previously implied default-origin value
can return to its default when the requiring selection is removed. User,
legacy, and migration origins remain explicit, including default-equal values.

Inactive nested answers remain in the recorded snapshot and are excluded from
the rendering view. Editing an inactive descendant directly is rejected using
its full manifest ancestry. Reanswer the parent first, or submit a parent choice
that activates the descendant in the same settings request. Parent reanswering
prompts only the descendants active under the new parent choices.

A provenance-only change is a real marker write. The settings result reports
`.tplaiter/project.yaml` in `changes` and in the existing `filesChanged` count,
which already includes changed metadata files. Repeating an unchanged answer
that is already recorded as `user` does not create another marker change.

Settings transactions retain the original answer beforeimages and explicit
pairs. The existing native Update cold carrier authenticates and reconstructs
those inputs, the exact answer afterimages, and the plan fingerprint while
preserving the transaction ID. Changed preimages and caller-rehashed answer
origins are rejected; a decoded receipt is not publication authority. This
bounded recovery path does not add a dedicated settings recovery or MCP
continuation tool.

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
also does not provide a dedicated settings recovery or continuation command.
General crash recovery, secret question attributes, and an operator
keep/drop/rename codec remain outside this bounded path. Signed data-only
answer migrations and deprecated-answer retention are described below.


## Signed data-only answer migration history

After native Update, Settings Read/reanswer validates `migrations.json` against
retained declarations in the freshly authenticated current manifest. Applied
IDs, digests, order and version boundaries must match. History is verified, not
reapplied during a same-version settings operation. Offline Diff uses the same
history contract.

Moved answers acquire `migration` origin while keeping their values. Untouched
origins and inactive snapshots remain recorded; inactive answers stay outside
active rendering. Deleted records are not copied back. Active default-origin
answers still follow signed defaults and requires. See [Native Update](native-update.md)
for selection, authored phase ordering, the single transaction and cold recovery.
Secret and managed-block decision policies remain separate work.

## Deprecated answers

A signed manifest may declare `deprecated: true` on a setting group or option.
The attribute is a strict boolean, independent of `status: planned`. A group
cannot declare both deprecation and a default; a default cannot select a
retired option. An option cannot be both planned and deprecated.

Fresh New, `--set`, answers files and questionnaires cannot introduce retired
answers. Fresh stored defaults omit deprecated groups, while the rendering view
uses their type-zero values. Retired options and their branches are absent from
fresh prompts and lint combinations. Lint never synthesizes a retired positive
constraint value or hides an invalid supported combination.

Native reanswer permits only values retained in authenticated current records.
A retired option can be confirmed unchanged or replaced with a supported option;
a multiselect can retain its current retired members while selecting supported
members. Once removed, a retired member cannot be reintroduced. A deprecated
group is read-only in the questionnaire; explicit CLI/MCP same-value confirmation
is permitted and records `user` intent. Changing that group's value is refused.
Original and final ancestry checks still prevent direct inactive descendant edits.

Untouched retired values retain their original answer source, including
`default` even when it equals a former default. This is the deliberate exception
to ordinary active default recomputation. Inactive values and origins remain
recorded but render zero. Requires cannot introduce a retired target, including
an already-satisfied type-zero requirement without a retained record.

Settings Read and mutation results report deterministic declaration references
through `TPL-W-NATIVE-DEPRECATED-ANSWER`, without scalar answer values. Update
uses the same diagnostic. Optional deprecation references are reconstructed and
fingerprinted in the internal plan; they are omitted when empty. Existing result
DTO fields and `filesChanged` semantics are unchanged.

Recorded rendering uses a separate opaque source/baseline snapshot calculation.
It cannot become a fresh New preview or grant source, execution or publication
authority. Settings transactions still reconstruct exact recorded beforeimages
and explicit pairs during same-ID cold authentication. Secret values, managed
conflict decisions and full lifecycle acceptance remain separate work.
