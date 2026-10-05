# Signed native Update

Signed file-only native Update CLI/MCP check, plan, and apply plus cold CLI Abort are published in `932d1c4`. They update one authenticated native project from its registered signed source to a target selected by a closed signed source input. Cold CLI Continue is implemented for authenticated preparing prefixes with a recorded receipt-directory identity, prepared, applying, and committed receipts, including repeated no-op terminal confirmation; success is reported after native Commit. The broader Update beta, settings/workspace updates, executable actions, and full recovery remain pending.

Use an installed, provisioned binary and a project created from an enrolled signed native template. Follow [installation](install.md) and [source enrollment](source-enrollment.md) first. A plain build without installed-launch registration cannot run this trust-gated command.

## CLI

Plan or apply an update with the installed project context and its exact root:

```sh
tplaiter update \
  --project-context <context-key> \
  --dir /absolute/canonical/project/root \
  --source-input /path/to/target-selection.json \
  --to <target-commit> \
  --json
```

`--project-context` selects an authenticated installed context. `--dir` is a locator and must resolve to that context's registered root; it is not an authority by itself. If `--project-context` is omitted, the installed registration's default context is used. The CLI verifies the selected context and root before planning or writing.

`--source-input` names the closed JSON source selection and its publisher-evidence locators. It is transport for a target selection, not a source authority. Update freshly verifies the signed source closure against the installed evidence and object roots. The current source is read from the registered project's sealed locks. Ambient Git state, local manifests, mutable refs, and network refresh are not used.

When supplied, `--to` must exactly equal the target commit in `--source-input`. Omitting it still uses the commit pinned by that signed selection. A mismatch is refused before any effect.

Use `--dry-run` for a read-only update plan. Use `--check` with `--source-input` to validate and report that target plan without writing. Use `--check` without source input, `--to`, or `--dry-run` to scan the authenticated project for remaining conflict-marker lines. `--all` is currently unavailable.

The apply path prepares and revalidates the plan, acquires the native transaction, then commits the project and registry transition. It uses the native three-way update model: the registered source is the base, the signed selection is the target, and the project's recorded baseline plus current files determine local edits. Additions, deletions, and non-overlapping edits can be published. A conflicting plan is reported as `conflicted` and preserves the project and registry; it does not publish conflict markers.

## MCP

The MCP `update` tool exposes the same bounded operation:

```json
{
  "dir": "/absolute/canonical/project/root",
  "projectContext": "<context-key>",
  "sourceInput": "/path/to/target-selection.json",
  "to": "<target-commit>",
  "dryRun": true,
  "check": false
}
```

`dir` is required. `projectContext`, `sourceInput`, and `to` have the same meanings as their CLI flags. `dryRun` and `check` select the read-only `update.plan` and `update.check` operations; with both false, the tool requests `update.apply`. MCP returns the same structured result envelope as the CLI's `--json` mode.

## Results and recovery

Structured results use `tplaiter.dev/result/v1`. The envelope identifies `update.plan`, `update.check`, or `update.apply`, the authenticated project, current and target refs, a plan digest, changes, diagnostics, and summary counters. A committed apply includes `transactionId`. A plan or check does not write and has no transaction ID. A no-change plan is reported with `status: "ok"`; a published update uses `status: "changes"`; an unpublishable conflict uses `status: "conflicted"`. Registry changes are reported as a diagnostic describing the sealed registry transition rather than as a project file.

If an apply leaves a native transaction that requires cold cleanup, abort it with its authenticated transaction ID:

```sh
tplaiter update abort <transaction-id> \
  --project-context <context-key> \
  --dir /absolute/canonical/project/root \
  --json
```

`abort` reopens only a freshly authenticated native Update receipt with the retained real leases, then rolls back that transaction. It does not use generic `new` recovery.

Cold CLI Continue uses the same installed context and exact root:

```sh
tplaiter update continue <transaction-id> \
  --project-context <context-key> \
  --dir /absolute/canonical/project/root \
  --json
```

It freshly authenticates the native Update receipt through `OpenUpdate`, retains the real writer leases, and revalidates the current project, registry, source material, and recorded storage identities before native `Commit`. Preparing prefixes with an authenticated receipt-directory identity can resume from zero, partial, or fully recorded staging: Continue exclusively restages missing authenticated images and records signed progress before entering the existing commit path. The installed-process proof kills staging children at zero, partial, and full recorded prefixes and checks cold completion and terminal repeat; it also covers fully applied but uncommitted `applying` receipts, committed and no-op terminal receipts, and repeated terminal confirmation. Success reports `update.continue`, `status: "ok"`, and the authenticated project and transaction ID. It is a CLI recovery command; the MCP `update` tool above continues to expose check, plan, and apply.

An unknown or unrecorded staging slot, orphan, replaced recorded inode, or changed reference remains ambiguous: Continue preserves the observed state instead of adopting or deleting uncertain material. A valid historical `preparing` receipt with `steps: []` and zero receipt-directory identity still authenticates, but Continue returns ambiguity and preserves receipt, stage, project, and registry. Abort and cold Abort retry remain available without normalizing that identity. This historical empty prefix is distinct from malformed `steps: null`, which fails authentication; the existing receipt schema has not changed. Rolled-back, tampered, missing, or mismatched receipts produce `TPL-E-NATIVE-UPDATE-TRANSACTION` (exit 6); finite-context and locator refusals retain their runtime trust classification. A failing Continue does not automatically call Abort: native Commit owns conditional restoration and publication uncertainty. Preserve the receipt and project for recovery rather than assuming every failure undid every change.

## Current limits

Update refuses target templates that declare hooks, commands, tools, environment playbooks, or AI configuration. It also refuses `--all`. Pre-receipt crashes, unrecorded staging, ambiguous historical empty preparing prefixes, recovery under another sealing authority, executable actions, settings/workspace updates, the full Update beta, and wider recovery remain outside supported Continue coverage. The published writer guard blocks incompatible unfinished native transactions. Read-only transaction inventory remains unchanged from `704f4aa`; the bounded integration in `7dcd37b` connects actual Runtime, Home, and CAS to ledger verification under existing held writer locks and a confined in-place migration API. It does not restore the full CLI migration flow or grant global recovery or naming/native receipt relocation. Inventory observations do not grant writer or recovery authority.

The earlier shared-home second-project refusal arose from a no-op zero-step receipt bug fixed in `1c71a99`. The installed CLI proof runs signed A-to-B and B-to-B updates for two distinct project contexts in one home under the same installation sealing authority, preserving the first project's bytes, modes, and inodes. This establishes the bounded same-install path; it does not establish authority across foreign installations. Historical malformed receipts containing `steps: null` still fail authentication; they are not automatically normalized or migrated.


## Signed data-only answer migration history

Native Update selects migrations from authenticated source and target manifest
`metadata.version`, independently of the exact commit used as a source selector.
A template may declare a closed `migrations` array with immutable `id`, `from`,
`to`, `phase` and `settings.rename` / `settings.delete` fields. Boundaries in
`(sourceVersion, targetVersion]` are selected in manifest order. Previously
applied IDs, declaration digests and positions must remain unchanged; an applied
boundary newer than the signed current version is refused.

Renames within one declaration are simultaneous. An unrelated occupied target
is refused; swaps and chains use the original records. Moved records retain
values and acquire `migration` origin. Untouched origins and inactive snapshots
remain recorded. Deletes remove exactly named records. Active default-origin
answers still follow target defaults and requires. Inactive answers do not
become active rendering inputs.

Data transformations follow the existing `ApplySettings` contract: combine the
`before` and `after` lists and apply them in authored declaration order before
resolving the target. Phase labels remain execution scheduling metadata; this
lane executes neither phase. Any selected executable `steps` are refused with
`migrations.ErrExecutionUnauthorized`; declarations do not confer execution,
provider, hook or source authority.

The original signed source and its original answers form the three-way base.
The migrated answers resolve the target. Answer marker, rendered files,
`migrations.json`, baseline, ownership and locks publish together in the existing
native Update transaction. Dry-run publishes nothing. Cold continuation freshly
reconstructs the same plan from sealed beforeimages and both signed selections,
retaining its transaction ID and fingerprint. Caller-rehashed altered answers or
ledger bytes and stale preimages are refused. No-migration material retains its
existing wire version and omits the optional migration report field.

Settings Read/reanswer and offline Diff verify retained applied history against
the current signed manifest. They do not reapply migrations. Ordered migration
IDs are reported as diagnostics without answer values. This supported slice is
data-only: secret answers, managed-block keep/drop/rename, and other
lifecycle views remain separate work.

## Recorded deprecated answers across Update

Signed target declarations may retire groups or options with `deprecated: true`.
The original signed source and its recorded answers still form the three-way
base. Selected data-only migrations transform complete answer records first;
only those retained or moved records supply the target's deprecated retention
context. Deleted records are not resurrected, and missing defaults cannot confer
retention rights. Retirement without a selected key migration also retains
existing answers. Ordinary supported active defaults still follow target defaults
and requires; inactive snapshots keep exact values and origins while rendering
zero. Untouched retired default-origin values deliberately retain their records.

Source-before rendering uses a read-only opaque snapshot carrier, separate from
fresh New preparation. Target retention is detached calculation context rebuilt
from authenticated marker or sealed beforeimages at publication and cold replay.
No caller boolean, origin label, answers file or decoded preview grants authority.

Dry-run remains read-only. Answer records, migration ledger, rendered files,
baseline, ownership and locks publish in the existing transaction. Same-ID cold
continuation reconstructs the exact fingerprint, including optional deprecation
references. Stale preimages, caller-rehashed origins, references or source
bindings are refused. Non-deprecated no-migration materials retain their existing
shape and behavior. `TPL-W-NATIVE-DEPRECATED-ANSWER` reports declaration references
without scalar answer values. See [Native Settings](native-settings.md) for
retained reanswer choices, fresh input refusals and the default-origin exception.
