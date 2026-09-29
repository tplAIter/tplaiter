# State ledger, transactions and ownership

This page describes the on-disk state that tplaiter keeps for a generated
project and in its home directory, and the guarantees around changing it. It
is reference material for contributors; the lifecycle commands (`new`,
`update`, `settings`, `verify`, `check`, `deps verify`) are built on these
packages.

## Where state lives

| Scope | Location | Contents |
|---|---|---|
| Project | `<project>/.tplaiter/` | project marker, provenance locks, baseline, ownership, resources, AI-managed files, generator targets, managed blocks, migrations |
| Home | `~/.tplaiter/` (or `$TPLAITER_HOME`) | project registry, config, index, run state, trust cache, global new-transaction journals |

Every path is classified by one table (`internal/stateledger/ledgerpath`):
its kind, the component allowed to write it, its retention policy and whether
it belongs to a transaction engine. The ledger inventory, the global
new-transaction engine and `migrate-state` all use that table.

### Project ledgers

| File | Kind | Retention |
|---|---|---|
| `project.yaml` | project marker (`tplater.dev/v1alpha1` or `tplaiter.dev/project/v2`) | permanent |
| `root-template.lock.json` | provenance v2 root lock | permanent |
| `template.lock.json` | provenance v2 dependency lock | permanent |
| `baseline.json`, `ownership.json`, `resources.lock.json`, `ai-managed.json`, `generator-targets.lock.json`, `managed-blocks.json`, `migrations.json` | lifecycle ledgers | permanent |
| `update.lock`, `update/active.json`, `update/tx-*` | update transaction | stable / until terminal |
| `new-transaction.pending` | marker of an unfinished `new` | until terminal |
| `graph-cache/` | derived cache | rebuildable |
| anything else | user data | preserved byte for byte |

A root template without dependencies always has a dependency lock with an
explicit `"dependencies": []`; the lock is never omitted and never `null`.

## Project marker migration (v1alpha1 to project/v2)

`stateledger.Plan` builds a sealed, pure migration plan. It needs a verifier
that re-checks the root lock against its source and, when the dependency lock
is missing, a proof that the root template has no dependencies, extends or
blocks; only then is an empty dependency lock synthesized. `ApplyPlan`
re-plans, requires the reviewed plan digest, writes the dependency lock first
and the new marker last (the commit point). Downgrades are refused; a newer
marker is reported as a future version. Profileless v1 locks are refused: they
must be re-resolved through the trust runtime by `update`.

## Read-only verification

`stateledger.VerifyStable` and `stateledger.VerifyDependencyLocks` read the
marker, every ledger and the lock pair without writing anything or contacting
the network. They require a verified trust runtime whose profile binding
matches the locks; a development profile is refused. With an evidence CAS,
every evidence object named by the locks must be present.

`readonlysnapshot` captures five components of a project (HEAD, index,
tracked files, untracked files, ledgers) with git isolated from user
configuration, credentials, prompts, optional locks and lazy fetches. Equal
snapshot digests before and after a command prove that it wrote nothing to the
project.

## Global new transaction

`new` publishes a project through one global transaction whose journal lives
in `~/.tplaiter/transactions/new/tx-<id>/`, outside the target tree:

1. The before image of the target is captured and the prepared journal is
   made durable before anything moves.
2. The target is staged next to its final path and a pending marker is placed
   in it; rendering happens in the staged tree.
3. Commit publishes the staged tree, updates the project registry under the
   home lock (compare-and-swap against the journaled before image), makes the
   commit record durable, and only then removes the pending marker.
4. Hooks run at least once each; completed hooks are never replayed, and a
   failed mandatory hook leaves the transaction committed and retryable.

Recovery is driven only by the durable journal and its content-addressed
evidence: a prepared journal is aborted (added files are removed and the
target returns to its before image; a modified pre-existing file makes abort
refuse without changing anything), anything later is continued. Every
failpoint of this sequence is covered by a test that kills the process and
recovers from disk.

Inventory statuses are `active`, `complete`, `aborted`, `future`,
`missing-cas`, `unsafe` and `orphan` (a directory without a journal). Garbage
collection selects only terminal records that are older than 30 days or beyond
the newest 100, plus orphans older than 30 days; it re-validates every
candidate while holding the global lock. Everything else is preserved
evidence.

## Ownership

`.tplaiter/ownership.json` records every template-owned path with its digest,
file mode or symlink target. Project policy can `exclude` paths, write them
only when absent (`skipIfExists`), or `restore` a tombstoned path. A path the
user deleted becomes a tombstone and is not recreated until a `restore` rule
matches it. Suppressed writes are listed under `skipped` with their reason
(`exclude`, `skipIfExists`, `tombstone`). The planner never writes to the
project; the caller applies the ledger image and file actions in one
transaction and can roll back with the recorded before image.

## Template migrations

`internal/migrations` selects the manifest migrations whose boundary lies in
`(current, target]`, verifies the applied-migrations ledger (digests, order,
no rewrite of history) and returns the new ledger bytes. Migrations that run
template code are returned only after the caller's execution authority
approved them; settings-only migrations are pure data. A branch or `latest`
selector is not a release version: the plan is marked unversioned and selects
nothing.

## Schemas

| Schema | Wire |
|---|---|
| `schema/state-ledger-project.v2.schema.json` | project marker v2 |
| `schema/state-ledger-migration-plan.v1.schema.json` | marker migration plan |
| `schema/state-ledger-report.v1.schema.json` | sealed ledger report |
| `schema/state-ledger-new-transaction.v1.schema.json` | global new-transaction journal |
| `schema/state-ledger-new-lock.v1.schema.json` | global lock holder metadata |
| `schema/state-ledger-migrations.v1.schema.json` | applied-migrations ledger |
| `schema/ownership.v1.schema.json` | ownership ledger |

The provenance lock schemas are `schema/root-template-lock.v2.schema.json` and
`schema/template-lock.v2.schema.json`.
