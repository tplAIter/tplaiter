# Existing-tree native generator transaction

Freeze base: `5ec3f53c8fd1ff07da0c5c09f2e0be746cf693c7`.
The accepted update planner/backend remain byte-unchanged from `799be662`.
This package currently admits **native generator plans only**. It is not yet an
update writer or a complete gen CLI implementation.

## Concrete API

```go
BeginNative(ctx context.Context, plan *gen.NativePlan) (*Transaction, error)
OpenNative(ctx context.Context, runtime *trustload.Runtime, home, id string) (*Transaction, error)
(*Transaction).ID() string
(*Transaction).Apply(ctx context.Context) error
(*Transaction).Commit(ctx context.Context) error
(*Transaction).Rollback(ctx context.Context) error
(*Transaction).Release()
```

`BeginNative` accepts the private authenticated planner, never decoded material,
report JSON, a trusted boolean, a caller key/signature, or a recovery callback.
It obtains the real lease and writer locks, then freshly replans and checks
original bytes, modes and inodes under those locks. Only an engine-created empty
`.tplaiter/update.lock` can be added to the original observation, and its actual
held inode must match; all other observation drift refuses. Anchor admission
requires the exact prior ownership record, original file kind/hash/mode and actual
captured file. Absence of ownership is refusal, not implicit adoption.

The root remains at its original path. The package holds a runtime-root lease,
the actual `.tplaiter/update.lock`, and the actual home `.lock`. Callers must not
already hold these writer locks. Each held lock inode is freshly checked.
The root and all traversed destination parent descriptors are checked against
captured identities. Every permutation is freshly observed before each mutation;
unchanged/future paths retain their original identities and published paths retain
the prepared afterimage identities.

## Neutral mechanics and admission boundary

Production mechanics are in `internal/projecttransaction/internal/engine`, with
no import of `gen` or `updateplan`. Go's nested `internal` visibility prohibits
imports of that low-level material/engine API from outside `projecttransaction`.
The public facade admits only concrete opaque planner objects; transport getters
and hashes do not give callers access to the physical writer.

The internal protocol is `Acquire(ctx, runtime, kind, draft)` followed by a fresh
operation-specific semantic admission under the retained locks, then `Seal(ctx,
material)`. Cold `Open(ctx, runtime, kind, home, id)` authenticates its journal and
actual runtime/root/home observations but returns an unadmitted handle. The
concrete adapter must freshly authenticate the opaque intent against real signed
sources, compare the complete rebuilt material, and call internal `Admit` before
any mutation. Engine mutation methods refuse an unadmitted handle. No caller
boolean, callback, injected key or public raw-material constructor exists.

The gen facade owns `gen.AuthenticateNativeMaterial`, including reconstruction
from fresh signed snapshots at each public operation. The neutral engine checks
actual installed identity/profile, held root/home/lock descriptors and complete
before/after inode permutations before each mutation. Root and home directory
identities are sealed; a cloned valid journal in a replacement foreign home must
refuse before creating writer locks there.

Current mechanics support file creation/conditional replacement and new
parent directories. Deletion and existing-directory modification are explicit
internal unsupported errors. No registry publication or update admission is
implemented; reserving a different update kind does not enable those operations.

## Durable protocol

The typed kind is `NativeGeneratorTransaction`, API
`tplaiter.dev/project-transaction/v1`. Journals live in
`home/transactions/project/tx-ID`, separate from creation's `transactions/new`.
The closed typed envelope is also refused if copied into creation's namespace.
No changes to `newtransaction` are required.

`plan.json` durably contains exact bounded before/after bytes, modes, directory
kinds, original inode observations, installed identity/profile, operations and
fingerprint. `state.json` records prepared inode identities, intent, completion
and rollback progress. Both records are authenticated with an internal sealing
key generated and consumed under the actual installed runtime's scratch root.
The MAC domain binds kind, API, absolute journal path and record filename. A
journal checksum or caller-supplied MAC does not authorize recovery. The seal is
local protection against project/journal tampering; it is not an OS isolation
claim against an actor who controls the runtime authority directory itself.

Prepared afterimage slots are under the existing project's
`.tplaiter/project-transactions/ID`. Existing targets use Darwin atomic exchange
or Linux RENAME_EXCHANGE; the original inode is retained in a slot. New targets
use exclusive rename. Intent is durable before publication. Slot and destination
identities are checked on both sides; a raced foreign displacement is exchanged
back only while the destination still contains our prepared inode. No ordinary
truncate/unlink fallback exists. Unsupported platforms refuse.

Cold reopen needs a freshly opened actual installed runtime, identity and signed
source resolution. It rebuilds the immutable generator plan and verifies its
fingerprint plus actual read-only marker, root/dependency/resource locks and
snippets. Source authority is never recovered from journal fields. Applying an
intent reconciles a publication that happened before its completion receipt.
Rollback likewise reconciles either side of its exchange window.

Failure/cancellation restores all independently classifiable owned paths, even
when another path is foreign. Foreign bytes/inodes and nonempty directories are
preserved; conflicts remain resumable. Internal rollback after a canceled apply
uses the already authenticated durable plan without reusing the expired context.
Terminal commit cannot be rolled back through the API. Repeated commit/rollback
is idempotent for its terminal state. Beginning preparation can leave a typed
receipt and owned slots after a storage error; rollback of recorded steps is
available, while continuation of incomplete preparation refuses.

Beforeimage slots and receipts are retained, including after terminal states.
No automatic GC or deletion of ambiguous/foreign scratch paths is implemented.
Wire documents are bounded at 128 MiB; an oversized immutable document is refused
before project artifact publication. There is no atomic visibility guarantee for
all files together: a transaction may be partially visible and then restored.

## Primary / Kepler coordination contract

Do not forge `gen.NativePlan` or construct `gen.NativeMaterial` for update. Current
`updateplan.Backend.Apply` remains a typed refusal. The next separately reviewed
admission should be concrete `BeginUpdate(ctx, *updateplan.Plan)` and
`OpenUpdate(ctx, *trustload.Runtime, home, id)` with distinct kind
`NativeUpdateTransaction`.

Kepler owns the opaque update-plan admission and reauthentication methods.
The neutral mechanics now exist behind the restricted adapter boundary.
Kepler must add methods on its opaque plan which reprepare mutation data after
real locks and verify both signed selections; the data remains transport, not a
writer grant. `projecttransaction.BeginUpdate` will consume that concrete opaque
plan and adapt its images to the internal engine. A cold update adapter must
rebuild phase-aware images from freshly verified current/target snapshots before
internal admission. These update constructor signatures are proposed, not yet
callable.

Dependency direction is composition root -> concrete projecttransaction
adapter -> updateplan + neutral internal engine. The planners must not import
the facade, and updateplan cannot import its nested internal engine. This avoids
an `updateplan -> projecttransaction -> updateplan` cycle. The composition root
must call the concrete update adapter; the existing planner Apply refusal remains
until that API is implemented and accepted. No injected trusted writer callback
is part of this contract.

Update also requires deletion publication, exact home registry before/after
images and parent/inode binding, fresh verification of both source capabilities,
renderer-version binding, and rollback/cold-recovery tests across registry and
file publication. None of these are claimed by the current generator API.

Formatter, build and hook actions remain explicit typed unavailable. This
transaction never executes manifest commands or a generic Runner/Exec fallback.
