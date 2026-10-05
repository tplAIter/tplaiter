# Read-only engine boundary required for transaction inventory

Base: published a91e6a2 (includes accepted Gen and corrective21-file Update engine).
Existing engine/gen/facade files are Kepler-owned and untouched in this worktree.

Implemented here: typed descriptive Record/Status, confined namespace-only
Discover, static path classifiers, and small stateledger classification plus
ProjectTransactionCandidates projection. No byte from seal.key, a journal or an
image is opened by Discover. These are observations, never verified terminal
status, recovery admission or migration permission. Existing stateledger generic
inventory still performs its existing classified file digest reads.

## Implemented concrete engine API (owned NEW inspect.go)

    InspectJournal(ctx context.Context, runtime *trustload.Runtime,
        home, id string) (JournalInspection, error)

The result must not expose a Transaction, Material, signing key or mutator.
It should carry typed current kind/version/phase, authenticated plan/progress
receipt digests and project binding, plus image/evidence diagnostics. Public
serialized data, injected signatures, expected IDs and caller trust flags cannot
construct a verified inspection. Inventory consumes the concrete inspector,
not an interchangeable caller-supplied authority callback.

Requirements:

- Pure observation: open only existing directories/key/receipts/slots. No
  privateDirectory, runtimeKey(create), Acquire, Open, writer lock creation,
  receipt synchronization, recovery or state mutation. Existing Open acquires
  three writer locks; even runtimeKey(false) invokes privateDirectory.
- Authenticate actual runtime and fresh selected project identity; seal domain
  includes version, kind, absolute journal directory and file name. Decode both
  plan.json and state.json strictly; match ID/kind/version/fingerprint. Validate
  bounded modes, single links, root/home/image directory identities and closed
  phase/step schema. Do not silently reinterpret new/v1 or the other native kind.
- Unsupported version is a future diagnostic and always refuses mutation or
  migration; an unsigned version header is never proof of authenticated terminal.
- Terminal observation verifies sealed receipt and retained own slot state. It
  must not compare the current project targets with the historical afterimage:
  later legitimate transactions can change those targets. Committed and fully
  rolled-back receipts persist; existence alone does not block migration.
- Slots are physical inode-preserving images, not CAS. Missing/unsafe slots are
  distinct from actual missing authenticated source-CAS objects. Source evidence
  must be derived from sealed material's actual source references (both actual
  update sources when applicable), using the actual runtime reader. No unsigned
  journal path can choose a CAS root. Historical terminal missing-CAS diagnostics
  must not be mistaken for an unfinished writer or generic GC eligibility.
- A selected runtime covers one project context. Home-wide status needs concrete
  installed-runtime coverage for every observed journal. Foreign/uncovered roots
  stay unresolved, never terminal by a raw path/phase claim. No arbitrary public
  material constructor or trusted callback is added to solve coverage.

## Concrete reader and remaining guarded integration

Inventory.Read now consumes the concrete engine inspector with *trustload.Runtime
and Home; no callback authority exists. Namespace-only catalog is a leaf used by
stateledger, while inventory imports engine and catalog. This split is necessary:
existing engine package tests import gen, which imports stateledger. Importing
engine-backed inventory directly from stateledger forms an actual test cycle.
The split compiles without editing accepted engine/gen tests or production files.
Inventory imports neither parent projecttransaction, gen, update nor updateplan.

Status keeps authenticated phase separate from evidence issues:
active (preparing/prepared/applying/rolling-back/rollback-conflicts), committed,
rolled-back, future, unsafe, missing-cas, missing-images and unresolved. Zero
Record is unverified, not committed. Active means unfinished, not live PID.

Connect a concrete readonly runtime to Inventory/VerifyStable/Plan through a
small explicit options adapter; retain creation status as a separate namespace.
Recheck migration policy under actual writer coordination, including project
update lock and home registry lock. Persistent lock presence proves no liveness.
No cached/public snapshot can authorize mutation.

Naming migration currently receives only filesystem roots, no installed runtime;
its TransactionEvidence probe is presence-only. It needs a concrete verified
entry point/coverage, not a global callback, unsigned phase parser or permanent
presence block. Existing migration Apply must recheck under its locks.

There is also a relocation constraint: engine HMAC includes the absolute journal
path and material binds Root/Home. A generic naming migration must not rewrite,
rename or copy these authority-bound receipts into a new root and call them
valid. If a terminal receipt is actually moved, an explicit authenticated
relocation/preservation protocol is needed. State migrations that keep the
bound roots can admit independently verified terminal history normally.

No generic newtransaction API, GC, formatter/build/hook execution gate or gen CLI
is enabled here. P05.1 closure and actual safe migration are still pending complete
coverage and guarded integration; discovery is not acceptance evidence
for those operations.

## Published writer guard dependency

Published a91e6a2 already calls engine.rejectActiveJournals after Acquire's real
locks/authentication and in Seal before preparation. The inventory inspector does
not add another writer-phase admission implementation. The previous experimental
CheckPriorJournals method and its overlay callsite proposal have been removed from
current source. Old9de counterexamples and overlays are retained as historical
proofs ONLY; they must not be applied to or asserted against current published21.
The focused current-floor fixture exercises published prepared/applying typed
ErrActive refusal and committed-next signed Gen, preserving the prior receipt.

## Remaining assembly boundaries

Stateledger classification/catalog inventory is integrated; authenticated
VerifyStable/migration admission is not yet integrated. BindingAuthority alone
cannot cover runtime CAS. Direct engine reader import into stateledger is blocked
by the proven existing-test cycle, not runtime production compilation. A concrete
higher-level adapter must compose stateledger verification and Inventory.Read
with *trustload.Runtime/Home, without accepting cached records or trust callbacks.
One exact disjoint option is NEW internal/stateledger/verified/projecttransaction.go
(and tests): imports stateledger + inventory + trustload, but gen continues to
import only the leaf stateledger. This needs a callsite in real migration/CLI
assembly and writer-time recheck; an unlocked observation cannot authorize writes.

The inspector now uses published21 expectedSteps validation and stepFiles,
slotPath/slotDirectory projections. Registry slots are in the journal directory;
deleted paths retain beforeimages after application/commit and no slot before
application/after rollback. Actual signed Update fixtures cover both closed
terminal phases, active phases, missing registry slots, and target-source CAS.
No current target comparison or terminal fsync is performed by inspection.
P05.1 remains open; no full-safe beta or CLI enablement claim is made here.

## Read-only publication uncertainty

Sealed/Terminal and committed/rolled-back describe the actual authenticated visible
receipt plus retained images, never a mutator's confirmed durable return. The new
Durability accessor explicitly reports not-observable-readonly for authenticated
observations (unverified for unauthenticated observations). File reads, stable
receipt bytes/inodes and MAC verification cannot reveal whether a prior directory
fsync completed. No Inspector path calls syncReceipt, fsync, repair or a cached
writer's terminal confirmation. No old target comparison is introduced.

The readonly observation MUST NOT replace the published engine's writer-side
terminal-confirmation protocol. Under real writer locks that protocol owns any
needed confirmation/retry of publication.
Uncertainty must not permanently block every valid historical terminal receipt.
The focused signed test faults publication after rename for committed and for a
real signed rollback receipt, verifies visible phase with unobserved durability,
then changes only in-memory cache and observes identical receipt again. The
rollback fixture exercises storage publication uncertainty on accepted9de; it
DOES NOT claim to reproduce or validate Kepler's new coldRollback fix/schema.

## Corrective current-marker and runtime-coverage boundary

Inspection reads the actual current .tplaiter/project.yaml through a confined
held parent, no-follow regular single-link descriptor, bounded strict YAML decode,
then validates the OBSERVED ID against the concrete installed runtime. It repeats
that observation immediately before projecting sealed status. Legitimate current
metadata may differ from the historical plan's marker/target images.

Authentication failure against one selected installed runtime does not establish
corruption or foreign ownership of a home journal. Without an independently
MAC-authenticated current-layout state receipt for that authority, a failed plan
MAC yields typed ErrInspectionUncovered and unsealed/nonterminal unresolved.
A matching authenticated state does retain unsafe plan-damage classification;
unsigned root/ownership labels are never used as a trust grant or key selector.
Home-wide coverage still needs actual installed runtime handles for each project.
Assembly is deferred until this corrective freeze is independently accepted.
