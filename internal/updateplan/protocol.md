# Bounded signed native update planning and application

The planner produces an opaque signed, fingerprinted plan. The concrete
`projecttransaction.ApplyUpdate` library facade now seals and applies that plan
using the existing-tree neutral engine on public Gen v5 (e9590a5). The project
root stays present. CLI/MCP wiring, settings, managed blocks, actions and broad
update readiness remain outside this packet. `updateplan.Backend.Apply` retains
its typed unsupported compatibility boundary; composition roots call the concrete
facade, keeping the dependency direction facade → planner + nested engine.

## Implemented preparation boundary

1. A concrete `trustload.Runtime` selects the installed project/root/principal/
   profile. The home path is an explicit registry locator, not a project authority. There
   is no caller project root, trusted flag or runner. The composition root supplies
   the actual renderer version; the bounded backend refuses historical renderer
   mismatch instead of relabeling current output with an old version.
2. `stateledger.VerifyStable` verifies actual marker identity/coherence, lock pair,
   profile binding and absence of project transaction evidence. The bounded
   retained-root scan refuses symlinks and special files, and captures all project
   paths/bytes/modes (including unrelated files) before preparation.
3. Rendering inputs come from the actual marker. `operationtrust.PrepareUpdate`
   independently verifies the current and target signed selections. Current source
   must equal the committed source lock. `PrepareNew` independently renders that
   source as the three-way base; no unsigned checkout or legacy renderer is used.
4. The baseline, desired ownership ledger and resource provenance must agree with
   the source render and retained verified resource image. The manifest snapshot
   must be the exact verified source bytes. Active managed/generator/AI/migration
   state and ownership policies are typed unsupported in this bounded packet.
5. Three-way decisions preserve user deletions, modified upstream removals and
   every foreign file. Only clean owned images can be replaced/deleted. Bounded
   same-length independent line edits merge; overlaps/binary/structural edits are
   conservative conflicts preserving ours. Permission changes are preserved.
6. Namespace checks include implicit directory ancestors and case-folded names
   in both the target and actual observed tree; file/directory and descendant
   collisions are refused without changing foreign bytes, modes or inodes.
   Target snippet images, typed provenance lock, root/dependency locks, baseline,
   ownership, exact manifest snapshot and marker are planned together. No target
   resource bytes come from a mutable checkout. The fingerprint includes all
   preimage file/directory modes, hashes, operation inputs and complete afterimages,
   including the exact registry bytes/mode and proposed afterimage. Unrelated
   registry entries and timestamps are retained; mismatched IDs/roots, source
   anchors, baseline digests and duplicate registry entries are refused.
   Snippets bypass ordinary text merging: differing local edits/deletions are
   preserved as conflicts. The complete proposed managed resource bytes and
   planned typed lock are validated against the verified target before the
   derived report `publishable` flag can be true. That flag reports consistency
   only, never writer authority; conflicted images cannot be applied.
7. A second scan and fresh marker/profile checks reject preparation drift.
   `Recheck` regenerates the whole plan and checks its digest, owner runtime,
   backend identity and every retained project file/directory inode. Detached report JSON is not an
   executable plan or an authorization grant. A matching string digest is not
   sufficient. No persisted report decoder is supplied yet.

Planning writes no project/home files, lock, registry or journal. Existing signed
preparation allocates and removes scratch below the authenticated scratch root;
this is not a claim that planning makes zero filesystem syscalls or writes zero
transient scratch bytes. The observation is not an atomic whole-tree snapshot.

## Concrete admission and durable mutation

`BeginUpdate(ctx, plan, fingerprint)` requires the real opaque Plan. It acquires
actual runtime/project, project update.lock and home registry writer leases,
then rebuilds current/target signed preparation under those leases. Only an
initially absent empty regular 0600 single-link update.lock may be introduced
by acquisition; its exact identity must match the engine's retained descriptor.
The full preimage read set, actual marker identity, resource images and exact
registry pair are freshly checked before Seal. No report decoder, caller trusted
boolean, arbitrary material constructor, signing key or callback grants mutation.

Afterimages include exact verified target snippets, typed provenance lock, source
locks, baseline, ownership, manifest and marker. All bytes/modes/kinds and both
signed selections are bound into the authenticated immutable receipt. Staging
never replaces these expected images with an ambient resnapshot. Newly staged
0755 parents use the fixed child mkdir with child-only umask; existing and foreign
directories are never chmodded. The registry stages separately under retained
home authority and publishes after project images. The terminal commit receipt
is written only after exact publication checks; project and registry form one
recoverable transaction, not an atomic simultaneous multi-file rename.

Conditional replacements retain original owned inodes in slots. Deletion moves
an exact owned before inode into an exclusive quarantine slot under held parent
and image-directory descriptors; it never blindly unlinks the target. A foreign
replacement at the publication boundary is restored exclusively or retained in
a recoverable slot if a second foreign creation prevents restoration. Abort
restores exact owned before bytes/modes/inodes while preserving foreign images.
Conflicts keep durable evidence. Root and existing directories are never removed.

Acquisition and pre-Seal checks authenticate bounded prior native journal metadata
under real leases. Unresolved native Gen/Update receipts refuse `ErrActive`;
terminal committed/rolled-back receipts do not require their historical targets
to remain current. This internal guard is distinct from the separately owned
read-only inventory API; receipt observations are not mutation grants.

## Cold recovery

`OpenUpdate(ctx, runtime, home, id, actualRendererVersion)` authenticates the
kind-bound receipt and actual root/home/lease identities, then freshly verifies
both signed selections and actual installed project/principal/profile/policy/
bootstrap binding. It reconstructs the plan from sealed original observations,
including three-way choices, exact target resource lock/images and registry pair,
and compares the complete material/fingerprint. It strictly rereads the rooted
marker as an exact sealed before/after image and rechecks its observed ID. The
renderer version comes from the trusted composition root, never the receipt.
The engine admits only authenticated phase/slot ownership. Continue reconciles
persisted intent whose publication occurred before its completion record; abort
restores owned images, retaining unexpected foreign states and journal evidence.

Preparing receipts can be cold-aborted; resuming an interrupted staging phase
is not currently supported. Foreign or corrupted preparation slots are never
adopted. A terminal receipt is evidence of the historical operation, not a promise
that later legitimate tree state equals that operation's afterimages. Live Commit
on a cancelled context still freshly authenticates semantics and lets the engine
conditionally roll back any already published owned images.

## Focused evidence and remaining scope

Actual signed fixtures exercise replacement, creation of an empty file and exact
0755 parent, deletion, registry publication, fresh-runtime cold commit, cold abort,
foreign project/registry replacements, signed B→B no-op after a terminal receipt,
current/target source and installed policy/renderer drift refusals, cancellation
after Apply, terminal rollback receipt persistence failures/retries, cold abort
of a preparing prefix, and real killed
child processes at deletion/registry publication before the completion record.
Continue and abort retain exact original inodes/modes and foreign images. The
corrected case-fold/ancestor namespace and exact-resource-lock counterexamples
remain covered by signed planner race tests. Only the Gen final-commit concern
and new journal guard are repeated where shared engine behavior changed.

This library packet does not wire installed CLI/MCP Update, grant actions/hooks/
environment/AI execution, implement managed-block migrations, or claim all crash
windows, cross-platform filesystems, full U07/U13 or beta readiness. Inspection
files and inventory integration remain separately owned. Independent review of
the actual writer delta is still required before publication.
