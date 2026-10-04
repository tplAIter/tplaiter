# Bounded native update protocol — first backend packet

This package implements signed preparation and fingerprinted afterimage planning.
It also plans exact bounded registry before/after images and refuses unfinished
global new journals. It does **not** implement live mutation, registry publication, recovery, CLI/MCP
wiring, settings updates, managed-block codecs, generation or actions. `Apply`
rechecks the actual plan and refuses conflicts, then returns `ErrApplyUnsupported`
without creating locks, journals or files. Do not mark the update leaf complete.

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

## Required next owned transaction seam (review before use)

The empty-target `newtransaction.BeginSealedWithFault` API cannot update an
existing tree. Neither its rename/abort path nor legacy `update.Plan.applyLegacy`
is appropriate for this task. Do not bypass them with write-then-unlink rollback.

The separately owned `internal/projecttransaction` primitive is the intended
future consumer after its API is accepted. This planner does not import or
implement it. Its mutation-image contract must be derived from a freshly
rechecked opaque plan under real writer locks: exact path/kind/bytes/mode
beforeimages and sealed afterimages, installed project authority, retained
root/parent identities, and the exact registry pair. Detached report JSON or
`publishable` alone cannot supply that contract or cold-recovery authority.

An existing-project transaction owner must:

- Hold the real project `update.lock` and home registry writer lock, checking the
  held descriptor identities against actual canonical root/parent observations.
  Locks serialize cooperating writers; they do not prove foreign file ownership.
- Rebuild this preparation under those locks; refuse changed marker, authority,
  file bytes/modes, root/parent identity, registry image or durable journal state.
- Prepare a bounded journal of exact before/after bytes and modes, **including**
  target resource bytes and all ledger afterimages. Journal inputs must be derived
  from this fresh opaque plan, never a caller-decoded mutation list.
- Seal the exact current registry preimage and planned afterimage: match one
  registered project by installed identity/root, preserve all unrelated entries,
  and update source/baseline status consistently with the project commit.
- Durably stage the afterimages before publishing; retain beforeimages and durable
  phase evidence through file and registry publication. Do not recapture arbitrary
  staging bytes as an expected afterimage.
- Use a reviewed held-parent conditional publication primitive. A check followed
  by ordinary rename/unlink is not a foreign-safe compare-and-swap. If ownership
  or content becomes ambiguous, retain both images/journal and return recoverable
  ownership uncertainty; never delete or chmod a foreign replacement.
- Define continue/abort for every durable phase and crash window. Recovery must
  verify journal integrity and fresh installed authority/current file identity;
  exact before/after classification is required, and foreign bytes must survive.
- Cover deterministic crashes before/after each file/ledger/registry publication,
  rollback and registry failures, foreign concurrent creation/replacement, tampered
  journals/CAS, marker swaps and inode replacement with actual signed versions.

Live apply, durable registry transaction and rollback/crash tests are intentionally absent
from this first planner freeze. They require this separate transaction seam; the
refusal is not evidence that those operations work. No hook/tool/env/AI action is
implicitly approved by either the prepared source proof or a plan fingerprint.
