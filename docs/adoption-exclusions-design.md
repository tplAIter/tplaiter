# tp-i9g.6.4 — native user-owned adoption design

Status: DESIGN ONLY; awaiting primary's exact scope approval. No implementation, migration or runtime acceptance is supplied by this document.

Foundation: published canonical main `154215753e50ef51e797913cc4940273122e6713`, including the accepted 19-file link/adopt integration and its repaired live receipt/mode guards. Prior dirty trees and review freezes remain intact. This task is the outstanding full template-path user-owned adoption requirement, not another narrower replacement for it.

## Verified current contracts and gaps

| Current symbol/path | Observed contract | Required change |
|---|---|---|
| `linkcmd.prepare`, `internal/linkcmd/linkcmd.go` | Exact installed root, signed commit/ref, opaque plan; altered/missing paths require explicit choices. `user-owned` currently returns `ErrExclusion`; clean-path/irrelevant choices refuse. | Admit exact eligible user-owned conflicts and reconstruct deterministic metadata from signed source plus sealed original observations. |
| `linkcmd.Reconstruct`, same file | Regenerates signed managed images; current recovery does not apply ownership choices. | Replay the validated adoption projection using immutable original observations, never current partial project bytes. |
| `projecttransaction/link.authenticate` | Authenticates actual receipt material and regenerates signed managed bytes. | Reproduce exclusions, origin commitment and exact inventories during cold/live semantic authentication. |
| First-marker engine | MAC-sealed immutable plan/state, persisted plan inode, exact user modes, sibling-only publication and registry recovery. | Preserve all safeguards; add a narrowly read-only historical adoption-evidence projection, not a new writer API. |
| `diffcmd.Run`, `internal/diffcmd/diff.go` | Refuses all marker Ownership, skipped/tombstones or incomplete artifact inventory; signed baseline must equal independent render. | Strict authenticated ownership partition; truthful drift for excluded paths, explicitly separated from writer authority. |
| `updateplan.Backend.reconstruct`, `validateOwned`, `targetMetadata`, `computeChanges` | Refuses marker ownership/skipped/tombstones, reconstructs both signed versions, computes ordinary three-way updates, regenerates full ownership metadata. Missing tracked files are preserved as user deletions. | Validate policy proof and exact partition, suppress every excluded write/delete/merge before mutation planning, retain policy through source changes. |
| `updateplan.buildMutation`, `materialFromPlan`, `AuthenticateUpdateMaterial` | Opaque plans only; exact semantic reconstruction under actual leases; complete original observations carried into MAC intent. Unchanged paths remain Before/After equal. | Derive protected paths independently, assert equality/absence of excluded images, bind origin proof in semantic intent and cold reconstruction. |
| `projecttransaction.updateEngineMaterial` | Explicit registry pair; currently `ReadOnlyPaths` empty. | Mark existing exclusions/protected ancestors read-only; authenticate missing exclusions before nonterminal advancement. |
| `ownership.Inventory` v1 | Artifacts, skipped reasons and tombstones already exist. | Reuse wire inventory with a narrower exact native-adoption interpretation; reject arbitrary generic policy labels. |
| `ownership.Build` | Generic policy planner can set baseline hashes from actual local bytes and retain excluded prior artifacts. | DO NOT call this function for native adoption/update. Those semantics do not prove a signed baseline. |
| `gen.PlanNative` / `recordOwnership`, `internal/gen/native_plan.go` | Reads artifacts, retains other inventory fields, can add artifacts for generated paths; does not authenticate or block adoption skipped/tombstone paths. | Mandatory coordination with v3 owner: refuse excluded targets and preserve the partition. These reserved files are not owned by this task. |
| `resultdto.ProjectLinkData` | Has `trackedConflicts`; `ProjectDiffData` has only counts. | Report user-owned decisions separately; expose drift with exclusion policy and signed reference scope. Do not label an exclusion as tracked. |

`schema/state-ledger-project.v2.schema.json` already has an object ownership section and fixed standard pointers. Adding arbitrary labels without strict consumer validation is not acceptable. Existing resource, generator-target, AI, migration and managed-block guards remain in force.

## Proposed model: full signed baseline, smaller authorized writer set

Let S be the complete independently reconstructed current source artifact set: rendered template outputs plus verified native generator resource images. Let E be the immutable exact-path user-owned exclusion set established at adoption. Let M be exclusions absent at adoption. Every E entry must originate in a conflicting ordinary whole-file rendered template path in the signed adoption source. M is a subset of E.

For each stable state:

- Baseline equals the complete signed renderer baseline, unchanged by E. Resource lock equals the complete signed resource reconstruction. Local bytes never enter either signed baseline.
- Inventory `version=1`; Artifacts are exactly S minus E, with signed desired hashes/modes/kinds and no duplicates. Native resource artifacts remain required and cannot be excluded.
- Skipped is exactly one sorted `{path, reason:"user-owned"}` for every E path, even when an upstream version no longer renders that path.
- Tombstones are exactly sorted M, with no artifact collision. They record authenticated initial deletion intent for excluded missing paths, not an inferred deletion of every tracked missing file. They remain durable even if the user later recreates a file; exclusion still protects it.
- Paths in E can never appear as artifacts, mutation targets or generated targets. Unknown skipped reasons, unrelated tombstones, missing artifact entries, false signed digests, duplicate/case/ancestor collisions and arbitrary nonempty marker policy objects refuse.
- Track semantics remain unchanged: a missing tracked path retains signed ownership and is reported deleted. It is not silently converted to an exclusion/tombstone.
- Full outputs and union S plus E must stay within existing 4096-path and byte bounds. No unlimited receipt scans or unbounded observations.

Eligibility deliberately excludes state/legacy/credential namespaces, generator resource paths, symlinks, hardlinks, special regular-file modes, managed-block providers, directory/glob policies, active generated targets, restore/skipIfExists rules and overlapping paths. Unsafe observations still refuse even if the caller requests user-owned. Extra non-template user files continue to be unowned without adding decisions.

### Strict marker policy and origin commitment

Use only this closed marker Ownership object, with no unrelated policy keys:

```text
ownership.nativeAdoption = {
  version: 1,
  decisionSHA256: domain_digest(canonical OriginRecord),
  origin: OriginRecord
}
OriginRecord = {
  projectID, profileBinding,
  sourceRootLockSHA256, sourceCommit, rendererVersion,
  renderInputsSHA256, decisionAt,
  exclusions: [
    {path, sourceSHA256, sourceMode: 0644,
     initialState: modified|missing, observedImageSHA256}
  ]
}
```

The canonical digest domain is `tplaiter.dev/native-adoption-decision/v1`. `observedImageSHA256` commits the initial existence/type/full relevant mode/device/inode/bytes observation; missing is a distinct encoded observation, not a zero-byte file. `decisionAt` reuses the plan's fixed stamp so locked re-planning is deterministic and separate attempts are distinguishable. Do not embed a secret or a MAC key in project state. Origin fields stay unchanged across Update; current source lineage stays in the normal signed root/dependency locks and full baseline.

The marker/inventory are projections, not authority. A caller can edit them; equality of two editable files must never establish approval.

### New read-only adoption-evidence API (scope approval required)

Add a facade under `internal/projecttransaction/adoption` backed by a new engine-owned read-only verifier. The facade returns an opaque Evidence value with private fields, no JSON decoder, no boolean-trusted constructor and no Apply/lease/writer methods. Only a concrete installed `*trustload.Runtime` can open it for the installed root, Home and canonical decision commitment.

The verifier uses the existing runtime-owned seal authority internally, without creating a key or storage, acquires no writer lease, and performs no fsync/publication/recovery. It scans a bounded native receipt inventory, filtering authenticated same-root/same-project/same-profile committed NativeLinkTransaction receipts. It requires exactly one matching committed origin decision; rolled-back, active, foreign, unsupported or ambiguous receipts do not confer policy authority. Read-only inspection is historical proof, not confirmation of terminal fsync durability.

For the match it revalidates exact signed plan/state bytes, persisted plan inode/receipt/root/Home identity and the immutable original Input/Before/Missing/After. It re-verifies the original signed source and reconstructs eligibility, original conflict state, local observation commitment, exact decision list and managed marker/inventory projection. The marker origin digest and every origin field must match that authenticated reconstruction. The proof contains original signed source/closure and plan/state digests; these are comparisons against actual authenticated evidence, not caller-supplied authority.

Receipt lookup uses the decision digest rather than inserting a transaction ID into a pre-transaction opaque plan, avoiding a circular plan fingerprint. Any hard scan limit failure refuses. Origin receipts/CAS become required durable evidence while any surviving policy references them; deletion/GC must not silently remove them. This is an explicit retention obligation, not a claim that current generic retention APIs already expose a pin.

Use an implementation dependency boundary without import cycles: pure `adoptionpolicy` parsers/projection helpers validate deterministic data only; the restricted facade returns actual authenticated origin data/capability. Consumer constructors obtain that capability from the concrete runtime and compare the data, rather than accepting a detached policy object as proof. The engine helper must not import linkcmd or provide a user-callable Material constructor.

## End-to-end adoption and recovery

1. Existing installed CLI/MCP intent selects `adopt` and literal per-path `track`/`user-owned` decisions. No new mutable catalog, selector, shell, command execution or key input.
2. Signed image preparation remains action-free and bounded. Observe every signed user path and relevant ancestor using current no-follow, byte/full-mode/inode and missing-path rules. A clean path choice is irrelevant and refuses; every conflict requires exactly one valid decision. Unknown paths, duplicates, simultaneous track/user-owned, unsafe targets and modified choices refuse before effects.
3. Pure projection takes verified signed images and original observations: preserve full baseline; reduce only ownership; fill policy origin commitment, skipped and missing tombstones. Track decisions retain existing ownership. Project registry BaselineSHA remains the signed baseline digest, not a local hash or ownership-subset digest.
4. Opaque fingerprint binds the full input, policy/origin record, all observations and every managed image. Begin reopens signed source and repeats the projection under actual installed project/Home leases with the same stamp. Stale inode/content/mode/presence/choice/source or installation state refuses before durable staging.
5. Publish only the owned sibling managed state and registry using current first-marker transaction. No user path is moved/chmodded/copied/written. Immutable receipt keeps the original decision and observations; existing live plan/state MAC and inode guards remain intact.
6. Cold link continue/abort regenerates the exact same policy and managed inventory from authenticated original material. It must not infer a new conflict from current staged/partial bytes. Forged caller material or changed evidence preserves the ambiguity and refuses. Continued committed adoption becomes the origin Evidence used by later consumers.

The existing recovery commands/actions remain real and unchanged. MCP still has exactly one project_link tool with link/adopt actions. No fake implemented recovery enum additions.

## Truthful signed diff

Diff still verifies actual installed authority, complete locks, independent signed current source reconstruction, full baseline/resource bytes and stable read coordination. Nonempty Ownership is admitted only through the exact policy parser plus actual opaque origin Evidence and strict inventory partition; blank policy projects retain current complete-inventory checks.

Observe both ordinary signed paths and durable E paths, recheck observations and receipt proof after the read. Compare current bytes/modes against independently reconstructed current signed bytes whenever the path is in S. Excluded modified or missing paths remain visible drift; `diff --exit-code` returns a finding for actual drift, rather than declaring a user-owned path signed-clean. They are not represented as writer grants or merge instructions.

For E paths no longer in current S, compare against the signed adoption-origin reference and label reference scope `adoption-origin`, not current template output. Report currentRef normally and separate referenceCommit/referenceScope per excluded observation. Never manufacture an empty signed expected image for an upstream-removed path. User recreation after a missing exclusion remains visible and protected.

Add a typed `excluded` observation list in ProjectDiffData (path, present, current digest/mode, expected signed digest/referenceCommit/referenceScope, drift, policy="user-owned"). Keep ordinary Change actions and counts truthful. Human CLI output marks exclusions explicitly. No false clean status or silent dropping from diff. Named project_diff output-schema entry is handed to primary; no wholesale schema/golden generation.

ProjectLinkData retains trackedConflicts for actual track choices and adds an ordered ownershipChoices/excludedPaths projection. Existing consumers do not suddenly receive user-owned entries inside a field claiming tracking. Result operation/kind identities stay unchanged.

## Update: exclusions are never mutation authority

Live planning obtains and refreshes origin Evidence after the normal installed stable-state checks. Cold semantic reconstruction obtains that same proof using the authenticated immutable beforeimages and current runtime/Home; it does not read a partial current marker as a new policy decision. Reconstruct signed source AND target closures independently; validate source baseline, resource lock, policy commitment and exact source inventory partition.

Construct changes over source/target/E union. Before ordinary merge/resource/settings handling, each E path becomes an explicit `keep` with reason `user-owned`: present Before/After identical, absent both nil, no conflict, no Content writer image. This applies when target changes, removes or later reintroduces the path. Conflicting file/directory/ancestor/case namespace transitions refuse instead of writing through an exclusion. Changing settings cannot restore or bypass E.

Target metadata uses the complete signed target baseline/resource images and recalculates only the strict inventory partition with the unchanged origin E/M commitment. Resource paths remain fully owned. For a genuine no-op preserve exact valid metadata encoding. An upstream removal/reintroduction changes signed metadata while the excluded user path and policy remain intact.

Mutation construction independently checks that no E path is write/delete/merge/create, and no mutation creates/removes/replaces an excluded ancestor. Every present E image remains byte/mode/device/inode identical in semantic Before/After; every absent E remains absent. Extra caller exclusion arrays cannot reduce validation.

For exclusion-bearing intent use a strictly gated UpdateMaterial version 2 containing the canonical policy commitment, actual origin proof digests, derived protected existing/missing path lists and bounded ProtectedObservation records; version 1 remains the exact current track-only path with no additional authority. These fields participate in semantic fingerprints and the engine MAC. AuthenticateUpdateMaterial reopens actual origin proof and independently regenerates every field and all expected images; supplied hashes alone never admit recovery.

Each ProtectedObservation binds path, existence/type, bytes digest, full permission plus setuid/setgid/sticky bits and device/inode for E and relevant ancestors. This separate frame is required because current updateplan.Image stores Perm() only and equalObservation does not compare directory special bits. Capture it from actual no-follow live observations, include it in the opaque Report/fingerprint, and compare it during locked re-planning. Cold semantic validation receives it only through the authenticated engine intent, checks coherence against the complete original Before/After, and the actual nonterminal guard checks it against held/path identities. Never reconstruct a full directory mode from a Perm-only image or accept caller-provided full-mode fields as authority. This change is confined to adoption.go/approved intent fields; no generic snapshot.go edit is requested.

The transaction adapter derives existing exclusions and protected ancestors into the engine's existing ReadOnlyPaths. A narrow new engine-owned admission/guard helper checks protected missing paths and full relevant modes/identity for nonterminal Update advancement, without granting writers, modifying generic checkPath or adding arbitrary callbacks. It derives protection from authenticated intent/semantic proof, not a mutable caller list. Phase-aware cold continue/abort preserve E and authenticate both current signed source/target and retained origin proof. Terminal historical retries must not freeze legitimate later user edits as if a new transaction were still pending.

Implementation must prove a usable nonterminal guard seam from the current engine. If that cannot be provided in the approved new helper without modifying shared transaction.go, STOP source expansion and hand primary the exact extra path/symbol change for coordination. No silent generic transaction rewrite is approved by this design.

Rollback restores managed policy/inventory/baseline/locks/registry images together; user exclusions never enter rollback writes or owned slot exchanges. A corrupt/missing origin receipt, source CAS or policy projection refuses live planning and cold nonterminal recovery while preserving evidence. No best-effort rebaseline or unguarded Plan.Apply.

## v3 gen/native reservations — mandatory integration coordination

No edits by this worker to `internal/cmd/gen_native.go`, `gen_native_test.go`, `gen_native_fixture_test.go`, `gen_native_process_test.go`, `internal/gen/native_plan.go`, `internal/gen/native_transaction.go` or gen DTO/MCP entries.

Current gen artifact checks alone are insufficient for a missing excluded target: recordOwnership can create a new artifact and keep the skipped/tombstone labels, breaking the partition. Coordinate these exact named requirements with the v3 owner BEFORE permitting gen on exclusion-bearing projects:

- PlanNative/buildNativeFromImages authenticate origin proof and the strict partition, or explicitly refuse the policy family until they do.
- render/add/recordOwnership refuse create/edit/append/anchor ownership of every E path and protected ancestor, including an absent tombstoned path; never turn E into an Artifact.
- recordOwnership preserves E/M and the origin commitment; native transaction recovery rechecks the same rule.
- Add owner-run real generator negative proof for present and missing exclusions and untouched ordinary track behavior.

If the other owner cannot coordinate immediately, a documented typed gen refusal for this policy family is required; do not publish an exclusion state that another installed writer can silently reclaim. This coordination is a scope prerequisite, not an assertion that the reserved files are already safe.

## Exact proposed implementation ownership (approval request)

All paths below are relative to the new canonical task tree. Approve this exact set before any source edits. No broad root/shared copies.

New worker-owned files:

1. `internal/adoptionpolicy/policy.go` — closed origin/policy parsing, canonical decisions and eligibility.
2. `internal/adoptionpolicy/inventory.go` — complete signed-set partition validation and deterministic metadata projection.
3. `internal/adoptionpolicy/policy_test.go`.
4. `internal/adoptionpolicy/inventory_test.go`.
5. `internal/projecttransaction/adoption/evidence.go` — opaque read-only origin facade.
6. `internal/projecttransaction/adoption/evidence_test.go`.
7. `internal/projecttransaction/internal/engine/adoption_evidence.go` — bounded authenticated historical link origin projection.
8. `internal/projecttransaction/internal/engine/adoption_evidence_test.go`.
9. `internal/projecttransaction/internal/engine/adoption_guards.go` — narrow phase-aware Update protection seam.
10. `internal/projecttransaction/internal/engine/adoption_guards_test.go`.
11. `internal/linkcmd/adoption.go` — deterministic image projection for live and sealed-original recovery.
12. `internal/diffcmd/adoption_test.go`.
13. `internal/updateplan/adoption.go` — authenticated partition, exclusion change decisions and target metadata.
14. `internal/updateplan/adoption_test.go`.
15. `internal/cmd/adopt_exclusions_process_test.go` — actual installed CLI/MCP/diff/Update and selected cold recovery.

Narrow worker edits to existing files:

16. `internal/linkcmd/linkcmd.go` — valid user-owned decisions, shared projection, sealed-observation reconstruction seam.
17. `internal/projecttransaction/link/transaction.go` — original-observation semantic reconstruction.
18. `internal/diffcmd/diff.go` — replace blanket ownership refusal with strict proof admission and excluded drift.
19. `internal/updateplan/plan.go` — strict source admission, protected decision ordering, complete signed target metadata.
20. `internal/updateplan/mutation.go` — independent excluded-write/ancestor rejection.
21. `internal/updateplan/native_update.go` — version-2 gated intent and fresh proof/recovery reconstruction.
22. `internal/projecttransaction/native_update.go` — derived read-only protection and guarded nonterminal admission.
23. `internal/cmd/link.go` — truthful decision reporting/help.
24. `internal/cmd/diff.go` — typed excluded observations and human labels.
25. `internal/resultdto/link_types.go` — track versus user-owned reporting.
26. `internal/resultdto/diff_types.go` — signed excluded drift observations.
27. `internal/mcpsrv/tools_link.go` — update only project_link description/owned data schema registration.
28. `docs/link-adopt.md` — supported policy, required origin evidence, user-file preservation and recovery behavior.
29. `docs/adoption-exclusions-design.md` — this design, implementation acceptance notes only after approval.

Primary-owned named integration only (not worker mutation permission): `schema/state-ledger-project.v2.schema.json` for the exact nativeAdoption object, any named UpdateMaterial v2 schema if primary publishes it, result operation data schemas, project_link/project_diff named descriptors in shared tool goldens, named count/union assertions and schema/golden tests. Existing unrelated descriptor bytes, especially run/gen/gen_batch/context, must remain exact. No data.go/result registry/new tools/root factory edits are proposed.

Reserved v3 paths require explicit owner coordination as above; they are outside the 29-path worker request. Shared transaction.go, trustload, execx, project_build, root registration and generic ownership.go are not proposed worker edits. Any newly discovered necessary path returns to primary as an exact scope extension before implementation.

## Acceptance proof to implement after approval

Use only public synthetic signed fixtures and the concrete installed runtime/binary. Persistent evidence lives outside public source. No old private implementation imports, arbitrary execution, paid models, DB actions or child delegation.

- Mixed adoption: modified path user-owned, modified path track, missing path user-owned, missing path track, extra executable user file. Verify bytes/full modes/inodes/root identity before/after; no missing-path recreation. Exact full signed baseline, partition, skipped, tombstones, origin MAC proof and truthful DTOs.
- Real installed MCP project_link adopt with user-owned; real signed diff returns modified/deleted observations marked excluded; clean tracked paths remain clean. All other canonical descriptors remain exact; only approved named output schema changes.
- Signed Update target changes/removes/reintroduces E paths and changes tracked paths/settings. Tracked updates work; excluded bytes/modes/inodes/absence remain exact in every version. Updated locks/full baseline/source closure and registry lineage verified, with unchanged origin commitment. User recreation of an initially missing E path is retained and observable.
- Invalid decisions: unknown/irrelevant/clean path, duplicate/contradictory choices, unsafe/internal/resource/block/ancestor/case collision, stale file inode/bytes/modes/presence/source/install. Refuse before managed effects, not just a late unsupported branch.
- Tamper tests: marker-only/inventory-only and coordinated marker+inventory edits; forged skipped/tombstones; altered origin record/hash; invalid/missing/foreign/rolled-back/duplicate receipt; changed plan/state bytes or equal-byte inode replacement; missing origin CAS. Rejection preserves changed evidence. No caller JSON material or hashes become authority.
- Selected abrupt link and Update journal/prepared/state/registry boundaries, cold continue/abort, exact managed rollback plus zero user-exclusion writes. Full-mode late drift, missing-path foreign creation and protected ancestor replacement refuse nonterminal advancement. Evidence must cover both pre-plan and post-Begin negatives.
- v3 owner gen create/edit/recovery negative proofs on present and missing E; policy-aware protection or explicit refusal, no ownership promotion.

Focused pure tests, negative actual-runtime tests and installed end-to-end proofs only; no broad matrix by default. Independent review of the new source freeze plus final primary-published replay are required before acceptance. Existing link/adopt proof is a foundation, not proof that this unimplemented design already works.


## Implementation wire precision

The original user observation is a closed typed value (`exists`, `directory`, full relevant `mode`, `device`, `inode`, `sha256`) committed by the domain-separated origin digest. Update v2 carries an explicit protection frame with the same observations, committed origin receipt ID and exact plan/receipt digests. Empty optional fields do not alter v1 transport. Supported empty/`file` regular artifact encodings normalize equivalently; ordering, paths, hashes, modes, skips and tombstones remain strict.

The current actual GC contract needs no new pin writer: new transaction GC cannot select project receipts, and production CAS has no delete API. A focused installed-runtime proof must reauthenticate the same origin and signed CAS reconstruction after actual `PlanGC`/`ExecuteGC`, including a caller-supplied project receipt ID. This is a required preservation contract, not permission for a future collector to delete referenced evidence.


## Implementation resolution on the approved current base

The owned implementation tree uses `cbb6e199e812e0c3bdc60c9d47340796b00300d7`; the original foundation above is the historical design input. The exact 29-path reservation is unchanged. No generic ownership builder, shared transaction engine source, generation source, shared schema or golden is edited.

The read-only facade consumes the existing closed first-marker v1 wire directly inside the trusted runtime. It verifies the existing kind/location-bound MAC, canonical exact envelope bytes, full mode, persisted immutable plan inode, receipt/root/Home identities, registry backup, and independently reconstructed signed origin projection. It creates no seal key and exports no seal material. The engine-owned verifier separately authenticates the same origin at each scoped mutation boundary. This split avoids an import cycle between updateplan and the existing engine's signed-boundary tests; neither facade permits a caller to construct authority from transport data.

Settings decisions continue for ordinary tracked paths and bypass exclusions. Version 2 preparation is restricted to the native Update kind; protected observations, current source CAS, origin proof and immutable material are rechecked before receipt/image directory preparation, staging, persistence, publication and rollback. Version 1 uses the existing engine.

The generation compatibility proof uses a separately frozen owner overlay; this packet has no generation implementation. The installed signed fixture declares generator targets on both a present excluded path and a missing excluded path. Common PlanNative, installed CLI and installed MCP all return the typed ownership refusal with zero changes and unchanged user/managed byte, mode and inode observations. The owner guard must be integrated before publication.

The named schema handoff consists of the existing `project_link` and `project_diff` objects only: optional ownershipChoices/excludedPaths and excluded signed-reference observations. All other 28 installed named objects remain identical to this base's golden. Production GC retention is established by the actual namespace-limited PlanGC/ExecuteGC contract and fresh signed origin/CAS reconstruction afterward; no extra pin writer or storage path is required.
