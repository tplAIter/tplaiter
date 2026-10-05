# Native link and adopt

`link` attaches managed state to an existing project that matches a signed native template. `adopt` keeps local modifications and deletions against the independently reconstructed signed baseline. Both preserve existing user file bytes, modes and inodes, including extra user files. Neither creates a missing template output nor executes template commands, hooks, tools or environment actions.

The project root and ID must already be enrolled as an installed named project context. The registry Home must be an existing canonical directory, outside the project root. Existing `.tplaiter` or `.tplater` state and an already registered project ID/path are refused. Source selection requires the exact signed commit; mutable catalog selectors are unavailable.

```sh
tplaiter link <commit> MyProject --project-context=my-project \
  --source-input=selection.json --module=example.test/project --dry-run

tplaiter adopt <commit> MyProject --project-context=my-project \
  --source-input=selection.json --module=example.test/project \
  --ownership=go.mod=track --ownership=missing.txt=track
```

Every differing or missing template path requires its own `path=track` or `path=user-owned` decision for `adopt`. Duplicate, unknown, irrelevant and invalid decisions are refused. `link` requires matching bytes and mode 0644 on each template output. `track` records the signed desired ownership image; it does not copy local bytes into the baseline or reset the local file's mode. Extra user files are outside template ownership and remain untouched.

`user-owned` preserves the current file bytes, mode and inode, or preserves absence. It is available only for an ordinary rendered whole-file template path that differs from the signed image or is missing. Managed state, native generator resources, managed blocks, extra user files, symlinks, hardlinks, special regular-file modes, globs and contradictory ancestor/case choices cannot be excluded. Clean signed paths cannot receive irrelevant ownership choices.

The complete independently signed renderer baseline and resource lock remain intact. The writer inventory contains the signed current artifacts minus exact exclusions, a sorted `user-owned` skipped entry for each exclusion, and a tombstone for each exclusion missing at adoption. These records survive upstream changes, removal and reintroduction. Update neither merges nor writes/deletes excluded paths, and refuses target topology that would replace their ancestors or collide by case. `track` continues to use the ordinary signed three-way behavior.

The closed marker policy binds original signed source/root-lock, renderer, rendering inputs, installed profile/project identity, decisions and initial observations. Marker JSON alone is not authority: diff and Update must freshly authenticate the committed first-marker origin under the actual installed runtime and reconstruct its signed afterimages. A tampered, replaced, missing, uncommitted or foreign origin refuses. Diff reports excluded observations and drift against the current signed source; when upstream has removed the path, it labels the signed reference as `adoption-origin` rather than presenting local bytes as a baseline.

Excluded projects use explicit native Update material v2. Its protection frame records existing and missing exclusions and their ancestors with full relevant modes and inode identities. A scoped transaction guard checks those observations, retained origin, immutable plan and current CAS evidence at nonterminal staging, persistence, publication and rollback boundaries. Drift refuses without modifying the changed user evidence. Projects without this policy retain native Update material v1.

Origin receipts live in Home's preserved `transactions/project` namespace. The current production `newtransaction.PlanGC`/`ExecuteGC` APIs select and remove only `transactions/new`; even a caller-supplied project origin ID cannot widen that scope. Production EvidenceCAS exposes read-only access, with no collector/deletion API. Consumers require retained receipt and CAS evidence on every fresh verification; disappearance refuses rather than synthesizing replacement lineage. A future collector must preserve these required references before enabling deletion.

Native generation has no policy-aware ownership writer yet. Its common planner must strictly refuse nonempty marker ownership, skipped entries or tombstones before any generated mutation. Adoption does not authorize ownership promotion by generation.

The operation prepares an opaque in-memory plan, reacquires the installation/source and re-plans under actual project and registry leases. It stages only managed state in a same-filesystem sibling and publishes `.tplaiter` by exclusive rename. It never moves or chmods the user's project root. A runtime-owned internal MAC binds immutable intent, original user observations, registry before/after, staging inode ownership and durable progress. The signed state also retains the immutable plan's owned inode. Live advancement and cold recovery revalidate exact persisted plan bytes/MAC and identity, refusing content changes, equal-byte inode replacement or removal without repairing altered evidence. User guards compare permission and special bits: regular setuid/setgid/sticky modes refuse; directory bits must equal the initial observation. Registry publication is coupled to the state transaction. Receipts remain under Home's native project transaction namespace; aborted staged state is retained as authenticated recovery evidence.

Qualified CLI recovery uses the original operation and an authenticated receipt ID:

```sh
tplaiter link continue <transaction-id> --project-context=my-project --json
tplaiter adopt abort <transaction-id> --project-context=my-project --json
```

A cold process reauthenticates current installed authority and signed source before continuing or aborting. It refuses altered receipts, moved roots/homes, replaced inodes, unexpected staging entries, stale source and ambiguous unrecorded writes. Preparing recovery resumes only the exact recorded prefix. A crash between an exclusive creation and its durable ownership record leaves an ambiguous entry; it is preserved and refused rather than adopted by matching bytes. Committed transactions cannot be aborted. Terminal retry confirms receipt durability and current marker/state identity.

The MCP tool is `project_link`. Its closed `action` field supports only `link` and `adopt`; recovery is provided by the qualified CLI commands. It accepts `dir`, `projectContext`, `ref`, `name`, `sourceInput`, optional `module`, `ownership` and `dryRun`, and reports existing `project.link`/`project.adopt` identities. Unknown arguments are rejected before starting the installed child. The tool name inventory remains unchanged. The named `project_link` and `project_diff` entries expose the new ownership/exclusion data; the other 28 descriptor objects remain unchanged. Shared schema and golden integration is a primary-owned named-entry handoff.

Receipt reading retains the accepted conservative coverage boundary: an unrelated project context's native receipt in the same registry Home can make verify/diff report unresolved coverage. No multi-project Home coverage extension, shared schema/golden update, recopy, rebaseline, broad P06 restoration or publication is included.

Focused local proof uses synthetic public signing keys, the actual installed binary for CLI/MCP, abrupt signed-runtime child exits at journal/stage/prepared/state-rename/registry-rename/commit boundaries, and cold recovery through fresh installed processes. User inode/byte/mode preservation, signed clean/modified/deleted lineage, source/receipt tampering and foreign matching inode refusal are checked. These synthetic proofs do not replace replay against new primary-published pins or independent review before publication.
