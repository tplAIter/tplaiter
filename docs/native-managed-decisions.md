# Source-bound managed Go files

Managed Go publication requires an installed authenticated project context,
enrolled signed source objects and publisher evidence, plus an independently
bound native formatter tool. Source selections and operator choices are bounded
transport. They do not grant source, process or write authority.

A file uses paired `tplater:managed-begin` and `tplater:managed-end` Go comments
with the same `id`; the begin comment also names its `provider`. Marker syntax,
pairing, order and providers are checked against actual signed rendering.
Inactive template branches are removed before marker validation. Arbitrary
comments, unmatched markers, unsupported languages and unsigned providers do
not acquire managed authority.

## Creation and exact adoption

New preparation reports two distinct requests for each managed file. Both
formatter executions consume the same staged input bytes, not the first pass's
output. Each request needs its own matching signed approval. Durable start is
recorded before native execution; cleanup and the native completion receipt are
verified before completion is recorded. Outputs must agree and preserve valid
markers. There is no unformatted managed apply route.

Link uses the same effect owner with a literal `link` purpose. Adoption requires
an exact authenticated source match. It publishes only the source/effect lineage
and owned control state; existing user-file bytes, modes and inodes remain
unchanged. A prepared Link carrier retains its transaction ID across recovery.

Native-v2 New uses the complete admitted dependency graph and its actual catalog,
context, answer, resource and output bindings. Its independent formatter subject
is included alongside all source subjects. V2 formatter frames, publications and
schema-3 New recovery carriers have separate version/digest domains. V1 frames
and ordinary unformatted action-free New remain separate routes. A failed v2
admission is never retried through v1. This root-Go managed route does not imply
all native-v2 ordinary or language-specific lifecycle views are supported.

## Update choices and effects

The closed `tplaiter.dev/managed-decisions/v1` document contains a `decisions`
array. Each item names `action`, `path`, `provider`, `oldID`,
`sourceRootLockSHA256`, `targetRootLockSHA256`, `baselineBodySHA256` and
`observedFileSHA256`. Paths are same-file Go paths. Digests bind the actual signed
source/target and observed local file; changing any observation makes the choice
stale. An empty array is explicit and differs from missing transport.

`keep` and `drop` resolve a locally edited block removed by the signed target.
KEEP retains local content with an authenticated upstream tombstone. DROP
removes that block. `rename` additionally requires `newID` and
`targetBodySHA256`, and the signed target must declare that exact same-file,
same-provider replacement. Cross-file, undeclared and unrelated choices refuse.

Update formats the clean signed target twice first, then the merged candidate
twice under separate requests and approvals. The formatted clean target becomes
the upstream baseline. Local content remains in the candidate and explicit
ledger state; it is never relabeled as clean upstream bytes.

Use `update --prepare --format-input <file> --decisions-input <file>` with the
ordinary signed target selection to inspect the next phase. The format document
is the same closed tool-selection/approval transport used by managed New and
Link. Import approvals for exactly the returned requests, then use
`--format-stage` to execute only that phase. Repeat preparation for the next
phase. Stage does not publish project or registry bytes. Once both phases are
complete, ordinary `update` with those selections/choices and an empty approvals
list prepares and commits the existing native Update transaction.

MCP tool `update` exposes the same `prepare`, `formatStage`, `formatInput` and
`decisionsInput` fields. Prepare returns `update.plan`; stage and publication
return `update.apply`. Closed argument decoding and existing admission remain
in force. Ordinary updates omit the optional managed input and retain their
existing material/hash behavior.

## Retained evidence and cold recovery

Cold recovery reconstructs typed intents from sealed beforeimages and signed
source selections. It verifies actual owner records, historical approvals at
their observed time, current publication approval when needed, exact images,
registry, ownership and receipt identity. It preserves the transaction ID and
fingerprint. Completed formatter effects are validated without starting them
again; an in-doubt effect is not blindly rerun.

Authenticated Settings and Diff reconstruct committed managed Update lineage
and its ledger. Diff may inspect a retained upstream tombstone only after that
ledger is verified; unrelated IDs/providers still refuse. Tampered lineage,
completion records, stale controls and foreign files never become a recovery or
publication grant. Read-only observations create no evidence stores.

The bounded root-Go implementation does not close portable/provider composition,
other language toolchains, executable migrations, hooks, secret consumers or the
full managed lifecycle beta. Synthetic signed operator fixtures exercise actual
native APIs and installed CLI/MCP; they do not certify an organization's policy
or grant real deployment authority.
