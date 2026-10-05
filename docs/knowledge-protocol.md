# Knowledge protocol v1

C01 adopts a bounded, data-only `tplaiter.dev/knowledge/v1` / `KnowledgeCatalog`
contract in core. External providers emit JSON conforming to
[`knowledge.v1.schema.json`](../schema/knowledge.v1.schema.json). They do not import
Go packages under `internal/`. The schema is self-contained and has no remote
references. Its `$id` identifies the vocabulary; it does not assert that a live
schema hosting service exists. Consumers should pin the repository release and
schema version they use.

The production core boundary is `internal/knowledge`: `Decode`, `Validate`,
`Project`, `ProjectExportCatalog`, `ProjectBlockExport`, and `ObserveSource`.
These functions are implemented and exercised by integration tests. This slice
adds no CLI/MCP command, contextpack selection, session/compiler schema,
provider enrollment, executor, or token accounting. Those compositions are
separate work. It does not claim full beta completion.

## Stable identity and pins

IDs have the form `namespace:kind:name`, with lowercase ASCII namespaces and
names. Supported identity kinds are `block`, `skill`, `resource`, `source`,
`catalog`, `owner`, `executor`, and `quality`. A namespace is a collision boundary,
not proof of organization ownership. No case folding or basename-derived identity
is performed. Duplicate IDs and duplicate source aliases are rejected.
Versions are explicit strict semantic versions; changing a version does not
change an ID. An unqualified local block/export ID cannot select a knowledge item.

Each source retains the existing complete `deps.PinnedSource` wire, including
`providerID` (exact spelling), alias, origin, template path, requested ref,
explicit commit algorithm and commit, tree/content/contract/evidence digests,
scalar parameters, and dependency aliases. Parameter and dependency ordering,
complete closure, and locator consistency are checked by the existing source
validator. Edges from that closure point **dependency → consumer**.

The source additionally carries a complete `provenance.RootSubject`: exact Git
subject and publisher statement/signature/key/checkpoint/inclusion CAS locators.
The source pin and anchor must agree on origin, template path, requested ref,
commit, tree digest and contract digest. Grammar-complete pins and proof locators
are still declarations until an actual runtime verifies them. A commit algorithm
cannot be silently inferred or changed.

Items bind a namespaced source ID to a relative source file path, SHA-256 content
pin, and exact Git regular-file mode (`100644` or `100755`). Knowledge v1 source
file paths use ASCII letters/digits, dot, underscore, hyphen and slash; absolute,
empty, dot/dot-dot components and backslash paths are rejected. Ownership is a
versioned owner ID plus policy digest **claim**, separate from source provenance
and filesystem ownership. It is never a permission to replace or delete a file.

Required metadata includes:

- Explicit update triggers: source, contract, content, dependencies, ownership,
  version, or quality. These are descriptive invalidation reasons, not automatic
  actions or subscriptions.
- `requires` and `produces`: closed namespaced references. Core projects requires
  as input → consumer and produces as producer → output workflow edges.
- `inputs` is an independently versioned `tplaiter.dev/knowledge-inputs/v1`
  contract with a mandatory closed `contextFloor`, projected as
  `workflow:context-floor` edges. The floor is descriptive required context that
  a future selector must retain; it grants no token budget or execution.
  Definitions carry a unique name, explicit required/optional boolean, scalar
  type (`string`, `integer`, `boolean`), explicit nullable flag, constraints and
  optional scalar default. Absent default, `false`, and literal `null` remain
  different in wire, typed model and graph. A null default/enum alternative is
  allowed only for nullable inputs. Null is still refused everywhere else.
  Constraints include nonnegative string min/max length (Unicode code points),
  bounded RE2 pattern, inclusive safe-integer min/max and typed unique enum.
  Core checks coherent ranges/types and that defaults satisfy constraints; no
  invocation values or command are evaluated. String bounds/pattern do not apply
  to a permitted null alternative. Empty constraints are explicit `{}`.
- Executor ID/version and input/output contract pins. No executable path, argv,
  environment, hook, approval, capability, or token-window field is supported.
- Quality ID/version/contract pin and declared/static/unresolved state. No quality
  check is run and no successful check result is synthesized.

An optional `export` retains the existing `exports.ExportEntry` verbatim,
including domain, local ID/name/version, content/tool pins, scalar parameters and
selector/contract/range requirements. Those export requirements remain distinct
from workflow `requires`. Export-entry version must match the item version.

## Graph projection and existing contracts

`Project` emits a canonical `graphdoc` v2 document with layer `knowledge`.
Nodes retain the full validated item/source JSON in their `descriptor` attribute,
plus catalog identity/version. Thus source anchors, update triggers, ownership,
executor and quality metadata are preserved rather than collapsed into labels.
The graph is digest-verifiable and independent of source/item/edge enumeration
order. Per-object encoded metadata is limited to graphdoc's 4,096-byte attribute
bound; it is never silently truncated.

Explicit edges carry a separate layer: `source`, `export`, `semantic`,
`workflow`, or `package`. Their graph kinds are `layer:relation`; neither an
import nor a package relation is automatically treated as a workflow dependency.
Source anchors and closed source dependencies are projected automatically.
Duplicate explicit/automatic relation keys are rejected. An unresolved explicit
edge may name a missing endpoint: core retains a placeholder, marks the graph
partial, and emits `KNOWLEDGE_UNRESOLVED`. Missing endpoints on declared/static
edges and missing workflow inputs/outputs are rejected.

`declared`, `static`, and `unresolved` are provider metadata states, not an
authentication ladder. Even an incoming `static` report has declared graphdoc
provenance: core has not independently run a scanner. Quality states remain
inside their descriptors; a graph's partial status specifically reports
unresolved graph relations. Wire `authenticated` states are not supported.

`ProjectExportCatalog` uses the existing strict public export-catalog decoder.
It matches the selected source's actual source-graph key, provider and contract
pin and compares complete selected export entries. Extra unselected catalog
exports are permitted; every selected item must match exactly. The projection
remains declared metadata and does not authenticate provider identity.

`ProjectBlockExport` uses the existing managed-block decoder, including its
historical `tplater.dev/block-export/v1` spelling. Mapping requires the selected
source, provider, local block ID, body path and version together; ambiguous or
missing mappings fail. Each matched node retains target, block definition
(including layout/order/anchor/replaces), export metadata/compatibility, merge
strategy and formatter declaration. No body is opened and no formatter is run.

The synthetic fixtures under `testdata/knowledge/` exercise existing pinned-source,
export catalog, block-export, graphdoc decoding and the existing graph renderer.
They contain public `example.test` identities and artificial pins; they are not
production trust evidence or copied corporate workflows.

## Read-only authenticated observation

`ObserveSource(ctx, runtime, resolution, descriptorBytes, sourceID)` takes a
concrete stable `trustverify.Runtime` and its opaque `VerifiedResolution`.
It rejects a resolution from another runtime, copies and validates descriptor
bytes, and matches the selected source's complete subject and proof locators.
It then freshly reauthenticates with `VerifySubject`, reads only the immutable
retained `SourceSnapshot`, and checks exact file kind, bytes/hash and mode for
all items anchored to that source. It freshly reauthenticates again and checks
cancellation before returning an immutable `Observation`. No caller boolean or
raw material constructor can manufacture this result.

`Observation.Graph()` adds a separate `sourceEvidenceState=authenticated` and
`evidenceScope=source-subject/publisher-evidence/item-bytes-mode` only to the
selected source and its checked items. Core-detected provenance points at the
selected source's actual statement CAS. All descriptor metadata stays declared.
Unselected sources, semantic/workflow/package relations, provider/owner/executor
labels, quality results, and generic `contentDigest`/`evidenceDigest` meanings in
source pins are **not** authenticated by that observation. It does not certify
that the descriptor itself was published by the source's signer. An observation
records the successful checks at that time; graph rendering does not refresh
trust or grant future operations.

Descriptors may live outside the source snapshot and describe that snapshot.
This avoids requiring a file to embed a digest of its own containing source
closure. A composition requiring authenticated descriptor authorship must obtain
its bytes from an independently verified source; C01 does not invent such an
admission rule. The reader has no write path, process runner, hook callback,
network provider, approval input, or mutation handle. Existing runtime authority
loading remains the trusted composition's responsibility. No trust-layer seam
was extended in this implementation.

## Diagnostics and limits

Core protocol errors are `*knowledge.Error` with stable code and location,
without echoing descriptor contents. Codes include `KNOWLEDGE_INVALID`,
`KNOWLEDGE_VERSION_UNSUPPORTED`, `KNOWLEDGE_PIN_INCOMPLETE`,
`KNOWLEDGE_ID_AMBIGUOUS`, `KNOWLEDGE_PIN_MISMATCH`,
`KNOWLEDGE_SOURCE_MISSING`, `KNOWLEDGE_SOURCE_STALE`, and
`KNOWLEDGE_SOURCE_MISMATCH`. Missing selected source/entry/blob is `SOURCE_MISSING`;
stale current kind/content/mode/subject is `SOURCE_STALE`; source pin/anchor or
selected evidence locator conflicts are `PIN_MISMATCH`. A wrong runtime or
invalid opaque observation still gives `SOURCE_MISMATCH`. Missing malformed pins
are `PIN_INCOMPLETE`, while duplicate IDs/references/relations are `ID_AMBIGUOUS`. Runtime trust failures
are wrapped with their existing causes; cancellation remains detectable with
`errors.Is`. Unknown protocol versions are refused, not interpreted as v1.

The byte limit is 1 MiB, with at most 128 sources, 512 items, and 1,024 explicit
edges. Per item: at most 16 requires, 16 produces, 8 distinct update triggers,
and 16 quality declarations. There are at most 16 input definitions, 16 context-floor references, and 16 enum
alternatives per definition; patterns are bounded to 256 bytes. Arrays are present
(empty where allowed); unknown fields, nulls outside nullable input default/enum
values, duplicate JSON keys and trailing JSON are rejected. JSON Schema
checks the portable structural subset. Core additionally enforces existing
source/export semantics, strict scalar-number lexemes, reference closure,
matching anchors, graph relation collisions and encoded byte bounds. Schema-only
validation is not source authentication or complete semantic admission.
