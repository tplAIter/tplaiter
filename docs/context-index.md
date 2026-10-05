# Read-only knowledge index

`internal/contextindex` adopts the public `tplaiter.dev/knowledge/v1`
catalog through the existing strict core decoder and canonical graph projection.
`New(catalogJSON, symbols)` owns its inputs. It performs no source reads,
imports, hooks, tool execution or writes. Symbols are finite provider-supplied
metadata anchored to catalog items, not a core parser's findings.

The reusable API is `Index.Retrieve(ctx, Request, []Binding)`. Query fields
combine with AND: exact ID, kind, source ID, path and symbol name, plus literal
substring text. Identifiers and paths are case sensitive. Kinds are block,
skill, resource, path and symbol. `One` requires exactly one match and diagnoses
missing or ambiguous matches before applying limits. A search without `One`
can successfully return no matches. No glob, shell, regexp or module evaluator
runs. Item IDs retain their catalog namespace. Path IDs use the source namespace
and SHA-256 of source ID plus path; they remain stable when bytes/version change.
Symbol IDs must have the namespaced `namespace:symbol:name` form.

## Required context and bounds

Results have version `tplaiter.dev/context-index-result/v1`. Primary matches
are sorted by ID. `Limit` defaults to 8 and is capped at 64. The result reports
total and omitted primary matches; these omissions concern optional search
results, never mandatory context. `Required` adds explicit task context IDs
(up to 32). Each selected symbol/path retains its anchored item. Required item
input floors, requires relations, source anchors, source dependencies and
upstream producers/export dependencies are expanded transitively. Missing
required endpoints refuse the whole request. Dependencies can exceed `Limit`.

Every graph relation incident to retained nodes is preserved with its original
layer, evidence label and provenance. Other endpoints are listed explicitly as
external references, including unresolved endpoints. Semantic/package edges
are retained without inventing prerequisites. Item descriptors preserve full
pins, ownership, version, update triggers, input/default/constraint semantics,
requires/produces, executor and quality metadata. The complete canonical graph
digest identifies the declared graph; it is not a signature or grant.

`MaxRecords` counts returned metadata records plus pinned source records
(default 64, ceiling 256). `MaxBytes` bounds the exact compact JSON encoding of
the whole packet, including the self-consistent `bytes` field (default 8192,
ceiling 32768). These are byte/count bounds, not token budgets, model windows or
a 256k guarantee. An oversized required floor or requested excerpt produces a
typed budget refusal and an empty packet, rather than a pruned success.

## Opt-in authenticated excerpts

Metadata-only retrieval ignores authority bindings and never opens sources.
`IncludeExcerpts` requires concrete existing `trustverify.Runtime` and opaque
`VerifiedResolution` bindings for every source contributing returned records.
Each binding is matched by `knowledge.ObserveSource` to the complete selected
source subject and publisher evidence; a label, forged descriptor pin or
resolution from another runtime cannot authorize reads.

The backend freshly authenticates each needed source, consumes the opaque C01
observation, then reads defensive blobs from the runtime's retained immutable
`SourceSnapshot`. It authenticates again before returning. This uses the
existing bounded Git/CAS snapshot reader and the trust store's confined
no-follow object reads. It does not reopen a mutable checkout, accept a caller
filesystem root, or extend `contextpack`'s private filesystem reader. C01 checks
all item anchors for that selected source, including digest, regular-file kind
and mode. Dependencies carrying only source pins remain declared when they
contribute no excerpt. This is scoped freshness at observation time, not an
atomic whole-tree or simultaneous multi-source snapshot claim.

Excerpts use the existing `contextpack.SourceExcerpt` representation, with
full-file digest and actual start/end lines. UTF-8 blobs are limited to 1 MiB;
each excerpt returns up to eight complete lines, bounded by `MaxExcerptBytes`
(default 512, ceiling 2048). A first line exceeding its byte bound refuses;
subsequent lines stop at the bound. No partial line or invalid UTF-8 is returned.
All returned records receive their requested excerpt or the request refuses.

Declared/static/unresolved metadata remains explicitly labelled. Separate
`sourceEvidence` identifies the actual selected publisher statement and its
scope: source subject, publisher evidence and item bytes/mode. It does not
authenticate provider identity, symbol locations, executor/quality assertions,
ownership policies, arbitrary pin fields or execution authority.

## Diagnostics and verification scope

`*contextindex.Error` distinguishes invalid requests, missing metadata or
bindings, ambiguity, stale/conflicting declared path anchors, and budget
refusal. Wrapped `*knowledge.Error` preserves unsupported catalog major,
incomplete pins, source pin mismatch, missing signed anchor, stale bytes/mode
and runtime/source mismatch. Cancellation causes remain identifiable with
`errors.Is`. No successful partial packet accompanies a refusal.

Focused tests use public synthetic catalogs and genuine locally signed source
fixtures. They exercise deterministic filters, required floors and incident
relations, exact byte/count limits, defensive copies/concurrent reads, selected
source evidence, distinct missing/digest/mode/pin outcomes, foreign runtime,
cancellation, retained-snapshot tamper refusal, unchanged fixture bytes/modes
and empty execution scratch. No paid providers, private source or imported
workflow is involved.

This is the reusable C03 backend. CLI/MCP exposure, task token ledger, mutable
documentation materialization, private provenance aggregation and the parent
beta goal remain separate work.
