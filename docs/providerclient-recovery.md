# Public local provider client

This client consumes existing `local-provider.session/v1` NDJSON through an
injected host-owned connection. It never launches a producer or reads private
implementation. Handshake requires `local-provider.descriptor/v1`, existing
read operations and `local-curated-read`; negotiation cannot grant authority.

`Open` captures live Source/Asset descriptors. `ReadCatalog` reconstructs whole
source pages using `page:N:<opaque cursor>`, stable scope/query/catalog pins and
exact compact SHA-256, then calls unchanged current C01 admission. `ReadAsset`
checks learned scope, captured source commit, returned descriptor, content bytes
and untrusted-content qualification. Producer bytes are never normalized.
`OpenLocal` additionally requires host-frozen metadata and verifies the SHA-256
of the reconstructed complete compact wire bytes before admission. Reordered
pages or equivalent objects with different byte order cannot return the frozen
binding. Within one source, distinct asset IDs sharing a path refuse with
`SESSION_ASSET_AMBIGUITY` because this mapping cannot preserve both identities.
Equal paths across distinct source identities remain representable. Description/source accessors
return copies. `RequireProduction` refuses: local transport integrity does not
certify organization admission or an authenticated organization principal.

Frames, aggregate bytes, exchanges, pages, deadlines and cancellation are bounded.
Partial EOF, malformed/ambiguous envelopes, oversized frames and slow peers fail
closed. Injected pipe transports must implement deadlines. Request IDs, schema,
capabilities, source/asset/pin, projection and effective budgets are checked.

The exact neutral fixture under `testdata/synthetic` is a label-neutralized
regression derivative, not a live producer receipt. Its deliberately invalid pin
syntax preserves C01 refusal coverage. Its cursor is explicitly synthetic and
not replayable; opaque digest fields are fixture claims. The full compact catalog
digest is recomputed and two-page reconstruction is exact. Original owned evidence
remains privately preserved; no private invocation reference is in this slice.

The build-tagged `TestActualProducer` uses host-injected real pipes or sockets.
It requires positive current C01 admission, two pages, four verified asset reads,
and actual refusal codes including foreign cursor replay. Raw runtime evidence is
kept private; only allowlisted counts, booleans and protocol codes are public.
Independent producer review and full organization admission remain separate.

The authoritative public base is `e49dd1f77492388e02b638ad6db1265224b97fcd`.
Current knowledge, deps and schema sources are used unchanged. No historical
recovery dependency is copied or substituted. No commit, push, database mutation,
delegation or publication is performed.

## Current-base validation

On the exact authoritative base, the actual corrected counterpart passed the
unmodified positive live gate on both pipes and sockets: current C01 admission,
two whole-source pages and full catalog digest checks, four scoped reads, and
eight actual refusal cases. Production admission still refuses. No overlay,
source-pin normalization or C01 changes were used. The public summary contains
only explicitly allowlisted counts, booleans and protocol refusal codes.
Private commands, executable metadata, logs and raw receipts stay outside Git.

Current package race tests, exact retained ambiguity/ordering counters, portable
schema/host-I/O assertions and actual pipes/socket regressions pass. The new
synthetic regressions fail against the reviewed implementation and pass after
these fixes. Exact source hashes, reviewed preimages and addition/fix patches
remain in private review tooling, outside the product tree. This establishes bounded local interoperability, not organization admission
or full-repository database/process/end-to-end acceptance.
