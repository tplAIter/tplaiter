# Local graph explorer

`go run ./cmd/graphview -root ./path/to/project -output graph.html` creates a
self-contained HTML/SVG/JavaScript view. It does not start a server, download
assets, or require npm or Python. Use `-input graph.json` to inspect a graph
that was produced by another local producer.

The explorer shows typed syntax nodes and edges with source and evidence
provenance. Search, type filters, direction and depth controls narrow the
view; clicking a node opens its path, line, provenance and relations. The
extractor follows no symlinks and ignores `.git`, `.tplaiter`, and `.tplater`.
Go parsing reports packages, imports, and declarations. Rust extraction is a
conservative lexer projection. Neither parser claims compiler resolution or
infers calls.

Graph JSON is validated before rendering: required envelope values, unique
nodes and edges, closed edge endpoints, bounded strings, node/edge limits, and
the advertised digest must all agree. The HTML embeds escaped JSON and escapes
text before placing it in the SVG or inspector.

`internal/contextpack` provides deterministic selected-node metadata for a
follow-on retrieval step. Its default budget is 8 KiB and the hard limit is 32
KiB. It reports omitted nodes, relations, excerpts, diagnostics, byte count,
and a labelled token estimate. Source excerpts are optional, relative to the
provided root, limited to a small line window, digest-bound, and metadata-only
when the requested budget cannot fit them. Application relations need explicit
attributed evidence; no call relation is fabricated from syntax.

When invoked with `-context-output`, the page embeds that immutable,
CLI-selected pack and labels its download **Download CLI-selected context pack**.
Browsing selection only changes the explorer; it does not alter the prepared
pack. The download is the compact Go JSON representation whose UTF-8 bytes are
checked against the pack's accounted byte count and the 32 KiB hard limit.
