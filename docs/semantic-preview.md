# Read-only semantic preview

`semantic preview --input request.json --dir PROJECT --max-bytes 32768 --json`
uses the exact installed project context and the same authenticated read-session
admission as graph inspection. MCP `semantic_preview` invokes that command with
the installed executable, not a caller-supplied binary. This observation route
creates no execution permit and writes no project files or graph cache.

First submit `{"apiVersion":"tplaiter.dev/semantic-preview/v1","action":"anchors","paths":["service.go"]}`.
The result includes the complete original bytes, syntax graph, independently
computed token anchors, and source manifest digest. Use the returned file digest,
beforeGraph digest and exact anchor in an `action:"preview"` edit. Edits name
unique IDs and are all resolved against the original image; shifted output
positions are never accepted as original anchors.

The four Go intents are `go.function-body.replace` (a complete brace-delimited
body, retaining receiver/signature), `go.import.add` (explicit path/optional alias,
a separate declaration), `go.import.remove` (the exact original import/path/alias),
and `go.comment-anchor.insert-statements` (statements before a unique standalone
line-comment token inside a function). Ambiguous comment ownership, overlaps,
duplicate insertion positions, stale images/graphs/anchors, unknown fields,
invalid syntax, symlinks and case aliases refuse. Comment substrings inside
strings are not anchors. Rust edits and inferred type/import repair are unavailable.

Input is a closed versioned document, at most64KiB, 1..8 edits/files, 16KiB per
payload and32KiB total payload. Supported sources are UTF-8 LF Go files; CRLF
refuses rather than normalizing bytes. Capture remains bounded at256 Go/Rust
files,1MiB each and16MiB total, but preview analyzes exactly the selected Go files.
Successful output includes complete before/after bytes as canonical base64,
modes/hashes/lengths, original/resulting anchors, separate before/after syntax
graphs, node/edge delta, full unified diff and edit-to-span mapping. Diff work is
bounded at8192 lines and2million comparisons; overflow refuses, without a summary
substitute. Go parsing verifies syntax only. Compilation and type checking are
not performed, and a syntax-valid result can fail to compile.

The complete CLI envelope including newline and actual complete SDK frame
(including escaped request ID and duplicated representations) must fit1024..32768
bytes. Successful observations are neither paged nor truncated. Over-budget
images or metadata refuse. Direct CLI retains its read session through the final
complete write. MCP captures a child observation and validates final serialized
bytes; the child's source lease ends before SDK delivery. These facts are an
observation, not a freshness grant or permission to apply them later.

Apply is unavailable. It needs a distinct semantic writer purpose, original
source admission, operation intent/approval, managed transaction/cold-recovery
contract and reauthenticated materialization. Generators and arbitrary updates
are not substitutes. Nonempty installed dependency-ledger context delivery is a
separate prerequisite and is not claimed by this preview's root fixture proof.
