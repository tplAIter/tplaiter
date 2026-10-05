# Approved offline Go dependency closure and default generation

The v1 project-build adapter remains dependency-free. The opt-in v2 declaration
uses `tplaiter.dev/project-build-action/v2`, `go-project-build-v2`, the existing
literal `go build -mod=readonly -buildvcs=false ./...` arguments, the toolchain
index digest, and `moduleIndexSHA256`. `genBuild: true` additionally permits this
same runner after a concrete native generation transaction. It does not permit
arbitrary commands, hooks, shell execution or online dependency resolution.

`modules/index.json` is an authenticated provider source blob using
`tplaiter.dev/go-module-closure/v1`. It declares exact module versions, public
Go h1 module/go.mod sums, normalized project go.mod digest, exact go.sum digest,
and bounded read-only expanded files with CAS chunk and file digests. Only the
project module name is normalized: the actual raw go.mod is independently bound
in every execution request. Requires, Go version and all other module contents
remain bound. Replacement/exclusion/toolchain directives, workspaces, vendor,
project embedded assets and cgo remain outside this slice. Authenticated module
assets, including protobuf edition defaults, are included without removing the
project-input guards.

Preparation and execution freshly authenticate the source, module index and CAS
bytes. Module h1 sums are recalculated over the complete expanded file set;
cache .mod metadata is checked against pinned go.sum and expanded go.mod where
present. The approved runner stages only authenticated toolchain, project and
module bytes with fresh HOME, GOPATH, module/build caches and temporary directory.
The existing Darwin sandbox denies network, ambient reads/executables and writes
to toolchain and module files. No host module cache is an execution input.
Receipts bind request, input closure, toolchain index and module index digests.

Default native `gen` and `gen batch` prepare a projected-input request using the
native plan's exact afterimage and fingerprint. A gen-scoped persistent signature
is required before applying files. After application, the material is checked
against actual current input and executed by the same approved project runner.
Only compiler exit 0 permits commit. Nonzero exit, cancellation, unavailable
material or guard loss roll back through the native transaction owner. A reaped
compiler failure retains its process receipt and reports no committed changes;
a rollback conflict remains a transaction failure. `--no-build` continues to be
an explicit file-only operation, without approval or preparation controls.

## Public evidence qualification

The focused Temporal fixture renders the actual public template-go main
`d0179547cd2e47b7564b0011bc5045799fc036bd` with workflow enabled. Its exact
published go.mod/go.sum pin Go SDK v1.29.1. The demonstrated index is specific to that workflow-enabled
module manifest; it does not authorize other template answer/dependency variants.
Explicit public HTTPS module acquisition
uses proxy.golang.org and sum.golang.org before enrollment. Runtime execution is
offline. The acquired graph and checksum evidence remain separate from source
publication evidence.

That published template has no native build declaration. The isolated template
change adds only literal build metadata, the two indexes and the updated manifest
contract digest. Until the parent publishes it, the installed proof authenticates
an explicitly named LOCAL unpublished metadata-overlay fixture with synthetic
publisher/approver keys. It proves actual dependency-bearing CLI/MCP execution
and the scoped authorization contract, not publication of new GitHub metadata,
full U13 completion, other platforms, or private Astra provenance.

For shared schemas, extract the named `run`, `gen` and `gen_batch` entries from the
actual installed stdio `tools/list`. The parent must splice only these entries,
preserving workspace, project_diff and all other tools. Never apply the historical
whole golden over a later shared integration.
