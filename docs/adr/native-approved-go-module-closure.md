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

## Historical local metadata-overlay evidence

The focused Temporal fixture renders the actual public template-go main
`d0179547cd2e47b7564b0011bc5045799fc036bd` with workflow enabled. Its exact
published go.mod/go.sum pin Go SDK v1.29.1. The demonstrated index is specific to that workflow-enabled
module manifest; it does not authorize other template answer/dependency variants.
Explicit public HTTPS module acquisition
uses proxy.golang.org and sum.golang.org before enrollment. Runtime execution is
offline. The acquired graph and checksum evidence remain separate from source
publication evidence.

At that historical `d0179547` checkpoint, the published template had no native
build declaration. The isolated template change added only literal build
metadata, the two indexes and the updated manifest contract digest. The installed
proof authenticated an explicitly named LOCAL unpublished metadata-overlay
fixture with synthetic publisher/approver keys. It remains evidence of actual
dependency-bearing CLI/MCP execution and the scoped authorization contract for
that fixture, not a replay of subsequently published GitHub metadata, full U13
completion, other platforms, or provenance for any other source.

## Published source and owner-audited installed replay

Core [`e49dd1f77492388e02b638ad6db1265224b97fcd`](https://github.com/tplAIter/tplaiter/commit/e49dd1f77492388e02b638ad6db1265224b97fcd)
publishes the v2 authenticated offline module-closure runner and default native
CLI/MCP `gen`/`gen batch` build path. Preparation binds the exact projected inputs
to a gen-scoped persistent approval before applying files; the transaction commits
only after the approved compiler succeeds. The bounded installed replay evidence
is qualified separately below.

Public template-go
[`57136713797afd1c99c294b97b07da5544cf8a3b`](https://github.com/tplAIter/template-go/commit/57136713797afd1c99c294b97b07da5544cf8a3b)
publishes the literal [v2 build declaration](https://github.com/tplAIter/template-go/blob/57136713797afd1c99c294b97b07da5544cf8a3b/actions/run/build.json)
with `genBuild: true` and authenticated toolchain/module index digests. Its bounded
scope is the exact `workflow=true` module manifest, including Temporal Go SDK
v1.29.1, on Darwin/arm64 with the pinned Go 1.27.1 toolchain. Compilation does not
establish Temporal client/worker execution or all-variant acceptance.

The published [README qualification](https://github.com/tplAIter/template-go/blob/57136713797afd1c99c294b97b07da5544cf8a3b/README.md#native-offline-build-scope)
keeps `workflow=false` as the template default, unsupported by this v2 build
metadata. Native `run build` and default generation refuse with
`TRUST_GO_MODULE_CLOSURE_UNAVAILABLE` before compiler execution; default generation
refuses before applying files. There is no automatic dependency-free v1 fallback,
ambient cache/toolchain fallback or online dependency resolution. Explicit
`--no-build` remains file-only generation.

Following prior independent code review, fresh installed replay against these
exact published core/template pins passed in 463.79 seconds. The owner audited
the recovery record, process receipts and clean exact-source binary image
SHA-256 `5bc8666c37220a567f9da5d284bf33e6e70d2f95e03b21355d75dc1715534bc6`.
Fresh HTTPS Git enrollment retained 72 actual objects. Actual CLI and MCP
`run build` exited 0; CLI and MCP default `gen` applied files and built with
`noBuild=false`, exit 0 and bound module/toolchain receipts. Unsigned approval
was refused with `TRUST_APPROVAL_REQUIRED`; a stale build grant after generation
was refused with `TRUST_APPROVAL_MISMATCH`, without a process receipt. The
signing/approval authority is a synthetic fixture, not official upstream
certification. This documentation refresh inspects the owner-audited evidence;
it does not claim a separate independent runtime replay.

The proof completed before the documentation-only public head move to
[`33f77490`](https://github.com/tplAIter/tplaiter/commit/33f77490e800fd57c0393a6abec0c91104785c89);
its binary and enrollment remain pinned to `e49dd1f` and `5713671`. The historical
LOCAL metadata-overlay proof and failed-compiler rollback counterproof retain
their original qualification; the negative compiler/rollback case was not
repeated in this published-pin replay. Temporal service/runtime workflows were
not executed. Support for the default-false module variant remains in progress;
other platforms, formatter, hooks, ordinary executable actions, full U13 and
whole-beta acceptance remain open.

For shared schemas, extract the named `run`, `gen` and `gen_batch` entries from the
actual installed stdio `tools/list`. The parent must splice only these entries,
preserving workspace, project_diff and all other tools. Never apply the historical
whole golden over a later shared integration.
