# Native current-baseline diff

`Run(ctx, installedRuntime, Options)` retains existing shared project/home writer
coordination and uses the concrete runtime's held CAS. A prior `VerifyObserved`
checks identity, root/dependency evidence, and native receipt readiness. The new
read session spans exact metadata reads, signed reconstruction, current-content
comparison, re-reading selected files, and final session authentication.

The source selection is derived from the closed lock pair, never a user-selected
checkout. `PrepareNew` is the same native signed reconstruction primitive used by
Update planning. It produces immutable expected images in bounded runtime-owned
scratch; no project/home/source state is written. The current engine baseline
must equal that reconstruction. The managed baseline must equal `BuildBaseline`
for its literal managed images, with each provider bound to the actual root
subject. Labels do not grant publisher, execution or ownership authority.

CLI: `diff [--project-context KEY] [--dir ROOT] [--exit-code] [--json]`.
It is offline by default; `--offline=false` refuses. Ordinary rows use `path`;
managed rows use the independent `(path, blockId)` identity. Text uses
`path#blockId`. Changing only two blocks creates two block rows and no whole-file
row. Skeleton/mode drift is a distinct `skeleton` row. File and block summary
counts are disjoint. Exit 0 means a successful observation; `--exit-code` changes
a nonempty diff to exit 1. Errors retain their typed status and have no partial
changes or verified project payload.

MCP: `project_diff` accepts only `dir`, `projectContext`, `exitCode`. Resolved `dir`
is forwarded as the explicit CLI root locator and child CWD. Unknown controls
refuse before child launch. Existing held-child transport performs all process
execution; this backend has no runner, shell, import, refresh, hook, or module
execution dependency.

Bounds: existing source/render limits, 4096 files, 64 MiB rendered/current total,
16 MiB per current file under the existing no-follow reader, 4096 total block and
change rows, at most 8192 marker tokens per parsed image, and paths at most 1024
bytes. Each current file is observed twice; advisory coordination plus exact
reobservations catches cooperating and foreign changes. No absent lock is created.

Supported baseline is the native action-free, dependency-free signed template
closure and its inert native generator source images. Managed markers can be
literal signed `copyWithoutRender` images. External BlockExport dependency
composition/adoption, ownership policies, tombstones, and extra Gen-owned inventory
entries are explicit refusals, not silently skipped. `updateplan.Prepare` itself
currently rejects managed images; it is not changed or presented as a block-aware
Update implementation. Link/adopt and parent P06 remain separate obligations.

Workspace-kind history has no fallback to an ordinary project Update receipt.
The accepted generic Inspector/read-session coverage governs readiness; unknown
or unresolved native coverage refuses. No Inspector or workspace engine changes
are part of this package.

The installed CLI/MCP test fixture provisions synthetic signed evidence on disk
and builds a real pinned-registration CLI. A signed literal block baseline is
materialized explicitly by the test, because CLI `new` still refuses managed
images. This proves installed diff, not managed-project creation/adoption. The
configured-action negative intentionally stores an inert negative fixture and
must be refused; resource admission success is not claimed for it. Snapshots
check paths, bytes, modes and inodes across project/home/object/evidence/store
roots. Access times are not a write proof. Test children are ordinary builds;
`go test -race` instruments the parent Go tests/backend calls.
