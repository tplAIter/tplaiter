<p align="center">
  <img src="https://raw.githubusercontent.com/tplAIter/.github/main/assets/banner.png?v=20260928" alt="tplAIter — Build with blocks. Spend fewer tokens." width="100%">
</p>

<h1 align="center">tplAIter</h1>

<p align="center">Composable template blocks and validation for AI-assisted product development.</p>

<p align="center"><strong>Status: development preview · not a release</strong></p>

<p align="center"><a href="https://github.com/tplAIter/template-base">base template</a> · <a href="https://github.com/tplAIter/template-go">Go template</a> · <a href="https://github.com/tplAIter/template-rust">Rust template</a> · <a href="https://github.com/tplAIter/docs">docs</a> · <a href="./docs/STATUS.md">status</a> · <a href="./docs/template-validation.md">template validation</a> · <a href="./docs/graph-explorer.md">graph explorer</a></p>

`tplaiter` is a Go command-line tool for working with template repositories and rendered projects. It preserves Go's `text/template` engine; template processing does not require a Python runtime.

## The intended workflow

An agent should not have to retype a service layout from scratch. Describe the
intent, ask an MCP tool for parameterized template blocks, compose them, then
validate the rendered result and its architecture. That gives local and
budget-conscious models a reviewable structure to work from, while frontier
models can spend more of their effort on product decisions.

```text
Intent: "Add a Go orders API with PostgreSQL and a worker"
  → MCP request: select parameters and blocks
  → template blocks: service, repository, transport, worker
  → validation: manifest, rendered project, language checks
```

This is the development direction, not a statement that the live CLI or MCP
workflow is complete today. The fixed lifecycle adapters needed for ordinary
`new` and `update` remain unavailable in this preview.

## What is here

- A Go 1.26+ CLI and the existing template processing engine.
- Manifest, schema, repository, statistics, and template validation packages.
- A reusable GitHub Action for linting `template.manifest.yaml` and rendering fixture projects.
- A local graph and context explorer (`cmd/graphview`) with provenance-aware views and bounded context packs.
- Trust and lifecycle building blocks under active engineering review.

### Evaluation targets, not measured results

We are targeting 30% fewer coding and retrieval tokens through reusable,
parameterized blocks. Reliability and maintainability remain qualitative goals
until they have a defined evaluation method.

Published template repositories are intended to use the shared checker, then run their generated-language checks in the caller workflow. The checker validates the manifest and rendered files without running template hooks, manifest commands, or reading credentials.

## Checkpoint status

This is a development preview. It has no published release, compatibility promise, production support commitment, or production-installed trust anchors.

The ordinary live `new` and `update` paths are unavailable until their fixed adapters are complete. A stock CLI stops those paths with `TRUST_ANCHOR_MISSING`; registering an anchor does not make the live lifecycle available and still leads to `TRUST_LIFECYCLE_UNAVAILABLE`. Fixed simulated registration tests cover dry-run and maintenance behavior, but they do not establish production provisioning or an end-to-end lifecycle.

Focused internal package checks cover template initialization, contribution, settings, statistics, repositories, and table rendering. The separate black-box lifecycle module remains a known limitation. Windows builds also require platform work for existing Unix-specific references in `execx` and `naming`.

## Local verification

With Go 1.26 or newer and the module dependencies available, run focused checks such as:

```sh
go test ./cmd/graphview ./cmd/templatecheck
go test ./internal/contextpack ./internal/graphview
```

The complete suite depends on the available module cache and checkpoint state; these focused commands are the small local checks shown here, rather than a claim that every package is production-ready. The validation workflow and its safety boundaries are documented in [template validation](./docs/template-validation.md).

### Canonical gates

The `Makefile` is the single entry point for local runs and CI (`.github/workflows/ci.yml`). Every target runs with `GOWORK=off`. The binary is named `tplaiter`.

| Target | What it checks |
| --- | --- |
| `make build` / `make install PREFIX=<dir>` | Builds `bin/tplaiter`; installs it into `<dir>/bin`. `REGISTRATION_PATH` and `REGISTRATION_SHA256` are empty by default, so a stock binary refuses trust-gated commands with `TRUST_ANCHOR_MISSING`. |
| `make build-linux`, `make cross` | Compiles every package for linux/amd64 and linux/arm64 (`cross` adds darwin; windows is informational only). |
| `make vet` | `go vet` for both modules, plus the root module for `GOOS=linux`. |
| `make fmt-check`, `make tidy-check` | gofumpt on tracked and untracked Go files; `go mod tidy -diff` for both modules. |
| `make lint` | golangci-lint v2 with the committed `.golangci.yml` and `tests/.golangci.yml`. |
| `make test-race`, `make e2e` | Unit tests with the race detector; the black-box `tests/` module. |
| `make verify` | All of the above. |
| `make verify-linux` | Build, vet, race tests and e2e for a Linux container (no lint or formatting tools needed). |

Run the Linux gate offline with a read-only module cache:

```sh
docker run --rm -v "$PWD":/src -v "$(go env GOMODCACHE)":/go/pkg/mod:ro -w /src \
  -e GOWORK=off -e GOFLAGS=-mod=readonly -e GOPROXY=off golang:1.27 make verify-linux
```

The `tests/` e2e module still fails with `TRUST_ANCHOR_MISSING` until the OSS installation registration lands, so `make verify` and `make verify-linux` are not green yet.

### Platform support (trust store, MCP transport, approved runner)

| Host | Trust store | `mcp-server` tool calls | Approved runner (hooks, build gates) |
| --- | --- | --- | --- |
| macOS arm64 | APFS | held stage (`F_GETPATH`) | Mach-O dyld/libSystem envelope |
| Linux amd64/arm64 | ext4 and overlayfs only | held stage (`/proc/self/fd`) | static ELF envelope |
| macOS amd64 | APFS | held stage | `TRUST_EXECUTION_UNAVAILABLE` |
| Windows, BSDs | unavailable (deferred) | `MCP_UNAVAILABLE` | `TRUST_EXECUTION_UNAVAILABLE` |

On Linux, a trust store on any other filesystem (tmpfs, btrfs, xfs, NFS, FUSE, 9p) is refused with `TRUST_STORE_FILESYSTEM_UNSUPPORTED`; keep `XDG_CONFIG_HOME`/`HOME` on a local ext4 or container overlay filesystem. The design and evidence are in [ADR-006](./docs/adr/ADR-006-linux-trust-store.md).

MCP tools are registered per domain in `internal/mcpsrv/tools_<domain>.go` and listed once in `toolRegistrars`; `internal/mcpsrv/testdata/tools.golden.txt` pins the tool names. CLI commands register through `registerCommand` in their own file and declare their pre-run class (`readonly`, `trust-owned`, `legacy-action` or the default `stateful`) with a cobra annotation; see `internal/cmd/prerun_class.go`.

## Template discovery

A template repository may hold a root template plus nested templates (the provider shape); `repo add`, `template list`, `lint-template` and `init-template` share one recursive, symlink-confined discovery with typed errors (`TPL-E-REPO-PATH-ESCAPE`, `TPL-E-REPO-DUP-NAME`, `TPL-E-REPO-DUP-PATH`). See [template discovery](./docs/template-discovery.md); `schema/repository.manifest.schema.json` describes `repo.manifest.yaml`.

## Machine-readable output

Every command behind an MCP tool accepts `--json` and prints exactly one
`tplaiter.dev/result/v1` envelope on stdout; MCP tools return the same
envelope as structured content and declare it as their `outputSchema`. Exit
codes come from one registry: 0 success, 1 findings, 2 usage, 3 and above
typed failures. See [docs/exit-codes.md](docs/exit-codes.md) and
[schema/result.v1.schema.json](schema/result.v1.schema.json).
