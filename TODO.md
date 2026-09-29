# Remaining work

An overview of tplAIter work. Current status and dependencies are tracked in Beads; the identifiers below refer to the local tracker, not to GitHub Issues. Work on the core beta-preview resumed on 2026-09-29; the ☑ rows below that date mark what has landed on `main`.

| Status | Work | Beads issues |
| --- | --- | --- |
| ☑ | Translate ordinary comments in the core sources and templates; runtime strings and testdata values are out of scope. | `tp-i9g.30.4` |
| ☑ | Translate the remaining Russian user-facing strings (CLI help, errors, MCP tool descriptions, docs) to English (2026-09-29). | `tp-i9g.2.3` |
| ☑ | Repair the baseline: Linux build, `go vet`, gofumpt, `go mod tidy`, golangci-lint config at zero issues, `make verify`, split MCP tool and CLI command registration, core PR CI (2026-09-29). | `tp-i9g.4.2.7`, `tp-i9g.15.1` |
| ☑ | OSS install registration and first-run `trust provision --oss`, installed-binary e2e trust fixture, safe install-root rotation (2026-09-29; merged without the final test run, re-verify in the next wave). | `tp-i9g.4.4`, `tp-i9g.4.3` |
| ☑ | Linux trust store for proven filesystems, Linux held-stage transport for `mcp-server`, approved runner on Linux (2026-09-29). | `tp-i9g.4.3.2` |
| ☐ | Finish verification of the trusted CLI/MCP launch and its negative scenarios; Windows is deferred. | `tp-i9g.4` |
| ☑ | Port the state ledger, crash-safe `new` transactions, ownership ledger, template migrations and the read-only snapshot (2026-09-29). | `tp-i9g.5.1`, `tp-qbk.4` |
| ☐ | Restore live `new`/`update`/`settings`/`workspace`, read-only `verify`/`check`, `diff`, `link`/`adopt`, `recopy`/`rebaseline` and reanswer. | `tp-i9g.5–6` |
| ☑ | `result/v1` typed envelope with output schemas on MCP tools, cancellation separated from timeout with process-group cleanup, stdio JSON-RPC contract suite (2026-09-29). | `tp-60o`, `tp-xd6.4`, `tp-xd6.5` |
| ☐ | Complete the CLI/MCP surface: restore `gen`/`run`/`env setup`/hooks, batch generation, compact output and full CLI↔MCP parity. | `tp-i9g.7` |
| ☑ | Discover nested templates under a root manifest with path and symlink confinement and duplicate detection (2026-09-29). | `tp-tdm` |
| ☐ | Complete composition and modifiers in the lifecycle; Go formatting is real, Rust/TypeScript formatting is typed-unsupported in the beta. | `tp-i9g.8` |
| ☐ | Complete Base/Go/Rust; implement React and the Next modifier. | `tp-i9g.9–13` |
| ☐ | Extend search, documentation and context retrieval on top of the finished graph. | `tp-i9g.14` |
| ☐ | Prepare distribution, internal overlays and fleet automation. | `tp-i9g.15–17` |
| ☐ | Run the overall regression and the final program acceptance. | `tp-i9g.20`, `tp-i9g.22` |
| ☐ | Benchmark: build a Go project with and without the tplAIter MCP using parallel Sonnet 5 agents; compare tokens and time. | `tp-2v2` |
