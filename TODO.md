# Remaining work

An overview of tplAIter work. Checked items describe implemented foundations; unchecked items remain open.

| Status | Work |
| --- | --- |
| ☑ | Translate ordinary comments in core sources and templates to English while preserving runtime strings and test data. |
| ☑ | Translate remaining Russian user-facing strings in CLI help, errors, MCP tool descriptions, and documentation to English. |
| ☑ | Repair the development baseline: Linux build, static checks, formatting, module maintenance, verification, separated CLI and MCP registration, and continuous integration. |
| ☑ | Provide accepted OSS installation registration, first-run trust provisioning, and installed-binary trust coverage; refuse installation-root reuse or rotation for unproven roots or roots with foreign entries before removing files. |
| ☑ | Support the Linux trust store on proven filesystems, held-stage MCP transport, and the approved Linux runner. |
| ☑ | Return a verified typed MCP error for an unsupported trust-store filesystem. |
| ☑ | Provide the state ledger, crash-safe transaction foundation, ownership tracking, template migrations, and read-only snapshots. |
| ☑ | Confine descriptor-based template checkout and coordinate real writer locks during migrations. |
| ☐ | Finish verification of trusted CLI/MCP launch behavior and its negative scenarios; Windows remains deferred. |
| ☐ | Restore ordinary live `new` and `update` workflows, settings and workspace operations, read-only checks, diff, linking, adoption, recopy, rebaseline, and reanswer. |
| ☑ | Provide the typed result envelope, MCP output schemas, cancellation and timeout separation with process cleanup, and the stdio JSON-RPC contract suite. |
| ☑ | Provide the executor foundation for persistently approved native actions; ordinary `run` and `gen` workflows remain pending. |
| ☐ | Complete the CLI/MCP surface: restore `gen`, `run`, environment setup, hooks, batch generation, compact output, and full CLI-to-MCP parity. |
| ☑ | Discover nested templates from a root manifest with path and symlink confinement and duplicate detection. |
| ☐ | Complete composition and modifiers across the lifecycle; Go formatting is implemented, while Rust and TypeScript formatting return typed unsupported results as an accepted beta limitation. |
| ☐ | Complete the Base, Go, and Rust templates and implement React and the Next modifier. |
| ☐ | Extend search, documentation, and context retrieval on top of the finished graph. |
| ☐ | Prepare distribution, overlays, and fleet automation. |
| ☐ | Reach beta readiness through the overall regression run and final program acceptance. |
| ☐ | Run matched concurrent Go-project benchmarks with and without the tplAIter MCP using the same requested Sonnet 5 model; verify model availability before execution and compare tokens, elapsed time, and acceptance quality. |
