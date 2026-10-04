# Read-only offline verification

The installed CLI and MCP readonly operations read authenticated installed evidence for one finite project context and report what they find. They do not refresh, use the network, execute project commands, or repair files.

## Install and enrollment

Install and provision the binary with the [source installation guide](install.md). Source builds can enroll public sources and finite project contexts through the [source enrollment guide](source-enrollment.md). A context has a key and an authenticated `rootPath`; the selected project root must be exactly that context root.

## CLI

Use an installed, provisioned binary and an enrolled context key:

```sh
tplaiter verify --project-context a --offline --json
tplaiter check --project-context a --offline --json
tplaiter deps verify --project-context a --offline --json
```

`--offline` is the supported mode. `--project-context` selects the installed finite context. `--dir` is an optional project locator whose absolute normalized path must equal the selected context's authenticated `rootPath`; symlink aliases are not resolved. The command can run from an unrelated child working directory; the locator still names the authenticated project root.

`verify` checks sealed project state and reports `entryCount`, `ledgerCount`, `dependencyCount`, and `dependencyState`. `check` reports ownership and drift with `status`, `managed.state`, `managed.modified`, `managed.missing`, `managed.invalid`, `findings`, and the nested verification projection. `deps verify` checks the canonical dependency lock pair and reports `verified`. Each data object also contains `offline: true`.

The JSON envelope uses the installed `tplaiter.dev/result/v1` contract with the operation-specific kind `ProjectVerify`, `ProjectCheck`, or `DepsVerify`, project identity and root on success, typed diagnostics on refusal, and no transaction, change, or artifact records for these operations. A clean check exits 0. A check that finds managed drift exits 1 and returns status `changes`; it does not modify the project.

## MCP

Start the installed server with `tplaiter mcp-server`. The readonly tools are `project_verify`, `project_check`, and `deps_verify`. Their arguments are `dir` (the existing child working directory), `targetDir` (optional project locator), `projectContext` (the enrolled context key), and `offline` (must be `true`). For example, a call may use `dir: "/work/child"`, `targetDir: "/projects/a"`, `projectContext: "a"`, and `offline: true`.

`dir` controls the MCP child process working directory. `targetDir` is passed as the CLI project locator and must equal the authenticated context root. They are independent, so an unrelated existing child directory may be used while verification targets the enrolled root.

Each tool publishes a closed output schema for its result data:

| Tool | Data projection |
| --- | --- |
| `project_verify` | `offline`, `entryCount`, `ledgerCount`, `dependencyCount`, `dependencyState` |
| `project_check` | `offline`, `apiVersion`, `status`, `managed`, `findings`, `verify` |
| `deps_verify` | `offline`, `verified` |

Transport cancellation returns a typed failed result with diagnostic code `MCP_CANCELLED`; the installed child and its process group are reaped and the server remains usable.

## Refusals and exit behavior

The CLI and MCP expose the same typed refusal envelope. `--offline=false` is unsupported and exits 8 with `TPL-E-ONLINE-UNSUPPORTED-001`. A context/root mismatch is a trust refusal, exits 5, and reports `TRUST_PROJECT_CONTEXT_MISMATCH`. An unknown or unavailable installed context is refused; a missing installed evidence object reports `TPL-E-OFFLINE-MISS-001` with exit 8, while a corrupt object reports `TPL-E-TRUST-001` with exit 5. Drift is the normal finding case: exit 1.

CLI cancellation preserves the typed cancellation cause and exits 3. MCP cancellation uses `MCP_CANCELLED` in the result envelope. These operations do not fall back to another trust store or origin, refresh missing evidence, contact a network, execute hooks or project commands, or repair a damaged project.

The readonly path does not initialize `HOME` or create missing state. The OSS installation has no production secret-digest provider: verification that requires one, private credential roots, and unknown home entries are refused before credential bytes are opened.
