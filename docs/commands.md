# Command reference

This reference records the public CLI at `3ccb11b2a3ac9a6033f45bc940333436a2587f28`. The 80 existing documented routes retain the earlier compiled-help reference; this refresh builds the current source offline and checks only the context group, its two added preview routes, and the operator registration helper. Run `tplaiter <command> --help` for the complete flags of your installed version. Command visibility does not establish that an installation has the authority or execution evidence to run it.

## Installation and admission

`go build .` builds a development binary; it does not enroll a trust installation. The source installation route is `make install`: it generates an operator-pinned registration, links its path and SHA-256 into the executable, and installs the binary. Run `tplaiter trust provision` to enroll the pinned initial state. `trust inspect` checks the installed binding; `trust contexts` lists registered project-context keys. A request key selects an installed entry; `--dir` is a locator that must agree with its registered root. Request JSON cannot provide authority.

The build-time command `go run ./cmd/tplaiter-oss-register --help` documents `--root`, `--output`, `--publishers`, `--source-packages`, `--local-sources`, `--project-contexts`, `--approvers`, `--execution-evidence`, `--local-providers` and `--rotate`. It is not an installed CLI subcommand. Inputs must satisfy the enrollment contracts in [ADR-005](adr/ADR-005-oss-install-registration.md). `--local-sources` requires project contexts, a fresh absent root, and forbids publishers, source packages and rotation. This offline source enrollment is distinct from an external provider session. Rotation discards the installation and trust store; it is not a routine refresh.

`make install` exposes `TRUST_ROOT`, `TRUST_PUBLISHERS`, `TRUST_SOURCE_PACKAGES`, `TRUST_LOCAL_SOURCES`, `TRUST_PROJECT_CONTEXTS` and `TRUST_ROTATE`. Staged `DESTDIR` installation requires both `REGISTRATION_PATH` and `REGISTRATION_SHA256`; supplying only one pin is invalid. Pins are build inputs, not runtime request flags.

## Published command routes

The following usage strings come from the compiled help. Groups are included because some also perform an action when invoked directly. `[flags]` is Cobra's notation; it does not mean every global flag grants an execution capability.

| Usage | Purpose from help |
| --- | --- |
| `tplaiter adopt <commit> <project-name> [flags]` | Attach signed native state to an existing project without writing user files |
| `tplaiter ai [command]` | Works with the ai-config directory copy that `tplaiter new` places in the project as .tplaiter/ai-config. Modules are gated by a `when` condition (§3.2) based on current project settings — a module without when is always active. |
| `tplaiter auth [command]` | Stores tokens in ~/.tplaiter/tplater.db (mode 0600) and supplies them to git operations via a built-in credential helper. See documentation |
| `tplaiter check [flags]` | Check verified project ownership and drift offline |
| `tplaiter completion [command]` | Generate the autocompletion script for tplaiter for the specified shell. |
| `tplaiter context [command]` | Read bounded context from installed signed sources |
| `tplaiter deps [command]` | Inspect and manage template dependencies |
| `tplaiter diff [flags]` | Compare current files and independent managed blocks with the signed baseline |
| `tplaiter doctor [flags]` | Check environment and tools of active template |
| `tplaiter env [command]` | The template declares environment.playbooks (SPEC-01 §2) — ansible playbooks for environment setup (infrastructure, dependencies, etc.). tplaiter is the single entry point for running them: it installs ansible if needed and executes the playbook with extra-vars from project settings and identification. |
| `tplaiter gen <kind> <name> [--<param> ...] [flags]` | Generates files and anchor insertions according to the template manifest generators (SPEC-01 §6). The kind and its snippets come from the template, not from the tplaiter binary — `tplaiter gen list` shows available kinds for the current project. |
| `tplaiter init-shell [bash\|zsh\|fish] [flags]` | init-shell prints the tplaiter completion script for the specified shell — the same as the built-in `tplaiter completion <shell>`. |
| `tplaiter init-template <name> [flags]` | Generates an empty tplaiter-compatible template repository: template.manifest.yaml skeleton with sample settings groups, files/ tree with working minimal example, generator, ai-config, environment playbook, NOTES, maintainer README, and GitHub Actions workflow with lint-template check. |
| `tplaiter link <commit> <project-name> [flags]` | Attach signed native state to an existing project without writing user files |
| `tplaiter lint-template [flags]` | Finds template repository manifest(s) (single at root or multi via repo.manifest.yaml/scan), validates each template, and runs trial renders across all "corner" settings combinations: defaults, each select/multiselect option, all toggles together (all-on), and full max. For each combo, checks rendering, NOTES, generator parsing, ai-config, and YAML environment playbooks. |
| `tplaiter mcp-server [flags]` | Runs an MCP server on top of the tplaiter CLI (pattern borrowed from goca, docs/research/clean-codegen.md §1): ~20 tools (repo/template/project/gen/...) are available to AI agents via the MCP protocol over stdio. Each tool executes tplaiter as a separate process with separate arguments (no shell interpolation). |
| `tplaiter migrate-state --root kind=source:destination [--root ...] \| --apply --plan file --expected-digest sha256 [flags]` | Build or apply explicit state migration |
| `tplaiter new <ref> <project-name> [flags]` | Creates a project from a signed, pinned native template using --source-input. The target must match the installed project context. Settings use --set/--answers/--defaults or an interactive survey. This foundation supports action-free templates; hooks, tools, environment, generators, AI resources and managed blocks require later lifecycle slices. |
| `tplaiter projects [command]` | Registry ~/.tplaiter/projects.yaml — a navigation convenience, not the source of truth (the source of truth is .tplaiter/ within each project). The registry is automatically updated by each tplaiter command run inside a project: directory relocation is tracked by stable id from .tplaiter/project.yaml, a project without an entry (cloned by a colleague) is registered on first discovery, and baselineSHA divergence (project updated on another machine) is updated on discovery. |
| `tplaiter repo [command]` | Add, update, and delete git repositories for templates (helm model). See documentation. |
| `tplaiter run [name] [-- args...] [flags]` | List commands, prepare a signed pure-Go build request, or compile the authenticated project with a persistent operator approval. No shell command execution. |
| `tplaiter self-upgrade [flags]` | Update tplaiter to the latest version |
| `tplaiter settings [command]` | Show and change authenticated native project settings |
| `tplaiter stats [flags]` | Compares a clean render of the pinned template version+answers (baseline) with the project working tree; for each file — status (identical/modified/deleted/extra), percentage of changed lines (LCS), and updateability class — auto (update will merge cleanly), conflict-prone (template historically modified this file), or manual-only (deleted baseline file, broken CODEGEN anchor, or edit in copyWithoutRender artifact). |
| `tplaiter template [command]` | List templates, view metadata with settings tree and documentation, and export template tree from added repositories. See documentation. |
| `tplaiter trust [command]` | Inspect and maintain the trust profile |
| `tplaiter update [flags]` | Updates the installed project context from its signed current source to the exact target in --source-input. --to, when supplied, must equal that pinned commit. --dir must match the installed root. --dry-run prepares a read-only plan; --check with source input checks that plan, otherwise it scans conflict markers. Conflicting plans preserve the project and registry. Actions, hooks, tools, environment and --all are unavailable. |
| `tplaiter upgrade [flags]` | Compares the project working tree with a clean render of the pinned template version (baseline, like `tplaiter stats`) and proposes changed files back to the template repository. Candidates are modified baseline files (go.mod/go.sum excluded as noisy); extra files are added only with explicit --files <glob>. Selected files are de-parametrized (slug/module/project name → placeholders `{{ .Project.* }}`), placed in the template `.tmpl` source tree in a new cache-clone branch, then opens an MR (`glab`) / PR (`gh`) depending on repository type. |
| `tplaiter verify [flags]` | Verify sealed project state using installed offline evidence |
| `tplaiter version [flags]` | Show tplaiter version |
| `tplaiter workspace [command]` | Operations on a signed Go workspace |
| `tplaiter adopt abort <transaction-id> [flags]` | Recover authenticated first-marker state and registry transaction |
| `tplaiter adopt continue <transaction-id> [flags]` | Recover authenticated first-marker state and registry transaction |
| `tplaiter ai gen [flags]` | Generate AI artifacts in project root |
| `tplaiter ai list [flags]` | List of ai-config modules (id/title/activation/when/available) |
| `tplaiter ai validate [flags]` | Validate ai-config source against project template manifest |
| `tplaiter auth add <host> [flags]` | Add/update token for host (and optionally repository) |
| `tplaiter auth import-gh [--hostname <h>] [flags]` | Import token from gh into tplaiter store |
| `tplaiter auth import-glab [--hostname <h>] [flags]` | Import token from glab into tplaiter store |
| `tplaiter auth list [flags]` | Show saved tokens (masked) |
| `tplaiter auth remove <id> [flags]` | Delete token by id |
| `tplaiter completion bash` | Generate the autocompletion script for the bash shell. |
| `tplaiter completion fish [flags]` | Generate the autocompletion script for the fish shell. |
| `tplaiter completion powershell [flags]` | Generate the autocompletion script for powershell. |
| `tplaiter completion zsh [flags]` | Generate the autocompletion script for the zsh shell. |
| `tplaiter context continue [flags]` | Context continue |
| `tplaiter context discover [flags]` | Context discover |
| `tplaiter context get [flags]` | Context get |
| `tplaiter context plan [flags]` | Context plan |
| `tplaiter context preview-catalog [flags]` | Read explicitly untrusted observed local provider data |
| `tplaiter context preview-resource [flags]` | Read explicitly untrusted observed local provider data |
| `tplaiter context schema [flags]` | Context schema |
| `tplaiter context search [flags]` | Context search |
| `tplaiter deps verify [flags]` | Verify the canonical dependency lock pair offline |
| `tplaiter env list [flags]` | Show environment playbooks from template manifest |
| `tplaiter env setup [name] [flags]` | Run environment playbook (default "setup") |
| `tplaiter gen batch --operations <JSON> [--no-build] [flags]` | Plans all operations before the first write and commits them in one native transaction. File-only generation requires --no-build; executable actions are unavailable. |
| `tplaiter gen list [flags]` | List generators from the authenticated native project |
| `tplaiter link abort <transaction-id> [flags]` | Recover authenticated first-marker state and registry transaction |
| `tplaiter link continue <transaction-id> [flags]` | Recover authenticated first-marker state and registry transaction |
| `tplaiter projects list [flags]` | STATUS column: |
| `tplaiter projects prune [flags]` | Removes entries where the directory at PATH does not exist or .tplaiter/project.yaml in it is missing (same criterion as STATUS=missing in `projects list`). Before deletion, prints the list of candidate entries; without --yes prompts for confirmation interactively (huh), in non-interactive mode requires --yes explicitly. |
| `tplaiter repo add <alias> <url> [flags]` | Add a template repository |
| `tplaiter repo list [flags]` | List repositories (ALIAS/URL/TYPE/TEMPLATES/UPDATED) |
| `tplaiter repo remove <alias> [flags]` | Delete a repository |
| `tplaiter repo update [alias] [flags]` | git fetch + reindex all repositories or one |
| `tplaiter settings edit [group] [flags]` | Reanswer an authenticated settings group |
| `tplaiter settings list [flags]` | Show authenticated current settings |
| `tplaiter settings set group=value [group2=value2 ...] [flags]` | Change settings through a signed same-version native plan |
| `tplaiter template list [flags]` | List catalog templates (NAME/REPO/VERSION/DESCRIPTION/LABELS) |
| `tplaiter template pull <ref> [flags]` | Resolves reference <ref>, checks out the selected version, and copies the entire template tree (manifest, files/, docs) to dest (defaults to ./<name>). dest must not exist or be an empty directory. |
| `tplaiter template show <ref> [flags]` | Resolves reference <ref> (full `repo/name@version` or short `name`), checks out the selected version, and prints: metadata header, settings groups tree, command list (`commands`), and docs file rendering (glamour with color output, otherwise as-is). |
| `tplaiter trust contexts [flags]` | List authenticated installed project contexts as JSON |
| `tplaiter trust inspect [flags]` | Verify the installed trust profile and print its binding |
| `tplaiter trust provision [flags]` | Enroll the trust store from the installation's pinned initial state (idempotent) |
| `tplaiter trust recover-state [flags]` | Recover the trust store after an interrupted update |
| `tplaiter trust refresh [flags]` | Apply a newer sealed bootstrap bundle to the trust store |
| `tplaiter update abort <transaction-id> [flags]` | Abort an authenticated native Update transaction |
| `tplaiter update continue <transaction-id> [flags]` | Continue an authenticated native Update transaction |
| `tplaiter workspace abort <transaction-id> [flags]` | abort an authenticated native workspace transaction |
| `tplaiter workspace add-service <name> [flags]` | Add a signed native Go service to an authenticated workspace |
| `tplaiter workspace continue <transaction-id> [flags]` | continue an authenticated native workspace transaction |

`help [command]` is Cobra's help route. `settings show` aliases `settings list`; root `--upgrade` aliases `self-upgrade`. Root also exposes `--help`, `--version` and `--verbose`; verbose is currently a placeholder, not an additional authority or diagnostic guarantee. The hidden `auth git-credential <get|store|erase>` route is a Git credential-helper interface, not a template action. Avoid sending its output into model context or logs.

## Bounded native context

Published actions are `discover`, `search`, `get`, `plan`, `continue` and `schema`. They share `--project-context`, `--dir`, `--request`, `--catalog-path`, `--id`, `--kind`, `--path`, `--text`, `--required`, `--limit`, `--max-records`, `--max-bytes`, `--max-excerpt-bytes`, `--cursor`, `--snapshot` and `--json`.

The native catalog is read inside the installed signed snapshot, not from caller filesystem JSON. `--request` accepts typed selector/bounds JSON and cannot be mixed with individual selector/bounds flags. The subcommand fixes the action. Continuations bind snapshot, query, scope and bounds. Defaults/ceilings are 8/16 primary entries, 64/256 records including sources, 512/2048 excerpt bytes, and 32768 output bytes. Mandatory required context must fit completely; smaller bounds are not permission to omit it.

Examples below require an already enrolled project context and an actual ID returned by discovery:

```sh
tplaiter trust inspect
tplaiter trust contexts
tplaiter context discover --project-context demo --limit 8 --json
tplaiter context search --project-context demo --text README --json
tplaiter context get --project-context demo --id 'SOURCE_ITEM_ID' --json
tplaiter context continue --project-context demo --cursor 'RETURNED_CURSOR' --json
tplaiter context schema --json
```

`SOURCE_ITEM_ID` and `RETURNED_CURSOR` are placeholders, not valid synthetic authority. `context schema` pulls the full schema on demand. See [exit codes](exit-codes.md) for result/v1 envelopes and refusals; `--json` is available only where command help advertises it.

## Projects and state

For an action-free signed template and a matching installed project target:

```sh
tplaiter new demo:v1 demo --source-input source-selection.json --project-context demo --defaults
tplaiter verify --project-context demo --json
tplaiter check --project-context demo --json
```

The example source input must carry real pinned selection/evidence locators. Native `new` explicitly limits support for hooks, tools, environment, generators, AI resources and managed blocks; visible historical action flags do not make those slices available. Legacy action paths without fixed installed execution evidence can return `TRUST_ACTION_UNAVAILABLE`. Online `verify`/`check` (`--offline=false`) is explicitly unavailable. Do not interpret help presence as a complete beta capability statement.

`migrate-state` first constructs a sealed plan; apply requires the reviewed file and its exact digest. Home/project roots and registry relocations are explicit. It does not automatically rename every historical identifier or migrate credential stores. See [compatibility identifiers](compatibility-identifiers.md).

## MCP

```sh
tplaiter mcp-server --print-config cursor
tplaiter mcp-server
```

An installed authenticated launcher is required for production transport. The server uses stdio JSON-RPC; logs belong on stderr. `--print-config` accepts `claude`, `cursor` or `vscode`. `--direct` remains visible for compatibility; the installed implementation fixes the child environment regardless of that flag. It is not a caller-controlled authority switch. Tools invoke a fixed executable with arguments, not shell interpolation or caller executable selection. The public registry and tools golden contain 30 tools; compiled long help's “~20 tools” is a stale estimate. All existing tools retain their contracts, including `project_link` and ownership/v3 rules. The context tool retains the six native actions above and now exposes `preview-catalog` and `preview-resource` through a separate typed local `preview` request.

Exact retained tool names: `ai_gen`, `context`, `project_link`, `deps_verify`, `doctor`, `env_setup`, `gen`, `gen_batch`, `gen_list`, `init_template`, `lint_template`, `project_check`, `project_diff`, `project_new`, `project_verify`, `projects_list`, `repo_add`, `repo_list`, `repo_remove`, `repo_update`, `run`, `settings_edit`, `settings_list`, `settings_set`, `stats`, `template_list`, `template_show`, `trust_inspect`, `update`, `workspace_add_service`.

## Installed local provider preview

`context preview-catalog` and `context preview-resource` are published at this snapshot, including the existing MCP `context` tool and the separate preview resource URI. They require an operator-selected, prestarted local service and a pinned OSS runtime-install/v2 registration. Qualification is exactly `local-untrusted-observed`; source authentication, publisher authentication and organization admission are `none`.

The real build-time writer now accepts `--local-providers` with `--project-contexts`, forbids rotation, and accepts at most eight closed operator host specs. It generates the installation ID and confined immutable registration pins. No local input preserves v1 semantics. Machine-specific socket/config files stay outside public repositories. To prepare a fresh installation, using your actual reviewed operator files and install root:

```sh
go run ./cmd/tplaiter-oss-register --root /absolute/install/trust --local-providers operator-input.json --project-contexts contexts.json --output registration.pins
```

Use the generated `REGISTRATION_PATH` and `REGISTRATION_SHA256` values as the existing build/install inputs, then run the installed binary's `trust provision`. `make install` does not forward a `TRUST_LOCAL_PROVIDERS` variable; generate the pins explicitly with the helper. Requests cannot substitute an endpoint or launch command. See [installed local preview](local-provider-preview.md) for the exact operator input and installation rules.

Initial transport is Darwin Unix sockets in a physical operator-owned 0700 namespace. The service is started and maintained separately; core never launches it. No-follow namespace checks and kernel UID/PID observations constrain the selected endpoint/account. Code identity remains `unchecked`; same-UID impersonation is not cryptographically excluded. These observations do not authenticate a source, publisher or organization.

Both preview actions expose `--project-context`, `--dir`, `--registration`, `--request` and `--json`. `--registration` cannot be mixed with `--request`. Unlike the native actions, local selection/bounds use the closed JSON request rather than individual `--id`/`--max-bytes` flags. Resource IDs must come from a captured catalog:

```sh
tplaiter context preview-catalog --project-context demo --registration local-demo --json
tplaiter context preview-resource --project-context demo --request '{"registrationID":"local-demo","sourceID":"CAPTURED_SOURCE_ID","assetID":"CAPTURED_ASSET_ID","maxBytes":32768}' --json
```

The names above are placeholders for installed/captured IDs. Request fields are `registrationID`, optional `sourceID`, `assetID`, `required`, `text`, `limit`, `maxRecords`, `maxBytes`, `expectedCatalogSHA256` and `includeCatalogWire`. Catalog mode rejects source/asset selectors. Resource mode reads bodies and mandatory floor content on the same connection. Complete successful CLI/MCP envelopes, selected metadata and mandatory content must fit; missing/overbudget mandatory content refuses without truncation. The maximum complete success is 32768 bytes, with tighter installed/caller ceilings applied. Cancellation closes the bounded session. There is no preview continuation or cross-session producer cursor.

The exact full catalog receipt remains internally captured and pin-validated. Default output includes selected metadata, required records/bodies and `observation.catalogSHA256`/`catalogByteLength`, without duplicating all catalog bytes. Explicit `includeCatalogWire: true` requests diagnostic base64 bytes; the entire diagnostic must fit or refuse. Selected metadata is a declared view, not remarshal proof of raw bytes. Same-connection body receipts preserve binary bytes. Integrity relative to producer-declared pins is separate from authenticity.

For MCP use `action: "preview-catalog"` or `"preview-resource"` and a typed `preview` object; native actions retain `request`, and mixing the branches refuses. The fresh preview resource template is `tplaiter://context-preview/{projectContext}/{registrationID}/{catalogSHA256}/{sourceID}/{assetID}`. Signed native `tplaiter://context/` remains separate. Preview returns `ContextData.localPreview`, not a verified native packet, authenticated snapshot, C03 source evidence or C04 spending allowance.

## Pending and unsupported routes

ROOT B1 provides internal source selection/read-lease APIs and a bindings schema. ROOT B2 CLI/MCP batch selection is not yet exposed at this snapshot. Ordinary dependency enrollment, organization read leases and full C02/E07 organization admission remain separate work. Local preview does not close those tasks or full 9.1. Caller endpoint paths, launch commands, code, credentials or trusted booleans are not supported runtime connection authority. This reference does not certify full beta readiness.
