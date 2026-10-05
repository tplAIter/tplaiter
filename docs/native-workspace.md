# Native workspace services

Commit `9ed7906` implements bounded signed Go service creation in an existing authenticated workspace, registration in `go.work` and the project registry, CLI/MCP dry-run, and cold CLI Continue/Abort. Full U07 flag coverage, aggregate workspace operations, workspace-wide generation, and generic Inspector certification remain unresolved.

Use an installed, provisioned binary with an enrolled signed workspace source and an independently signed service source. See [installation](install.md) and [source enrollment](source-enrollment.md). The existing workspace must retain its authenticated project state and registered source selection.

## Select the workspace and service

`--project-context` selects a finite installed workspace key; omitting it uses the installation default. `--dir` locates that workspace's exact recorded root. Required `--service-context` selects a distinct installed service key linked to that workspace at exactly `services/<slug>` under the same installation authority. These controls do not enroll a context or authorize an arbitrary child path.

Required `--source-input` is a path to the service's closed native source-selection JSON. It binds the exact commit, tree and contract digests and signed evidence references; the requested ref must equal the commit and dependencies must be empty. The selection is untrusted transport until authenticated. The signed templates must declare `type=workspace` and `type=service`, respectively; the rendered service must contain the requested Go module.

For installed keys `workspace` and `billing`, with `billing` bound to `/absolute/workspace/services/billing`:

```sh
tplaiter workspace add-service billing \
  --project-context workspace --service-context billing \
  --dir /absolute/workspace --source-input /absolute/service-source.json \
  --defaults --dry-run --json
```

Remove `--dry-run` to create the service and register it through the native transaction. `--module` defaults to `<workspace module>/services/<slug>`; `--set group=value`, `--defaults` and `--port` supply bounded service settings. When declared by the template, `workflow=true` is forced. Successful JSON uses the `workspace.add-service` result envelope; an applied operation reports its transaction ID after commit.

The MCP tool `workspace_add_service` requires `dir`, `name`, `serviceContext` and `sourceInput`; `projectContext` is optional and `dryRun` requests authentication and reporting without changes. Its child CLI receives the explicit workspace locator and context keys.

## Recover and retain the limits

Cold CLI recovery requires the original transaction ID and both installed contexts:

```sh
tplaiter workspace continue <transaction-id> \
  --project-context workspace --service-context billing \
  --dir /absolute/workspace --json

tplaiter workspace abort <transaction-id> \
  --project-context workspace --service-context billing \
  --dir /absolute/workspace --json
```

Recovery reauthenticates retained material and current ownership. A historical terminal repeat with a replaced service inode safely refuses, even when bytes match; a receipt alone does not establish present ownership. Preserve conflicting objects and transaction evidence rather than replacing files to force recovery. MCP exposes service creation and dry-run; these recovery commands are CLI operations.

Answers files and environment execution are unsupported. Declared tools, playbooks, hooks, commands and AI configuration refuse on this native creation route; skip flags do not authorize them. This bounded operation does not certify generic Inspector use, all workspace flags, aggregate operations or workspace-wide generation.
