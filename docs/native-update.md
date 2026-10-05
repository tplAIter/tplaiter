# Signed native Update

This page describes the bounded signed native Update CLI and MCP candidate. It updates one authenticated native project from its registered signed source to a target selected by a closed signed source input. It does not enable the broader Update beta, settings or workspace updates, template actions, or a general recovery workflow.

Use an installed, provisioned binary and a project created from an enrolled signed native template. Follow [installation](install.md) and [source enrollment](source-enrollment.md) first. A plain build without installed-launch registration cannot run this trust-gated command.

## CLI

Plan or apply an update with the installed project context and its exact root:

```sh
tplaiter update \
  --project-context <context-key> \
  --dir /absolute/canonical/project/root \
  --source-input /path/to/target-selection.json \
  --to <target-commit> \
  --json
```

`--project-context` selects an authenticated installed context. `--dir` is a locator and must resolve to that context's registered root; it is not an authority by itself. If `--project-context` is omitted, the installed registration's default context is used. The CLI verifies the selected context and root before planning or writing.

`--source-input` names the closed JSON source selection and its publisher-evidence locators. It is transport for a target selection, not a source authority. Update freshly verifies the signed source closure against the installed evidence and object roots. The current source is read from the registered project's sealed locks. Ambient Git state, local manifests, mutable refs, and network refresh are not used.

When supplied, `--to` must exactly equal the target commit in `--source-input`. Omitting it still uses the commit pinned by that signed selection. A mismatch is refused before any effect.

Use `--dry-run` for a read-only update plan. Use `--check` with `--source-input` to validate and report that target plan without writing. Use `--check` without source input, `--to`, or `--dry-run` to scan the authenticated project for remaining conflict-marker lines. `--all` is currently unavailable.

The apply path prepares and revalidates the plan, acquires the native transaction, then commits the project and registry transition. It uses the native three-way update model: the registered source is the base, the signed selection is the target, and the project's recorded baseline plus current files determine local edits. Additions, deletions, and non-overlapping edits can be published. A conflicting plan is reported as `conflicted` and preserves the project and registry; it does not publish conflict markers.

## MCP

The MCP `update` tool exposes the same bounded operation:

```json
{
  "dir": "/absolute/canonical/project/root",
  "projectContext": "<context-key>",
  "sourceInput": "/path/to/target-selection.json",
  "to": "<target-commit>",
  "dryRun": true,
  "check": false
}
```

`dir` is required. `projectContext`, `sourceInput`, and `to` have the same meanings as their CLI flags. `dryRun` and `check` select the read-only `update.plan` and `update.check` operations; with both false, the tool requests `update.apply`. MCP returns the same structured result envelope as the CLI's `--json` mode.

## Results and recovery

Structured results use `tplaiter.dev/result/v1`. The envelope identifies `update.plan`, `update.check`, or `update.apply`, the authenticated project, current and target refs, a plan digest, changes, diagnostics, and summary counters. A committed apply includes `transactionId`. A plan or check does not write and has no transaction ID. A no-change plan is reported with `status: "ok"`; a published update uses `status: "changes"`; an unpublishable conflict uses `status: "conflicted"`. Registry changes are reported as a diagnostic describing the sealed registry transition rather than as a project file.

If an apply leaves a native transaction that requires cold cleanup, abort it with its authenticated transaction ID:

```sh
tplaiter update abort <transaction-id> \
  --project-context <context-key> \
  --dir /absolute/canonical/project/root \
  --json
```

`abort` reopens only a freshly authenticated native Update receipt with the retained real leases, then rolls back that transaction. It does not use generic `new` recovery. `tplaiter update continue <transaction-id>` is currently typed as unavailable: the native facade does not yet expose the authenticated phase needed to distinguish a preparing transaction from receipt or ownership authentication failures. No cold Continue success is claimed.

## Current limits

The candidate refuses target templates that declare hooks, commands, tools, environment playbooks, or AI configuration. It also refuses `--all`. Actions, settings updates, workspace updates, the full Update beta, inspector inventory, and wider recovery remain pending.

A shared-home probe reproduced an authentication refusal when a second project context attempts native Update after the first project has updated in the same tplaiter home. The isolated-home CLI and MCP path is covered; shared-home multi-project completion remains a library-owner limitation pending its fix. This page does not claim that limitation is resolved.
