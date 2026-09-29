# Exit codes, `--json` and the result/v1 envelope

Every `tplaiter` command exits with a code from one registry, and every
command behind an MCP tool accepts `--json` to print a single
[result/v1](../schema/result.v1.schema.json) envelope on stdout. MCP tools
return the same envelope as structured content. This page is the contract for
scripts, CI jobs and agents.

## Exit-code registry

| Code | Name | Meaning |
|---:|---|---|
| 0 | success | The command did what was asked. |
| 1 | finding | The command ran and found something: conflict markers (`update --check`), lint failures (`lint-template`), a critical tool missing (`doctor`), a diff. |
| 2 | usage | Unknown command or flag, wrong number of arguments. Nothing ran. |
| 3 | operational | The command failed for an ordinary reason (not inside a project, template not found, git failed). The default for an untyped error. |
| 4 | conflict | Conflicts are left for manual resolution (`update`, `settings set`). |
| 5 | trust | Refused by the trust policy (for example `TRUST_ANCHOR_MISSING`, `TRUST_PIN_MISMATCH`, `TRUST_EXPIRED`). |
| 6 | transaction | A lifecycle transaction could not be prepared, committed or recovered. |
| 7 | incompatible | Incompatible version, schema or state. |
| 8 | unavailable | The operation is unavailable in this build or configuration (`TRUST_*_UNAVAILABLE`, `TRUST_*_UNSUPPORTED`, `MCP_UNAVAILABLE`). |
| 9 | internal | An internal contract was violated (a bug). |
| 10 | child | With `--json`: a process run on the user's behalf (a manifest command, a playbook) exited non-zero; `data.childExitCode` has its status. |

Rules:

- Codes 0–2 are stable in meaning across all commands; 3 and above are typed
  failures chosen by the error, never by parsing error text.
- A trust or transport code counts only when an error's whole message is the
  code token (optionally prefixed by its package, such as
  `trustload: TRUST_ANCHOR_MISSING`).
- In text mode `run <command>` and `env setup` propagate the child's own exit
  status unchanged, as `make` does. Use `--json` when the status must be
  unambiguous.
- `update` and `settings set` used to exit 2 for remaining conflicts; they
  now exit 4 (`2` is reserved for usage errors).

## The result/v1 envelope

```json
{
  "apiVersion": "tplaiter.dev/result/v1",
  "kind": "RepoList",
  "operation": "repo.list",
  "status": "ok",
  "project": null,
  "transactionId": null,
  "summary": {"filesChanged": 0, "blocksChanged": 0, "conflicts": 0},
  "changes": [],
  "diagnostics": [],
  "artifacts": [],
  "meta": {"tplaiterVersion": "v0.1.0-preview.1", "schemaVersion": 1},
  "data": {"repositories": [{"alias": "fixture", "type": "git", "templates": 1, "url": "file:///srv/git.example.test/templates.git"}]}
}
```

- `operation` and `kind` come from one registry
  (`internal/resultdto/registry.go`); a consumer can rely on the pair.
- `project` is `null` for global operations (repositories, catalog, trust,
  the project registry). Project operations carry `{id, root}` whenever the
  status is `ok`, `changes` or `conflicted`; `id` is the stable id from
  `.tplaiter/project.yaml`.
- `status` is one of `ok`, `changes`, `conflicted`, `blocked`, `failed`,
  `not-applicable`, and always agrees with the exit code:

  | Exit | Allowed statuses |
  |---|---|
  | 0 | ok, changes, not-applicable |
  | 1 | changes, conflicted, failed, not-applicable |
  | 2 | failed |
  | 3 | failed, blocked |
  | 4 | conflicted |
  | 5–8 | blocked, failed |
  | 9, 10 | failed |

- `diagnostics[].code` is the stable identity of a finding or failure;
  `message` is a fixed, safe sentence. Raw error text, child output, answers
  and credentials never appear in an envelope. When a command fails before it
  can describe the failure, the envelope carries `CLI_USAGE`,
  `TPL-E-PROJECT-NOT-FOUND`, the trust code(s), or `CLI_OPERATION_FAILED`;
  the human-readable error stays on stderr.
- `data` is the operation-specific payload. Its shape is published per MCP
  tool in the tool's `outputSchema`.
- The bytes are canonical: collections are sorted, empty collections are `[]`,
  object keys inside `data` are sorted. The same logical result always has the
  same bytes, which is what CLI↔MCP parity tests compare. Two independent runs
  may differ only in `transactionId`, a temporary `project.root`, and the
  timestamp/duration keys `createdAt`, `updatedAt`, `lastSeenAt`,
  `durationMs` (`resultdto.NormalizeVolatile`).
- Decoders reject unknown major versions, schema versions, operations and
  statuses, duplicate keys and nulls in required fields; they accept unknown
  additive fields.

With `--json`, stdout carries exactly one envelope line. Progress output and
tables are suppressed (the envelope's `data` holds the same information);
warnings and the human-readable error still go to stderr.

## MCP transport codes

The MCP server runs every tool as a separate `tplaiter` child with `--json`.
When the child cannot deliver its own envelope, the server returns one with
`status: "failed"` (or `blocked`) and one of these diagnostic codes:

| Code | When | `details` |
|---|---|---|
| `MCP_TIMEOUT` | The tool's own deadline expired. | `durationMs` |
| `MCP_CANCELLED` | The client sent `notifications/cancelled` for the request (or the server shut down). | `durationMs` |
| `MCP_OUTPUT_LIMIT` | The child wrote more than 1 MiB to stdout or 64 KiB to stderr. | `durationMs` |
| `MCP_UNAVAILABLE` | The child could not be started. | `durationMs` |
| `MCP_INVALID_ARGUMENT` | An argument was rejected before any child started (for example `dir` does not exist). | `argument` |
| `MCP_CONTRACT_INVALID` | The child exited without a valid envelope for the requested operation, or with a status that disagrees with its exit code. | `childExitCode` |

Cancellation and timeouts stop the whole child process group: the group
receives `SIGTERM`, has a grace period (2 s by default) to exit, then receives
`SIGKILL`; any member that survives its leader is killed as well. Grandchild
processes (git helpers, `$SHELL -c` pipelines) therefore never outlive a
stopped call. `durationMs` is measured until the group is gone. The same
graceful stop applies to hooks run by the CLI.
