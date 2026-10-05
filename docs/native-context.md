# Native context CLI and MCP

The accepted frontend reads resource/path context derived from the installed signed root source. It verifies the installed runtime and source snapshot; arbitrary filesystem catalogs, caller readers and caller model-capacity claims are refused. Full C05 remains open for external C02 consumer compatibility, signed catalog selection/routing, broader native mapping and trusted model-window instrumentation.

Use an installed project-context key. An optional `--dir` must match its registered root:

```sh
tplaiter context discover --project-context=project --limit=1 --max-bytes=32768 --json
tplaiter context search --project-context=project --kind=resource --text=note --json
tplaiter context get --project-context=project --id='<entry.id>' --snapshot='<data.snapshot>' --json
tplaiter context continue --project-context=project --cursor='<data.nextCursor>' --json
tplaiter context plan --project-context=project --limit=1 --json
tplaiter context schema --json
```

Use returned IDs, snapshot and cursor values literally. A continuation is bound to its original scope, query, bounds, required floor and snapshot; replacement selectors or bounds refuse. Resource reads use the exact `entry.resourceUri` returned by discovery.

MCP exposes one read-only `context` tool. For example:

```json
{"name":"context","arguments":{"action":"discover","projectContext":"project","request":{"limit":1,"maxBytes":32768}}}
```

Actions are `discover`, `search`, `get`, `continue`, `plan` and `schema`. The compact descriptor does not repeat the full contract; request `action: "schema"` on demand.

`maxBytes` bounds compact ContextData JSON and the local retrieval wire/output obligations. Its default and maximum are 32768 bytes. It does not bound the outer CLI result/v1, MCP summary/tool result, JSON-RPC reply, global tool catalog or caller model history/system envelope. Those wrappers require separate budgeting. In one independently measured signed fixture, compact data was 14437 bytes, CLI stdout 14849 bytes and the full JSON-RPC reply 15045 bytes; these are fixture-specific sizes, not fixed allowances.

Local byte retrieval uses real C04 reservations, delivery and successful Finish reconciliation. `plan` retains that byte plan but returns blocked `CONTEXT_WINDOW_UNKNOWN`: a trusted model/tokenizer window is unavailable, counted tokens remain zero, and no 256k capacity is asserted. An installed nonempty external dependency closure currently refuses `CONTEXT_PROVIDER_UNAVAILABLE`; private C02 compatibility is unverified.
