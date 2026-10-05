# Authenticated native ROOT context

Bounded ROOT B2 is implemented in [`211b17a`](https://github.com/tplAIter/tplaiter/commit/211b17a0d23aba06139cd29fa2150d480121c00f), using the ROOT B1 authenticated selection and read-lease foundation. It delivers a complete task-context projection from one installed signed ROOT source through CLI and MCP. It does not write selected files into a project, execute a skill, grant an action permit, authenticate an organization or establish a trusted model window. Full P09.2, published template-base proof and nonempty dependency enrollment remain open.

## Installed authority and source binding

Use the installed executable with a provisioned trust profile and a registered project context; a development `go build` does not enroll that authority. See [installation and admission](commands.md#installation-and-admission). The context key selects an installed entry; an optional directory is only a locator and must agree with its registered root. Request JSON cannot supply a runtime, publisher, executable, provider endpoint, reader or authority Boolean.

The consumer opens an authenticated read-only session, admits the signed current root and verifies the root/dependency lock pair and installed trust-profile binding. The dependency list must currently be empty. A caller cannot substitute a root identity with an alias or provider ID. Catalog, payload and file reads come from retained verified snapshot objects, with content digests and regular-file modes checked; they do not open a caller's live provider directory.

The default binding is the signed source object `catalog/context-root-bindings.v1.json`. `bindingsPath` may choose another valid snapshot-relative binding path, not an arbitrary filesystem file. Its closed contract is [context-root-bindings.v1.schema.json](../schema/context-root-bindings.v1.schema.json):

```json
{
  "apiVersion": "tplaiter.dev/context-root-bindings/v1",
  "kind": "ContextRootBindings",
  "source": {
    "alias": "base",
    "providerID": "neutral",
    "parameters": [],
    "entriesPath": "catalog/entries.json",
    "payloadDirectory": "catalog/payloads",
    "toolPath": "catalog/tool.md"
  }
}
```

These example names describe source metadata; they confer no permission. The binding must already be included in an admitted signed source. All six source keys are required; unknown or duplicate keys refuse, and source `parameters` must be the empty array. Alias/provider tokens follow the published schema. Paths must satisfy portable snapshot-relative validation and the compiled 256-byte UTF-8 bound; `entriesPath` and `toolPath` must differ. The binding is capped at 64 KiB and requires mode `100644`.

The consumer reads the declared export catalog and tool descriptor, every declared export payload at `<payloadDirectory>/<exportID>.json`, and referenced file blobs. Catalog/payload/individual blob reads are capped at 1 MiB and their aggregate source collection at 16 MiB. Referenced metadata must be regular `100644` files; file images may be `100644` or `100755`. Payloads with managed blocks or structured slots are unavailable on this read-only complete-file route. Source collection is validated before selection, so an invalid unselected declared payload can still refuse.

## CLI request

The compiled public route is `tplaiter context select [flags]`. Flags are `--project-context`, `--dir`, `--request`, `--json`, help and global verbosity. ROOT selection uses its closed JSON request; it does not add individual selector or byte-bound flags.

```sh
tplaiter context select --project-context=project --request='{"selections":[{"apiVersion":"tplaiter.dev/export-selection/v1","selector":"base.skill.review","bindings":[]}],"maxRecords":256,"maxBytes":32768}' --json
```

`project` and `base.skill.review` are illustrative. Use the exact installed context and exports declared by its signed source; this command succeeds only when those entries and the required source objects are admitted. Add `--dir` only for the matching installed root.

`RootSelectionRequest` accepts only these fields:

| Field | Contract |
| --- | --- |
| `selections` | Required array of 1–16 closed export selections. |
| `bindingsPath` | Optional signed snapshot-relative path; defaults to `catalog/context-root-bindings.v1.json`. |
| `maxRecords` | Defaults to 256 when omitted or zero; allowed effective range 1–256. It cannot omit mandatory records. |
| `maxBytes` | Defaults to 32768 when omitted or zero; allowed effective range 1–32768 bytes. Complete success must fit. |
| `snapshot` | Optional expected snapshot returned by an earlier identical selection; mismatch refuses as stale. |

CLI request JSON is limited to 16384 bytes. Unknown keys, duplicate keys, invalid types or selectors, empty/duplicate selections and invalid bounds refuse. Each selection requires exactly `apiVersion`, `selector` and `bindings`; the version is `tplaiter.dev/export-selection/v1`. Selectors identify `alias.domain.name` exports. Binding entries are closed scalar `name`/`value` pairs, sorted by unique name, and must satisfy the selected export's parameter declarations. Explicit `[]` is required when there are none.

## MCP request and typed result

Use the existing read-only `context` tool:

```json
{
  "name": "context",
  "arguments": {
    "action": "select",
    "projectContext": "project",
    "rootSelection": {
      "selections": [
        {"apiVersion": "tplaiter.dev/export-selection/v1", "selector": "base.skill.review", "bindings": []}
      ],
      "maxBytes": 32768
    }
  }
}
```

Optional `dir` has the same installed-root locator meaning. `rootSelection` is required for `select` and is exclusive with `request` and `preview`, even if those other keys contain empty objects. Other actions cannot accept `rootSelection`. The arguments are strictly decoded and capped at 16384 bytes. Use `tplaiter context schema --json` or MCP `context` with `action: "schema"` to obtain the full input/output contract.

Success uses the result/v1 operation `context.query` and `ContextData` with `action: "select"`, `catalogOrigin: "authenticated-installed-native-root"`, `snapshot` and `nativeRootSelection`. The latter is `ContextRootSelectionData`:

- `body` records API version `tplaiter.dev/context-root-selection/v1`, trust profile, snapshot, lock/binding/source-graph/catalog digests, requested selections, resolved export graph, required context packet and complete file images. Qualification is `authenticated-installed-native-root`; materialization scope is `task-context-preview`.
- Each `files` entry has selected/export identity, source and target paths, mode, `contentSHA256` and exact binary `content` represented as JSON base64. Images are sorted by target path. Transitive export requirements and shared dependency chains are resolved into the graph.
- `delivery` records `local-byte-delivery-finished`, envelope/body/response digests, actual envelope bytes, output reservation, local profile and reconciled spending. This is real local byte delivery, not a model call or organization certificate.
- Nested `bytes` measures the serialized selection DTO; outer `ContextData.bytes` measures that data object. The final frontend also measures the complete success frame separately.

Materialization uses a virtual empty preview inventory and returns images without applying them. It does not prove the actual project is empty, establish ownership or authorize subsequent writes.

## Complete floor, frame bounds and held lease

Every projected metadata record and selected file record is mandatory. The floor includes the manifest, contract, binding, entries/tool metadata, selected payloads and selected file records. The existing C03 floor admits at most 32 required IDs; a larger projection refuses. A smaller caller `maxRecords` cannot bypass that floor. File images remain complete even though the required retrieval packet also carries bounded excerpts. There is no ROOT paging, truncation or continuation route.

Local C04 planning counts the actual required packet and complete-image guard, reserves output bytes, performs delivery and reconciles Finish. The same effective `maxBytes` also bounds the complete successful CLI result/v1 frame including its newline. For MCP it additionally bounds the final JSON-RPC reply including request ID, tool-result wrappers and their duplicated representations. An inner DTO fitting is insufficient; wrapper overhead or a large request ID can make the complete response refuse. Refusal frames are diagnostics, not truncated successes or promised successful frames under the same ceiling. These ROOT rules do not change the compact-data bounds of older [native context actions](native-context.md).

The read lease stays held through emission. Immediately before CLI output, the consumer rechecks session state, root/dependency lock digests and observed source. MCP retains the fixed installed child and its selection through final SDK serialization; the final writer verifies exact expected frame bytes, checks its ceiling and asks the still-live child to recheck before writing. The lease closes after completion, cancellation, stale admission or output failure. Cancellation interrupts blocked output and cleans up the child; a partial failed write does not append another success/result frame. Internal delivery correlation is managed by the server and is not a public authority input.

The snapshot digest binds installed project/profile, root/dependency locks, binding, source graph, catalog and selection graph. Reusing a snapshot with changed inputs refuses; it is not a cursor, continuing lease or authorization token. Read-only leases and byte evidence do not certify future state.

Malformed input is typed invalid; unavailable or missing source/floor, stale bindings and complete-budget overflow refuse without a successful `nativeRootSelection`. ROOT frontend codes include `CONTEXT_FRONTEND_INVALID`, `CONTEXT_FRONTEND_MISSING`, `CONTEXT_FRONTEND_STALE`, `CONTEXT_FRONTEND_BUDGET` and `CONTEXT_PROVIDER_UNAVAILABLE`; underlying admission/transport failures retain their own diagnostics. Model `windowState` remains `unknown` with no trusted token capacity.

This bounded route does not complete published template-base proof, nonempty dependencies, organization read leases/admission, full C02/E07, whole P09.2 or beta readiness. [Local provider preview](local-provider-preview.md) remains explicitly untrusted and separate.
