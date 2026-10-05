# Compatibility identifiers

Inventory baseline: public `3ccb11b2a3ac9a6033f45bc940333436a2587f28`. Product naming is `tplaiter`; the Go module is `github.com/tplAIter/tplaiter`. Historical strings below are retained deliberately or remain implementation cleanup work. Do not replace them mechanically: changing bytes can change parser behavior, signatures, pins, paths, database compatibility or test oracles. This document changes no reader, writer or fixture.

## Paths, environment and storage

| Exact identifier | Classification and rule |
| --- | --- |
| `TPLAITER_HOME`, `TPLATER_HOME` | Current home selector and compatibility alias. Distinct nonempty cleaned values refuse; otherwise the selected nonempty value wins. Default is `~/.tplaiter`. No silent merge from `~/.tplater`. |
| `TPLAITER_SELF_REPO`, `TPLATER_SELF_REPO` | Current self-repository selector and retained compatibility alias; preserve identity-resolution rules. |
| `.tplaiter`, `.tplater` | Current state namespace and explicit legacy discovery/migration namespace. Both remain reserved against source payload/materialization traversal. |
| `config.yaml`, `index.yaml`, `projects.yaml`, `state.yaml`, `.lock`, `repos/` | Local home-state names; naming changes require explicit migration, not search/replace. |
| `.tplaiter/project.yaml`, `.tplater/project.yaml` | Current project marker and legacy marker discovery. Legacy presence is not native authenticated enrollment. |
| `.tplaiter/root-template.lock.json`, `.tplaiter/template.lock.json`, `.tplaiter/baseline.json`, `.tplaiter/ownership.json`, `.tplaiter/resources.lock.json`, `.tplaiter/ai-managed.json`, `.tplaiter/generator-targets.lock.json`, `.tplaiter/managed-blocks.json`, `.tplaiter/migrations.json` | Sealed project-state path identities in project/v2; ownership/v3 semantics are independent of product spelling. |
| `tplater.db` | Retained authentication database basename under the selected home. Tables `schema_version` and `credentials` remain storage contracts. Never inspect or export credential content for migration proof. |
| `bootstrap.sqlite` | Installed trust-store basename; `installation`, `blobs`, `accepted`, `transitions` are persistence tables, not public request authority. SQLite journal/WAL/SHM companions are confined store files. |
| `auth.json`, `credentials.json`, `credentials.db` | Explicit credential-file exclusions in the naming migration. Their mention is not permission to copy or convert content. |
| `.tplaiter-migration-sealed`, `.tplaiter-naming-migration-<digest-prefix>.json`, `.tplaiter-migration-*`, `.<name>.tplaiter-legacy-<digest-prefix>`, `.<name>.tplaiter-naming.lock` | Migration sentinel, journal, staging, archive and lock identities. Successful supported migration seals legacy writes; arbitrary old binaries/manual edits are outside that guarantee. |
| `catalog/context-root-bindings.v1.json` | Default ROOT B1 bindings path; does not imply a published B2 frontend. |

Environment variables used only by subprocess tests (for example `TPLAITER_ENROLL_CRASH_CHILD`, `TPLAITER_ENROLL_CRASH_PAYLOAD`, `TPLAITER_NS004_HOT_ROOT`, `TPLAITER_NS004_HOT_READY`, `TPLAITER_MARKER_FD_REUSE_CHILD`, `TPLAITER_MARKER_CLOSE_TERMINAL_CHILD`) are test coordination, not installed authority inputs. Proxy variables affect networking; registration linker pins fix installation selection. Neither grants source authentication.

## Retained grammar and production residuals

| Literal | Classification |
| --- | --- |
| `tplater.dev/v1alpha1` | Template manifest API group/version and historical Project marker; migration validates the expected legacy Project kind. Preserve API values independently of UI branding. |
| `requires.tplaiter`, `requires.tplater` | Current requirement key and compatibility key. Conflicting values refuse. |
| `tplater:if`, `tplater:if!`, `tplater:begin`, `tplater:end` | In-file conditional grammar parsed after rendering; unknown/unmatched markers refuse. These are template syntax, not branding prose. |
| `tplater:managed-begin`, `tplater:managed-end` | Managed-block wire grammar. Begin requires `id=<id> provider=<provider>`; end requires `id=<id>`. ID is `[A-Za-z][A-Za-z0-9._-]{0,127}`; provider is `[A-Za-z][A-Za-z0-9._/-]{0,127}`. Preserve marker bytes and baseline digests. Native action-free images reject unsupported managed markers. |
| `tplater.dev/block-export/v1`, `tplater.dev/managed-block/v1` | Retained block export/marker versions; not renamed by a CLI rename. |
| `compatibility.tplater` | Exact block-export YAML/JSON field, read alongside `compatibility.markerSchema` and retained when serialized. Validation requires a nonblank string and the exact marker schema; the spelling is not an executable instruction or proof of source authority. Preserve the field name and pinned document bytes. |
| `// tplater:gen:example` | Literal insertion anchor in the shipped example generator manifest. The generator matches the configured anchor in its target file and prepares insertion before it; it is template content, distinct from conditional marker grammar. Preserve matching manifest/target anchor bytes when evolving an existing template. |
| `tplater.dev/root-template-lock/v1`, `tplater.dev/template-lock/v1`, `tplater.dev/update-plan/v1` | Explicit profileless legacy detection/refusal inputs in provenance. They do not upgrade themselves to current authenticated native state. |
| `tplater-8356cc1d9c066af0253bff9d3f50fc28c51863d0` | Exact supported legacy writer floor in naming plan validation. Historical identifier, not the current source pin. |
| `tplater_project_root` | Existing Ansible extra-variable interface. Rename requires coordinated template interface migration. |
| `tplater/upgrade-<slug>-<timestamp>`, `tplater-upgrade-<timestamp>`, `TPLATER-REVIEW: file belongs to a conditional vertical` | Existing contribution branch, patch directory and manual-review marker formats. Production naming residuals, not removed by this docs leaf. |
| `tplater-extravars-*.json`, `tplater-lint-*`, `tplater-checkout-<alias>-*`, `tplater-render-*` | Temporary file/directory prefixes retained in production implementation. `renderref.Render` creates `tplater-render-*` with `os.MkdirTemp`, renders into it, reads result bytes and defers directory removal; the prefix is not a CLI name or serialized source authority. These non-wire cleanup candidates remain unchanged. |

Trustload tokens are nonempty valid UTF-8 excluding exactly NUL, CR, LF, TAB, ASCII space, `/` and `\`. Form feed, vertical tab and non-ASCII whitespace are not globally forbidden. Operator writer project-key constraints are a separate narrower contract; never narrow global admission merely to match JSON Schema `\s`. JSON Schema `maxLength` counts Unicode code points; Go byte limits count UTF-8 bytes. Where bounded registration/request contracts impose byte limits, schema character limits alone cannot prove admission parity.

## Provider wire and integrity

`local-provider.session/v1` is the actual neutral NDJSON protocol; `local-provider.descriptor/v1` is its descriptor version. Requests carry `version` and `op`, with operation-specific `id`, `schemaVersions`, `requiredOperations`, `requiredCapabilities`, `sourceId`, `assetId`, `pin`, `path`, `projection`, `deadlineMs` and `budget`. Knowledge pagination uses `page:N:<cursor>` projections. A renamed alternative session protocol is not compatible.

Public provider fixtures live in `internal/providerclient/testdata/wire/{session-v1.schema.json,pinned-descriptor-v1.schema.json}` and `internal/providerclient/testdata/synthetic/{session-v1.schema.json,knowledge.v1.schema.json,manifest.json,full-catalog.json,receipt.ndjson,expected-digests.json}`. They are synthetic; preserving them preserves exact frame, alias, pin and digest expectations. Exact reconstructed catalog wire bytes and same-connection read receipts establish content integrity, not organization authentication. Caller JSON and schema acceptance cannot mint capabilities.

Installed local registration IDs and referenced project keys are limited to 64 UTF-8 bytes. The new registration and runtime-v2 schemas preserve the explicit token exclusions above, including refusal of trailing forbidden line breaks; global project-context keys do not gain that 64-byte cap. Schema character bounds do not replace byte admission. Runtime-v2 local registrations select only installed endpoints; they do not upgrade observed local content to authenticated source claims. The separate resource URI is `tplaiter://context-preview/{projectContext}/{registrationID}/{catalogSHA256}/{sourceID}/{assetID}`; signed native `tplaiter://context/` is unchanged.

## Published schema names and IDs

These exact filenames and `$id` values were read from `schema/*.json`. An ID is a serialized compatibility name; it need not resolve over the network. Versioned schema changes require explicit migration/version policy. Schemas without `$id` still retain their filenames as tooling interfaces. This snapshot adds only three published schema files to the earlier 33-file inventory (36 total); their `apiVersion` constants are `tplaiter.dev/context-local-preview/v1`, `tplaiter.dev/local-provider-registration/v1` and `tplaiter.dev/runtime-install/v2`.

| File under `schema/` | `$id` |
| --- | --- |
| `block-export.v1.schema.json` | `https://tplater.dev/schema/block-export.v1.schema.json` |
| `bootstrap-descriptor.v1.schema.json` | `tplaiter.dev/bootstrap-descriptor/v1` |
| `bootstrap-provisioning.v1.schema.json` | `tplaiter.dev/bootstrap-provisioning/v1` |
| `context-root-bindings.v1.schema.json` | `https://tplaiter.dev/schema/context-root-bindings.v1.schema.json` |
| `execution-approval.v1.schema.json` | `https://tplaiter.dev/schema/execution-approval.v1.schema.json` |
| `execution-policy.v1.schema.json` | `https://tplaiter.dev/schema/execution-policy.v1.schema.json` |
| `execution-request.v1.schema.json` | `(no $id)` |
| `export-payload.v1.schema.json` | `https://tplaiter.dev/schema/export-payload.v1.schema.json` |
| `formatter-plan.v1.schema.json` | `https://tplaiter.dev/schema/formatter-plan.v1.schema.json` |
| `knowledge.v1.schema.json` | `https://tplaiter.dev/schema/knowledge.v1.schema.json` |
| `modifier.v1.schema.json` | `https://tplaiter.dev/schema/modifier.v1.schema.json` |
| `naming-migration-plan.v1.schema.json` | `tplaiter.dev/naming-migration-plan/v1` |
| `naming-migration-receipt.v1.schema.json` | `tplaiter.dev/naming-migration-receipt/v1` |
| `native-template-contract.v1.schema.json` | `(no $id)` |
| `oss-accepted-state.v1.schema.json` | `tplaiter.dev/oss-accepted-state/v1` |
| `ownership.v1.schema.json` | `tplaiter.dev/ownership/v1` |
| `public-trust-metadata.v1.schema.json` | `tplaiter.dev/public-trust-metadata/v1` |
| `publisher-statement.v1.schema.json` | `tplaiter.dev/publisher-statement/v1` |
| `repository.manifest.schema.json` | `https://tplater.dev/schema/repository.manifest.schema.json` |
| `result.v1.schema.json` | `https://tplaiter.dev/schema/result.v1.schema.json` |
| `root-template-lock.v2.schema.json` | `tplaiter.dev/root-template-lock/v2` |
| `state-ledger-migration-plan.v1.schema.json` | `tplaiter.dev/state-migration-plan/v1` |
| `state-ledger-migrations.v1.schema.json` | `tplaiter.dev/migrations/v1` |
| `state-ledger-new-lock.v1.schema.json` | `tplaiter.dev/new-lock/v1` |
| `state-ledger-new-transaction.v1.schema.json` | `tplaiter.dev/new-transaction/v1` |
| `state-ledger-project.v2.schema.json` | `tplaiter.dev/project/v2` |
| `state-ledger-report.v1.schema.json` | `tplaiter.dev/state-ledger-report/v1` |
| `template-lock.v2.schema.json` | `tplaiter.dev/template-lock/v2` |
| `template.manifest.schema.json` | `https://tplater.dev/schema/template.manifest.schema.json` |
| `trust-profile-binding.v1.schema.json` | `tplaiter.dev/trust-profile-binding/v1` |
| `typescript-comments.v1.schema.json` | `https://tplaiter.dev/schema/typescript-comments.v1.schema.json` |
| `typescript-provider.v1.schema.json` | `https://tplaiter.dev/schema/typescript-provider.v1.schema.json` |
| `update-plan.v2.schema.json` | `tplaiter.dev/update-plan/v2` |
| `context-local-preview.v1.schema.json` | `tplaiter.dev/context-local-preview/v1` |
| `local-provider-registration.v1.schema.json` | `tplaiter.dev/local-provider-registration/v1` |
| `runtime-install.v2.schema.json` | `tplaiter.dev/runtime-install/v2` |

Production API literals also retained in code (including contracts without a standalone top-level schema):

- `local-provider.descriptor/v1`
- `local-provider.session/v1`
- `tplaiter.dev/authority/v1`
- `tplaiter.dev/bootstrap-descriptor/v1`
- `tplaiter.dev/bootstrap-effective-config/v1`
- `tplaiter.dev/bootstrap-provisioning/v1`
- `tplaiter.dev/bootstrap-store-marker/v1`
- `tplaiter.dev/composition-graph/v1`
- `tplaiter.dev/composition-input/v1`
- `tplaiter.dev/context-cursor/v1`
- `tplaiter.dev/context-index-result/v1`
- `tplaiter.dev/context-pack/v1`
- `tplaiter.dev/context-root-bindings/v1`
- `tplaiter.dev/context-root-selection/v1`
- `tplaiter.dev/development-authority/v1`
- `tplaiter.dev/development-update-plan/v1`
- `tplaiter.dev/execution-approval/v1`
- `tplaiter.dev/execution-content/v1`
- `tplaiter.dev/execution-environment/v1`
- `tplaiter.dev/execution-policy/v1`
- `tplaiter.dev/execution-request/v1`
- `tplaiter.dev/export-catalog/v1`
- `tplaiter.dev/export-graph/v1`
- `tplaiter.dev/export-payload/v1`
- `tplaiter.dev/export-selection/v1`
- `tplaiter.dev/formatter-plan/v1`
- `tplaiter.dev/formatter-tool/v1`
- `tplaiter.dev/go-module-closure/v1`
- `tplaiter.dev/go-toolchain-index/v1`
- `tplaiter.dev/graph/v2`
- `tplaiter.dev/initial-enrollment-contract/v1`
- `tplaiter.dev/initial-source-package/v1`
- `tplaiter.dev/installed-launch-registration/v1`
- `tplaiter.dev/knowledge-inputs/v1`
- `tplaiter.dev/knowledge/v1`
- `tplaiter.dev/local-operator-source-publication/v1`
- `tplaiter.dev/modifier/v1`
- `tplaiter.dev/naming-migration-plan/v1`
- `tplaiter.dev/naming-migration-receipt/v1`
- `tplaiter.dev/naming-source/v1`
- `tplaiter.dev/native-adoption-decision/v1`
- `tplaiter.dev/native-link-plan/v1`
- `tplaiter.dev/native-template-contract/v1`
- `tplaiter.dev/native-update-material/v1`
- `tplaiter.dev/native-update-material/v2`
- `tplaiter.dev/native-update-plan/v1`
- `tplaiter.dev/native-workspace-plan/v1`
- `tplaiter.dev/new-lock/v1`
- `tplaiter.dev/new-transaction/`
- `tplaiter.dev/new-transaction/commit/v1`
- `tplaiter.dev/new-transaction/v1`
- `tplaiter.dev/operation-inputs/v1`
- `tplaiter.dev/operator-pin-record/v1`
- `tplaiter.dev/oss-accepted-state/v1`
- `tplaiter.dev/pinned-source/v1`
- `tplaiter.dev/portable/v1`
- `tplaiter.dev/prerun-class`
- `tplaiter.dev/prerun-class-no-args`
- `tplaiter.dev/project-build-action/v1`
- `tplaiter.dev/project-build-action/v2`
- `tplaiter.dev/project-build-action/v3`
- `tplaiter.dev/project-build-selection/v1`
- `tplaiter.dev/project-check/v1`
- `tplaiter.dev/project-transaction/`
- `tplaiter.dev/project-transaction/v1`
- `tplaiter.dev/project/v2`
- `tplaiter.dev/publisher-scope-set/v1`
- `tplaiter.dev/publisher-statement/v1`
- `tplaiter.dev/result-operation`
- `tplaiter.dev/result/v1`
- `tplaiter.dev/root-template-lock/v2`
- `tplaiter.dev/runtime-effective-config/v1`
- `tplaiter.dev/runtime-install/v1`
- `tplaiter.dev/runtime-policy/v1`
- `tplaiter.dev/scoped-authority/v1`
- `tplaiter.dev/source-content-tree/v1`
- `tplaiter.dev/source-contract/v1`
- `tplaiter.dev/source-selection-input/v1`
- `tplaiter.dev/state-ledger-report/v1`
- `tplaiter.dev/state-migration-plan/v1`
- `tplaiter.dev/stored-bootstrap-bundle/v1`
- `tplaiter.dev/template-lock/v2`
- `tplaiter.dev/tool-options/v1`
- `tplaiter.dev/transparency-checkpoint/v1`
- `tplaiter.dev/transparency-consistency/v1`
- `tplaiter.dev/transparency-inclusion/v1`
- `tplaiter.dev/trust-profile-binding/v1`
- `tplaiter.dev/trust-receipt/v1`
- `tplaiter.dev/trust-roots/v1`
- `tplaiter.dev/typescript-comments/v1`
- `tplaiter.dev/typescript-provider/v1`
- `tplaiter.dev/update-plan/v2`
- `tplaiter.dev/usage-args`
- `tplater.dev/block-export/v1`
- `tplater.dev/managed-block/v1`
- `tplater.dev/root-template-lock/v1`
- `tplater.dev/template-lock/v1`
- `tplater.dev/update-plan/v1`
- `tplater.dev/v1alpha1`

- `tplaiter.dev/context-local-preview/v1`

- `tplaiter.dev/initial-enrollment-contract/v2`

- `tplaiter.dev/local-provider-registration/v1`

- `tplaiter.dev/runtime-install/v2`

## Fixtures and scope of completion

`tests/testdata/mcp/tools.schema.golden.json` fixes the 30-tool descriptor surface. Preserve the other 29 raw descriptors when changing context, including `project_link`; project ownership/v3 receipts must keep their field/version semantics. Historical fixture spellings and negative legacy samples are test inputs, not current supported commands. `internal/testfixture` supplies public synthetic signed-runtime material; it is not a production authority producer.

This inventory separates current product/module names, retained wire and filesystem/storage contracts, explicit legacy recognition, synthetic fixture history, and production cleanup residuals. It does not certify full beta readiness, ROOT B2 frontend delivery or C02/E07 organization admission. Installed local preview is now available with qualification `local-untrusted-observed`; it is not authenticated external-provider admission. See [commands](commands.md) for the current/pending route boundary. No private producer source, invocation records, assets or organization identifiers are part of this reference.
