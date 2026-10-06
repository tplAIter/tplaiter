# Initial source enrollment for source builds

The default build remains unconfigured for real template sources. Initial signed
external packages are supported with `TRUST_PUBLISHERS`, `TRUST_SOURCE_PACKAGES`,
and `TRUST_PROJECT_CONTEXTS`. A package does not authorize its own key: the
operator must separately approve its public publisher key and exact scope.

An explicit offline local route is available for **one** operator-approved source:

```sh
make install TRUST_ROOT=/absolute/existing-parent/absent-install \
  TRUST_LOCAL_SOURCES=/absolute/local-sources.json \
  TRUST_PROJECT_CONTEXTS=/absolute/project-contexts.json PREFIX=/absolute/prefix
```

`local-sources.json` is a closed public JSON array, containing exactly one object:

```json
[
  {
    "repositoryPath": "/absolute/local-repository",
    "origin": "https://github.com/tplAIter/template-go",
    "templatePath": ".",
    "commit": "d0179547cd2e47b7564b0011bc5045799fc036bd"
  }
]
```

`origin` is the operator's approved identity for these bytes. Capture makes no
claim about remote fetching, upstream signature, authorship or ownership.
The local repository path is a locator and is omitted from public provenance.
The exact immutable commit is required; checkout edits, tags and branches are
never source bytes. This Go example supports installation and native project
creation with its six
validated inert generator snippets. Creation seals their exact verified bytes,
source provenance and ownership together with the project. Generator execution,
commands, environment setup, hooks and later lifecycle actions remain outside
this acceptance path. The default generated Go project uses only the standard
library and can be built and tested with `GOPROXY=off`.

`project-contexts.json` is a finite array of existing `ProjectContext` values:

```json
[
  {
    "key": "go-smoke",
    "projectID": "operator-approved-project-id",
    "submitterPrincipalID": "principal:operator",
    "minimumProfile": "oss",
    "rootPath": "/absolute/existing-parent/absent-project"
  }
]
```

Contexts must have unique identities and nonoverlapping canonical roots outside
the trust installation. Each root is an existing directory or one absent leaf
beneath an existing parent. Every parent component must be a real directory.
Source metadata cannot choose project identity, principal, profile or root.

Existing `REGISTRATION_PATH`/`REGISTRATION_SHA256` linker pins select a separate
install route. Make rejects combining either pin with explicit local sources,
external packages, publisher keys, project contexts or rotation before any
build/install recipe, including under `make -n`.

Local mode forbids `TRUST_PUBLISHERS`, `TRUST_SOURCE_PACKAGES` and rotation. Its
installation destination must be absent, including an existing empty directory.
It captures and validates the entire selected closure, native contract and
canonical publisher-statement subject/scope before
creating a process-local ephemeral Ed25519 source key, distinct from the bootstrap
anchor. The truthful issuer is `local-operator-<public-fingerprint-hex>`. Signing
uses the decoded 32-byte publisher-statement domain digest. Private keys are never
serialized or retained, and buffers are erased on success/error paths on a best
effort basis. There is no credential/profile input or installed signing tool.

The ordinary signed package then goes through the same importer, source verifier,
common transparency checkpoint, per-artifact inclusion proofs and enrollment
receipt as external packages. `config/local-publisher.json` records only public
operator attestation. Its raw digest participates in the enrollment contract
pinned by the registration. `config/source-selections.json` remains a public
untrusted locator list: runtime consumers must authenticate/reverify selections.

## Offline capture limits

Supported sources are SHA-1 repository-format-0 ordinary repositories with real
`.git` directories or explicitly supplied bare roots. Linked worktrees, gitdir or
commondir files, symlinked paths, shallow/graft/replace layouts, includes/extensions,
worktree declarations, alternates and promisor/partial-clone layouts are refused.
Git never runs against the original repository. Capture copies only confined
regular objects into an owned temporary bare snapshot with generated minimal
config/HEAD; no source config, refs, hooks, includes or alternate routes are copied.
The fixed streaming Git process is owned by a capture-specific `execx` helper.
It inherits no environment, buffers no command output and cannot fetch objects.
The frame reader retains its limits before allocation; cleanup kills and waits
for the owned child on every path.

There are at most 32 pack/index pairs, each container at most 128 MiB, at most
8192 loose files and at most 256 MiB copied bytes. Matching bounded regular `.rev`
reverse-index files and `objects/info/packs` metadata are ignored, never copied or
used; other auxiliary layouts are refused. Large local repositories can therefore
fail even for a small selection; capture never fetches or expands these limits.
Object response headers are at most 128 bytes. Commit/tree payloads are at most
1 MiB, blobs 16 MiB, the contract 1 MiB, and raw captured frames total at most
64 MiB. Limits precede payload allocation. Every exact raw object is rehashed.
Traversal reads only the commit, required ancestor trees and selected descendants,
never parent commits or sibling subtrees. Computed capture identity is a distinct
non-capability result; ordinary verification still requires both expected digests.

## Publication and cancellation

`GenerateWithContext` checks cancellation throughout capture, validation, entropy,
evidence and staging. `Generate` remains a background-context wrapper. The register
process handles interrupt/termination signals and emits linker pins only after
verified publication. Precommit failures clean owned staging; foreign destination
entries, including a racing empty directory, remain untouched.

The commit boundary is the native exclusive no-replace rename. Cancellation after
that point preserves the published installation and completes parent sync and
reauthentication with an independent finalization context. A successful finalization
returns the committed result despite cancellation. Sync/load failure returns
`ErrPublicationCommitted` and `PublicationState=committed-unconfirmed`, retaining the
installation. Pin-output failures also report committed status. Verify that exact
installation before linking; do not retry local generation with new keys or rotate.
An existing external installation can still be reused only with its exact accepted
enrollment contract and retained objects/evidence. Post-install refresh requires a
separate eligible signer and append-only authority transition.

## Installed Go acceptance smoke

The focused black-box test uses a fresh temporary prefix/trust root and isolated
HOME/XDG/state. It invokes real `make install`, then `trust provision`, CLI `new`
and MCP `project_new` for finite A/B contexts with absent custom target roots.
The removable public source copy is deleted after capture, before either create.
A read-only observer checks stable state and registry against the installed
registration; it supplies no private keys or runtime authority. Exact snippet
bytes, resource provenance, ownership and empty generator-target records are
checked before offline `go build ./...` and `go test ./...`. Replay and invalid
context/source calls must refuse without changing accepted state.

```sh
GOWORK=off go test -C tests -run '^TestStockInstalledPublicGo$' -count=1 -v
```

By default the source repository is reconstructed from the pinned public raw
Git objects already checked into the integration fixtures. To exercise an actual
local public checkout, set `TPLAITER_STOCK_GO_SOURCE=/absolute/public/repository`;
the test captures a disposable copy and leaves the supplied tree untouched.
`TPLAITER_STOCK_GO_ARTIFACTS=/absolute/absent-directory` retains install and
creation evidence for review. This smoke accepts only default stdlib Go creation
and inert resource retention; it does not establish beta completion or live
generator/action support.

## Generic inert content bundles

The build-time registrar additionally accepts `--local-source-bundle` with a
closed JSON array of 2–16 existing capture inputs, bounded to 64 KiB. Exactly one
captured source must be an existing native template and the other 1–15 must be
inert content indexes. Source identity is the canonical `origin`/`templatePath`
pair; duplicate identities refuse even for different commits. Repository paths
and commits are operator selections, never installed request fields. There is
no caller-supplied kind, capability, signing key, reader or launch command.

An inert contract uses existing `tplaiter.dev/export-payload/v1` and its existing
valid export-ID syntax. It has empty `slots` and `blocks`, and an explicitly
ordered complete regular-file index. Each `sourcePath` equals `targetPath` and
matches the captured file's exact mode and body SHA-256. Only the contract's own
leaf is excluded from that index; LICENSE, README and every other selected file
must be covered. Extra, missing, reordered or mismatched records refuse. This
contract describes source repository geometry, not generated application layout.
It does not declare a root, native context dependency, tool or executable action.

Capture, full immutable verification, type derivation, index validation and
canonical statement/scope validation finish for **all** subjects before any
signing-key entropy. The fixed aggregate selected-object limit remains 64 MiB.
The installation root must be absent; explicit operator project contexts are
required, and other source modes, external publisher/package inputs and rotation
are forbidden. Cancellation, confinement and publication rules are unchanged.

```sh
go run ./cmd/tplaiter-oss-register \
  --root /absolute/existing-parent/absent-install \
  --local-source-bundle /absolute/source-bundle.json \
  --project-contexts /absolute/project-contexts.json
```

The ordinary `--transaction --destination /absolute/bin/tplaiter` route can build
and publish an executable with the resulting immutable registration linker pins.
There is no new Makefile variable or installed CLI input for this bundle.
The array contains existing capture records, including actual immutable committed
source pins; do not substitute report hashes or invent unpublished commits.

A distinct ephemeral key signs each source; a separate anchor signs the normal
installation. `config/local-publisher.json` is an array of existing public
local-publication records for bundle mode, digest-bound to enrollment. The old
one-source record remains an object. Its `local-operator` provenance makes no
upstream authorship or organization claim. Both signatures and full object
closures pass the normal importer and transparency binding. Generic source
selections retain actual statement CAS/signature/checkpoint/inclusion evidence;
capture or content digests are not substitutes for statement CAS.

Inert sources are explicitly excluded from native context bindings, dependency
associations and root/generator preparation. They remain readable through the
existing authenticated runtime and `deps.SourceReader`; native preparation must
still refuse them. No modifier conversion/reversal or Bun action is granted by
this route. Published React plus independently committed modifier content is the
first intended real two-source acceptance, pending its actual content publication
and normal registration receipts. Synthetic producer tests alone do not prove
that installation or complete P12/P13 delivery.

The existing `--local-sources` mode remains native-only and exactly one source.
Zero-input installation semantics and formats remain unchanged.
