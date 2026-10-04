# Installing tplaiter from source

tplaiter refuses every trust-gated command (`new`, `update`, `trust *`, `mcp-server`) unless the binary was linked against an **installed-launch registration**. A plain `go build` or `make build` produces a *stock* binary without one, which answers `TRUST_ANCHOR_MISSING`. The design is recorded in [ADR-005](./adr/ADR-005-oss-install-registration.md).

This page covers the OSS profile built from source. There is no published release yet, and release archives are out of scope until the release-distribution registration exists.

For the installed readonly operations, see [offline verification](offline-verification.md). They use the enrolled finite project contexts described in the [source enrollment guide](source-enrollment.md) and require an exact authenticated project root.

## Requirements

- macOS (verified on arm64) or Linux. Both have a secure trust store (see ADR-006 for Linux), so `trust provision` works on both. Windows is not supported.
- Go 1.26 or newer, `make` and `git`.
- An install prefix that **you own**. The trust store lives under the prefix and is written by the user who runs `trust provision`. A per-user prefix such as `~/.local` is the recommended layout.

## Install

```sh
make install PREFIX="$HOME/.local"
```

`make install` does three things:

1. It runs `go run ./cmd/tplaiter-oss-register --root "$TRUST_ROOT"`. `TRUST_ROOT` defaults to `$(PREFIX)/lib/tplaiter/trust`. The tool generates a fresh operator-pinned OSS installation there, described below, and prints the registration path and digest.
2. It builds `bin/tplaiter` with those two values as linker pins:

   ```
   -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath=<TRUST_ROOT>/registration.json
   -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:<digest>
   ```

3. It installs the binary into `$(PREFIX)/bin`.

The install root is resolved to a symlink-free absolute path, because the loaders open every path component without following symlinks. Paths containing whitespace, quotes, `$`, backquotes or backslashes are rejected, since they cannot pass through make and the linker intact.

Variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PREFIX` | `/usr/local` | Installation prefix; the binary goes to `$(PREFIX)/bin`. |
| `TRUST_ROOT` | `$(PREFIX)/lib/tplaiter/trust` | Absolute directory for the trust documents and the trust store. |
| `TRUST_PUBLISHERS` | empty | Optional JSON file listing trusted template publishers (see below). |
| `TRUST_SOURCE_PACKAGES` | empty | Public initial signed-source package JSON. |
| `TRUST_PROJECT_CONTEXTS` | empty | Finite operator-approved project contexts JSON. |
| `TRUST_LOCAL_SOURCES` | empty | One offline local-operator source JSON; requires contexts and an absent trust root, and forbids publishers, external packages and rotation. |
| `TRUST_ROTATE` | empty | `1` discards the existing installation, including its trust store, and generates a new one. |
| `REGISTRATION_PATH`, `REGISTRATION_SHA256` | empty | Link against an existing registration instead of generating one. Set both or neither. |

`DESTDIR` staging is refused unless both registration pins are given, because a generated registration records absolute paths that must be valid at run time.

Re-running `make install` keeps a valid existing installation and its enrolled store, so an upgrade does not need provisioning again. `make install` only writes to, reuses or rotates a `TRUST_ROOT` that is empty or provably a tplaiter installation: it holds the `.tplaiter-install` ownership marker (or, for installations that predate the marker, a valid `registration.json` pointing inside the root) and no entries other than the ones listed in the layout below. Any other directory, such as `$HOME`, is refused even with `TRUST_ROTATE=1`, and nothing in it is touched; choose an empty or new directory instead. When an owned `TRUST_ROOT` does not form a valid installation, `make install` stops and asks for `TRUST_ROTATE=1`. It also stops when `TRUST_PUBLISHERS` names a publisher set that differs from the one the existing installation trusts (a different key, issuer, source origin, template path or object root); it never silently drops the requested publishers. An identical publisher set, or no `TRUST_PUBLISHERS` at all, keeps the installation as it is.

## Provision (first run)

```sh
tplaiter trust provision
```

This enrolls the trust store from the initial state and bundle pinned by the installation. It reads no other input. It is idempotent: a second run prints `trust store already provisioned`. Until it has run, `trust inspect` and `mcp-server` fail with:

```
error: TRUST_NOT_PROVISIONED: run 'tplaiter trust provision' once after installation
```

The other trust-gated commands (`new`, `update`) do not run this check yet and report the store-level error `TRUST_ANCHOR_MISSING` instead.

## Inspect

```sh
tplaiter trust inspect --json
```

This prints the verified trust-profile binding, plus the installation it was loaded from:

```json
{
  "apiVersion": "tplaiter.dev/trust-profile-binding/v1",
  "id": "oss",
  "definitionVersion": 1,
  "configSHA256": "sha256:…",
  "policySHA256": "sha256:…",
  "authoritySHA256": "sha256:…",
  "assurance": "publisher-verified",
  "evidenceClass": "production",
  "installation": {
    "installationID": "oss-…",
    "registrationSHA256": "sha256:…",
    "runtimeConfigSHA256": "sha256:…",
    "store": "provisioned"
  }
}
```

The profile is always `oss`. The `development` profile is refused in an installed launch. Neither environment variables (`HOME`, `XDG_*`, `TPLAITER_*`) nor flags take part in selecting trust material; only the linker pins do.

`tplaiter mcp-server` uses the same registration. After provisioning it answers the MCP `initialize` request over stdio.

## What the installation contains

`TRUST_ROOT` has this layout (directories `0700`, files `0600`):

| Path | Content |
| --- | --- |
| `.tplaiter-install` | Ownership marker, written first. Rotation and reuse require it (see above). |
| `registration.json` | Installed-launch registration: profile `oss`, pins of `config/runtime.json` and `config/operator.json`, installation ID and project key. Its digest is linked into the binary. |
| `config/runtime.json` | Runtime installation: pins of every document below, the evidence, object, scratch and project roots, and the OSS store location. |
| `config/descriptor.json` | Bootstrap descriptor: the install-local anchor public key, the policy origin and the publisher scopes. |
| `config/operator.json`, `config/provisioning.json` | Operator pin record and `operator-pinned` provisioning record. |
| `config/policy.json` | Execution policy. It has no approvers, so no template-derived action can be approved yet. |
| `config/state.json`, `config/bundle.json` | Initial accepted state and sealed bootstrap bundle used by `trust provision`. |
| `evidence/` | Content-addressed evidence: the signed trust-root envelope, receipt, checkpoint and inclusion proof. |
| `objects/`, `scratch/`, `projects/default/` | Object, scratch and project roots referenced by the runtime installation. |
| `store/` | The trust store, created by `trust provision`. |

The generator creates the anchor Ed25519 key, signs the trust-root envelope with it, and discards it. **No private key is ever written to disk.**

By default the installation trusts no real template source: its only publisher scope is a placeholder over the unresolvable `https://local.tplaiter.invalid/unconfigured` origin, whose key is also discarded. To trust publishers, pass a JSON file:

```json
[
  {
    "issuer": "example-publisher",
    "publicKeyBase64": "<base64 Ed25519 public key>",
    "sourceOrigin": "https://git.example.test/templates",
    "templatePath": ".",
    "objectRoot": "/absolute/path/to/loose/git/objects"
  }
]
```

```sh
make install PREFIX="$HOME/.local" TRUST_PUBLISHERS=publishers.json TRUST_ROTATE=1
```

The publisher set is part of the pinned descriptor, so changing it means rotating the installation and provisioning again.

## Initial public signed-source enrollment (source builds)

The build-time registration tool accepts a bounded initial importer. This is
an installation foundation; it does not make `repo add` a trust-enrollment
command or enable live source selection in every CLI/MCP operation.

Supply operator-approved `publishers.json` as above, **omitting `objectRoot`**:
this importer always derives object roots inside the new installation. A public
`source-packages.json` is a list of 1–32 records:

```json
[
  {
    "apiVersion": "tplaiter.dev/initial-source-package/v1",
    "statement": {
      "apiVersion": "tplaiter.dev/publisher-statement/v1",
      "policyOrigin": "https://local.tplaiter.invalid/policy",
      "issuer": "example-publisher",
      "predicate": "https://local.tplaiter.invalid/predicate/template-source",
      "usage": "template-source",
      "subject": {
        "origin": "https://git.example.test/templates",
        "templatePath": ".",
        "commit": "<full lowercase Git OID>",
        "treeSHA256": "sha256:<canonical source-content-tree/v1 digest>",
        "contractSHA256": "sha256:<source-contract/v1 digest>"
      }
    },
    "signature": "<unpadded base64url Ed25519 signature>",
    "keyFingerprint": "sha256:<approved public key fingerprint>",
    "objects": {"<Git OID>": "<base64 raw Git frame>"}
  }
]
```

The signature covers the 32 decoded bytes of
`bootstrap.DomainDigest("tplaiter.dev/publisher-statement/v1", statement)`.
Statement CAS is the raw statement JSON hash; transparency leaves contain its
CAS digest **text**, not the signed digest or JSON bytes. Package fingerprints
are checked against the approved publisher input; packages cannot enroll keys.
Policy origin, issuer, source origin, template path, predicate and usage must
match the approved scope exactly.

Each object value encodes uncompressed `kind SP decimal-size NUL data`, keyed
by its rehashed SHA-1 or SHA-256 Git OID. Include exactly the commit, ancestor
trees and selected template subtree closure; compressed loose objects, packs,
unused objects, symlink/gitlink modes and mutable refs are refused. Limits are
32 packages, 8,192 objects per package, 64 MiB aggregate raw objects and 96 MiB
input JSON, plus the existing verifier's source bounds. The verified subtree
must contain a native `template.contract.json` with no dependencies and the
exact raw hash of `template.manifest.yaml`. Native manifests may declare
validated inert generator snippets. Their exact
verified bytes are retained under `.tplaiter/generators/`, with source provenance
in `.tplaiter/resources.lock.json` and file ownership in the separate ownership
inventory. Creation does not execute generators or populate generator targets.
Commands, tool requirements, environment playbooks and create/update hooks remain
unsupported by this enrollment route. No fetch, checkout or signing service runs.

An optional `project-contexts.json` contains 1–32 finite contexts, using the
existing runtime type:

```json
[
  {"key":"a","projectID":"project-a","submitterPrincipalID":"principal:operator","minimumProfile":"oss","rootPath":"/absolute/canonical/projects/a"},
  {"key":"b","projectID":"project-b","submitterPrincipalID":"principal:operator","minimumProfile":"oss","rootPath":"/absolute/canonical/projects/b"}
]
```

Keys, IDs and roots must be distinct. Roots cannot nest, overlap the install
root, traverse symlinks or weaken the OSS profile. The submitter must already
exist in the generated policy (`principal:operator` or `principal:publisher`).
A target may be an existing directory or one absent leaf beneath an existing
canonical directory; enrolling it creates no project content. Each runtime
selects one authenticated `ProjectContexts` key through existing
`RuntimeOptions.ProjectKey`; no dynamic registry or ordinary CLI root/reader
trust override is introduced. The registration selects the first supplied
context by default. CLI `new --project-context <key> --dir <target>` selects an
authenticated context and requires the target to equal its root. MCP
`project_new` uses `projectContext` and `targetDir`; its `dir` is an existing
child working directory, which may be unrelated to the absent target.

Choose an **absent** install-root path beneath an existing canonical parent, then link with the
printed pins:

```sh
go run ./cmd/tplaiter-oss-register \
  --root /absolute/canonical/new-trust \
  --publishers publishers.json \
  --source-packages source-packages.json \
  --project-contexts project-contexts.json \
  --output registration.pins
make install PREFIX="$HOME/.local" $(cat registration.pins)
tplaiter trust provision
```

The generator builds one common initial checkpoint containing the envelope
payload leaf and every signed statement CAS leaf. Existing bootstrap APIs
verify each signature, exact scope and receipt-bound inclusion before confined
object/evidence publication. Files and directories are synced in private
staging before native exclusive atomic publication into the absent install root.
Linux uses `renameat2(RENAME_NOREPLACE)` and macOS uses
`renameatx_np(RENAME_EXCL)`. Any existing destination, including an empty
directory created concurrently, is preserved. Unsupported filesystems are
refused without an overwrite fallback. Public JSON inputs are opened
nonblocking and checked as regular files on the opened descriptor, so a FIFO
with no writer is refused without waiting. An invalid
import or conflicting immutable bytes cannot replace a prior installation.
Orphan CAS bytes confer no authority. `config/source-selections.json` is a list
of **untrusted locators** in the existing SourceSelection wire format; consumers
must call `Runtime.VerifySubject` again. No independent publisher checkpoint
can replace the accepted installation checkpoint.

`config/enrollment.json` records the initial source/context contract digest,
also carried in the linker-pinned registration. Reuse with explicit inputs
requires the same contract and publisher set, and checks retained object and
signature bytes. Changed sources or contexts require a fresh root and new
linker pins; this slice does not update installed authority. `--rotate` is
refused for an installation carrying this contract, even when the input flags
are omitted, so it cannot covertly reset an enrolled store. Omitting all input
flags when reusing an existing installation preserves it.

For an offline operator-attested source, `make install` also accepts
`TRUST_LOCAL_SOURCES` together with finite `TRUST_PROJECT_CONTEXTS`; see
[source enrollment](./source-enrollment.md) for the closed public inputs. This
official producer generates a distinct ephemeral source-signing key in process
and discards it, retaining only public attestation. It accepts no private key,
credential file or private profile, and installs no signing helper. Release
distribution, later source versions,
authority refresh and general post-install project enrollment remain separate.

## Rotate

```sh
make install PREFIX="$HOME/.local" TRUST_ROTATE=1
tplaiter trust provision
```

Rotation replaces every generated document and removes the old trust store. It only runs on a `TRUST_ROOT` proven to be a tplaiter installation that holds no foreign entries, so it never deletes files it did not create. The new binary carries new pins, and the previous binary stops working because its registration is gone. Rotate when the validity window ends (five years from generation) or when the publisher set changes.

## Uninstall

```sh
rm "$HOME/.local/bin/tplaiter"
rm -rf "$HOME/.local/lib/tplaiter/trust"
```

The token store for template repositories (`~/.tplaiter/tplater.db`) and other per-user state under `~/.tplaiter` are separate from the trust installation. Remove them only if you no longer need the saved tokens and registered projects.
