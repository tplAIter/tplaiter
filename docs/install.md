# Installing tplaiter from source

tplaiter refuses every trust-gated command (`new`, `update`, `trust *`, `mcp-server`) unless the binary was linked against an **installed-launch registration**. A plain `go build` or `make build` produces a *stock* binary without one, which answers `TRUST_ANCHOR_MISSING`. The design is recorded in [ADR-005](./adr/ADR-005-oss-install-registration.md).

This page covers the OSS profile built from source. There is no published release yet, and release archives are out of scope until the release-distribution registration exists.

## Requirements

- macOS (verified on arm64). The secure trust store is not yet available on Linux, so Linux builds install but `trust provision` fails there until the Linux store lands. Windows is not supported.
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
| `TRUST_ROTATE` | empty | `1` discards the existing installation, including its trust store, and generates a new one. |
| `REGISTRATION_PATH`, `REGISTRATION_SHA256` | empty | Link against an existing registration instead of generating one. Set both or neither. |

`DESTDIR` staging is refused unless both registration pins are given, because a generated registration records absolute paths that must be valid at run time.

Re-running `make install` keeps a valid existing installation and its enrolled store, so an upgrade does not need provisioning again. When the documents under `TRUST_ROOT` do not form a valid installation, `make install` stops and asks for `TRUST_ROTATE=1`.

## Provision (first run)

```sh
tplaiter trust provision
```

This enrolls the trust store from the initial state and bundle pinned by the installation. It reads no other input. It is idempotent: a second run prints `trust store already provisioned`. Until it has run, trust-gated commands fail with:

```
error: TRUST_NOT_PROVISIONED: run 'tplaiter trust provision' once after installation
```

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

## Rotate

```sh
make install PREFIX="$HOME/.local" TRUST_ROTATE=1
tplaiter trust provision
```

Rotation replaces every generated document and removes the old trust store. The new binary carries new pins, and the previous binary stops working because its registration is gone. Rotate when the validity window ends (five years from generation) or when the publisher set changes.

## Uninstall

```sh
rm "$HOME/.local/bin/tplaiter"
rm -rf "$HOME/.local/lib/tplaiter/trust"
```

The token store for template repositories (`~/.tplaiter/tplater.db`) and other per-user state under `~/.tplaiter` are separate from the trust installation. Remove them only if you no longer need the saved tokens and registered projects.
