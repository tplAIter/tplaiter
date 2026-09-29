# ADR-005: OSS install registration and first-run provisioning

- Status: accepted (work package U02, bead tp-i9g.4.4)
- Date: 2026-09-29
- Related: tp-i9g.4 (P04 portable trust profiles), tp-i9g.4.2.7 (T7 fresh-process evidence), tp-i9g.4.3 (credential boundary), tp-23d (OSS part), user decision D4 (no development or unsigned profile in an installed launch)

## Context

Every trust-gated command composes its runtime from an **installed-launch registration**. The binary reads that registration from a path fixed at link time and checks it against a digest also fixed at link time (`internal/cmd/trust_launch.go`, variables `installedRegistrationPath` and `installedRegistrationSHA256`). Flags and environment variables never take part in the selection.

The registration pins, by digest, the runtime installation document (`trustload.RuntimeInstall`) and the operator pin record. The runtime installation in turn pins the bootstrap descriptor (anchor keys and publisher scopes), the provisioning record, the execution policy, the initial accepted state and bundle, and the evidence, object, scratch, project and store locations. The `development` profile is refused at three layers: the registration decoder, `trustload.RuntimeInstall.Validate`, and provenance planning.

The published core had no way to produce such a registration. A stock `make build` binary therefore failed every trust-gated command, including `mcp-server`, with `TRUST_ANCHOR_MISSING`. The e2e module failed for the same reason. `trust provision` already existed, but it needs the linker-pinned registration first.

The core question was a chicken-and-egg problem. The registration digest must be known when the binary is linked. The installation, however, needs per-install values: an installation ID, a project key, absolute paths, and fresh anchor keys. Where do those values come from, and when?

## Decision

**Generate the installation before linking, and link against it.** `make install` runs as follows:

1. `go run ./cmd/tplaiter-oss-register --root $(TRUST_ROOT)` (package `internal/ossinstall`) generates a complete OSS installation under `TRUST_ROOT` (default `$(PREFIX)/lib/tplaiter/trust`):
   - It creates a fresh Ed25519 **anchor** key and a trust-root envelope that lists the publisher keys. The anchor signs the envelope.
   - It records the envelope in a one-leaf transparency log: checkpoint, inclusion proof and receipt.
   - It writes the descriptor, the operator pin record, the provisioning record (mode `operator-pinned`), the execution policy, the initial accepted state and bundle, the runtime installation, and finally `registration.json`. Each document pins the ones below it by digest.
   - It discards the anchor private key, and the placeholder publisher key when one is used. **No private key is ever written to disk.** A unit test feeds deterministic entropy and scans every generated file for the seeds and private keys in raw, base64 and hex form.
   - It prints `REGISTRATION_PATH` and `REGISTRATION_SHA256`.
2. `make build` links the binary with exactly those two `-X` pins.
3. `tplaiter trust provision` is the **first-run provisioning**. It enrolls the trust store from the pinned initial state and bundle only; nothing else is read. It is idempotent. Until it has run, `trust inspect` and `mcp-server` fail with `TRUST_NOT_PROVISIONED` and a hint; `new` and `update` currently report `TRUST_ANCHOR_MISSING` from runtime composition.

The chicken-and-egg problem disappears because the registration never depends on the binary: every per-install value is generated before linking, and the binary only carries the resulting digest. Re-running `make install` reuses a valid installation, so upgrades keep the enrolled store. Reuse never drops requested publishers: when `TRUST_PUBLISHERS` differs from the publisher set the installation trusts, generation fails with `ErrPublishersChanged` and asks for `TRUST_ROTATE=1`. `TRUST_ROTATE=1` generates a new installation and requires a fresh `trust provision`.

Resulting properties:

- **Profile `oss`, never `development`.** D4 holds, and no unsigned launch profile was added. `trust inspect --json` reports `"id":"oss"` and `"assurance":"publisher-verified"`.
- **The operator is the anchor.** The provisioning mode `operator-pinned` records that the installing operator, not a release publisher, pinned the descriptor. The evidence class is `production` because the keys and signatures are real and were generated for this installation. `simulated` stays reserved for test fixtures whose seeds are public.
- **Nothing is selected by environment.** Every path in the installation is absolute and symlink-free: the generator resolves `TRUST_ROOT`, and the loaders use `O_NOFOLLOW` on each component. A hostile `HOME`, `XDG_*` or `TPLAITER_PROFILE` cannot change the binding; the e2e test `TestInstalledTrust/environment_never_selects_trust` proves it.
- **Default trust is empty.** Without `TRUST_PUBLISHERS`, the only publisher scope is a placeholder over the unresolvable `https://local.tplaiter.invalid/unconfigured` origin. The `.invalid` TLD is reserved by RFC 2606, and the placeholder key is discarded, so no template source verifies. The execution policy has no approvers. The installation proves the trust launch without granting any authority to templates.
- **Inspectability.** `trust inspect --json` keeps the stable binding fields at the top level and adds an `installation` object: installation ID, registration digest, runtime-config digest and store state.

## Alternatives considered

1. **A registration at a fixed per-OS path under `$XDG_CONFIG_HOME` or `~/Library/Application Support`, written by `trust provision --oss` on first run.** Rejected. The binary would have to derive the registration location from `HOME`/`XDG_*`, which makes the environment select trust material. That breaks the invariant stated in `trust_launch.go`, and the T7 hostile-home test exists to prevent it. Its digest also cannot be linked in, because it would only exist after the binary is built.
2. **A `development` or unsigned launch profile for source builds.** Rejected by user decision D4. The profile is refused at three layers by design.
3. **A publisher-signed `release-distribution` registration with fixed paths, shipped in release archives.** This is the right model for prebuilt artifacts, and it needs a project signing key and a release process. It is deferred to the release work (P15, with no releases per D7). The `ossinstall` package and its registration type are the seam it will reuse.
4. **Deterministic, reproducible installation contents.** Rejected. Fresh anchor keys per installation are the point of an operator pin, and a deterministic key would be a shared, public anchor.

## Consequences

- A `make install` binary runs `trust provision`, `trust inspect` and `mcp-server` without hand-made linker flags (DoD item 2). The `tests/` harness uses the same generator and pins in `TestMain`, and `internal/testfixture.BuildInstalled` provides the same for package tests.
- The binary belongs to its installation. Moving or deleting `TRUST_ROOT` disables it with `TRUST_ANCHOR_MISSING`, and editing any pinned document fails with `TRUST_PIN_MISMATCH` or `TRUST_CONFIG_INVALID`. An attacker who can write both the binary and `TRUST_ROOT` can replace both. That is equivalent to replacing the binary and out of scope.
- The install prefix must be owned by the user who provisions it. System-wide multi-user installs (for example, root-owned `/usr/local` shared by several users) are not supported yet.
- `DESTDIR` staging requires explicit pins, because generated registrations record run-time absolute paths.
- Prebuilt archives (goreleaser snapshot, U12) cannot carry a per-install registration. U12's DoD re-run (amendment A23) has two options: build the snapshot's source with `make install`, or link the snapshot binary with explicit `REGISTRATION_PATH`/`REGISTRATION_SHA256` from `tplaiter-oss-register`. Alternative 3 is the long-term answer.
- Open seams for later work packages:
  - **U07 (live lifecycle):** configure template publishers, for example the neutral `example.test` fixture provider, through `ossinstall.Options.Publishers` or `TRUST_PUBLISHERS`. Replace the single `default` project context (rooted in `TRUST_ROOT/projects/default`) with per-project contexts for arbitrary project directories.
  - **U13 (trusted actions):** add approvers to the generated execution policy; today it has none.
  - **U03 (Linux store):** landed (ADR-006). The e2e and package fixtures now require provisioning on Linux as well as macOS; only other platforms (Windows, deferred) skip trust-dependent cases.
- `mcp-server` now resolves symlinks in its executable path before creating the held stage (after `--print-config`, so client snippets keep the launch path). Installs reached through a symlinked directory, such as macOS `/var` or `/tmp` or a package-manager shim, previously reported `MCP_UNAVAILABLE`.
