# ADR-006: Linux trust store, MCP held stage and approved runner

- Status: accepted (beta-preview scope)
- Date: 2026-09-29
- Work package: U03 (beads tp-i9g.4.3.2, tp-i9g.7.2; Windows stays deferred under tp-6v4)

## Context

Until this change the secure trust store, the MCP held-stage transport and the
approved execution runner existed only on Darwin (arm64). On Linux the store
reported `storePlatformAvailable() == false`, `mcp-server` returned
`MCP_UNAVAILABLE` for every tool call, and `execx.NewApprovedRunner` refused
with `TRUST_EXECUTION_UNAVAILABLE`. Cross-compilation succeeded, but a build
that compiles is not evidence that locking, durability or descriptor handling
are correct, so enablement had to follow a native proof.

## Decision

### 1. Trust store: closed filesystem allowlist

The store runs on Linux only when the store root's filesystem, identified by
`fstatfs(2)` on the held directory descriptor (never by path), is in a closed
allowlist:

| Family | `f_type` | Status | Evidence |
| --- | --- | --- | --- |
| ext2/ext3/ext4 | `0xEF53` | admitted | full `internal/trustload` matrix on a Docker named volume (ext4) |
| overlayfs | `0x794c7630` | admitted | full `internal/trustload` matrix on the container root (overlayfs over ext4) |
| tmpfs | `0x01021994` | refused | no durability across reboot; `TestLinuxStoreRefusesTmpfsRoot` proves the real refusal |
| btrfs, xfs | `0x9123683E`, `0x58465342` | refused | not yet proven; can be admitted after the same matrix passes natively |
| NFS, FUSE (including virtiofs host shares), 9p | `0x6969`, `0x65735546`, `0x01021997` | refused | unreliable `flock(2)` / no-replace rename semantics |
| anything else | – | refused | fail-closed default |

A refused family returns the typed `trustload: TRUST_STORE_FILESYSTEM_UNSUPPORTED`
(`trustload.ErrStoreFilesystemUnsupported`). It is a refinement of
`TRUST_PROVENANCE_UNAVAILABLE`: `errors.Is(err, ErrProvenanceUnavailable)` stays
true, so every existing fail-closed branch is unchanged, while operators see the
precise reason. Enrollment on a refused family creates nothing; an existing root
on a refused family is refused before any lock or SQLite binding is taken.

The Linux primitives are:

- locking: `flock(2)` on the held root directory descriptor (shared for readers,
  exclusive for writers), identical to Darwin;
- durability: `fsync(2)` of the file and of the parent directory (Linux has no
  `F_FULLFSYNC`; ext4 `fsync` issues the cache flush);
- marker activation: `renameat2(RENAME_NOREPLACE)`, with no plain-rename
  fallback (a kernel or filesystem without it fails closed);
- identity: the same `dev`/`ino`, owner and `0700` checks as Darwin; `atime` is
  read through the `Atim` field.

The native proofs are the existing store tests (journal, crash via killed child
processes, cold recovery, reload, lease/lock contention, descriptor ledgers,
VFS faults) plus Linux-only tests in `store_filesystem_linux_test.go`
(allowlist, tmpfs refusal, no-replace rename, lock exclusion).

### 2. MCP held stage on Linux

`child_stage_unix.go` is now shared by Darwin and Linux. The stage copies the
executable into a private `0700` directory under the authenticated scratch
root, writes it `0500` with `O_EXCL|O_NOFOLLOW|O_CLOEXEC`, fsyncs it, keeps an
`O_CLOEXEC` read descriptor, and before every launch re-verifies the SHA-256 of
the held bytes and that the launch path still names the held inode
(`lstat` dev/ino, regular file). Close removes the directory. The only
platform-specific piece is resolving a descriptor to a path: Darwin uses
`fcntl(F_GETPATH)`, Linux reads `/proc/self/fd/<n>` and refuses unlinked
(`" (deleted)"`) or pseudo-file results and any path whose inode differs from
the descriptor's. A host without a mounted `/proc` reports `MCP_UNAVAILABLE`.

`memfd_create`/`execveat` was considered and not used: executing through
`/proc/self/fd` changes `argv[0]` and `/proc/self/exe` semantics for the child,
and the verified private copy already gives the required guarantees.

### 3. Approved runner on Linux

`execx.NewApprovedRunner` admits `darwin/arm64`, `linux/amd64` and
`linux/arm64` (`approvedHostSupported`). The staging and process-group code in
`approved_stage.go` is shared; the native admission envelope is per platform:

- Darwin: thin arm64 Mach-O whose loader closure is exactly `/usr/lib/dyld`
  plus libSystem (gofmt additionally admits libresolv), unchanged;
- Linux: a statically linked ELF64 little-endian `ET_EXEC` for the host machine
  with no `PT_INTERP` and no `PT_DYNAMIC`, at least one executable `PT_LOAD`,
  no writable-and-executable segment, and in-bounds segments.

Signed formatter tool records bind to the host envelope identifier
(`operationtrust.FormatterNativeEnvelope()`):
`darwin-arm64-dyld-libsystem-libresolv-v1`, `linux-amd64-static-elf-v1`,
`linux-arm64-static-elf-v1`. A record signed for one envelope never admits a
tool on another host.

## Consequences

- Linux installs can enroll, read, refresh and recover the trust store, run
  `mcp-server` tool calls, and execute approved native material.
- Intel macOS, Windows and the BSDs remain typed-unavailable (store:
  `TRUST_PROVENANCE_UNAVAILABLE`; runner: `TRUST_EXECUTION_UNAVAILABLE`; MCP:
  `MCP_UNAVAILABLE`). Windows is deferred (tp-6v4, P21).
- Docker on macOS runs a Linux arm64 VM; local evidence is therefore
  linux/arm64. linux/amd64 is covered by the same code paths and by the GitHub
  `ubuntu-latest` CI job once the branch is pushed, which is the authoritative
  proof on a real ext4 runner.
- Template publishers who ship a formatter tool must publish one signed record
  per host envelope they support.
