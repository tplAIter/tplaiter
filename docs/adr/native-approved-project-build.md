# Native approved pure-Go project build (U13 7.4.6)

Status: bounded implementation and focused local runtime proof; independent final
review and integration remain. This slice restores only literal `run build` for
an authenticated dependency-free Go project on Darwin arm64. Other actions,
environment playbooks, hooks and the parent U13 remain open.

## Authority and material

The signed source manifest selects one exact build declaration and action record.
The record pins a closed toolchain index. Declaration admission strictly validates
index JSON/schema/version, canonical paths, modes, digest and chunk declarations,
required tools and bounds. It neither reads host executables nor grants execution.
Empty command declarations remain compatible. Tools/playbooks/hooks/AI refusals
are retained at resource and project-creation admission. The update adapter stays
unchanged and still refuses command-bearing targets.

Fresh OSS registration accepts explicit public approver records and execution
chunks. Existing default registrations still have zero approvers. No invocation
human approval or profile override is enabled. `run build --prepare` produces the
exact request. An external operator signs the persistent grant; `--approval-input`
verifies that actual signature against the installed policy, then imports only
public grant/signature objects into persistent CAS. Malformed signatures, stale
request bindings and persistence failures expose a typed `TRUST_APPROVAL_MISMATCH`
without untrusted verifier text; cancellation is preserved. A focused installed-CAS
regression proves that a stale changed-input grant persists neither object and that
the exact external synthetic signature persists and reverifies. Runtime clients accept no
private signer key or caller-selected approval authority.

The index authenticates the Go driver, compiler, linker, assembler and required
standard library files through bounded CAS chunks and full file hashes, plus Go
build information/version checks. No archive inflation or unsigned PATH driver
selection occurs. Source-object limits remain unchanged. The separate index is
bounded to 8 MiB, 20,000 files and 512 MiB total, with at most 16 chunks of 4 MiB
per file. Current project inputs are captured through held no-follow traversal:
regular Go files, dependency-free go.mod and selected project metadata. Current
edits change the request. Symlinks, vendor/workspace directives, module dependency
or replacement directives and embedded file requests are refused. CGO is disabled.

Authorization binds the source, project identity, profile, answers, input closure,
arguments, environment, toolchain and timeout. The material is rechecked before
spawn and cannot cross runtimes. The stage uses verified copied toolchain bytes
and isolated HOME, caches and project input. Darwin launches the resolved path of
a held staged driver with file-identity checks, following the existing approved
runner pattern. It never executes `/dev/fd/3`: that launch operand is rejected by
this host. The sandbox permits stage writes, refuses toolchain writes and ambient
executables, denies network and denies reads outside stage and the fixed OS library
closure. The literal root directory `/` is readable for loader ancestry; its
descendants are not thereby permitted. Required guard loss returns a typed refusal,
without a process receipt; optional bounded launcher diagnostics remain distinct.

The runner issues an opaque receipt for its exact canonical request only after
reaping its real process. Structured results bind input/index/request and output
hashes and retain the real child exit. MCP forwards native controls through the
actual installed CLI child. No shell fallback is reachable.

## Observed focused runtime evidence

`final-installed-project-build-capacity-restored.log`: final installed CLI fixture
PASS in 199.21 seconds (package duration 199.856 seconds), using actual local Go 1.27.1 darwin/arm64,
fresh synthetic publisher and approver keys, authenticated source objects,
persistent signature import and isolated HOME/XDG. Observed cases:

- CLI compilation: child exit 0 with a runner-issued receipt.
- Actual stdio MCP run: child exit 0 and the same request/input/index bindings.
- Cancellation after the driver created its isolated cache: child exit 130,
  cancelled=true, timedOut=false; the process was reaped.
- A current main.go syntax edit invalidated the prior persistent grant. A fresh
  request and external signature reached the real compiler, which returned exit 1
  and `syntax error: unexpected name error at end of statement`. JSON CLI exit was
  10, with a failure receipt for the changed input closure.
- No persistent approval returned `TRUST_APPROVAL_REQUIRED`; the stale changed-input
  grant returned typed `TRUST_APPROVAL_MISMATCH`. Both refused before a process
  receipt. A separate importer test verified neither grant nor signature object
  was persisted on stale refusal.

The final installed fixture image SHA256 was
`779ee98c5a6ac232dde97ad8591d08421a200db8b2bdd6f1740b020536164e00`.
The toolchain index digest was
`sha256:3f87ae9030a30f7a31b58be227fe87b530e3b0c6bbf101bc6abcfb6be90640c4`.
The held-driver microprobe records driver digest
`548608a910c46de32c65a3934f461b1787acf6ddd371044826068d8503b8509b`.
The exact-profile microprobe accepted a held Go version launch and synthetic stage
writes; synthetic outside reads/writes, toolchain mutation, ambient execution and
loopback network connection were OS-denied. No machine credential values were read
to test these denials.

Cicero's unchanged counterexamples (`not JSON` and an unknown-version empty index)
now both refuse at the actual resource admission gate. Focused pure-index and
receipt/runtime guard tests passed; no installed fixture was repeated solely for
index admission. The final runtime fixture includes the corrected index validator,
receipt binding, cancellation normalization and typed approval importer.

Raw predecessors remain immutable. Replay 7 passed before these final guard
tightenings. A later unprivileged replay correctly refused outer-sandbox loss
(`sandbox_apply: Operation not permitted`) without a receipt. After the exact
held-Go microprobe passed, a replay produced CLI/MCP receipts but failed stage
creation under severe disk pressure (`TRUST_STAGE_FAILED`; underlying errno was
not captured). The complete final fixture passed after disk capacity recovered.
These failed logs are retained and are not counted as successful compiler proof. This is an uncommitted patch based on ab311895, not a clean
published build, full host matrix, arbitrary run adapter or U13 completion claim.

## Portable reproduction and integration

Run in the public task checkout with compatible cached public repository
dependencies, an explicitly selected owned GOCACHE, GOPROXY disabled and an
execution context that permits applying the restrictive local Seatbelt profile:

```sh
export GOCACHE=/path/to/owned/public-go-cache
GOPROXY=off GOTOOLCHAIN=local go test ./internal/resources ./internal/operationtrust ./internal/trustload -run 'TestIndependentMalformedToolchainAdmission|TestNativeGeneratorProjectBuildAdmission|TestProjectBuildRecordContract|TestToolchainIndexClosedAdmission|TestProjectBuildMaterialGuardLossRefuses' -count=1 -v
GOPROXY=off GOTOOLCHAIN=local go test ./internal/execx -run 'TestProjectGoGuardHeldLaunch|TestProjectGoLoaderClosedActualDriver|TestProjectBuildOpaqueReceiptBinding' -count=1 -v
GOPROXY=off GOTOOLCHAIN=local go test ./internal/ossinstall -run 'TestApprovalImportMalformedRefusesBeforeLoadOrWrite|TestApprovalImportStaleBindingNoPersistentEffects' -count=1 -v
GOPROXY=off GOTOOLCHAIN=local go test ./internal/cmd -run '^TestNativeProjectBuildInstalledCLI$' -count=1 -v -timeout 15m
```

The sandbox microprobe requires an execution context capable of applying a local
Darwin sandbox. Run it before the installed fixture when diagnosing a launcher.
No machine installation path is required by the reproduction: fixture toolchain
capture uses the actual Go runtime's GOROOT, authenticates its bytes and signs the
resulting fixture closure. Temporary project paths in raw receipts are exact
local evidence; a separate sanitized sharing copy replaces them, while original
raw hashes are retained. Public fixture keys are synthetic and no production
signing keys, app auth stores, installation rotation, remote providers or paid
model calls participate.

Merge only the `run` entry from the generated `run-tool-fragment.json` into the
current shared tool-schema golden. Preserve settings_edit and the current
27-tool count. The worker does not edit either shared golden or settings code.
All ten changed existing-file preimages match public 90bccd525 exactly; this is
source compatibility, not proof of a binary compiled from that full tree. Source
preimages, per-file hashes, full patch and deltas against the original 24-file
freeze and both 26-file freezes are delivered separately. No Beads, commits or pushes are performed.
