# Concrete ledger, reader and migration assembly

Implemented against published ab311895586b5070d23084a3f283327602e8e379.
The final packet separately verifies byte-identical preimages/absences on the
current public floor; engine, Inspector/inventory, gen and update are unchanged.
The original15 freeze remains immutable, including its rejected writer boundary.

## Actual read-only consumers

`internal/cmd/verify.go:runVerify` supplies Runtime, Home, actual runtime CAS and
its narrow secret classifier to `projectverify.VerifyObserved`. When an explicit
Runtime or a concrete Runtime CAS is present, VerifyObserved requires that exact
runtime's live TrustRuntime pointer, CAS pointer and registered root. Closed,
wrapped-CAS and mismatched authority inputs do not fall back to interface-only
verification. Interface-only compatibility verification cannot authenticate a
discovered native namespace and refuses it as unresolved. It does not discover
an unspecified Home or claim global journal coverage.

`OpenReadOnly` returns a private ReadSession retaining shared, nonblocking locks
on the actual existing project `update.lock` and Home `.lock` inodes. No lock,
key, journal or cache is created. A live writer refuses before receipt projection;
a retained prepared journal refuses after authentication. Missing lock inodes
are tolerated only without discovered native receipts and must remain absent.
The session checks root/state/home/lock identities and reauthenticates current
marker, runtime lifetime, receipt/CAS metadata and the exact ledger observation
before public projection. VerifyObserved retains it through canonical summary
projection and closes it on every path. VerifyReadOnly/Load use the same session;
private observations inside Apply inherit its already-held exclusive locks.
Plan also retains reader coordination while proving the current signed source.

The current marker's canonical identity check preserves the established trust
code and nested runtime cause before native journal status projection. Primary
public mappings remain: active/future/unsupported/uncovered/missing-images ->
TPL-E-TX-ACTIVE-001; unsafe -> TPL-E-STATE-001; missing-CAS ->
TPL-E-OFFLINE-MISS-001. Current-marker identity mismatch remains TPL-E-TRUST-001,
with the existing TRUST_RUNTIME_INVALID cause where applicable. Internal journal
IDs, phases or paths are not public diagnostic details. Native registry-image
slots are classified only by exact canonical namespace and numeric slot grammar;
unknown reserved files still refuse the CLI secret classifier before reading.

Historical authenticated own terminal receipts do not require old afterimages
to equal current targets after another legitimate Gen. Missing evidence remains
diagnostic, not silently accepted. Different sealing authorities stay unresolved;
no unsigned owner label or missing-key initializer grants coverage. A visible
terminal receipt is historical evidence, never a claim that prior fsync succeeded.

## Concrete in-place migration and corrected writer boundary

Plan uses the installed runtime's held CAS and proves signatures for the root
and every existing dependency subject. No caller RootVerifier, CAS, boolean or
exported authenticated material grants native migration admission. Missing
source/dependency synthesis is unavailable. Legacy marker conversion is supported
in place with Root/Home unchanged and an existing dependency pair. A legacy
marker with native journals remains a typed refusal; it is never normalized.

Apply retains actual project and Home exclusive writer locks, then duplicates
those retained descriptors into a BoundMigrationWriter. This low-level object is
confinement, not a trust grant. After the final INNER PlanContext, the writer
checks retained root/state/home/lock bindings before any mutation. Immediately
before each publication it checks those bindings again and verifies the retained
actual target inode/mode/bytes. Temporary creation, cleanup, rename and directory
sync are relative to the retained state-directory fd; an absolute raced Root
path cannot redirect a write into a foreign replacement. Ordinary compatibility
writers stay separate and do not claim concrete native admission.

The independent exact P2 scheduling repro now refuses with markerChanged=false.
Strengthened actual-runtime tests preserve replacement and retained-original
bytes/modes/inodes for state-directory and Home-lock replacement, confirm release
and fresh reviewed retry, and prove ordinary legacy migration succeeds. A focused
IO race test replaces the namespace at the final rename boundary and preserves
both markers. This is not a new general legacy rollback/recovery protocol.
An advisory lock absent at plan time can make a reviewed digest stale on first
Apply; the operation refuses rather than weakening that fingerprint.

## Naming migrate-state

The existing real naming Plan/Apply/Recover call chain refuses reserved native
namespaces in sources it would move, including a self-hashed plan containing
reserved entries. Apply checks under its existing writer locks; Recover validates
the source/archive preimage and checks the retained namespace. Already committed
naming destinations may acquire legitimate native history and are not permanently
blocked. Native receipt relocation remains unsupported; generic new/v1 never
parses these receipts. In-place marker migration does not relocate authority.

## Evidence and readiness limits

The combined packet contains exact source, preimages/absence proofs, a combined
patch, prior15 corrective delta, and raw focused logs. Signed CLI tests prove
live/prepared refusal, terminal and next-Gen success, future/unsafe/missing-CAS,
foreign current marker, different installed authority and runtime non-downgrade,
with bytes/modes/inodes unchanged. Current-marker/public mapping and zero-write
compatibility fixtures pass. Scoped unfiltered lint and Linux compile pass;
Linux execution is not claimed. The old227s matrix is historical evidence only
and was not repeated or presented as current corrective validation.

The worker marks the packet ready for independent corrective review, not accepted
or published. P05.1/5.1.1 closure remains with primary after that review and exact
integration; no full beta, action execution or receipt relocation claim is made.
