package projectverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/readonlysnapshot"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestVerifyRefusesAuthorityBeforeReadingProject(t *testing.T) {
	_, err := Verify(context.Background(), t.TempDir(), nil, Options{})
	var diagnosticErr *resultdto.DiagnosticError
	if !errors.As(err, &diagnosticErr) || diagnosticErr.Value.Code != TrustCode || resultdto.Classify(err) != resultdto.ExitTrust {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyRefusesMissingOfflineEvidence(t *testing.T) {
	_, err := Verify(context.Background(), t.TempDir(), nil, Options{})
	if err == nil {
		t.Fatal("missing stable authority was accepted")
	}
	if got := resultdto.ProjectDiagnostics(err); len(got) != 1 || got[0].Code != TrustCode {
		t.Fatalf("diagnostics = %#v", got)
	}
}

func TestClassifyPublicCodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{name: "missing root", err: fs.ErrNotExist, code: RootMissingCode},
		{name: "offline miss", err: &readonlysnapshot.OfflineMissError{Subject: "evidence"}, code: OfflineMissCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.err)
			diagnostics := resultdto.ProjectDiagnostics(got)
			if len(diagnostics) != 1 || diagnostics[0].Code != tc.code {
				t.Fatalf("diagnostics = %#v", diagnostics)
			}
		})
	}
}

func TestVerifySignedFixtureAndExplicitEmptyDependencies(t *testing.T) {
	projectRoot, home, runtime, cas, _ := signedProject(t)
	report, err := Verify(context.Background(), projectRoot, runtime.TrustRuntime(), Options{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}})
	if err != nil {
		t.Fatal(err)
	}
	if report.ProjectID != "project-t6b" || report.DependencyCount != 0 || report.DependencyState != "not-applicable" || !report.Offline {
		t.Fatalf("report=%+v", report)
	}
}

func TestVerifyCountsActualDependencyArray(t *testing.T) {
	projectRoot, home, runtime, cas, _ := signedProject(t)
	raw, err := os.ReadFile(filepath.Join(projectRoot, ".tplaiter", stateledger.RootLockFile))
	if err != nil {
		t.Fatal(err)
	}
	rootLock, err := provenance.DecodeRootTemplateLock(raw)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := stateledger.NewDependencyLock(*rootLock, []provenance.DependencySubject{provenance.DependencySubject(rootLock.Root)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := stateledger.WriteLockPair(projectRoot, *rootLock, dependencies); err != nil {
		t.Fatal(err)
	}
	report, err := Verify(context.Background(), projectRoot, runtime.TrustRuntime(), Options{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}})
	if err != nil || report.DependencyCount != 1 || report.DependencyState != "verified" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestVerifyRejectsMarkerReplayAgainstCanonicalIdentity(t *testing.T) {
	projectA, homeA, runtimeA, casA, _ := signedProject(t)
	projectB, _, _, _, _ := signedProject(t)
	markerA, err := os.ReadFile(filepath.Join(projectA, ".tplaiter", "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectB, ".tplaiter", "project.yaml"), markerA, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stateledger.VerifyStable(context.Background(), projectB, runtimeA.TrustRuntime(), stateledger.StableVerifyOptions{HomeRoot: homeA, CAS: casA, SecretProvider: publicHome{}}); err == nil {
		t.Fatal("canonical verifier accepted a replayed marker")
	}
	_, err = Verify(context.Background(), projectB, runtimeA.TrustRuntime(), Options{HomeRoot: homeA, CAS: casA, SecretProvider: publicHome{}})
	var diagnosticErr *resultdto.DiagnosticError
	if !errors.As(err, &diagnosticErr) || diagnosticErr.Value.Code != TrustCode {
		t.Fatalf("U08 accepted mismatched marker: %v", err)
	}
}

func TestVerifyReportsMissingCASAsOfflineMiss(t *testing.T) {
	projectRoot, home, runtime, cas, missing := signedProject(t)
	cas.missing = missing
	_, err := Verify(context.Background(), projectRoot, runtime.TrustRuntime(), Options{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}})
	var diagnosticErr *resultdto.DiagnosticError
	if !errors.As(err, &diagnosticErr) || diagnosticErr.Value.Code != OfflineMissCode {
		t.Fatalf("error=%v", err)
	}
}

func TestVerifyRejectsTamperedLockAsDigest(t *testing.T) {
	projectRoot, home, runtime, cas, _ := signedProject(t)
	path := filepath.Join(projectRoot, ".tplaiter", stateledger.RootLockFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(context.Background(), projectRoot, runtime.TrustRuntime(), Options{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}})
	var diagnosticErr *resultdto.DiagnosticError
	if !errors.As(err, &diagnosticErr) || diagnosticErr.Value.Code != DigestCode {
		t.Fatalf("error=%v", err)
	}
}

func TestVerifyZeroWritesAllComponentsHomeXDGAndNetwork(t *testing.T) {
	projectRoot, home, runtime, cas, _ := signedProject(t)
	xdg := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "visible.txt"), []byte("home"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xdg, "config"), []byte("xdg"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := execx.NewRecordingRunner().SetDefault(execx.Response{})
	beforeProject, err := readonlysnapshot.ProjectWith(context.Background(), projectRoot, readonlysnapshot.Options{Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	before := treeImage(t, projectRoot, home, xdg, cas.trustRoot)
	beforeCalls := len(runner.Calls)
	oldTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("network request during readonly verification")
		return nil, nil
	})
	_, verifyErr := Verify(context.Background(), projectRoot, runtime.TrustRuntime(), Options{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}})
	http.DefaultTransport = oldTransport
	if len(runner.Calls) != beforeCalls {
		t.Fatal("verification launched a snapshot subprocess")
	}
	if verifyErr != nil {
		t.Fatal(verifyErr)
	}
	afterProject, err := readonlysnapshot.ProjectWith(context.Background(), projectRoot, readonlysnapshot.Options{Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeProject, afterProject) || before != treeImage(t, projectRoot, home, xdg, cas.trustRoot) {
		t.Fatal("readonly verification changed project, home/XDG, or snapshot components")
	}
}

type publicHome struct{}

func (publicHome) DigestSecret(context.Context, stateledger.SecretLocator) (stateledger.SecretDigestResult, error) {
	return stateledger.SecretDigestResult{Classified: false}, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func signedProject(t *testing.T) (string, string, *trustload.Runtime, *fixtureEvidenceReader, string) {
	t.Helper()
	fixture := testfixture.NewGofmtFixture(t)
	runtime, resolution := fixture.Open(t)
	projectRoot := fixture.Project()
	if err := os.MkdirAll(filepath.Join(projectRoot, ".tplaiter"), 0o700); err != nil {
		t.Fatal(err)
	}
	binding := runtime.TrustRuntime().Binding()
	refs := resolution.Evidence()
	subject := resolution.Subject()
	rootLock, err := stateledger.SealRootLock(provenance.RootTemplateLock{
		APIVersion: provenance.RootTemplateLockAPIVersion, Kind: provenance.RootTemplateLockKind,
		TrustProfile: binding, Policy: provenance.PolicyBinding{PolicySHA256: binding.PolicySHA256},
		Root:     provenance.RootSubjectFromTrust(subject, bootstrap.PublisherEvidence{StatementCAS: refs.StatementCAS, SignatureCAS: refs.SignatureCAS, KeyFingerprint: refs.KeyFingerprint}, refs.CheckpointCAS, refs.InclusionProofCAS),
		Renderer: provenance.RendererIdentity{Name: "fixture", Version: "v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := stateledger.NewDependencyLock(rootLock, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := stateledger.WriteLockPair(projectRoot, rootLock, dependencies); err != nil {
		t.Fatal(err)
	}
	pointers := stateledger.StandardPointers()
	for _, rel := range pointers.Paths() {
		if rel == stateledger.StateDir+"/"+stateledger.RootLockFile || rel == stateledger.StateDir+"/"+stateledger.DependencyLockFile {
			continue
		}
		if err := os.WriteFile(filepath.Join(projectRoot, filepath.FromSlash(rel)), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	marker := stateledger.ProjectV2{APIVersion: stateledger.ProjectV2APIVersion, Kind: "Project", ID: runtime.ProjectContext().ProjectID, Template: stateledger.TemplateIdentity{Repo: "fixture", Name: "signed", RequestedRef: subject.RequestedRef, ResolvedCommit: subject.Commit}, Project: map[string]any{}, Answers: map[string]stateledger.Answer{}, State: pointers}
	markerRaw, err := yaml.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".tplaiter", "project.yaml"), markerRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	evidenceRoot := filepath.Join(filepath.Dir(fixture.Scratch()), "evidence")
	localCAS, err := evidencecas.NewFSReader(evidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	rawInstall, err := os.ReadFile(filepath.Join(filepath.Dir(fixture.Scratch()), "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	install, err := trustload.DecodeRuntimeInstall(rawInstall)
	if err != nil {
		t.Fatal(err)
	}
	installDigest, err := install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	selection := trustload.LaunchSelection{Profile: install.Profile, RuntimeConfig: trustload.FilePin{Path: filepath.Join(filepath.Dir(fixture.Scratch()), "runtime.json"), SHA256: installDigest}, OperatorRecord: install.OperatorRecord, InstallationID: install.InstallationID}
	store, err := trustload.OpenReadOnly(context.Background(), selection)
	if err != nil {
		t.Fatal(err)
	}
	cas := &fixtureEvidenceReader{store: store, local: localCAS, trustRoot: filepath.Dir(evidenceRoot)}
	t.Cleanup(func() { _ = cas.Close() })
	return projectRoot, t.TempDir(), runtime, cas, refs.StatementCAS
}

type fixtureEvidenceReader struct {
	store     *trustload.Store
	local     *evidencecas.FSReader
	missing   string
	trustRoot string
}

func (r *fixtureEvidenceReader) Read(ctx context.Context, ref string) ([]byte, error) {
	if ref == r.missing {
		return nil, fmt.Errorf("fixture CAS miss: %w", fs.ErrNotExist)
	}
	if raw, err := r.store.Read(ctx, ref); err == nil {
		return raw, nil
	}
	return r.local.Read(ctx, ref)
}

func (r *fixtureEvidenceReader) Close() error {
	return errors.Join(r.store.Close(), r.local.Close())
}

func treeImage(t *testing.T, roots ...string) string {
	t.Helper()
	var rows []string
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			row := path + "|" + info.Mode().String()
			if info.Mode().IsRegular() {
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				hash := sha256.Sum256(data)
				row += "|" + hex.EncodeToString(hash[:])
			} else if info.Mode()&os.ModeSymlink != 0 {
				target, readErr := os.Readlink(path)
				if readErr != nil {
					return readErr
				}
				row += "|" + target
			}
			rows = append(rows, row)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

type restoringAuthority struct {
	*trustverify.Runtime
	restore func()
	once    bool
}

func (a *restoringAuthority) Binding() bootstrap.ProfileBinding {
	if !a.once {
		a.once = true
		a.restore()
	}
	return a.Runtime.Binding()
}

type cancellingAuthority struct {
	*trustverify.Runtime
	cancel context.CancelFunc
	calls  int
	at     int
}

func (a *cancellingAuthority) CheckProjectIdentity(ctx context.Context, root, id string) error {
	a.calls++
	if a.calls == a.at {
		a.cancel()
	}
	return a.Runtime.CheckProjectIdentity(ctx, root, id)
}

type changingCAS struct {
	evidencecas.Reader
	calls int
	hook  func(int)
}

func (r *changingCAS) Read(ctx context.Context, ref string) ([]byte, error) {
	r.calls++
	r.hook(r.calls)
	return r.Reader.Read(ctx, ref)
}

func oneDependency(t *testing.T, root string) (provenance.RootTemplateLock, provenance.TemplateLock) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, ".tplaiter", stateledger.RootLockFile))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := provenance.DecodeRootTemplateLock(raw)
	if err != nil {
		t.Fatal(err)
	}
	deps, err := stateledger.NewDependencyLock(*lock, []provenance.DependencySubject{provenance.DependencySubject(lock.Root)})
	if err != nil {
		t.Fatal(err)
	}
	return *lock, deps
}

func TestCanonicalObservationRestoresAuthenticB(t *testing.T) {
	root, home, runtime, cas, _ := signedProject(t)
	markerPath := filepath.Join(root, ".tplaiter", "project.yaml")
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	lock, deps := oneDependency(t, root)
	if err := os.WriteFile(markerPath, []byte("id: foreign-A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authority := &restoringAuthority{Runtime: runtime.TrustRuntime(), restore: func() {
		if err := os.WriteFile(markerPath, marker, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := stateledger.WriteLockPair(root, lock, deps); err != nil {
			t.Fatal(err)
		}
	}}
	report, err := Verify(context.Background(), root, authority, Options{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}})
	if err != nil || report.ProjectID != runtime.ProjectContext().ProjectID || report.DependencyCount != 1 || report.DependencyState != "verified" {
		t.Fatalf("foreign cached report: %+v %v", report, err)
	}
	if _, err := stateledger.VerifyStable(context.Background(), root, runtime.TrustRuntime(), stateledger.StableVerifyOptions{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}}); err != nil {
		t.Fatal(err)
	}
}

func TestMutableDependencyObservationRejectsChangeAllowsExactRevert(t *testing.T) {
	root, home, runtime, cas, _ := signedProject(t)
	lock, deps := oneDependency(t, root)
	empty, err := stateledger.NewDependencyLock(lock, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Four CAS reads occur in VerifyStable; the fifth is in summary projection.
	for _, start := range []int{1, 5} {
		for _, revert := range []bool{false, true} {
			if _, _, err := stateledger.WriteLockPair(root, lock, deps); err != nil {
				t.Fatal(err)
			}
			reader := &changingCAS{Reader: cas, hook: func(call int) {
				if call == start {
					if _, _, err := stateledger.WriteLockPair(root, lock, empty); err != nil {
						t.Fatal(err)
					}
				}
				if call == start+1 && revert {
					if _, _, err := stateledger.WriteLockPair(root, lock, deps); err != nil {
						t.Fatal(err)
					}
				}
			}}
			report, err := Verify(context.Background(), root, runtime.TrustRuntime(), Options{HomeRoot: home, CAS: reader, SecretProvider: publicHome{}})
			if revert {
				if err != nil || report.DependencyCount != 1 {
					t.Fatalf("exact revert: %+v %v", report, err)
				}
			} else if err == nil || !errors.Is(err, stateledger.ErrUnsafe) {
				t.Fatalf("mutation accepted: %+v %v", report, err)
			}
		}
	}
}

func TestCancelledSignedFIFOAndSymlinkDoNotRead(t *testing.T) {
	root, home, runtime, cas, _ := signedProject(t)
	marker := filepath.Join(root, ".tplaiter", "project.yaml")
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(marker, 0o600); err != nil {
		t.Fatal(err)
	}
	check := func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan error, 1)
		go func() {
			_, err := Verify(ctx, root, runtime.TrustRuntime(), Options{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}})
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) || resultdto.Classify(err) != ExitCancelled {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancelled verification blocked before context check")
		}
	}
	check()
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "unread-fifo")
	if err := syscall.Mkfifo(outside, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, marker); err != nil {
		t.Fatal(err)
	}
	check()
	if _, err := Verify(context.Background(), root, runtime.TrustRuntime(), Options{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}}); err == nil {
		t.Fatal("external symlink accepted")
	}
}

func TestLateRealIdentityCancellationAndTypedCodes(t *testing.T) {
	root, home, runtime, cas, _ := signedProject(t)
	for _, stage := range []int{2, 3} {
		ctx, cancel := context.WithCancel(context.Background())
		authority := &cancellingAuthority{Runtime: runtime.TrustRuntime(), cancel: cancel, at: stage}
		_, err := Verify(ctx, root, authority, Options{HomeRoot: home, CAS: cas, SecretProvider: publicHome{}})
		cancel()
		if !errors.Is(err, context.Canceled) || resultdto.Classify(err) != ExitCancelled {
			t.Fatalf("stage %d: %v", stage, err)
		}
		diagnostics := resultdto.ProjectDiagnostics(err)
		if len(diagnostics) != 1 || diagnostics[0].Code != CancelledCode {
			t.Fatal(diagnostics)
		}
	}
	for _, text := range []string{"unrelated digest mismatch", "unrelated active", "unrelated self hash", "nonterminal"} {
		diagnostic := resultdto.ProjectDiagnostics(classify(errors.New(text)))
		if len(diagnostic) != 1 || diagnostic[0].Code != StateCode {
			t.Fatal(text, diagnostic)
		}
	}
	invalid := classify(fmt.Errorf("%w: unrelated invalid evidence", stateledger.ErrEvidence))
	if resultdto.ProjectDiagnostics(invalid)[0].Code == OfflineMissCode {
		t.Fatal("invalid evidence called missing")
	}
}

func TestHeldObservationBoundsAndParentConfinement(t *testing.T) {
	root := t.TempDir()
	observation, err := OpenObservation(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observation.Close() }()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "asset"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "parent")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"parent/asset", "../outside", "/absolute"} {
		if _, err := observation.ReadState(context.Background(), rel); err == nil {
			t.Fatal("unconfined path accepted", rel)
		}
	}
	f, err := os.Create(filepath.Join(root, "huge"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((16 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := observation.ReadState(context.Background(), "huge"); !errors.Is(err, stateledger.ErrUnsafe) {
		t.Fatal("unbounded file accepted", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := observation.ReadState(ctx, "huge"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		err := classify(errors.Join(stateledger.ErrProjectIdentity, resultdto.NewDiagnosticError(resultdto.Diagnostic{Code: TrustCode}, resultdto.ExitTrust, cause)))
		if resultdto.Classify(err) != ExitCancelled || !errors.Is(err, cause) {
			t.Fatal("wrapped cancellation lost", err)
		}
	}
}
