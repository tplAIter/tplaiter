package projectcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"

	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func TestRunFailsClosedWithoutStableAuthority(t *testing.T) {
	report, err := Run(context.Background(), Options{ProjectRoot: t.TempDir()})
	if err == nil || report.Status != "fail" || report.Managed.State != "invalid" {
		t.Fatalf("report=%+v err=%v", report, err)
	}

	result, code, resultErr := RunResult(context.Background(), Options{ProjectRoot: t.TempDir()}, "test")
	if resultErr == nil || code != int(resultdto.ExitTrust) || result.Status != resultdto.StatusBlocked {
		t.Fatalf("result=%+v code=%d err=%v", result, code, resultErr)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "TPL-E-TRUST-001" {
		t.Fatalf("diagnostics=%#v", result.Diagnostics)
	}
	var diagnosticErr *resultdto.DiagnosticError
	if !errors.As(resultErr, &diagnosticErr) {
		t.Fatalf("error type=%T", resultErr)
	}
}

func TestCheckManagedReportsModifiedMissingAndModeDrift(t *testing.T) {
	root := t.TempDir()
	writeManaged := func(rel, body string, mode os.FileMode) ownership.Artifact {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		artifact, err := ownership.ArtifactFor(rel, []byte(body), mode, "")
		if err != nil {
			t.Fatal(err)
		}
		return artifact
	}
	modified := writeManaged("modified.txt", "before", 0o644)
	missing := writeManaged("missing.txt", "gone", 0o644)
	mode := writeManaged("mode.txt", "mode", 0o644)
	if err := ownership.Initialize(root, map[string]ownership.Artifact{modified.Path: modified, missing.Path: missing, mode.Path: mode}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "modified.txt"), []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "missing.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "mode.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	managed, err := checkManaged(root)
	if err != nil {
		t.Fatal(err)
	}
	if managed.State != "drift" || managed.Modified == nil || managed.Missing == nil || len(managed.Modified) != 2 || len(managed.Missing) != 1 {
		t.Fatalf("managed=%+v", managed)
	}
}

func TestCheckManagedRejectsEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	artifact, err := ownership.ArtifactFor("bin/tool", []byte("../outside"), 0, "../outside")
	if err != nil {
		t.Fatal(err)
	}
	if err := ownership.Initialize(root, map[string]ownership.Artifact{artifact.Path: artifact}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside", filepath.Join(root, "bin", "tool")); err != nil {
		t.Fatal(err)
	}
	managed, err := checkManaged(root)
	if err != nil {
		t.Fatal(err)
	}
	if managed.State != "drift" || len(managed.Invalid) != 1 || managed.Invalid[0] != "bin/tool" {
		t.Fatalf("managed=%+v", managed)
	}
}

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
		return nil, errors.New("fixture CAS miss")
	}
	if raw, err := r.store.Read(ctx, ref); err == nil {
		return raw, nil
	}
	return r.local.Read(ctx, ref)
}

func (r *fixtureEvidenceReader) Close() error {
	return errors.Join(r.store.Close(), r.local.Close())
}

type publicHome struct{}

func (publicHome) DigestSecret(context.Context, stateledger.SecretLocator) (stateledger.SecretDigestResult, error) {
	return stateledger.SecretDigestResult{Classified: false}, nil
}

func TestSignedInventoryInvalidNeverProjectsOK(t *testing.T) {
	root, home, runtime, cas, _ := signedProject(t)
	opts := Options{ProjectRoot: root, HomeRoot: home, Authority: runtime.TrustRuntime(), CAS: cas, SecretProvider: publicHome{}}
	invalid := []string{
		`{}`, `{"Version":1}`, `{"version":1,"version":1}`, `{"version":1,"skipped":[{"path":"safe","reason":""}]}`, `{"version":1,"artifacts":[],"tombstones":["../escape"]}`,
		`{"version":1,"tombstones":["safe","safe"]}`,
		`{"version":1,"artifacts":[{"path":"safe","sha256":"bad"}]}`,
		`{"version":1,"artifacts":[{"path":"safe","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"device"}]}`,
		`{"version":1,"artifacts":[{"path":"safe","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mode":512}]}`,
		`{"version":1,"artifacts":[{"path":"safe","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"file"}],"tombstones":["safe"]}`,
		`{"version":1,"tombstones":[".tplaiter/update/active.json"]}`,
		`{"version":1,"artifacts":[{"path":"../outside","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`,
	}
	for _, raw := range invalid {
		if err := os.WriteFile(filepath.Join(root, ownership.InventoryRelPath), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		report, err := Run(context.Background(), opts)
		if err == nil || report.Status != "fail" || report.Managed.State != "invalid" || len(report.Managed.Invalid) == 0 {
			t.Fatalf("invalid ownership concealed: %s %+v %v", raw, report, err)
		}
		result, code, err := RunResult(context.Background(), opts, "test")
		if err == nil || code == 0 || result.Status == resultdto.StatusOK || len(result.Diagnostics) == 0 {
			t.Fatalf("invalid inventory projected ok: %s %+v %d %v", raw, result, code, err)
		}
	}
	body := []byte("owned source\n")
	if err := os.WriteFile(filepath.Join(root, "owned.txt"), body, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("owned.txt", filepath.Join(root, "owned-link")); err != nil {
		t.Fatal(err)
	}
	file, err := ownership.ArtifactFor("owned.txt", body, 0o640, "")
	if err != nil {
		t.Fatal(err)
	}
	link, err := ownership.ArtifactFor("owned-link", []byte("owned.txt"), 0, "owned.txt")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ownership.Inventory{Version: 1, Artifacts: []ownership.Artifact{file, link}, Tombstones: []string{"old.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ownership.InventoryRelPath), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	xdg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	before := treeImage(t, root, home, xdg, cas.trustRoot)
	oldTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) { t.Fatal("network during check"); return nil, nil })
	report, err := Run(context.Background(), opts)
	if err != nil || report.Status != "pass" || report.Managed.State != "clean" {
		t.Fatalf("valid source ownership refused: %+v %v", report, err)
	}
	result, code, err := RunResult(context.Background(), opts, "test")
	if err != nil || code != 0 || result.Status != resultdto.StatusOK {
		t.Fatalf("clean result: %+v %d %v", result, code, err)
	}
	if before != treeImage(t, root, home, xdg, cas.trustRoot) {
		t.Fatal("check wrote project, HOME/XDG or trust/source root")
	}
}

func TestHeldOwnershipReaderRefusesFIFOAndExternalSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".tplaiter"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ownership.InventoryRelPath)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := checkManagedObserved(context.Background(), root, nil); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("inventory FIFO blocked")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-fifo")
	if err := syscall.Mkfifo(outside, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	_, err := checkManagedObserved(context.Background(), root, nil)
	if err == nil {
		t.Fatal("inventory symlink followed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = checkManagedObserved(ctx, root, nil)
	if !errors.Is(err, context.Canceled) || resultdto.Classify(err) != projectverify.ExitCancelled {
		t.Fatal(err)
	}
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

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRemovedVerifiedInventoryIsNotClean(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".tplaiter"), 0o700); err != nil {
		t.Fatal(err)
	}
	snapshot := &stateledger.Snapshot{Entries: []stateledger.Entry{{Scope: "project", Path: ownership.InventoryRelPath, Exists: true}}}
	state, err := checkManagedObserved(context.Background(), root, snapshot)
	if err == nil || state.State != "invalid" {
		t.Fatalf("removed verified inventory concealed: %+v %v", state, err)
	}
}
