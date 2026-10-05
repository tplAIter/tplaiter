//go:build darwin || linux

package gen_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"gopkg.in/yaml.v3"
)

const publicGoCommit = "d0179547cd2e47b7564b0011bc5045799fc036bd"

func strconvItoa(v int) string { return strconv.Itoa(v) }

type noNativeResourceSpawn struct{ t *testing.T }

func (r noNativeResourceSpawn) Run(context.Context, string, []string, execx.Options) (execx.Result, error) {
	r.t.Fatal("unexpected command execution")
	return execx.Result{}, errors.New("spawn refused")
}

func (r noNativeResourceSpawn) LookPath(string) (string, error) {
	r.t.Fatal("unexpected tool probe")
	return "", errors.New("probe refused")
}

func nativeGoSource(t *testing.T, root, _, _, _ string) ([]byte, trustverify.Subject) {
	t.Helper()
	var fixture struct {
		Commit  string            `json:"commit"`
		Origin  string            `json:"origin"`
		Objects map[string][]byte `json:"objects"`
	}
	raw, err := os.ReadFile("../newcmd/testdata/nativecreationfixtures/template-go-d017.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != publicGoCommit || fixture.Origin != "https://github.com/tplAIter/template-go" {
		t.Fatal("wrong public fixture")
	}
	object := func(kind, id string) []byte {
		raw, ok := fixture.Objects[id]
		if !ok {
			t.Fatalf("missing fixture object %s", id)
		}
		header, data, ok := bytes.Cut(raw, []byte{0})
		if !ok || string(header) != kind+" "+strconv.Itoa(len(data)) {
			t.Fatal("bad fixture frame")
		}
		return data
	}

	put := func(kind, id string) []byte {
		b := object(kind, id)
		raw := append([]byte(kind+" "+strconvItoa(len(b))+"\x00"), b...)
		if err := os.WriteFile(filepath.Join(root, id), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return b
	}
	commit := put("commit", publicGoCommit)
	tree := strings.TrimPrefix(strings.SplitN(string(commit), "\n", 2)[0], "tree ")
	put("tree", tree)
	var entries []trustverify.SourceEntry
	var contract []byte
	var walk func(string, string)
	walk = func(treeID, prefix string) {
		data := object("tree", treeID)
		for len(data) > 0 {
			header, rest, ok := bytes.Cut(data, []byte{0})
			if !ok || len(rest) < 20 {
				t.Fatal("bad Git tree")
			}
			mode, name, ok := strings.Cut(string(header), " ")
			if !ok {
				t.Fatal("bad tree entry")
			}
			oid := hex.EncodeToString(rest[:20])
			data = rest[20:]
			kind := "blob"
			entry := trustverify.SourceEntry{Path: prefix + name, Kind: "file", Mode: mode}
			if mode == "40000" {
				kind = "tree"
				entry.Kind = "directory"
			}
			b := put(kind, oid)
			if kind == "blob" {
				entry.ContentSHA256 = evidencecas.Digest(b)
			}
			if entry.Path == "template.contract.json" {
				contract = b
			}
			entries = append(entries, entry)
			if kind == "tree" {
				walk(oid, prefix+name+"/")
			}
		}
	}
	walk(tree, "")

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	treeDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-content-tree/v1", struct {
		APIVersion string                    `json:"apiVersion"`
		Entries    []trustverify.SourceEntry `json:"entries"`
	}{"tplaiter.dev/source-content-tree/v1", entries})
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", evidencecas.Digest(contract)})
	if err != nil {
		t.Fatal(err)
	}
	return contract, trustverify.Subject{Origin: "https://github.com/tplAIter/template-go", TemplatePath: ".", RequestedRef: publicGoCommit, Commit: publicGoCommit, TreeSHA256: treeDigest, ContractSHA256: contractDigest}
}

func nativeSignedProject(t *testing.T) (*trustload.Runtime, string, string) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rawObjects := filepath.Join(base, "raw")
	if err := os.Mkdir(rawObjects, 0o700); err != nil {
		t.Fatal(err)
	}
	_, publicSubject := nativeGoSource(t, rawObjects, "", "", "")
	repository := filepath.Join(base, "source")
	entries, err := os.ReadDir(rawObjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		id := entry.Name()
		raw, err := os.ReadFile(filepath.Join(rawObjects, id))
		if err != nil {
			t.Fatal(err)
		}
		objectPath := filepath.Join(repository, ".git", "objects", id[:2], id[2:])
		if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(objectPath)
		if err != nil {
			t.Fatal(err)
		}
		writer := zlib.NewWriter(file)
		if _, err := writer.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repository, ".git", "config"), []byte("[core]\nrepositoryformatversion=0\nbare=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "project")
	result, err := ossinstall.GenerateWithContext(ctx, ossinstall.Options{
		Root:            filepath.Join(base, "installation"),
		LocalSources:    []sourcepackage.CaptureInput{{RepositoryPath: repository, Origin: publicSubject.Origin, TemplatePath: ".", Commit: publicGoCommit}},
		ProjectContexts: []trustload.ProjectContext{{Key: "go", ProjectID: "project-local-go", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: target}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PublicationState != "committed" {
		t.Fatalf("installation publication: %s", result.PublicationState)
	}
	registrationRaw, err := os.ReadFile(result.RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	if evidencecas.Digest(registrationRaw) != result.RegistrationSHA256 {
		t.Fatal("registration raw pin mismatch")
	}
	registration, err := ossinstall.DecodeRegistration(registrationRaw)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := trustload.Load(ctx, registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	// Enroll only the ordinary bootstrap closure. Source CAS remains in the
	// published installation; it is not injected as privileged store material.
	stateRaw, err := os.ReadFile(loaded.Install.OSS.InitialStatePath)
	if err != nil {
		t.Fatal(err)
	}
	bundleRaw, err := os.ReadFile(loaded.Install.OSS.InitialBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := trustload.DecodeStoredBundle(bundleRaw)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := evidencecas.NewFSReader(loaded.Install.EvidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	refs := []string{bundle.EnvelopeCAS, bundle.ReceiptCAS, bundle.Transparency.CheckpointCAS, bundle.Transparency.InclusionProofCAS}
	evidence := map[string][]byte{}
	for i := 0; i < len(refs); i++ {
		ref := refs[i]
		if _, ok := evidence[ref]; ok {
			continue
		}
		raw, err := reader.Read(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		evidence[ref] = raw
		if ref == bundle.EnvelopeCAS {
			envelope, err := bootstrap.DecodeEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range envelope.RootKeys {
				refs = append(refs, key.PublicKeyCAS)
			}
			for _, signature := range envelope.Signatures {
				refs = append(refs, signature.SignatureCAS)
			}
		}
	}
	factory := func(r evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(r, bootstrap.ClockFunc(time.Now), nil, 0)
	}
	if err := trustload.Enroll(ctx, registration.Selection(), factory, stateRaw, bundleRaw, evidence); err != nil {
		t.Fatal(err)
	}
	runtime, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: registration.Selection(), ProjectKey: "go", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	selectionsRaw, err := os.ReadFile(result.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var selections []operationtrust.SourceSelection
	if err := canonicaljson.DecodeStrict(selectionsRaw, &selections); err != nil || len(selections) != 1 {
		t.Fatalf("selection: %v %v", selections, err)
	}
	selected := selections[0]
	if selected.TrustSubject() != publicSubject {
		t.Fatal("capture changed exact public subject")
	}
	resolution, err := runtime.TrustRuntime().VerifySubject(ctx, selected.TrustSubject(), selected.EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	if !resolution.ValidFor(runtime.TrustRuntime(), runtime.TrustRuntime().Binding()) {
		t.Fatal("source capability not runtime-bound")
	}
	recordRaw, err := os.ReadFile(filepath.Join(result.Root, "config", "local-publisher.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record ossinstall.LocalPublication
	if err := canonicaljson.DecodeStrict(recordRaw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Issuer != "local-operator-"+strings.TrimPrefix(record.KeyFingerprint, "sha256:") || record.Mode != "local-operator" || record.Subject.Commit != publicGoCommit || record.Subject.TreeSHA256 != publicSubject.TreeSHA256 || record.Subject.ContractSHA256 != publicSubject.ContractSHA256 || record.KeyFingerprint != selected.Evidence.KeyFingerprint || bytes.Contains(recordRaw, []byte(repository)) {
		t.Fatal("local operator publication tuple mismatch")
	}
	// Once verified, removal of the input object repository cannot affect new.
	if err := os.RemoveAll(repository); err != nil {
		t.Fatal(err)
	}
	sourceInput, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	d := newcmd.Deps{Runtime: runtime, Home: home, SourceInput: sourceInput, Runner: noNativeResourceSpawn{t}, Out: &bytes.Buffer{}}
	opts := newcmd.Options{Ref: publicGoCommit, ProjectName: "Local Go", Dir: target, Module: "example.test/neutral", Defaults: true, NoHooks: true, NoDepsCheck: true, CLIVersion: "v1.0.0"}
	if err := newcmd.Run(ctx, opts, d); err != nil {
		t.Fatal(err)
	}
	launch, err := json.Marshal(registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "fixture-launch.json"), launch, 0o600); err != nil {
		t.Fatal(err)
	}
	return runtime, home, target
}

func nativePlan(t *testing.T, r *trustload.Runtime, home string) *gen.NativePlan {
	t.Helper()
	p, err := gen.PlanNative(context.Background(), r, home, []gen.NativeOperation{{Kind: "entity", Name: "Widget", Provided: nil}})
	if _, ok := any(r.TrustRuntime()).(interface {
		CheckProjectIdentity(context.Context, string, string) error
	}); !ok {
		if !errors.Is(err, gen.ErrNativeIdentityUnavailable) {
			t.Fatalf("missing identity API did not refuse: %v", err)
		}
		t.Skip("accepted identity API not integrated in base; test its fail-closed boundary")
	}
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNativeSignedPlanAndOwnedCommit(t *testing.T) {
	r, home, root := nativeSignedProject(t)
	p := nativePlan(t, r, home)
	result := p.Result()
	if len(result.CreatedFiles) == 0 {
		t.Fatal("no outputs")
	}
	for _, name := range result.CreatedFiles {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("planning wrote output")
		}
	}
	for _, action := range []gen.NativeAction{gen.NativeFormat, gen.NativeBuild, gen.NativeHook} {
		if !errors.Is(p.ExecuteAction(context.Background(), action), gen.ErrExecutionUnavailable) {
			t.Fatal("action became executable")
		}
	}
	// Caller mutation of reporting slices cannot redirect writer authority.
	result.CreatedFiles[0] = "foreign.txt"
	tx, err := projecttransaction.BeginNative(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "foreign.txt")); !os.IsNotExist(err) {
		t.Fatal("report changed authority")
	}
	if _, err := gen.PlanNative(context.Background(), r, home, []gen.NativeOperation{{Kind: "entity", Name: "Widget", Provided: nil}}); err == nil {
		t.Fatal("repeat accepted")
	}
}

func TestNativeSignedRefusesTamperedMaterial(t *testing.T) {
	for _, name := range []string{".tplaiter/generators/generators/entity/types.go.tmpl", ".tplaiter/resources.lock.json", ".tplaiter/root-template.lock.json", ".tplaiter/project.yaml"} {
		t.Run(name, func(t *testing.T) {
			r, home, root := nativeSignedProject(t)
			if _, ok := any(r.TrustRuntime()).(interface {
				CheckProjectIdentity(context.Context, string, string) error
			}); !ok {
				t.Skip("identity API integration required")
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte("tampered"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := gen.PlanNative(context.Background(), r, home, []gen.NativeOperation{{Kind: "entity", Name: "Widget"}}); err == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
}

func TestNativeSignedRollbackModesAndRecovery(t *testing.T) {
	r, home, root := nativeSignedProject(t)
	// Mode preservation is part of the exact captured beforeimage, including
	// preexisting files untouched by generation.
	if err := os.Chmod(filepath.Join(root, "cmd/service/main.go"), 0o600); err != nil {
		t.Fatal(err)
	}
	rawInventory, err := os.ReadFile(filepath.Join(root, ".tplaiter/ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inv ownership.Inventory
	if err := json.Unmarshal(rawInventory, &inv); err != nil {
		t.Fatal(err)
	}
	for i := range inv.Artifacts {
		if inv.Artifacts[i].Path == "cmd/service/main.go" {
			inv.Artifacts[i].Mode = 0o600
		}
	}
	rawInventory, err = canonicaljson.Canonical(inv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".tplaiter/ownership.json"), rawInventory, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, ".tplaiter/ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := nativePlan(t, r, home)
	tx, err := projecttransaction.BeginNative(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := tx.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	tx, err = projecttransaction.OpenNative(context.Background(), r, home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(filepath.Join(root, "cmd/service/main.go"))
	if err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatal("before mode lost")
	}
	after, err := os.ReadFile(filepath.Join(root, ".tplaiter/ownership.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("ownership beforeimage lost")
	}
	for _, name := range p.Result().CreatedFiles {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("output survived rollback")
		}
	}
}

func TestNativeSignedForeignStageAndJournalRefuse(t *testing.T) {
	r, home, root := nativeSignedProject(t)
	p := nativePlan(t, r, home)
	tx, err := projecttransaction.BeginNative(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := tx.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	if err := newtransaction.Continue(home, id, home); err == nil {
		t.Fatal("generic creation recovery accepted typed gen journal")
	}
	foreign := filepath.Join(root, p.Result().CreatedFiles[0])
	old, err := os.ReadFile(foreign)
	if err != nil {
		t.Fatal(err)
	}
	replacement := foreign + ".foreign"
	if err := os.WriteFile(replacement, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, foreign); err != nil {
		t.Fatal(err)
	}
	r = reopenNativeRuntime(t, r, home)
	cold, err := projecttransaction.OpenNative(context.Background(), r, home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Release()
	if err := cold.Rollback(context.Background()); !errors.Is(err, projecttransaction.ErrConflict) {
		t.Fatalf("foreign rollback: %v", err)
	}
	if b, err := os.ReadFile(foreign); err != nil || string(b) != "foreign" || bytes.Equal(b, old) {
		t.Fatal("foreign replacement lost")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("original root disappeared")
	}
	journal := filepath.Join(home, "transactions", "project", "tx-"+id, "state.json")
	if err := os.WriteFile(journal, []byte(`{"payload":{},"mac":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cold.Release()
	if _, err := projecttransaction.OpenNative(context.Background(), r, home, id); !errors.Is(err, projecttransaction.ErrAuthentication) {
		t.Fatalf("tampered journal: %v", err)
	}
}

func TestNativeSignedForeignTargetAndCancelledStart(t *testing.T) {
	r, home, root := nativeSignedProject(t)
	p := nativePlan(t, r, home)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := projecttransaction.BeginNative(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	result := p.Result()
	name := filepath.Join(root, result.CreatedFiles[0])
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("foreign target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := projecttransaction.BeginNative(context.Background(), p); !errors.Is(err, gen.ErrNativeOwnership) && !errors.Is(err, projecttransaction.ErrConflict) {
		t.Fatalf("foreign target: %v", err)
	}
	if b, err := os.ReadFile(name); err != nil || string(b) != "foreign target" {
		t.Fatal("foreign target lost")
	}
}

func TestNativeSignedColdRecoveryCommits(t *testing.T) {
	r, home, root := nativeSignedProject(t)
	p := nativePlan(t, r, home)
	tx, err := projecttransaction.BeginNative(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	r = reopenNativeRuntime(t, r, home)
	cold, err := projecttransaction.OpenNative(context.Background(), r, home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Release()
	if err := cold.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cold.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range p.Result().CreatedFiles {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func reopenNativeRuntime(t *testing.T, old *trustload.Runtime, home string) *trustload.Runtime {
	t.Helper()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, "fixture-launch.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selection trustload.LaunchSelection
	if err := json.Unmarshal(raw, &selection); err != nil {
		t.Fatal(err)
	}
	fresh, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: selection, ProjectKey: "go", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	return fresh
}

func TestNativeSignedForeignAnchorRefused(t *testing.T) {
	for _, remove := range []bool{true, false} {
		t.Run(strconv.FormatBool(remove), func(t *testing.T) {
			r, home, root := nativeSignedProject(t)
			name := filepath.Join(root, "cmd/service/main.go")
			original, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			foreign := append([]byte("// foreign\n"), original...)
			replacement := name + ".foreign"
			if err := os.WriteFile(replacement, foreign, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, name); err != nil {
				t.Fatal(err)
			}
			identity, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			if remove {
				ledger := filepath.Join(root, ".tplaiter/ownership.json")
				raw, err := os.ReadFile(ledger)
				if err != nil {
					t.Fatal(err)
				}
				var inv ownership.Inventory
				if err := json.Unmarshal(raw, &inv); err != nil {
					t.Fatal(err)
				}
				kept := inv.Artifacts[:0]
				for _, a := range inv.Artifacts {
					if a.Path != "cmd/service/main.go" {
						kept = append(kept, a)
					}
				}
				inv.Artifacts = kept
				raw, err = canonicaljson.Canonical(inv)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(ledger, raw, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := gen.PlanNative(context.Background(), r, home, []gen.NativeOperation{{Kind: "entity", Name: "Widget"}}); err == nil {
				t.Fatal("foreign anchor adopted")
			}
			actual, err := os.ReadFile(name)
			info, staterr := os.Stat(name)
			if err != nil || staterr != nil || !bytes.Equal(actual, foreign) || info.Mode().Perm() != 0o600 || !os.SameFile(identity, info) {
				t.Fatal("foreign anchor changed")
			}
		})
	}
}

// Fault injection uses only context checks already required by the production
// primitive, at a real observed ledger publication; no writer hook grants trust.
type ledgerFaultContext struct {
	context.Context
	once      sync.Once
	observe   func() bool
	fault     func()
	cancelled bool
}

func (c *ledgerFaultContext) Err() error {
	if c.observe() {
		c.once.Do(c.fault)
	}
	if c.cancelled {
		return context.Canceled
	}
	return nil
}

func TestNativeSignedPartialLedgerFaults(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(strconv.FormatBool(cancel), func(t *testing.T) {
			r, home, root := nativeSignedProject(t)
			p := nativePlan(t, r, home)
			ledger := filepath.Join(root, ".tplaiter/generator-targets.lock.json")
			before, readerr := os.ReadFile(ledger)
			existed := readerr == nil
			ownershipPath := filepath.Join(root, ".tplaiter/ownership.json")
			beforeOwnership, err := os.ReadFile(ownershipPath)
			if err != nil {
				t.Fatal(err)
			}
			anchor := filepath.Join(root, "cmd/service/main.go")
			anchorBefore, err := os.ReadFile(anchor)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := projecttransaction.BeginNative(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Release()
			triggered := false
			var foreignInfo os.FileInfo
			ctx := &ledgerFaultContext{Context: context.Background()}
			ctx.observe = func() bool {
				current, err := os.ReadFile(ledger)
				return err == nil && (!existed || !bytes.Equal(current, before))
			}
			ctx.fault = func() {
				triggered = true
				if cancel {
					ctx.cancelled = true
					return
				}
				replacement := anchor + ".foreign"
				if err := os.WriteFile(replacement, []byte("foreign anchor"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, anchor); err != nil {
					t.Fatal(err)
				}
				foreignInfo, _ = os.Stat(anchor)
			}
			err = tx.Apply(ctx)
			if !triggered || err == nil {
				t.Fatalf("fault not refused: triggered=%v err=%v", triggered, err)
			}
			if cancel && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if _, err := os.Stat(root); err != nil {
				t.Fatal("root absent")
			}
			actual, err := os.ReadFile(ownershipPath)
			if err != nil || !bytes.Equal(actual, beforeOwnership) {
				t.Fatal("partial ownership rollback failed")
			}
			actual, err = os.ReadFile(ledger)
			if existed {
				if err != nil || !bytes.Equal(actual, before) {
					t.Fatal("ledger beforeimage lost")
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("new ledger survived rollback")
			}
			actual, err = os.ReadFile(anchor)
			info, staterr := os.Stat(anchor)
			if cancel {
				if err != nil || !bytes.Equal(actual, anchorBefore) {
					t.Fatal("anchor beforeimage lost")
				}
			} else if err != nil || staterr != nil || string(actual) != "foreign anchor" || !os.SameFile(info, foreignInfo) {
				t.Fatal("foreign inode lost")
			}
			id := tx.ID()
			tx.Release()
			r = reopenNativeRuntime(t, r, home)
			cold, err := projecttransaction.OpenNative(context.Background(), r, home, id)
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Release()
			err = cold.Rollback(context.Background())
			if cancel {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, projecttransaction.ErrConflict) {
				t.Fatalf("cold conflict: %v", err)
			}
		})
	}
}

func TestNativeTransactionKilledChild(t *testing.T) {
	home := os.Getenv("TPLAITER_NATIVE_TX_CHILD_HOME")
	if home == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(home, "fixture-launch.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selection trustload.LaunchSelection
	if err := json.Unmarshal(raw, &selection); err != nil {
		t.Fatal(err)
	}
	r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: selection, ProjectKey: "go", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p := nativePlan(t, r, home)
	tx, err := projecttransaction.BeginNative(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := os.WriteFile(filepath.Join(home, "child-id"), []byte(tx.ID()), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(r.ProjectContext().RootPath, ".tplaiter/generator-targets.lock.json")
	ctx := &ledgerFaultContext{Context: context.Background()}
	ctx.observe = func() bool { _, err := os.Stat(ledger); return err == nil }
	ctx.fault = func() {
		if err := os.WriteFile(filepath.Join(home, "child-paused"), []byte("published-ledger"), 0o600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	if err := tx.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	t.Fatal("child reached end without boundary pause")
}

func TestNativeSignedKilledProcessRecovery(t *testing.T) {
	r, home, root := nativeSignedProject(t)
	p := nativePlan(t, r, home)
	// Only this exact owned test executable/PID is launched and killed. Production
	// formatting/build/hook execution remains unavailable.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestNativeTransactionKilledChild$", "-test.timeout=45s")
	cmd.Env = []string{"TPLAITER_NATIVE_TX_CHILD_HOME=" + home}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(home, "child-paused")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			waited = true
			t.Fatalf("no child boundary: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waited = true
	if _, err := os.Stat(root); err != nil {
		t.Fatal("root disappeared during partial apply")
	}
	raw, err := os.ReadFile(filepath.Join(home, "child-id"))
	if err != nil {
		t.Fatal(err)
	}
	r = reopenNativeRuntime(t, r, home)
	cold, err := projecttransaction.OpenNative(context.Background(), r, home, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Release()
	if err := cold.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range p.Result().CreatedFiles {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeSignedColdTamperingRefused(t *testing.T) {
	for _, target := range []string{"plan", "snippet", "afterimage"} {
		t.Run(target, func(t *testing.T) {
			r, home, root := nativeSignedProject(t)
			p := nativePlan(t, r, home)
			tx, err := projecttransaction.BeginNative(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			id := tx.ID()
			tx.Release()
			switch target {
			case "plan":
				name := filepath.Join(home, "transactions/project/tx-"+id, "plan.json")
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				changed := bytes.Replace(raw, []byte("Widget"), []byte("Forged"), 1)
				if bytes.Equal(changed, raw) {
					t.Fatal("no changed plan input")
				}
				if err := os.WriteFile(name, changed, 0o600); err != nil {
					t.Fatal(err)
				}
			case "snippet":
				name := filepath.Join(root, ".tplaiter/generators/generators/entity/types.go.tmpl")
				if err := os.WriteFile(name, []byte("foreign snippet"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "afterimage":
				name := filepath.Join(root, ".tplaiter/project-transactions", id, "000000")
				if err := os.WriteFile(name, []byte("forged afterimage"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			r = reopenNativeRuntime(t, r, home)
			cold, err := projecttransaction.OpenNative(context.Background(), r, home, id)
			if target == "afterimage" {
				if err != nil {
					t.Fatal(err)
				}
				defer cold.Release()
				if err := cold.Apply(context.Background()); err == nil {
					t.Fatal("afterimage accepted")
				}
			} else if err == nil {
				cold.Release()
				t.Fatal("cold tamper admitted")
			}
			for _, name := range p.Result().CreatedFiles {
				if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
					t.Fatal("tampered recovery published")
				}
			}
			if _, err := os.Stat(root); err != nil {
				t.Fatal("root absent")
			}
		})
	}
}

func TestNativeSignedReleasedStageGenericRefused(t *testing.T) {
	r, home, root := nativeSignedProject(t)
	p := nativePlan(t, r, home)
	tx, err := projecttransaction.BeginNative(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	if err := newtransaction.Continue(home, id, home); err == nil {
		t.Fatal("generic recovery published unapplied native stage")
	}
	// Even placement in the creation namespace cannot turn the typed envelope
	// into a creation journal; its closed wire/version contract refuses it.
	copied := filepath.Join(home, "transactions/new/tx-"+id)
	if err := os.MkdirAll(copied, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, "transactions/project/tx-"+id, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "active.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newtransaction.Continue(home, id, home); err == nil {
		t.Fatal("creation decoder accepted native envelope")
	}
	for _, name := range p.Result().CreatedFiles {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("generic recovery wrote output")
		}
	}
	r = reopenNativeRuntime(t, r, home)
	cold, err := projecttransaction.OpenNative(context.Background(), r, home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Release()
	if err := cold.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSignedForeignHomeColdRefused(t *testing.T) {
	r, home, _ := nativeSignedProject(t)
	p := nativePlan(t, r, home)
	tx, err := projecttransaction.BeginNative(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	heldHome := home + ".original"
	if err := os.Rename(home, heldHome); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(home, "foreign")
	if err := os.WriteFile(sentinel, []byte("foreign-home"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "transactions/project/tx-"+id)
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"plan.json", "state.json"} {
		raw, err := os.ReadFile(filepath.Join(heldHome, "transactions/project/tx-"+id, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if cold, err := projecttransaction.OpenNative(context.Background(), r, home, id); err == nil {
		cold.Release()
		t.Fatal("foreign home adopted")
	}
	actual, err := os.ReadFile(sentinel)
	current, other := os.Stat(sentinel)
	if err != nil || other != nil || string(actual) != "foreign-home" || !os.SameFile(identity, current) {
		t.Fatal("foreign home modified")
	}
	if _, err := os.Stat(filepath.Join(home, ".lock")); !os.IsNotExist(err) {
		t.Fatal("lock created in foreign home")
	}
}

// Synthetic stable policy-bearing ledgers exercise both fresh planning and cold
// semantic reconstruction; this is not COORD6.4 adoption delivery evidence.
func TestNativeSignedExcludedPolicyRefusesFreshAndCold(t *testing.T) {
	for _, kind := range []string{"ownership", "skipped", "tombstone"} {
		for _, present := range []bool{false, true} {
			t.Run(kind+"/"+strconv.FormatBool(present), func(t *testing.T) {
				r, home, root := nativeSignedProject(t)
				p := nativePlan(t, r, home)
				material, _, err := p.TransactionMaterial(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				target := p.Result().CreatedFiles[0]
				markerPath := filepath.Join(root, ".tplaiter/project.yaml")
				inventoryPath := filepath.Join(root, ownership.InventoryRelPath)
				markerRaw, err := os.ReadFile(markerPath)
				if err != nil {
					t.Fatal(err)
				}
				inventoryRaw, err := os.ReadFile(inventoryPath)
				if err != nil {
					t.Fatal(err)
				}
				var marker stateledger.ProjectV2
				if err := yaml.Unmarshal(markerRaw, &marker); err != nil {
					t.Fatal(err)
				}
				var inventory ownership.Inventory
				if err := canonicaljson.DecodeStrict(inventoryRaw, &inventory); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "ownership":
					marker.Ownership = map[string]any{"user_owned": []string{target}}
				case "skipped":
					inventory.Skipped = []ownership.Decision{{Path: target, Reason: "user-owned"}}
				case "tombstone":
					inventory.Tombstones = []string{target}
				}
				markerRaw, err = yaml.Marshal(marker)
				if err != nil {
					t.Fatal(err)
				}
				inventoryRaw, err = canonicaljson.Canonical(inventory)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(markerPath, markerRaw, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(inventoryPath, inventoryRaw, 0644); err != nil {
					t.Fatal(err)
				}
				targetPath := filepath.Join(root, target)
				if present {
					if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(targetPath, []byte("user-owned bytes"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := stateledger.VerifyStable(context.Background(), root, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
					t.Fatalf("synthetic fixture must be stable: %v", err)
				}
				if _, err := gen.PlanNative(context.Background(), r, home, []gen.NativeOperation{{Kind: "entity", Name: "Widget"}}); !errors.Is(err, gen.ErrNativeOwnership) {
					t.Fatalf("fresh: %v", err)
				}
				markerFile := material.Before[".tplaiter/project.yaml"]
				markerFile.Data = markerRaw
				material.Before[".tplaiter/project.yaml"] = markerFile
				inventoryFile := material.Before[ownership.InventoryRelPath]
				inventoryFile.Data = inventoryRaw
				material.Before[ownership.InventoryRelPath] = inventoryFile
				if present {
					material.Before[target] = gen.NativeFile{Data: []byte("user-owned bytes"), Mode: 0600}
				}
				if err := gen.AuthenticateNativeMaterial(context.Background(), r, material); !errors.Is(err, gen.ErrNativeOwnership) {
					t.Fatalf("cold reconstruction: %v", err)
				}
				gotMarker, _ := os.ReadFile(markerPath)
				gotInventory, _ := os.ReadFile(inventoryPath)
				if !bytes.Equal(gotMarker, markerRaw) || !bytes.Equal(gotInventory, inventoryRaw) {
					t.Fatal("refusal mutated ledger")
				}
				got, err := os.ReadFile(targetPath)
				if present {
					if err != nil || string(got) != "user-owned bytes" {
						t.Fatal("excluded target changed")
					}
				} else if !os.IsNotExist(err) {
					t.Fatal("missing excluded target created")
				}
			})
		}
	}
}
