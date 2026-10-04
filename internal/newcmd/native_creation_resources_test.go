package newcmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const publicGoCommit = "d0179547cd2e47b7564b0011bc5045799fc036bd"

// This harness reads only pinned Git objects. No checkout bytes, branch
// resolution, development authority or mocked trusted flag enter creation.
func nativeGoSource(t *testing.T, root, _, _, _ string) ([]byte, trustverify.Subject) {
	t.Helper()
	var fixture struct {
		Commit  string            `json:"commit"`
		Origin  string            `json:"origin"`
		Objects map[string][]byte `json:"objects"`
	}
	raw, err := os.ReadFile("testdata/nativecreationfixtures/template-go-d017.json")
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

type noNativeResourceSpawn struct{ t *testing.T }

func (r noNativeResourceSpawn) Run(_ context.Context, _ string, _ []string, _ execx.Options) (execx.Result, error) {
	r.t.Fatal("native resource creation spawned a tool")
	return execx.Result{}, errors.New("unexpected process")
}

func (r noNativeResourceSpawn) LookPath(_ string) (string, error) {
	r.t.Fatal("native resource creation probed a tool")
	return "", errors.New("unexpected probe")
}

func nativeGoFixture(t *testing.T) (*t5DIntegrationFixture, Options, Deps) {
	t.Helper()
	f := t5DNewIntegrationFixtureWithSource(t, nativeGoSource)
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	home := filepath.Join(f.dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	// Exercise an absent project target, not a pre-created output tree.
	if err := os.Remove(f.project); err != nil {
		t.Fatal(err)
	}
	return f, Options{Ref: publicGoCommit, ProjectName: "Neutral Service", Dir: f.project, Module: "example.test/neutral", Defaults: true, NoHooks: true, NoDepsCheck: true, CLIVersion: "v1.0.0"}, Deps{Runtime: runtime, Home: home, SourceInput: t5DSelection(f.source, f.sourceRefs), Runner: noNativeResourceSpawn{t}, Out: &bytes.Buffer{}, Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }}
}

func assertNativeGoResources(t *testing.T, f *t5DIntegrationFixture, d Deps) {
	t.Helper()
	read := func(p string) []byte {
		b, err := os.ReadFile(filepath.Join(f.project, p))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	root, err := provenance.DecodeRootTemplateLock(read(".tplaiter/root-template.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := resources.DecodeResourceLockV2(read(resources.NativeResourceLockPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Artifacts) != 6 || root.Root.Commit != publicGoCommit || root.Root.Origin != f.source.Origin {
		t.Fatalf("resource identity/count: %+v", lock)
	}
	selection, err := operationtrust.DecodeSourceSelection(d.SourceInput)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := d.Runtime.TrustRuntime().VerifySubject(context.Background(), selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.Runtime.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		t.Fatal(err)
	}
	images := &resources.ResourceImages{Files: map[string][]byte{}, Lock: *lock}
	var inv ownership.Inventory
	err = json.Unmarshal(read(ownership.InventoryRelPath), &inv)
	if err != nil {
		t.Fatal(err)
	}
	owned := map[string]ownership.Artifact{}
	for _, a := range inv.Artifacts {
		owned[a.Path] = a
	}
	for _, a := range lock.Artifacts {
		actual := read(a.Path)
		expected, ok := snapshot.Blob(a.SourcePath)
		if !ok || !bytes.Equal(actual, expected) || evidencecas.Digest(actual) != a.SHA256 {
			t.Fatalf("exact snippet bytes: %s", a.Path)
		}
		stat, err := os.Lstat(filepath.Join(f.project, a.Path))
		if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0o644 {
			t.Fatalf("snippet mode: %v %v", stat, err)
		}
		own, ok := owned[a.Path]
		if !ok || own.SHA256 != strings.TrimPrefix(a.SHA256, "sha256:") || own.Mode != a.Mode || own.Kind != "" || own.Target != "" {
			t.Fatalf("ownership: %+v", own)
		}
		images.Files[a.Path] = actual
	}
	if err := images.Validate(*root); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read(".tplaiter/generator-targets.lock.json"), []byte(`{"targets":[],"version":1}`)) {
		t.Fatal("generator was recorded as executed")
	}
	if !bytes.Contains(read("go.mod"), []byte("module example.test/neutral")) {
		t.Fatal("actual Go project not rendered")
	}
	projects, err := state.LoadProjects(d.Home)
	if err != nil || len(projects.Items) != 1 || projects.Items[0].ID != d.Runtime.ProjectContext().ProjectID || projects.Items[0].Path != f.project {
		t.Fatalf("registry: %+v %v", projects, err)
	}
	if journals, err := newtransaction.List(d.Home); err != nil || len(journals) != 0 {
		t.Fatalf("unfinalized transaction: %+v %v", journals, err)
	}
	// No provenance field can be inserted into the closed ownership wire.
	raw := read(ownership.InventoryRelPath)
	if bytes.Contains(raw, []byte(`"provider"`)) || bytes.Contains(raw, []byte(`"source"`)) {
		t.Fatal("provenance leaked into ownership")
	}
}

func TestNativeGoSignedCreateResources(t *testing.T) {
	f, opts, d := nativeGoFixture(t)
	if err := Run(context.Background(), opts, d); err != nil {
		t.Fatal(err)
	}
	assertNativeGoResources(t, f, d)
}

func TestNativeGoResourcesRecoverTogether(t *testing.T) {
	for _, point := range []string{"commit.before_staging_publish", "commit.after_staging_publish", "commit.after_registry", "finalize.before_journal"} {
		t.Run(point, func(t *testing.T) {
			f, opts, d := nativeGoFixture(t)
			err := runLive(context.Background(), opts, d, func(p string) error {
				if p == point {
					return newtransaction.ErrInjectedCrash
				}
				return nil
			})
			if !errors.Is(err, newtransaction.ErrInjectedCrash) {
				t.Fatal(err)
			}
			journals, err := newtransaction.List(d.Home)
			if err != nil || len(journals) != 1 {
				t.Fatalf("journals: %+v %v", journals, err)
			}
			if err := newtransaction.Continue(d.Home, journals[0].ID, d.Home); err != nil {
				t.Fatal(err)
			}
			assertNativeGoResources(t, f, d)
		})
	}
}

func TestNativeGoResourceTamperAndForeignRecoveryRefuse(t *testing.T) {
	for _, name := range []string{resources.NativeResourceLockPath, ".tplaiter/generators/generators/entity/types.go.tmpl", ".tplaiter/generators/foreign.txt"} {
		t.Run(name, func(t *testing.T) {
			f, opts, d := nativeGoFixture(t)
			var staging string
			err := runLive(context.Background(), opts, d, func(p string) error {
				if p != "commit.before_staging_publish" {
					return nil
				}
				journals, err := newtransaction.List(d.Home)
				if err != nil || len(journals) != 1 {
					t.Fatalf("journals: %v %v", journals, err)
				}
				staging = journals[0].Staging
				return os.WriteFile(filepath.Join(staging, name), []byte("foreign replacement"), 0o644)
			})
			if !errors.Is(err, newtransaction.ErrOwnershipUncertain) {
				t.Fatalf("tamper published: %v", err)
			}
			journals, _ := newtransaction.List(d.Home)
			if len(journals) != 1 {
				t.Fatalf("journals: %v", journals)
			}
			if err := newtransaction.Continue(d.Home, journals[0].ID, d.Home); err == nil {
				t.Fatal("recovery accepted tamper")
			}
			if err := newtransaction.AbortByID(d.Home, journals[0].ID); err == nil {
				t.Fatal("abort destroyed foreign bytes")
			}
			b, err := os.ReadFile(filepath.Join(staging, name))
			if err != nil || string(b) != "foreign replacement" {
				t.Fatal("foreign image lost")
			}
			if _, err := os.Lstat(f.project); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("project published: %v", err)
			}
			if _, err := os.Stat(state.ProjectsPath(d.Home)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("registry published")
			}
		})
	}
}

func TestNativeGoResourceCapabilityAndLockBinding(t *testing.T) {
	_, opts, d := nativeGoFixture(t)
	selected, _ := operationtrust.DecodeSourceSelection(d.SourceInput)
	resolution, err := d.Runtime.TrustRuntime().VerifySubject(context.Background(), selected.TrustSubject(), selected.EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare(context.Background(), d.Runtime, operationtrust.PrepareNewInput{SourceInput: d.SourceInput, Render: t5DRenderInput(), RendererVersion: opts.CLIVersion})
	if err != nil {
		t.Fatal(err)
	}
	root := prepared.RootLock()
	if _, err := resources.PlanNativeGeneratorImages(nil, resolution, root); err == nil {
		t.Fatal("nil runtime")
	}
	if _, err := resources.PlanNativeGeneratorImages(d.Runtime.TrustRuntime(), &trustverify.VerifiedResolution{}, root); err == nil {
		t.Fatal("forged capability")
	}
	if _, err := resources.PlanNativeGeneratorImages(d.Runtime.TrustRuntime(), resolution, root); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"bytes", "missing", "extra", "provider", "source", "mode", "path", "hash", "root", "profile", "order"} {
		t.Run(mutation, func(t *testing.T) {
			copyImages, err := resources.PlanNativeGeneratorImages(d.Runtime.TrustRuntime(), resolution, root)
			if err != nil {
				t.Fatal(err)
			}
			a := &copyImages.Lock.Artifacts[0]
			switch mutation {
			case "bytes":
				copyImages.Files[a.Path] = []byte("tamper")
			case "missing":
				delete(copyImages.Files, a.Path)
			case "extra":
				copyImages.Files[".tplaiter/generators/extra"] = nil
			case "provider":
				a.Provider.Origin = "https://foreign.test"
			case "source":
				a.Source.Commit = strings.Repeat("0", 40)
			case "mode":
				a.Mode = 0o755
			case "path":
				a.Path = ".tplaiter/project.yaml"
			case "hash":
				a.SHA256 = evidencecas.Digest(nil)
			case "root":
				copyImages.Lock.RootLockSHA256 = evidencecas.Digest(nil)
			case "profile":
				copyImages.Lock.TrustProfile.PolicySHA256 = evidencecas.Digest(nil)
			case "order":
				copyImages.Lock.Artifacts[0], copyImages.Lock.Artifacts[1] = copyImages.Lock.Artifacts[1], copyImages.Lock.Artifacts[0]
			}
			if copyImages.Validate(root) == nil {
				t.Fatal("lock/image tamper accepted")
			}
		})
	}
	wrong := root
	wrong.Root.SignatureCAS = evidencecas.Digest(nil)
	wrong.RootLockSHA256, err = wrong.ComputeSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resources.PlanNativeGeneratorImages(d.Runtime.TrustRuntime(), resolution, wrong); err == nil {
		t.Fatal("caller evidence accepted")
	}
}

func TestNativeGoConcurrentForeignBeforeSealing(t *testing.T) {
	for _, point := range []string{"begin.before_journal", "begin.after_marker"} {
		t.Run(point, func(t *testing.T) {
			f, opts, d := nativeGoFixture(t)
			var foreign string
			err := runLive(context.Background(), opts, d, func(p string) error {
				if p != point {
					return nil
				}
				root := f.project
				if point == "begin.after_marker" {
					matches, err := filepath.Glob(filepath.Join(filepath.Dir(root), "."+filepath.Base(root)+".tplaiter-new-*"))
					if err != nil || len(matches) != 1 {
						t.Fatalf("staging: %v %v", matches, err)
					}
					root = matches[0]
				}
				foreign = filepath.Join(root, "foreign.txt")
				return os.WriteFile(foreign, []byte("concurrent foreign"), 0o644)
			})
			if !errors.Is(err, newtransaction.ErrOwnershipUncertain) {
				t.Fatalf("foreign accepted: %v", err)
			}
			journals, err := newtransaction.List(d.Home)
			if err != nil || len(journals) != 1 {
				t.Fatalf("journal: %v %v", journals, err)
			}
			if newtransaction.Continue(d.Home, journals[0].ID, d.Home) == nil {
				t.Fatal("continued foreign image")
			}
			if newtransaction.AbortByID(d.Home, journals[0].ID) == nil {
				t.Fatal("deleted foreign image")
			}
			b, err := os.ReadFile(foreign)
			if err != nil || string(b) != "concurrent foreign" {
				t.Fatalf("lost foreign: %q %v", b, err)
			}
			if _, err := os.Stat(state.ProjectsPath(d.Home)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("foreign registered")
			}
		})
	}
}
