package contextcmd

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

type rootFixture struct {
	objectRoot          string
	runtime             *trustload.Runtime
	root, home, install string
	selection           operationtrust.SourceSelection
}

func rootRequest(selectors ...string) RootSelectionRequest {
	r := RootSelectionRequest{Selections: []exports.Selection{}}
	for _, s := range selectors {
		r.Selections = append(r.Selections, exports.Selection{APIVersion: exports.SelectionAPIVersion, Selector: s, Bindings: []exports.ScalarParameter{}})
	}
	return r
}

func rootJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// The repository consists solely of generic public test data. Loose immutable
// Git objects are authored in memory; no commit/push or provider program runs.
func rootFixtureSource(t *testing.T, repo string, variant string) string {
	t.Helper()
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: neutral-context\n  version: 1.0.0\nengine:\n  type: gotemplate\n  root: files\n")
	contract := rootJSON(t, operationtrust.NativeContract{APIVersion: operationtrust.NativeContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: []string{}})
	contractDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", evidencecas.Digest(contract)})
	if err != nil {
		t.Fatal(err)
	}
	tool := []byte("Readonly task context, no tool execution.\n")
	files := map[string][]byte{"template.manifest.yaml": manifest, "template.contract.json": contract, "files/hello.txt.tmpl": []byte("hello\n"), DefaultRootBindingsPath: rootBindingWire(), "catalog/tool.md": tool}
	entries := []exports.ExportEntry{}
	for _, v := range []struct{ id, domain, name, body string }{{"context", "block", "context", "Retain source pins and prerequisites.\n"}, {"review", "skill", "review", "Review the public project.\n"}, {"careful", "approach", "careful", "Read the project context before changes.\n"}} {
		if variant == "missing-floor" && v.id == "context" {
			continue
		}
		body := []byte(v.body)
		if variant == "large-image" && v.id == "review" {
			body = bytes.Repeat([]byte("complete resource bytes\n"), 300)
		}
		sourcePath := "resources/" + v.id + ".md"
		payload := rootJSON(t, exports.ExportPayload{APIVersion: exports.ExportPayloadAPIVersion, ExportID: v.id, Files: []exports.PayloadFile{{SourcePath: sourcePath, TargetPath: "context/" + v.id + ".md", Mode: "100644", ContentSHA256: evidencecas.Digest(body)}}, Slots: []exports.PayloadSlot{}, Blocks: []exports.PayloadBlock{}})
		requires := []exports.ExportRequirement{}
		if v.id != "context" {
			requires = append(requires, exports.ExportRequirement{Selector: "base.block.context", ContractDigest: contractDigest, CompatibleRange: ">=1.0.0 <2.0.0"})
		}
		entries = append(entries, exports.ExportEntry{ID: v.id, Domain: v.domain, Name: v.name, Version: "1.0.0", ContentDigest: evidencecas.Digest(payload), Parameters: []exports.ScalarParameter{}, ToolDigest: evidencecas.Digest(tool), Requires: requires})
		files[sourcePath] = body
		files["catalog/payloads/"+v.id+".json"] = payload
	}
	files["catalog/entries.json"] = rootJSON(t, entries)
	switch variant {
	case "missing-binding":
		delete(files, DefaultRootBindingsPath)
	case "tool-mismatch":
		files["catalog/tool.md"] = []byte("changed signed tool declaration\n")
	case "malformed-duplicate":
		files["catalog/entries.json"] = []byte(strings.Replace(string(files["catalog/entries.json"]), `"id":"context"`, `"id":"context","id":"context"`, 1))
	}
	objects := map[string][]byte{}
	add := func(kind string, b []byte) string {
		raw := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(b))), b...)
		h := sha1.Sum(raw)
		id := hex.EncodeToString(h[:])
		objects[id] = raw
		return id
	}
	var tree func(string) string
	tree = func(prefix string) string {
		names := map[string]bool{}
		for p := range files {
			if strings.HasPrefix(p, prefix) {
				names[strings.SplitN(strings.TrimPrefix(p, prefix), "/", 2)[0]] = true
			}
		}
		ordered := []string{}
		for n := range names {
			ordered = append(ordered, n)
		}
		sort.Strings(ordered)
		var raw []byte
		for _, n := range ordered {
			p := prefix + n
			mode := "100644"
			id := ""
			if b, ok := files[p]; ok {
				id = add("blob", b)
			} else {
				mode = "40000"
				id = tree(p + "/")
			}
			oid, _ := hex.DecodeString(id)
			raw = append(raw, []byte(mode+" "+n+"\x00")...)
			raw = append(raw, oid...)
		}
		return add("tree", raw)
	}
	commit := add("commit", []byte("tree "+tree("")+"\n\nPublic synthetic ROOT fixture; no upstream authorship claim.\n"))
	for id, raw := range objects {
		p := filepath.Join(repo, ".git", "objects", id[:2], id[2:])
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		f, e := os.Create(p)
		if e != nil {
			t.Fatal(e)
		}
		z := zlib.NewWriter(f)
		if _, e = z.Write(raw); e != nil {
			t.Fatal(e)
		}
		if e = z.Close(); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
	}
	if err = os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\nrepositoryformatversion=0\nbare=false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return commit
}

func normalRootFixture(t *testing.T, variant string) *rootFixture {
	t.Helper()
	testfixture.RequireTrustStore(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(base, "public-fixture")
	commit := rootFixtureSource(t, repo, variant)
	project := filepath.Join(base, "project")
	home := filepath.Join(base, "home")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	generated, err := ossinstall.GenerateWithContext(context.Background(), ossinstall.Options{Root: filepath.Join(base, "install"), LocalSources: []sourcepackage.CaptureInput{{RepositoryPath: repo, Origin: "https://example.test/neutral-context", TemplatePath: ".", Commit: commit}}, ProjectContexts: []trustload.ProjectContext{{Key: "root", ProjectID: "project-root-fixture", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: project}}})
	if err != nil {
		t.Fatal(err)
	}
	registrationRaw, err := os.ReadFile(generated.RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := ossinstall.DecodeRegistration(registrationRaw)
	if err != nil {
		t.Fatal(err)
	}
	selectionRaw, err := os.ReadFile(generated.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var selections []operationtrust.SourceSelection
	if err = json.Unmarshal(selectionRaw, &selections); err != nil || len(selections) != 1 {
		t.Fatal("normal source enrollment did not produce one selection", err)
	}
	selectionPath := filepath.Join(base, "source-selection.json")
	if err = os.WriteFile(selectionPath, rootJSON(t, selections[0]), 0600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-trimpath", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+generated.RegistrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+generated.RegistrationSHA256, "-o", bin, ".")
	build.Dir = testfixture.ModuleRoot(t)
	// The build inherits no credentials or caller authority. Module cache is the
	// toolchain's ordinary public dependency cache; network installs are disabled.
	cacheCmd := exec.Command(testfixture.GoBinary(t), "env", "GOMODCACHE")
	cache, err := cacheCmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	build.Env = []string{"PATH=" + filepath.Join(testfixture.GoRoot(t), "bin") + ":/usr/bin:/bin", "HOME=" + home, "GOCACHE=/private/tmp/tplaiter-root-b1-gocache", "GOMODCACHE=" + strings.TrimSpace(string(cache)), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off", "CGO_ENABLED=0"}
	if raw, e := build.CombinedOutput(); e != nil {
		t.Fatalf("normal installed build: %v %s", e, raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(args ...string) {
		c := exec.CommandContext(ctx, bin, args...)
		c.Dir = base
		c.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "TPLAITER_HOME=" + home}
		if raw, e := c.CombinedOutput(); e != nil {
			t.Fatalf("normal installed %s: %v %s", args[0], e, raw)
		}
	}
	run("trust", "provision")
	run("new", commit, "project", "--dir", project, "--source-input", selectionPath, "--defaults", "--no-hooks", "--json")
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: registration.Selection(), ProjectKey: "root", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	t.Log("normal installed build -> trust provision -> new --source-input --defaults --no-hooks; authority=local-operator; source=public-synthetic")
	loaded, err := trustload.Load(context.Background(), registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	return &rootFixture{objectRoot: loaded.Install.ObjectOrigins[0].RootPath, runtime: runtime, root: project, home: home, install: generated.Root, selection: selections[0]}
}

func rootReadImage(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			value := info.Mode().String()
			if !d.IsDir() {
				b, e := os.ReadFile(p)
				if e != nil {
					return e
				}
				value += evidencecas.Digest(b)
			}
			out[p] = value
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestRootSelectionNormalInstalledRoot(t *testing.T) {
	f := normalRootFixture(t, "")
	before := rootReadImage(t, f.root, f.home, f.install)
	for _, selector := range []string{"base.block.context", "base.skill.review", "base.approach.careful"} {
		t.Run(selector, func(t *testing.T) {
			s, err := BeginRootSelection(context.Background(), f.runtime, rootRequest(selector))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			out := s.Result()
			want := 1
			if selector != "base.block.context" {
				want = 2
			}
			if len(out.Body.Graph.Selected) != want || len(out.Body.Files) != want || len(out.Body.Packet.SourceEvidence) != 1 {
				t.Fatal("incomplete authenticated closure")
			}
			anchor := out.Body.Packet.Sources[0].Anchor
			pin := out.Body.Packet.Sources[0].Pin
			if anchor.Subject() != f.selection.TrustSubject() || pin.Commit != anchor.Commit || pin.ContractDigest != anchor.ContractSHA256 || pin.EvidenceDigest != anchor.StatementCAS || pin.Alias != "base" || pin.ProviderID != "neutral" {
				t.Fatal("source pins were invented or lost")
			}
			for _, file := range out.Body.Files {
				if len(file.Content) == 0 || evidencecas.Digest(file.Content) != file.ContentSHA256 || file.SelectedIdentity == "" {
					t.Fatal("missing full signed image")
				}
			}
			if err = s.Recheck(context.Background()); err != nil {
				t.Fatal(err)
			}
			out.Body.Files[0].Content[0] ^= 1
			if bytes.Equal(out.Body.Files[0].Content, s.Result().Body.Files[0].Content) {
				t.Fatal("result aliases retained content")
			}
			t.Logf("selected=%d edges=%d required-floor=%d wire=%d response=%d DTO=%d pins=%s", want, len(out.Body.Graph.Edges), len(out.Body.Packet.RequiredFloor), out.Delivery.EnvelopeBytes, out.Delivery.Spending.OutputBytes, out.Bytes, pin.Commit)
		})
	}
	if !reflect.DeepEqual(before, rootReadImage(t, f.root, f.home, f.install)) {
		t.Fatal("ROOT context mutated installed state")
	}
}

func TestRootSelectionRequiredClosure(t *testing.T) {
	f := normalRootFixture(t, "")
	s, err := BeginRootSelection(context.Background(), f.runtime, rootRequest("base.block.context", "base.skill.review"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	out := s.Result()
	if len(out.Body.Graph.Selected) != 2 || len(out.Body.Graph.Edges) != 1 || len(out.Body.Files) != 2 {
		t.Fatal("shared prerequisite closure incomplete")
	}
	for _, v := range out.Body.Graph.Selected {
		if v.ID == "context" && len(v.Chains) != 2 {
			t.Fatal("shared prerequisite chains missing")
		}
	}
}

func TestRootSelectionAdmissionRefusals(t *testing.T) {
	f := normalRootFixture(t, "")
	for name, req := range map[string]RootSelectionRequest{"missing": rootRequest("base.block.missing"), "unknown-alias": rootRequest("other.skill.review"), "duplicate": rootRequest("base.skill.review", "base.skill.review"), "empty": {}, "stale-snapshot": func() RootSelectionRequest {
		r := rootRequest("base.block.context")
		r.Snapshot = evidencecas.Digest(nil)
		return r
	}(), "floor-count": func() RootSelectionRequest { r := rootRequest("base.skill.review"); r.MaxRecords = 1; return r }()} {
		t.Run(name, func(t *testing.T) {
			s, err := BeginRootSelection(context.Background(), f.runtime, req)
			if err == nil || s != nil {
				t.Fatal("accepted incomplete/stale request")
			}
		})
	}
	for _, variant := range []string{"missing-floor", "missing-binding", "tool-mismatch", "malformed-duplicate"} {
		t.Run(variant, func(t *testing.T) {
			f := normalRootFixture(t, variant)
			s, err := BeginRootSelection(context.Background(), f.runtime, rootRequest("base.skill.review"))
			if err == nil || s != nil {
				t.Fatal("invalid signed declarations returned context")
			}
			t.Logf("whole refusal: %v", err)
		})
	}
}

func TestRootSelectionHeldSession(t *testing.T) {
	f := normalRootFixture(t, "")
	s, err := BeginRootSelection(context.Background(), f.runtime, rootRequest("base.block.context"))
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(f.root, ".tplaiter", "root-template.lock.json")
	raw, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(lock, append(append([]byte(nil), raw...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Recheck(context.Background()); err == nil {
		t.Fatal("changed installed lock accepted")
	}
	if s.Result().Bytes != 0 {
		t.Fatal("failed recheck kept publishable result")
	}
	if err = os.WriteFile(lock, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s, err = BeginRootSelection(ctx, f.runtime, rootRequest("base.block.context"))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err = s.Recheck(ctx); !errors.Is(err, context.Canceled) && Code(err) != Stale {
		t.Fatal("cancelled session accepted", err)
	}
	s.Close()
	if s.Result().Bytes != 0 {
		t.Fatal("closed carrier retains output")
	}
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if s, err = BeginRootSelection(cancelled, f.runtime, rootRequest("base.block.context")); !errors.Is(err, context.Canceled) || s != nil {
		t.Fatal("pre-cancel did not refuse")
	}
}

func TestRootSelectionFreshSourceRecheck(t *testing.T) {
	f := normalRootFixture(t, "")
	s, err := BeginRootSelection(context.Background(), f.runtime, rootRequest("base.skill.review"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The retained snapshot still has its old bytes. A real fresh source check
	// must reject the changed object behind the pinned immutable commit.
	p := filepath.Join(f.objectRoot, f.selection.Subject.Commit)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), raw...)
	changed[len(changed)-1] ^= 1
	if err = os.WriteFile(p, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Recheck(context.Background()); err == nil {
		t.Fatal("cached verified snapshot hid source object tampering")
	}
	if s.Result().Bytes != 0 {
		t.Fatal("failed source recheck retained deliverable output")
	}
	t.Log("fresh pinned-source recheck rejects tampering despite retained immutable snapshot; carrier revoked")
}
