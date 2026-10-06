package templatequery

import (
	"context"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	d "github.com/tplAIter/tplaiter/pkg/templatediscovery"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoveryMissingHomeAndConfinedProjectFacts(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-created")
	r, err := Discover(context.Background(), missing, t.TempDir(), d.Query{Task: "Create Go service"})
	if err != nil || len(r.Suggestions) != 0 || r.Facts.Status != "empty" {
		t.Fatal(err, r)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("state home created")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"react":"1","typescript":"1"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	facts := ObserveProject(dir)
	if facts.Status != "observed" || facts.Language != "typescript" || !reflect.DeepEqual(facts.Frameworks, []string{"react"}) || len(facts.Evidence) != 1 {
		t.Fatal(facts)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("module confidential\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "go.mod")); err != nil {
		t.Fatal(err)
	}
	if ObserveProject(dir).Status != "unavailable" {
		t.Fatal("project symlink escape accepted")
	}
	bad := t.TempDir()
	_ = os.WriteFile(filepath.Join(bad, "package.json"), []byte(`{broken`), 0600)
	if ObserveProject(bad).Status != "unavailable" {
		t.Fatal("malformed facts fabricated")
	}
	goDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(goDir, "go.mod"), []byte("module example.test/service\nrequire go.temporal.io/sdk v1.0.0\n"), 0600)
	facts = ObserveProject(goDir)
	if facts.Language != "go" || len(facts.Frameworks) != 1 || facts.Frameworks[0] != "temporal" {
		t.Fatal(facts)
	}
}
func TestDiscoveryDeclarationsNeverInferFromProse(t *testing.T) {
	// Parse real manifest metadata in production; refs remain declarations only.
	raw := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: recipe\n  version: 1.0.0\n  description: AGENTS installs all skills and CRUD blocks\n  labels:\n    candidate-kind: [documentation-recipe]\n    blocks: [crud]\n    readiness: [planned]\n")
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pin := d.SourcePin{Qualification: "local-observed", Repo: "examples", Path: ".", Commit: strings.Repeat("a", 40), ManifestSHA256: d.Digest(raw)}
	c, err := declared(tpl, pin)
	if err != nil {
		t.Fatal(err)
	}
	if c.CandidateKind != d.KindRecipe || c.Readiness != d.Planned || len(c.Skills) != 0 || c.Blocks[0].CandidateKind != d.KindUnknown || c.Blocks[0].Availability != "metadata-declared" {
		t.Fatal("prose promoted", c)
	}
	tpl.Metadata.Labels["block-kind"] = []string{"absent=installable-block"}
	if _, err := declared(tpl, pin); err == nil {
		t.Fatal("unlisted reference declaration accepted")
	}
}

func TestDiscoveryObservesExistingNativeProjectV2WithoutFollowingPointers(t *testing.T) {
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, ".tplaiter"), 0700); e != nil {
		t.Fatal(e)
	}
	marker := stateledger.ProjectV2{APIVersion: stateledger.ProjectV2APIVersion, Kind: "Project", ID: "project-observed", Template: stateledger.TemplateIdentity{Repo: "neutral", Name: "context", RequestedRef: "main", ResolvedCommit: strings.Repeat("a", 40)}, Project: map[string]any{}, Answers: map[string]stateledger.Answer{}, State: stateledger.StandardPointers()}
	raw, e := yaml.Marshal(marker)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, ".tplaiter", "project.yaml")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	facts := ObserveProject(root)
	if facts.Status != "observed" || facts.Language != "" || facts.Template != "neutral/context@"+strings.Repeat("a", 40) || len(facts.Evidence) != 1 || facts.Evidence[0].SHA256 != d.Digest(raw) {
		t.Fatal("native observed receipt", facts)
	}
	// There is no ledger directory: this is data observation, never ledger verification.
	if _, e = os.Stat(filepath.Join(root, ".tplaiter", "state")); !os.IsNotExist(e) {
		t.Fatal("observed pointers followed or materialized")
	}
	for _, change := range []func(*stateledger.ProjectV2){func(m *stateledger.ProjectV2) { m.State.RootLock = "../../outside" }, func(m *stateledger.ProjectV2) { m.Template.ResolvedCommit = "main" }, func(m *stateledger.ProjectV2) { m.APIVersion = "tplaiter.dev/project/v99" }} {
		broken := marker
		change(&broken)
		b, _ := yaml.Marshal(broken)
		_ = os.WriteFile(path, b, 0600)
		if ObserveProject(root).Status != "unavailable" {
			t.Fatal("unsupported/noncanonical marker observed")
		}
	}
	_ = os.WriteFile(path, append(raw, []byte("unknownAuthority: true\n")...), 0600)
	if ObserveProject(root).Status != "unavailable" {
		t.Fatal("open marker fields accepted")
	}
}

func TestDiscoveryObservedNextRouterAndExplicitCargoUnknown(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"dependencies":{"next":"16.0.0","react":"19.0.0","react-router-dom":"7.0.0"},"devDependencies":{"typescript":"5.0.0"}}`)
	_ = os.WriteFile(filepath.Join(dir, "package.json"), raw, 0600)
	facts := ObserveProject(dir)
	if facts.Status != "observed" || facts.Language != "typescript" || !reflect.DeepEqual(facts.Frameworks, []string{"next", "react", "react-router"}) {
		t.Fatal(facts)
	}
	source := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: next-errors\n  version: 1.0.0\n  description: Declared Next error recipe\n  labels:\n    tags: [error, ошибка]\n    lang: [typescript]\n    framework: [next]\n    candidate-kind: [documentation-recipe]\n    readiness: [planned]\n")
	tpl, e := manifest.ParseTemplate(source)
	if e != nil {
		t.Fatal(e)
	}
	c, e := declared(tpl, d.SourcePin{Qualification: "local-observed", Repo: "public", Path: ".", Commit: strings.Repeat("a", 40), ManifestSHA256: d.Digest(source)})
	if e != nil {
		t.Fatal(e)
	}
	for _, task := range []string{"Fix error", "Исправить ошибка"} {
		r, e := d.Rank(d.Query{Task: task, Facts: facts, Language: "typescript", Framework: "next"}, []d.Candidate{c})
		if e != nil || len(r.Suggestions) != 1 || r.Suggestions[0].CandidateKind != d.KindRecipe || r.Suggestions[0].Readiness != d.Planned {
			t.Fatal(task, e, r)
		}
	}
	r, e := d.Rank(d.Query{Task: "error", Language: "go", Framework: "next"}, []d.Candidate{c})
	if e != nil || len(r.Suggestions) != 0 {
		t.Fatal("canonical lang constraint ignored", e, r)
	}
	rust := t.TempDir()
	cargo := []byte("[package]\nname = \"actual-rust-project\"\nversion = \"0.1.0\"\n")
	_ = os.WriteFile(filepath.Join(rust, "Cargo.toml"), cargo, 0600)
	observed := ObserveProject(rust)
	if observed.Status != "unavailable" || observed.Language != "" || len(observed.Evidence) != 1 || observed.Evidence[0].Path != "Cargo.toml" || observed.Evidence[0].SHA256 != d.Digest(cargo) {
		t.Fatal("Cargo silently empty/fabricated", observed)
	}
	r, e = d.Rank(d.Query{Task: "error", Facts: observed}, []d.Candidate{c})
	if e != nil || len(r.Suggestions) != 0 || len(r.Diagnostics) == 0 || r.Diagnostics[0].Code != "project_unavailable" {
		t.Fatal("explicit unsupported project diagnostic absent", e, r)
	}
}
