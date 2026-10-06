package contextsource

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestNativeNewOpaqueClosureAndCopies(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	sources, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	input := NativeNewInput{Render: renderref.Input{Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}, RendererVersion: "1.0.0"}
	p, err := PrepareNativeNew(ctx, f.runtime, sources, input)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	root, err := p.RootLock(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := p.DependencyLock(ctx, f.runtime)
	if err != nil || len(dependencies.Dependencies) != 3 || provenance.ValidateLockPair(root, dependencies) != nil {
		t.Fatalf("complete lock: %+v %v", dependencies, err)
	}
	rendered, err := p.Rendered(ctx, f.runtime)
	if err != nil || string(rendered.Files["hello.txt"]) != "Hello public project.\n" {
		t.Fatalf("root render: %+v %v", rendered, err)
	}
	dependencies.Dependencies[0].Commit = "changed"
	rendered.Files["hello.txt"][0] = 'X'
	rendered.Template.Metadata.Name = "changed"
	rendered.Baseline.Files["hello.txt"] = "changed"
	again, err := p.Rendered(ctx, f.runtime)
	if err != nil || string(again.Files["hello.txt"]) != "Hello public project.\n" || again.Template.Metadata.Name == "changed" || again.Baseline.Files["hello.txt"] == "changed" {
		t.Fatal("mutable intent")
	}
	locks, err := p.DependencyLock(ctx, f.runtime)
	if err != nil || locks.Dependencies[0].Commit == "changed" {
		t.Fatal("mutable ledger")
	}
	if p.RecheckFor(ctx, &trustload.Runtime{}) == nil {
		t.Fatal("foreign runtime accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.Rendered(cancelled, f.runtime); err == nil {
		t.Fatal("cancel ignored")
	}
	sources.Close()
	if p.RecheckFor(ctx, f.runtime) == nil {
		t.Fatal("closed source carrier accepted")
	}
}

func TestNativeNewRefusesFabricatedIntent(t *testing.T) {
	p := &PreparedNativeNew{}
	if _, err := p.RootLock(context.Background(), &trustload.Runtime{}); err == nil {
		t.Fatal("fabricated intent")
	}
	if _, err := PrepareNativeNew(context.Background(), &trustload.Runtime{}, &PreparedContextSources{}, NativeNewInput{RendererVersion: "1.0.0"}); err == nil {
		t.Fatal("fabricated source grant")
	}
}

func TestNativeNewFreshTypedAnswersPreserveCodecSemantics(t *testing.T) {
	tpl := &manifest.Template{Settings: []manifest.SettingGroup{
		{Group: "text", Type: manifest.TypeString},
		{Group: "count", Type: manifest.TypeInt},
		{Group: "enabled", Type: manifest.TypeToggle},
		{Group: "choice", Type: manifest.TypeSelect, Options: []manifest.Option{{ID: "current"}, {ID: "retired", Deprecated: true}, {ID: "future", Status: manifest.StatusPlanned}}},
		{Group: "many", Type: manifest.TypeMultiselect, Options: []manifest.Option{{ID: "current"}, {ID: "retired", Deprecated: true}}},
		{Group: "retiredGroup", Type: manifest.TypeString, Deprecated: true},
	}}
	values := settings.Values{"text": "  keep = text\n", "count": 3, "enabled": true, "choice": "current", "many": []string{"current"}}
	if err := validateNativeNewValues(tpl, values); err != nil {
		t.Fatal(err)
	}
	resolved, err := settings.Resolve(tpl, values)
	if err != nil || resolved.Values["text"] != values["text"] || resolved.Values["count"] != 3 || resolved.Values["enabled"] != true {
		t.Fatalf("fresh typed answers changed: %+v %v", resolved, err)
	}
	if err := validateNativeNewValues(tpl, settings.Values{"choice": "", "many": []string{}}); err != nil {
		t.Fatalf("existing unselected zeros refused: %v", err)
	}
	for name, values := range map[string]settings.Values{
		"wrong-string": {"text": 3}, "wrong-int": {"count": "3"}, "wrong-toggle": {"enabled": "true"},
		"unknown-group": {"absent": true}, "unknown-option": {"choice": "absent"}, "planned-option": {"choice": "future"},
		"deprecated-option": {"choice": "retired"}, "deprecated-list": {"many": []string{"current", "retired"}},
		"deprecated-group": {"retiredGroup": "new answer"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateNativeNewValues(tpl, values); err == nil {
				t.Fatal("invalid fresh answer accepted")
			}
		})
	}
}

const nativeManagedExample = "package example\n// tplater:managed-begin id=example provider=root-content\nfunc Example( ) int {return 1}\n// tplater:managed-end id=example\n"

func managedNativeFixture(t *testing.T) *contextFixture {
	t.Helper()
	return newContextFixture(t, func(alias string, files map[string][]byte) {
		if alias == "root" {
			files["files/example.go.tmpl"] = []byte(nativeManagedExample)
		}
	})
}
func managedNativeInput() NativeNewInput {
	return NativeNewInput{Render: renderref.Input{Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}, RendererVersion: "1.0.0"}
}

func TestManagedNativeNewSignedClosureAndCopies(t *testing.T) {
	f := managedNativeFixture(t)
	ctx := context.Background()
	source, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err = PrepareNativeNew(ctx, f.runtime, source, managedNativeInput()); err == nil {
		t.Fatal("action-free entry accepted managed content")
	}
	p, err := PrepareManagedNativeNew(ctx, f.runtime, source, managedNativeInput())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	root, err := p.RootLock(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := p.DependencyLock(ctx, f.runtime)
	if err != nil || len(dependencies.Dependencies) != 3 || provenance.ValidateLockPair(root, dependencies) != nil {
		t.Fatalf("complete original locks: %+v %v", dependencies, err)
	}
	pins, err := p.SourcePins(ctx, f.runtime)
	if err != nil || len(pins) != 4 {
		t.Fatal("incomplete pins", err)
	}
	for _, pin := range pins {
		proof := f.proofs[pin.Alias]
		if pin.Origin != proof.Subject.Origin || pin.Commit != proof.Subject.Commit || pin.TreeDigest != proof.Subject.TreeSHA256 || pin.ContractDigest != proof.Subject.ContractSHA256 || pin.EvidenceDigest != proof.Evidence.StatementCAS || pin.ProviderID != "provider."+pin.Alias || string(pin.Parameters[0].Value) != `"plain"` {
			t.Fatalf("lost original pin: %+v", pin)
		}
	}
	for _, dep := range dependencies.Dependencies {
		found := false
		for _, proof := range f.proofs {
			if dep.Commit == proof.Subject.Commit {
				found = true
				if dep.StatementCAS != proof.Evidence.StatementCAS || dep.SignatureCAS != proof.Evidence.SignatureCAS || dep.CheckpointCAS != proof.Evidence.CheckpointCAS || dep.InclusionProofCAS != proof.Evidence.InclusionProofCAS {
					t.Fatal("replaced original evidence")
				}
			}
		}
		if !found {
			t.Fatal("invented dependency subject")
		}
	}
	graph, err := p.SourceGraph(ctx, f.runtime)
	if err != nil || len(graph.Nodes) != 4 || len(graph.Edges) != 4 {
		t.Fatal("incomplete DAG", err)
	}
	catalogs, err := p.Catalogs(ctx, f.runtime)
	if err != nil || len(catalogs) != 4 {
		t.Fatal("incomplete catalogs", err)
	}
	plain := []exports.Catalog{}
	for _, c := range catalogs {
		plain = append(plain, c.Catalog)
	}
	selection, err := exports.ResolveSelections([]exports.Selection{{APIVersion: exports.SelectionAPIVersion, Selector: "root.skill.notes", Bindings: []exports.ScalarParameter{}}}, &graph, plain)
	if err != nil || len(selection.Selected) != 4 || len(selection.Edges) != 4 {
		t.Fatal("required closure lost", err)
	}
	for _, entry := range selection.Selected {
		if entry.Provider == "provider.leaf" && len(entry.Chains) != 2 {
			t.Fatal("shared leaf chain lost")
		}
	}
	rendered, err := p.Rendered(ctx, f.runtime)
	if err != nil || string(rendered.Files["example.go"]) != nativeManagedExample || string(rendered.Files["hello.txt"]) != "Hello public project.\n" {
		t.Fatal("render changed or discarded inert content", err)
	}
	files, err := p.ManagedFiles(ctx, f.runtime)
	if err != nil || len(files) != 1 || files[0].Mode != "100644" || files[0].InputSHA256 != evidencecas.Digest([]byte(nativeManagedExample)) || len(files[0].Markers) != 2 || files[0].Markers[0].Provider != "root-content" {
		t.Fatal("managed inventory", err)
	}
	marker := files[0].Markers[0]
	if string(rendered.Files[files[0].Path][marker.Start:marker.End]) != "// tplater:managed-begin id=example provider=root-content\n" {
		t.Fatal("marker offsets are not exact input")
	}
	operation, err := p.OperationBase(ctx, f.runtime)
	if err != nil || operation.Scope != "new" || len(operation.Subjects) != 4 || operation.Actions == nil || len(operation.Actions) != 0 || operation.PreimageSHA256 != evidencecas.Digest(nil) {
		t.Fatal("not a complete actions-empty New calculation", err)
	}
	digest, err := trustverify.ComputeOperationInputsSHA256(operation)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := p.OperationInputsSHA256(ctx, f.runtime)
	if err != nil || stored != digest {
		t.Fatal("operation identity", err)
	}
	domain, err := p.ContextDigest(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	// Re-admit the same originals in reverse transport order, not fabricated pins.
	reversed := f.input
	reversed.Sources = append([]ContextSourceProof{}, f.input.Sources...)
	slices.Reverse(reversed.Sources)
	otherSource, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, reversed))
	if err != nil {
		t.Fatal(err)
	}
	defer otherSource.Close()
	other, err := PrepareManagedNativeNew(ctx, f.runtime, otherSource, managedNativeInput())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherDomain, err := other.ContextDigest(ctx, f.runtime)
	if err != nil || otherDomain != domain {
		t.Fatal("source transport order changed managed context")
	}
	otherOperation, err := other.OperationInputsSHA256(ctx, f.runtime)
	if err != nil || otherOperation != digest {
		t.Fatal("source transport order changed operation")
	}
	pins[0].Parameters[0].Value[0] = 'X'
	pins[0].Dependencies = append(pins[0].Dependencies, "fake")
	graph.Nodes[0].Provenance[0].Alias = "fake"
	graph.Edges[0].Consumer = "fake"
	catalogs[0].Payloads[0].Raw[0] = 'X'
	catalogs[0].Blobs[0].Content[0] = 'X'
	catalogs[0].Catalog.Exports[0].Name = "fake"
	operation.Subjects[0].Commit = "fake"
	operation.Actions = append(operation.Actions, trustverify.ActionMaterial{})
	files[0].Markers[0].ID = "fake"
	rendered.Files["example.go"][0] = 'X'
	againPins, err := p.SourcePins(ctx, f.runtime)
	if err != nil || string(againPins[0].Parameters[0].Value) != `"plain"` {
		t.Fatal("mutable pin projection")
	}
	againGraph, err := p.SourceGraph(ctx, f.runtime)
	if err != nil || againGraph.Nodes[0].Provenance[0].Alias == "fake" || againGraph.Edges[0].Consumer == "fake" {
		t.Fatal("mutable graph projection")
	}
	againCatalogs, err := p.Catalogs(ctx, f.runtime)
	if err != nil || againCatalogs[0].Payloads[0].Raw[0] == 'X' || againCatalogs[0].Blobs[0].Content[0] == 'X' || againCatalogs[0].Catalog.Exports[0].Name == "fake" {
		t.Fatal("mutable catalog projection")
	}
	againOperation, err := p.OperationBase(ctx, f.runtime)
	if err != nil || len(againOperation.Actions) != 0 || againOperation.Subjects[0].Commit == "fake" {
		t.Fatal("mutable operation projection")
	}
	againFiles, err := p.ManagedFiles(ctx, f.runtime)
	if err != nil || againFiles[0].Markers[0].ID == "fake" {
		t.Fatal("mutable marker projection")
	}
	againRendered, err := p.Rendered(ctx, f.runtime)
	if err != nil || string(againRendered.Files["example.go"]) != nativeManagedExample {
		t.Fatal("mutable rendered image")
	}
	if _, err = os.Stat(f.runtime.ProjectContext().RootPath); !os.IsNotExist(err) {
		t.Fatal("calculation created project")
	}
	t.Logf("real signed loader: sources=4 dependencySubjects=3 DAGedges=4 catalogs=4 requiredExports=4 requiredEdges=4 exactManagedImages=1 actions=0 context=%s operation=%s", domain, digest)
}

func TestManagedNativeNewSignedMarkerRefusals(t *testing.T) {
	for name, alter := range map[string]func(map[string][]byte){
		"missing": func(files map[string][]byte) {},
		"raw-string": func(files map[string][]byte) {
			files["files/example.go.tmpl"] = []byte("package example\nvar s = `\n// tplater:managed-begin id=x provider=root\nbody\n// tplater:managed-end id=x\n`\n")
		},
		"unpaired": func(files map[string][]byte) {
			files["files/example.go.tmpl"] = []byte("package example\n// tplater:managed-begin id=x provider=root\n")
		},
		"non-Go": func(files map[string][]byte) { files["files/example.txt.tmpl"] = []byte(nativeManagedExample) },
		"case-collision": func(files map[string][]byte) {
			files["files/example.go.tmpl"] = []byte(nativeManagedExample)
			files["files/Example.go.tmpl"] = []byte(nativeManagedExample)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newContextFixture(t, func(alias string, files map[string][]byte) {
				if alias == "root" {
					alter(files)
				}
			})
			source, err := PrepareContextSources(context.Background(), f.runtime, contextJSON(t, f.input))
			if err != nil {
				t.Fatal("signed source admission unexpectedly failed", err)
			}
			defer source.Close()
			if p, err := PrepareManagedNativeNew(context.Background(), f.runtime, source, managedNativeInput()); err == nil {
				p.Close()
				t.Fatal("managed calculation accepted invalid signed content")
			}
			if _, err := os.Stat(f.runtime.ProjectContext().RootPath); !os.IsNotExist(err) {
				t.Fatal("refusal wrote project")
			}
		})
	}
}

func TestManagedNativeNewLifetimeAndFreshness(t *testing.T) {
	f := managedNativeFixture(t)
	for name, input := range map[string]ContextSourceSelection{
		"missing-shared-leaf":        {APIVersion: f.input.APIVersion, Root: f.input.Root, Sources: append([]ContextSourceProof{}, f.input.Sources[:2]...)},
		"root-evidence-substitution": {APIVersion: f.input.APIVersion, Root: ContextSourceProof{Subject: f.input.Root.Subject, Evidence: f.input.Sources[0].Evidence}, Sources: append([]ContextSourceProof{}, f.input.Sources...)},
	} {
		t.Run(name, func(t *testing.T) {
			if admitted, err := PrepareContextSources(context.Background(), f.runtime, contextJSON(t, input)); err == nil {
				admitted.Close()
				t.Fatal("incomplete/substituted original evidence admitted")
			}
		})
	}

	ctx := context.Background()
	source, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	p, err := PrepareManagedNativeNew(ctx, f.runtime, source, managedNativeInput())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	assertRefusal := func(ctx context.Context, r *trustload.Runtime) {
		t.Helper()
		if _, err := p.ManagedFiles(ctx, r); err == nil {
			t.Fatal("managed files ignored invalid lifetime")
		}
		if _, err := p.OperationBase(ctx, r); err == nil {
			t.Fatal("operation ignored invalid lifetime")
		}
		if _, err := p.SourcePins(ctx, r); err == nil {
			t.Fatal("pins ignored invalid lifetime")
		}
		if _, err := p.SourceGraph(ctx, r); err == nil {
			t.Fatal("graph ignored invalid lifetime")
		}
		if _, err := p.Catalogs(ctx, r); err == nil {
			t.Fatal("catalogs ignored invalid lifetime")
		}
	}
	assertRefusal(ctx, &trustload.Runtime{})
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	assertRefusal(cancelled, f.runtime)
	policy, err := os.ReadFile(f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	contextWrite(t, f.policyPath, append(policy, ' '))
	assertRefusal(ctx, f.runtime)
	contextWrite(t, f.policyPath, policy)
	if err := p.RecheckFor(ctx, f.runtime); err != nil {
		t.Fatal("restore did not restore actual carrier", err)
	}
	file := filepath.Join(f.objectRoot, f.input.Sources[0].Subject.Commit)
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	contextWrite(t, file, []byte("tampered"))
	assertRefusal(ctx, f.runtime)
	contextWrite(t, file, original)
	if err := p.RecheckFor(ctx, f.runtime); err != nil {
		t.Fatal(err)
	}
	p.Close()
	assertRefusal(ctx, f.runtime)
	q, err := PrepareManagedNativeNew(ctx, f.runtime, source, managedNativeInput())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	source.Close()
	if _, err := q.Catalogs(ctx, f.runtime); err == nil {
		t.Fatal("closed sources retained capability")
	}
	if _, err := (&PreparedNativeNew{}).OperationBase(ctx, f.runtime); err == nil {
		t.Fatal("fabricated intent accepted")
	}
}

func TestManagedNativeNewTopologyAndGrammarCounters(t *testing.T) {
	for name, files := range map[string]map[string][]byte{
		"ancestor":      {"example.go": []byte(nativeManagedExample), "context": []byte("file"), "context/notes.md": []byte("nested")},
		"case-ancestor": {"example.go": []byte(nativeManagedExample), "CONTEXT": []byte("file"), "context/notes.md": []byte("nested")},
		"reserved-case": {"example.go": []byte(nativeManagedExample), ".TPLAITER/state": []byte("state")},
		"nested":        {"example.go": []byte("package example\n// tplater:managed-begin id=x provider=root\n// tplater:managed-begin id=y provider=root\n// tplater:managed-end id=y\n// tplater:managed-end id=x\n")},
		"duplicate":     {"example.go": []byte(nativeManagedExample + strings.TrimPrefix(nativeManagedExample, "package example\n"))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := nativeManagedInventory(context.Background(), files); err == nil {
				t.Fatal("invalid topology or existing grammar accepted")
			}
		})
	}
	f := newContextFixture(t, nil)
	source, err := PrepareContextSources(context.Background(), f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	ordinary, err := PrepareNativeNew(context.Background(), f.runtime, source, managedNativeInput())
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	if _, err := ordinary.ManagedFiles(context.Background(), f.runtime); err == nil {
		t.Fatal("ordinary intent acquired managed mode")
	}
	base, err := ordinary.OperationBase(context.Background(), f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := trustverify.ComputeOperationInputsSHA256(base)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := ordinary.OperationInputsSHA256(context.Background(), f.runtime)
	if err != nil || !reflect.DeepEqual(digest, stored) {
		t.Fatal("ordinary operation changed")
	}
}
