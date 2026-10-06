package contextsource

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextauth"
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

func TestNativeNewProjectionEquivalentDetachedAndFresh(t *testing.T) {
	f := managedNativeFixture(t)
	ctx := context.Background()
	sources, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	p, err := PrepareManagedNativeNew(ctx, f.runtime, sources, managedNativeInput())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.rendered.Resolved.Values["nested"] = map[string]any{"items": []any{map[string]any{"value": "original"}}}
	p.rendered.Resolved.Values["empty"] = []string{}
	p.rendered.Resolved.ActiveValues["empty"] = []string{}
	originalValues := p.rendered.Resolved.Values.Clone()
	originalActiveValues := p.rendered.Resolved.ActiveValues.Clone()

	projection, err := p.Projection(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	root, err := p.RootLock(ctx, f.runtime)
	if err != nil || !reflect.DeepEqual(projection.RootLock, root) {
		t.Fatal("projection root lock differs", err)
	}
	dependencies, err := p.DependencyLock(ctx, f.runtime)
	if err != nil || !reflect.DeepEqual(projection.DependencyLock, dependencies) || len(projection.DependencyLock.Dependencies) != len(dependencies.Dependencies) {
		t.Fatalf("projection dependency lock differs: projection=%+v getter=%+v err=%v", projection.DependencyLock, dependencies, err)
	}
	for i := range dependencies.Dependencies {
		if projection.DependencyLock.Dependencies[i] != dependencies.Dependencies[i] {
			t.Fatalf("projection dependency %d differs", i)
		}
	}
	resolution, err := p.RootResolution(ctx, f.runtime)
	if err != nil || projection.RootResolution != resolution {
		t.Fatal("projection did not retain actual opaque resolution", err)
	}
	rendered, err := p.Rendered(ctx, f.runtime)
	if err != nil || !reflect.DeepEqual(projection.Rendered, rendered) {
		t.Fatal("projection render differs", err)
	}
	if len(projection.ManagedFiles) != 1 || len(projection.ManagedFiles[0].Markers) == 0 || len(projection.OperationBase.Actions) != 0 {
		t.Fatal("projection omitted managed calculation data")
	}
	if !reflect.DeepEqual(projection.Rendered.Resolved.Values["empty"], originalValues["empty"]) || !reflect.DeepEqual(projection.Rendered.Resolved.ActiveValues["empty"], originalActiveValues["empty"]) || projection.Rendered.Resolved.Values["empty"] == nil || projection.Rendered.Resolved.ActiveValues["empty"] == nil {
		t.Fatal("projection changed original empty typed values")
	}
	valuesJSON, err := json.Marshal(projection.Rendered.Resolved.Values)
	if err != nil || !strings.Contains(string(valuesJSON), `"empty":[]`) {
		t.Fatalf("projection changed Values empty typed value JSON shape: %s", valuesJSON)
	}
	activeValuesJSON, err := json.Marshal(projection.Rendered.Resolved.ActiveValues)
	if err != nil || !strings.Contains(string(activeValuesJSON), `"empty":[]`) {
		t.Fatalf("projection changed ActiveValues empty typed value JSON shape: %s", activeValuesJSON)
	}

	projection.Manifest[0] = 'x'
	projection.DependencyLock.Dependencies[0].Commit = "tampered"
	projection.Rendered.Files["example.go"][0] = 'x'
	projection.Rendered.Template.Metadata.Name = "tampered"
	projection.Rendered.Baseline.Files["example.go"] = "tampered"
	projection.Rendered.Resolved.Values["nested"].(map[string]any)["items"].([]any)[0].(map[string]any)["value"] = "tampered"
	projection.ManagedFiles[0].Markers[0].ID = "tampered"
	projection.OperationBase.Subjects[0].Commit = "tampered"
	again, err := p.Projection(ctx, f.runtime)
	nested := again.Rendered.Resolved.Values["nested"].(map[string]any)["items"].([]any)[0].(map[string]any)["value"]
	if err != nil || string(again.Rendered.Files["example.go"]) != nativeManagedExample || again.Rendered.Template.Metadata.Name == "tampered" || nested == "tampered" || again.ManagedFiles[0].Markers[0].ID == "tampered" || again.OperationBase.Subjects[0].Commit == "tampered" {
		t.Fatal("projection leaked mutable nested data", err)
	}

	if _, err = p.Projection(ctx, &trustload.Runtime{}); err == nil {
		t.Fatal("foreign runtime accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = p.Projection(cancelled, f.runtime); err == nil {
		t.Fatal("cancelled projection accepted")
	}
	p.owner = nil
	if _, err = p.Projection(ctx, f.runtime); err == nil {
		t.Fatal("tampered owner accepted")
	}
	p.owner = f.runtime
	sources.Close()
	if _, err = p.Projection(ctx, f.runtime); err == nil {
		t.Fatal("closed source carrier accepted")
	}
}

func TestNativeNewProjectionClonesNonEmptyCollections(t *testing.T) {
	lock := provenance.TemplateLock{Dependencies: []provenance.DependencySubject{{Origin: "https://example.test/dep", TemplatePath: ".", Commit: strings.Repeat("a", 40)}}}
	clonedLock := cloneTemplateLock(lock)
	if !reflect.DeepEqual(clonedLock, lock) || len(clonedLock.Dependencies) != 1 {
		t.Fatalf("dependency records were not retained: %+v", clonedLock)
	}
	clonedLock.Dependencies[0].Origin = "tampered"
	if lock.Dependencies[0].Origin == "tampered" {
		t.Fatal("dependency records share mutable backing storage")
	}

	operation := trustverify.OperationInputs{Subjects: []trustverify.Provider{{Origin: "https://example.test/provider", TemplatePath: ".", Commit: strings.Repeat("b", 40)}}, Actions: []trustverify.ActionMaterial{}}
	clonedOperation := cloneOperationInputs(operation)
	if !reflect.DeepEqual(clonedOperation, operation) || len(clonedOperation.Subjects) != 1 || clonedOperation.Actions == nil {
		t.Fatalf("operation records were not retained: %+v", clonedOperation)
	}
	clonedOperation.Subjects[0].Origin = "tampered"
	if operation.Subjects[0].Origin == "tampered" {
		t.Fatal("provider records share mutable backing storage")
	}
}

func TestNativeNewProjectionPreservesEmptyJSONCollections(t *testing.T) {
	projection := NativeNewProjection{
		DependencyLock: cloneTemplateLock(provenance.TemplateLock{Dependencies: []provenance.DependencySubject{}}),
		OperationBase:  cloneOperationInputs(trustverify.OperationInputs{Subjects: []trustverify.Provider{}, Actions: []trustverify.ActionMaterial{}}),
	}
	if projection.DependencyLock.Dependencies == nil || projection.OperationBase.Subjects == nil || projection.OperationBase.Actions == nil {
		t.Fatal("projection changed present empty collections to nil")
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"dependencies":[]`) || !strings.Contains(text, `"subjects":[]`) || !strings.Contains(text, `"actions":[]`) {
		t.Fatalf("projection lost canonical empty arrays: %s", text)
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

// The direct compiled consumer receives original runtime admissions, not a
// transport capsule or caller-created snapshot. Both routes use one kernel.
func TestSourceClosureDirectSignedParityAndDAG(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	source, e := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	pins, e := source.Pins(ctx)
	if e != nil {
		t.Fatal(e)
	}
	originals := map[string]*trustverify.VerifiedResolution{}
	for _, pin := range pins {
		v, e := source.Resolution(ctx, pin.Alias)
		if e != nil {
			t.Fatal(e)
		}
		originals[pin.Alias] = v
	}
	direct, e := contextauth.AdmitSourceClosure(ctx, f.runtime, originals["root"], []*trustverify.VerifiedResolution{originals["b"], originals["leaf"], originals["a"]})
	if e != nil {
		t.Fatal(e)
	}
	defer direct.Close()
	actual, e := direct.Pins(ctx)
	if e != nil || !reflect.DeepEqual(actual, pins) {
		t.Fatal("direct pins diverged", e)
	}
	graph, e := direct.SourceGraph(ctx)
	if e != nil {
		t.Fatal(e)
	}
	expected, e := source.SourceGraph(ctx)
	if e != nil || !reflect.DeepEqual(graph, expected) {
		t.Fatal("direct graph diverged", e)
	}
	if len(graph.Nodes) != 4 || len(graph.Edges) != 4 {
		t.Fatal("incomplete authenticated DAG")
	}
	catalogs, e := direct.Catalogs(ctx)
	if e != nil {
		t.Fatal(e)
	}
	want, e := source.Catalogs(ctx)
	if e != nil || !reflect.DeepEqual(catalogs, want) {
		t.Fatal("direct catalog diverged", e)
	}
	if len(catalogs) != 4 {
		t.Fatal("incomplete catalog")
	}
	subjects, e := direct.OperationSubjects(ctx, f.runtime)
	if e != nil || len(subjects) != 4 {
		t.Fatal("root-only subject projection", e)
	}
	for _, pin := range pins {
		v, e := direct.Resolution(ctx, pin.Alias)
		if e != nil || v != originals[pin.Alias] || v.Subject() != contextSubject(f.proofs[pin.Alias]) || v.Evidence() != contextEvidence(f.proofs[pin.Alias]) {
			t.Fatal("original carrier replaced", e)
		}
		s := v.Subject()
		provider := trustverify.Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
		if !slices.Contains(subjects, provider) {
			t.Fatal("dependency subject dropped")
		}
		data, e := direct.CatalogData(ctx, pin.Alias)
		if e != nil {
			t.Fatal(e)
		}
		saved, e := source.CatalogData(ctx, pin.Alias)
		if e != nil || !reflect.DeepEqual(data, saved) {
			t.Fatal("direct data diverged", e)
		}
		if string(data.Entries) != string(f.files[pin.Alias]["catalog/entries.json"]) || string(data.Tool) != string(f.files[pin.Alias]["catalog/tool.md"]) || len(data.Payloads) != 1 || len(data.Blobs) != 1 || string(data.Payloads[0].Raw) != string(f.files[pin.Alias]["catalog/payloads/notes.json"]) || string(data.Blobs[0].Content) != string(f.files[pin.Alias]["docs/notes.md"]) {
			t.Fatal("exact authenticated catalog images missing")
		}
		data.Blobs[0].Content[0] = 'X'
		data.Payloads[0].Raw[0] = 'X'
		again, e := direct.CatalogData(ctx, pin.Alias)
		if e != nil || !reflect.DeepEqual(again, saved) {
			t.Fatal("mutable source data", e)
		}
	}
	root, e := direct.RootResolution(ctx, f.runtime)
	if e != nil || root != originals["root"] {
		t.Fatal("root original changed", e)
	}
	subjects[0].Commit = "changed"
	again, e := direct.OperationSubjects(ctx, f.runtime)
	if e != nil || again[0].Commit == "changed" {
		t.Fatal("mutable subjects", e)
	}
	plain := []exports.Catalog{}
	for _, c := range catalogs {
		plain = append(plain, c.Catalog)
	}
	selection, e := exports.ResolveSelections([]exports.Selection{{APIVersion: exports.SelectionAPIVersion, Selector: "root.skill.notes", Bindings: []exports.ScalarParameter{}}}, &graph, plain)
	if e != nil || len(selection.Selected) != 4 || len(selection.Edges) != 4 {
		t.Fatal("required closure lost", e)
	}
	for _, s := range selection.Selected {
		if s.Provider == "provider.leaf" && len(s.Chains) != 2 {
			t.Fatal("shared transitive chains lost")
		}
	}
	t.Logf("actual direct kernel: sources=%d edges=%d catalogs=%d originalSubjects=%d requiredExports=%d requiredEdges=%d digest=%s", len(pins), len(graph.Edges), len(catalogs), len(again), len(selection.Selected), len(selection.Edges), selection.Digest)
	foreign, e := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: contextFixtureClock{}})
	if e != nil {
		t.Fatal(e)
	}
	defer foreign.Close()
	foreignDep, e := foreign.TrustRuntime().VerifySubject(ctx, contextSubject(f.proofs["a"]), contextEvidence(f.proofs["a"]))
	if e != nil {
		t.Fatal(e)
	}
	for name, deps := range map[string][]*trustverify.VerifiedResolution{
		"missing": {originals["a"], originals["b"]}, "duplicate": {originals["a"], originals["b"], originals["leaf"], originals["a"]}, "nil": {originals["a"], nil, originals["leaf"]}, "foreign-dependency": {foreignDep, originals["b"], originals["leaf"]}, "fabricated": {&trustverify.VerifiedResolution{}, originals["b"], originals["leaf"]},
	} {
		t.Run(name, func(t *testing.T) {
			if c, e := contextauth.AdmitSourceClosure(ctx, f.runtime, root, deps); e == nil {
				c.Close()
				t.Fatal("invalid original closure accepted")
			}
		})
	}
	if c, e := contextauth.AdmitSourceClosure(ctx, f.runtime, originals["a"], []*trustverify.VerifiedResolution{root, originals["b"], originals["leaf"]}); e == nil {
		c.Close()
		t.Fatal("unreachable originals accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := contextauth.AdmitSourceClosure(cancelled, f.runtime, root, []*trustverify.VerifiedResolution{originals["a"], originals["b"], originals["leaf"]}); e == nil {
		t.Fatal("cancelled admission")
	}
	if direct.RecheckFor(ctx, foreign) == nil {
		t.Fatal("foreign consumption accepted")
	}
	// A copied opaque value cannot establish a fresh lifetime or become an owner.
	copied := reflect.New(reflect.TypeOf(direct).Elem())
	copied.Elem().Set(reflect.ValueOf(direct).Elem())
	if copied.Interface().(*contextauth.VerifiedSourceClosure).Recheck(ctx) == nil {
		t.Fatal("copied carrier accepted")
	}
	source.Close()
	if direct.Recheck(ctx) != nil {
		t.Fatal("independently admitted owner incorrectly closed with transport wrapper")
	}
}

func TestManagedFormatterSourceBorrowLifetime(t *testing.T) {
	f := managedNativeFixture(t)
	ctx := context.Background()
	source, e := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	intent, e := PrepareManagedNativeNew(ctx, f.runtime, source, managedNativeInput())
	if e != nil {
		t.Fatal(e)
	}
	defer intent.Close()
	carrier, e := intent.FormatterSources(ctx, f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	subjects, e := carrier.OperationSubjects(ctx, f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	op, e := intent.OperationBase(ctx, f.runtime)
	if e != nil || !reflect.DeepEqual(subjects, op.Subjects) || len(op.Actions) != 0 || len(subjects) != 4 {
		t.Fatal("formatter projection changed complete actions-empty calculation", e)
	}
	if again, e := intent.FormatterSources(ctx, f.runtime); e != nil || again != carrier {
		t.Fatal("borrow was replaced", e)
	}
	child, e := carrier.Borrow(ctx, f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	defer child.Close()
	sibling, e := PrepareManagedNativeNew(ctx, f.runtime, source, managedNativeInput())
	if e != nil {
		t.Fatal(e)
	}
	defer sibling.Close()
	siblingCarrier, e := sibling.FormatterSources(ctx, f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := intent.FormatterSources(cancelled, f.runtime); e == nil {
		t.Fatal("cancelled borrow")
	}
	if _, e := intent.FormatterSources(ctx, &trustload.Runtime{}); e == nil {
		t.Fatal("foreign borrow")
	}
	if _, e := carrier.OperationSubjects(cancelled, f.runtime); e == nil {
		t.Fatal("cancelled subject projection")
	}
	copied := reflect.New(reflect.TypeOf(intent).Elem())
	copied.Elem().Set(reflect.ValueOf(intent).Elem())
	if _, e := copied.Interface().(*PreparedNativeNew).FormatterSources(ctx, f.runtime); e == nil {
		t.Fatal("copied intent obtained carrier")
	}
	intent.Close()
	if carrier.Recheck(ctx) == nil || child.Recheck(ctx) == nil {
		t.Fatal("intent close failed to invalidate descendants")
	}
	if source.Recheck(ctx) != nil || siblingCarrier.Recheck(ctx) != nil {
		t.Fatal("intent close invalidated independent source/intent")
	}
	source.Close()
	if siblingCarrier.Recheck(ctx) == nil {
		t.Fatal("source close failed to invalidate formatter borrow")
	}
	if _, e := sibling.FormatterSources(ctx, f.runtime); e == nil {
		t.Fatal("closed source recreated carrier")
	}

	ordinaryFixture := newContextFixture(t, nil)
	ordinarySource, e := PrepareContextSources(ctx, ordinaryFixture.runtime, contextJSON(t, ordinaryFixture.input))
	if e != nil {
		t.Fatal(e)
	}
	defer ordinarySource.Close()
	ordinary, e := PrepareNativeNew(ctx, ordinaryFixture.runtime, ordinarySource, managedNativeInput())
	if e != nil {
		t.Fatal(e)
	}
	defer ordinary.Close()
	if _, e := ordinary.FormatterSources(ctx, ordinaryFixture.runtime); e == nil {
		t.Fatal("ordinary action-free calculation became formatter authority")
	}
}

func TestManagedFormatterSourceFreshnessAndClosedBorrow(t *testing.T) {
	f := managedNativeFixture(t)
	ctx := context.Background()
	source, e := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	intent, e := PrepareManagedNativeNew(ctx, f.runtime, source, managedNativeInput())
	if e != nil {
		t.Fatal(e)
	}
	defer intent.Close()
	carrier, e := intent.FormatterSources(ctx, f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	assertRefuses := func() {
		t.Helper()
		if carrier.RecheckFor(ctx, f.runtime) == nil {
			t.Fatal("stale carrier accepted")
		}
		if _, e := intent.FormatterSources(ctx, f.runtime); e == nil {
			t.Fatal("stale intent supplied carrier")
		}
		if _, e := carrier.Catalogs(ctx); e == nil {
			t.Fatal("stale catalog projection")
		}
	}
	for _, file := range []string{f.policyPath, filepath.Join(f.objectRoot, f.proofs["leaf"].Subject.Commit)} {
		raw, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		contextWrite(t, file, append(raw, 'x'))
		assertRefuses()
		contextWrite(t, file, raw)
		if e := carrier.Recheck(ctx); e != nil {
			t.Fatal("restored original rejected", e)
		}
	}
	carrier.Close()
	if source.Recheck(ctx) != nil {
		t.Fatal("borrow close closed original owner")
	}
	if _, e := intent.FormatterSources(ctx, f.runtime); e == nil {
		t.Fatal("closed borrow resurrected")
	}
}

func contextActionGateDocument(t *testing.T) map[string]any {
	t.Helper()
	d := evidencecas.Digest([]byte("neutral declaration data"))
	return map[string]any{"apiVersion": "tplaiter.dev/template-actions/v1", "actions": []any{map[string]any{"id": "check", "purpose": "run", "class": "staged-native-readonly/v1", "profile": "linux-static-fd-go127-poll/v1", "version": 1, "kind": "command", "phase": "standalone", "shell": false, "parameters": []any{}, "argv": []any{map[string]any{"kind": "literal", "value": "checker"}}, "inputs": []any{}, "stdin": map[string]any{"root": "provider", "path": "stdin.txt", "mode": "100644", "sha256": d}, "tool": map[string]any{"provider": map[string]any{"origin": "https://example.test/neutral-tool", "templatePath": ".", "commit": strings.Repeat("a", 40), "treeSHA256": d, "contractSHA256": d}, "evidence": map[string]any{"format": "tplaiter.dev/publisher-statement/v1", "statementCAS": d, "signatureCAS": d, "keyFingerprint": d, "checkpointCAS": d, "inclusionProofCAS": d}, "id": "checker", "version": "1.0.0", "recordSHA256": d}, "environment": map[string]any{"apiVersion": "tplaiter.dev/execution-environment/v1", "inherit": false, "variables": []any{map[string]any{"name": "LANG", "value": "C"}}, "capabilities": []any{}}, "workingDirectory": map[string]any{"root": "provider", "path": ".tplaiter-execution"}, "timeoutMillis": 5000, "stdoutLimit": 128 << 10, "stderrLimit": 16 << 10}}}
}

func TestNativeNewDeclaredActionGate(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "actual-retained-positive", true: "missing-metadata-refusal"}[bad], func(t *testing.T) {
			f := newContextFixture(t, func(alias string, files map[string][]byte) {
				if alias != "root" {
					return
				}
				files["template.manifest.yaml"] = append(files["template.manifest.yaml"], []byte("commands:\n  check:\n    run: tplaiter-action:check\n")...)
				var c NativeContextContract
				if e := json.Unmarshal(files["template.contract.json"], &c); e != nil {
					t.Fatal(e)
				}
				c.ManifestSHA256 = evidencecas.Digest(files["template.manifest.yaml"])
				files["template.contract.json"] = contextJSON(t, c)
				raw, e := canonicaljson.Canonical(contextActionGateDocument(t))
				if e != nil {
					t.Fatal(e)
				}
				if !bad {
					files["actions/run/actions.json"] = raw
				}
				files["stdin.txt"] = []byte("neutral declaration data")
			})
			ctx := context.Background()
			sources, e := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
			if e != nil {
				t.Fatal(e)
			}
			defer sources.Close()
			result, e := PrepareNativeNew(ctx, f.runtime, sources, NativeNewInput{Render: renderref.Input{Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}, RendererVersion: "1.0.0"})
			if bad {
				if e == nil {
					result.Close()
					t.Fatal("missing metadata accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer result.Close()
			rendered, e := result.Rendered(ctx, f.runtime)
			if e != nil || string(rendered.Files["hello.txt"]) != "Hello public project.\n" {
				t.Fatal("inert rendering changed", e)
			}
		})
	}
}
