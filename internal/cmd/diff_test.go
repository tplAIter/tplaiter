package cmd

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Materialize a synthetic on-disk signed baseline. This deliberately does not
// claim that new/link/adopt can create managed projects: those slices remain
// separate. The installed diff process must independently authenticate it.
func materializeDiffFixture(t *testing.T, f t5FFixture, unsupported bool) {
	t.Helper()
	ctx := context.Background()
	r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	input := t5FSelection(f.source, f.sourceRefs)
	prepared, err := operationtrust.PrepareNew(ctx, r, operationtrust.PrepareNewInput{SourceInput: input, RendererVersion: "dev", Render: renderref.Input{Repo: "fixture", Values: renderref.Values(map[string]any{"label": "ok"}), Project: manifest.ProjectInfo{Name: "project", Slug: "project", Module: "example.test/project"}, Runtime: manifest.ProjectRuntime{Port: 8080}}})
	if err != nil {
		t.Fatal(err)
	}
	root := prepared.RootLock()
	deps := prepared.DependencyLock()
	result := prepared.Rendered()
	selected, err := operationtrust.DecodeSourceSelection(input)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := r.TrustRuntime().VerifySubject(ctx, selected.TrustSubject(), selected.EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	images, err := resources.PlanNativeGeneratorImages(r.TrustRuntime(), resolution, root)
	if unsupported {
		// Negative fixture only: resource creation correctly refuses this source.
		// Store an empty inert inventory to exercise diff's signed action refusal;
		// no creation or resource-admission success is claimed for this image.
		images = &resources.ResourceImages{Files: map[string][]byte{}, Lock: resources.ResourceLockV2{Version: 2, RootLockSHA256: root.RootLockSHA256, TrustProfile: root.TrustProfile, Artifacts: []resources.ResourceArtifact{}}}
	} else if err != nil {
		t.Fatal(err)
	}
	managed, err := managedblocks.BuildBaseline(map[string][]byte{"hello.txt": result.Files["hello.txt"]}, []managedblocks.ProviderSource{{Provider: "fixture", Source: root.Root}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	files := result.Files
	for p, b := range images.Files {
		files[p] = b
	}
	inv := ownership.Inventory{Version: 1, Artifacts: []ownership.Artifact{}}
	for p, b := range files {
		a, e := ownership.ArtifactFor(p, b, 0o644, "")
		if e != nil {
			t.Fatal(e)
		}
		inv.Artifacts = append(inv.Artifacts, a)
	}
	answers := map[string]stateledger.Answer{}
	for k, v := range result.Resolved.Values {
		answers[k] = stateledger.Answer{Value: v, Source: "default"}
	}
	marker := stateledger.ProjectV2{APIVersion: stateledger.ProjectV2APIVersion, Kind: "Project", ID: r.ProjectContext().ProjectID, Template: stateledger.TemplateIdentity{Repo: "fixture", Name: result.Template.Metadata.Name, RequestedRef: root.Root.RequestedRef, ResolvedCommit: root.Root.Commit}, Project: map[string]any{"name": "project", "slug": "project", "module": "example.test/project", "system": "", "domain": ""}, Runtime: map[string]any{"port": 8080}, Answers: answers, State: stateledger.StandardPointers()}
	for p, v := range map[string]any{engine.BaselineRelPath: result.Baseline, ownership.InventoryRelPath: inv, ".tplaiter/root-template.lock.json": root, ".tplaiter/template.lock.json": deps, ".tplaiter/resources.lock.json": images.Lock, ".tplaiter/managed-blocks.json": managed, ".tplaiter/ai-managed.json": struct {
		Version int      `json:"version"`
		Files   []string `json:"files"`
	}{1, []string{}}, ".tplaiter/generator-targets.lock.json": struct {
		Version int   `json:"version"`
		Targets []any `json:"targets"`
	}{1, []any{}}, ".tplaiter/migrations.json": migrations.Ledger{Version: 1, Applied: []migrations.LedgerEntry{}}} {
		b, e := canonicaljson.Canonical(v)
		if e != nil {
			t.Fatal(e)
		}
		files[p] = b
	}
	files[".tplaiter/project.yaml"], err = yaml.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	src, err := operationtrust.SnapshotFS(r.TrustRuntime(), resolution)
	if err != nil {
		t.Fatal(err)
	}
	files[manifest.SnapshotRelPath], err = fs.ReadFile(src, "template.manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for p, b := range files {
		path := filepath.Join(f.projectRoot, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := stateledger.VerifyStable(ctx, f.projectRoot, r.TrustRuntime(), stateledger.StableVerifyOptions{CAS: r}); err != nil {
		t.Fatal(err)
	}
}
