package settingscmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/managed"
	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Native uses one concrete installed runtime. Neither discovery manifests nor
// a legacy mutable repo manager can supply settings authority.
type Native struct {
	runtime        *trustload.Runtime
	home, renderer string
}

type NativeView struct {
	Warnings  []string
	Template  *manifest.Template
	Values    settings.Values
	Answers   map[string]stateledger.Answer
	Selection stateledger.TemplateIdentity
	source    []byte
}

func NewNative(r *trustload.Runtime, home, renderer string) (*Native, error) {
	if r == nil || r.TrustRuntime() == nil || home == "" || renderer == "" {
		return nil, updateRuntimeError()
	}
	return &Native{runtime: r, home: home, renderer: renderer}, nil
}
func updateRuntimeError() error { return errors.New("TRUST_RUNTIME_INVALID") }

// Read binds marker/lock/resource bytes to a verified stable snapshot and fresh
// signed CAS resolution, then re-verifies the snapshot before returning facts.
func (n *Native) Read(ctx context.Context) (*NativeView, error) {
	if n == nil || n.runtime == nil || ctx == nil {
		return nil, updateRuntimeError()
	}
	r := n.runtime
	root := r.ProjectContext().RootPath
	snapshot, err := stateledger.VerifyStable(ctx, root, r.TrustRuntime(), stateledger.StableVerifyOptions{})
	if err != nil {
		return nil, err
	}
	observation, err := projectverify.OpenObservation(ctx, root)
	if err != nil {
		return nil, err
	}
	defer observation.Close()
	read := func(name string) ([]byte, error) { return observation.ReadVerified(ctx, snapshot, ".tplaiter/"+name) }
	raw, err := read("project.yaml")
	if err != nil {
		return nil, err
	}
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(raw, &marker); err != nil {
		return nil, err
	}
	if err := r.TrustRuntime().CheckProjectIdentity(ctx, root, marker.ID); err != nil {
		return nil, err
	}
	rootRaw, err := read("root-template.lock.json")
	if err != nil {
		return nil, err
	}
	lock, err := provenance.DecodeRootTemplateLock(rootRaw)
	if err != nil {
		return nil, err
	}
	depRaw, err := read("template.lock.json")
	if err != nil {
		return nil, err
	}
	deps, err := provenance.DecodeTemplateLock(depRaw)
	if err != nil {
		return nil, err
	}
	if provenance.ValidateLockPair(*lock, *deps) != nil || !lock.TrustProfile.Equal(r.TrustRuntime().Binding()) || lock.Renderer.Version != n.renderer {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	source := lock.Root
	selection := operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: operationtrust.SelectionSubject{Origin: source.Origin, TemplatePath: source.TemplatePath, RequestedRef: source.RequestedRef, Commit: source.Commit, TreeSHA256: source.TreeSHA256, ContractSHA256: source.ContractSHA256}, Evidence: operationtrust.SelectionEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: source.StatementCAS, SignatureCAS: source.SignatureCAS, KeyFingerprint: source.KeyFingerprint, CheckpointCAS: source.CheckpointCAS, InclusionProofCAS: source.InclusionProofCAS}, Dependencies: []string{}}
	input, err := json.Marshal(selection)
	if err != nil {
		return nil, err
	}
	resolution, err := r.TrustRuntime().VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	sourceFS, err := operationtrust.SnapshotFS(r.TrustRuntime(), resolution)
	if err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(sourceFS)
	if err != nil {
		return nil, err
	}
	rawManifest, err := r.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	manifestBytes, ok := rawManifest.Blob("template.manifest.yaml")
	if !ok {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	snapshotManifest, err := read("manifest.snapshot.yaml")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(snapshotManifest, manifestBytes) || marker.Template.Name != tpl.Metadata.Name || marker.Template.ResolvedCommit != lock.Root.Commit || marker.Template.RequestedRef != lock.Root.RequestedRef {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	if _, err := operationtrust.DecodeNativeContract(rawManifest.ContractBytes(), manifestBytes); err != nil {
		return nil, err
	}
	images, err := resources.PlanNativeGeneratorImages(r.TrustRuntime(), resolution, *lock)
	if err != nil {
		return nil, err
	}
	resourceLock, err := read("resources.lock.json")
	if err != nil {
		return nil, err
	}
	expected, err := canonicaljson.Canonical(images.Lock)
	if err != nil || !bytes.Equal(expected, resourceLock) {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	for path, expected := range images.Files {
		actual, err := observation.ReadVerified(ctx, snapshot, path)
		if err != nil || !bytes.Equal(actual, expected) {
			return nil, operationtrust.ErrSourceAdapterUnsupported
		}
	}
	ledger, err := read("migrations.json")
	if err != nil {
		return nil, err
	}
	if err := migrations.ValidateAppliedHistory(tpl.Migrations, tpl.Metadata.Version, ledger); err != nil {
		return nil, err
	}
	values := settings.Values{}
	for key, a := range marker.Answers {
		values[key] = a.Value
	}
	// A stripped lineage must not enter the ordinary reader merely because the
	// locator is absent. Derive managed presence from the authenticated render.
	text := func(key string) string { value, _ := marker.Project[key].(string); return value }
	port, ok := marker.Runtime["port"].(int)
	if !ok || port < 0 || port > 65535 {
		return nil, stateledger.ErrUnsafe
	}
	prepared, err := operationtrust.PrepareSnapshot(ctx, r, operationtrust.PrepareSnapshotInput{SourceInput: input, RendererVersion: n.renderer, Render: renderref.Input{Repo: marker.Template.Repo, Values: renderref.Values(values), Project: manifest.ProjectInfo{Name: text("name"), Slug: text("slug"), Module: text("module"), System: text("system"), Domain: text("domain")}, Runtime: manifest.ProjectRuntime{Port: port}}})
	if err != nil {
		return nil, err
	}
	required := false
	for _, raw := range prepared.Rendered().Files {
		if bytes.Contains(raw, []byte("tplater:managed-")) {
			required = true
			break
		}
	}
	lineage, err := observation.ReadState(ctx, managed.LineagePath)
	if err != nil {
		return nil, err
	}
	if required || lineage.Exists {
		if _, err := managed.Read(ctx, r, n.home, n.renderer); err != nil {
			return nil, err
		}
	}
	resolved, err := settings.ResolveRecorded(tpl, renderref.Values(values), renderref.Values(values))
	if err != nil {
		return nil, err
	}
	fresh, err := stateledger.VerifyStable(ctx, root, r.TrustRuntime(), stateledger.StableVerifyOptions{})
	if err != nil {
		return nil, err
	}
	before, err := canonicaljson.Canonical(snapshot)
	if err != nil {
		return nil, err
	}
	after, err := canonicaljson.Canonical(fresh)
	if err != nil || !bytes.Equal(before, after) {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	return &NativeView{Warnings: append([]string(nil), resolved.Report.Warnings...), Template: tpl, Values: resolved.Values.Clone(), Answers: marker.Answers, Selection: marker.Template, source: input}, nil
}

func (n *Native) Prepare(ctx context.Context, pairs []string) (*projecttransaction.SettingsPlan, error) {
	view, err := n.Read(ctx)
	if err != nil {
		return nil, err
	}
	return projecttransaction.PlanSettings(ctx, n.runtime, n.home, n.renderer, view.source, pairs)
}

// Reanswer asks only the selected group/subtree against the verified manifest;
// the resulting typed answers are transported as pairs and revalidated at Seal.
func Reanswer(view *NativeView, group string, d Deps) ([]string, error) {
	if view == nil || view.Template == nil || d.Prompter == nil || !d.Interactive {
		return nil, errors.New("settings edit: authenticated view and interactive prompter required")
	}
	if !groupExists(view.Template, group) {
		return nil, fmt.Errorf("settings edit: unknown group %q", group)
	}
	return surveyReanswer(view, group, d)
}
