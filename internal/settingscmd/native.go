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
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
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
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

// Native uses one concrete installed runtime. Neither discovery manifests nor
// a legacy mutable repo manager can supply settings authority.
type Native struct {
	runtime        *trustload.Runtime
	home, renderer string
}

type NativeView struct {
	Warnings       []string
	Template       *manifest.Template
	Values         settings.Values
	Answers        map[string]stateledger.Answer
	Selection      stateledger.TemplateIdentity
	source         []byte
	snapshotSHA256 string
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
	values := settings.Values{}
	for key, answer := range marker.Answers {
		values[key] = answer.Value
	}
	text := func(key string) string { value, _ := marker.Project[key].(string); return value }
	port, ok := marker.Runtime["port"].(int)
	if !ok || port < 0 || port > 65535 {
		return nil, stateledger.ErrUnsafe
	}
	render := renderref.Input{Repo: marker.Template.Repo, Values: renderref.Values(values), Project: manifest.ProjectInfo{Name: text("name"), Slug: text("slug"), Module: text("module"), System: text("system"), Domain: text("domain")}, Runtime: manifest.ProjectRuntime{Port: port}}
	var images *resources.ResourceImages
	var rendered *renderref.Result
	if _, legacyErr := operationtrust.DecodeNativeContract(rawManifest.ContractBytes(), manifestBytes); legacyErr == nil {
		images, err = resources.PlanNativeGeneratorImages(r.TrustRuntime(), resolution, *lock)
		if err != nil {
			return nil, err
		}
		prepared, err := operationtrust.PrepareSnapshot(ctx, r, operationtrust.PrepareSnapshotInput{SourceInput: input, RendererVersion: n.renderer, Render: render})
		if err != nil {
			return nil, err
		}
		rendered = prepared.Rendered()
	} else {
		if _, err := contextsource.DecodeNativeContextContractV2(rawManifest.ContractBytes(), manifestBytes); err != nil {
			return nil, err
		}
		sources, err := sourceadapter.PrepareRecordedContextSources(ctx, r, rootRaw, depRaw)
		if err != nil {
			return nil, err
		}
		defer sources.Close()
		input, err = sourceadapter.RecordedContextSourceInput(ctx, r, rootRaw, depRaw)
		if err != nil {
			return nil, err
		}
		prepared, err := contextsource.PrepareRecordedNativeSnapshot(ctx, r, sources, contextsource.RecordedNativeSnapshotInput{Render: render, RecordedValues: values, RendererVersion: n.renderer})
		if err != nil {
			return nil, err
		}
		defer prepared.Close()
		images, err = resources.PlanContextNativeSnapshotGeneratorImages(ctx, r, prepared)
		if err != nil {
			return nil, err
		}
		rendered, err = prepared.Rendered(ctx, r)
		if err != nil {
			return nil, err
		}
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
	blockRaw, err := read("managed-blocks.json")
	if err != nil {
		return nil, err
	}
	recordedBlocks, err := managedblocks.ParseBaseline(blockRaw)
	if err != nil {
		return nil, err
	}
	required := len(recordedBlocks.Files) > 0
	for _, raw := range rendered.Files {
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
	return &NativeView{Warnings: append([]string(nil), resolved.Report.Warnings...), Template: tpl, Values: resolved.Values.Clone(), Answers: marker.Answers, Selection: marker.Template, source: input, snapshotSHA256: evidencecas.Digest(before)}, nil
}

func (n *Native) Prepare(ctx context.Context, pairs []string) (*projecttransaction.SettingsPlan, error) {
	view, err := n.Read(ctx)
	if err != nil {
		return nil, err
	}
	return projecttransaction.PlanSettings(ctx, n.runtime, n.home, n.renderer, view.source, pairs)
}

// CapturedSettingsPairs carries bounded operator choices between formatter
// phases. Its digests detect stale observations; this record grants no action.
type CapturedSettingsPairs struct {
	APIVersion        string   `json:"apiVersion"`
	SourceInputSHA256 string   `json:"sourceInputSHA256"`
	SnapshotSHA256    string   `json:"snapshotSHA256"`
	Group             string   `json:"group"`
	Pairs             []string `json:"pairs"`
}

func captureSettingsPairs(view *NativeView, group string, pairs []string) (CapturedSettingsPairs, error) {
	if view == nil || view.Template == nil || len(view.source) == 0 || view.snapshotSHA256 == "" || len(pairs) == 0 {
		return CapturedSettingsPairs{}, updateplan.ErrSettingsInput
	}
	if _, err := updateplan.ResolveSettingsAnswers(view.Template, view.Answers, pairs); err != nil {
		return CapturedSettingsPairs{}, err
	}
	if group != "" {
		if !groupExists(view.Template, group) {
			return CapturedSettingsPairs{}, updateplan.ErrSettingsInput
		}
		allowed := groupWithDescendants(view.Template, group)
		for _, pair := range pairs {
			key, _, err := settings.ParseRecordedSet(view.Template, pair, view.Values)
			if err != nil || !allowed[key] {
				return CapturedSettingsPairs{}, updateplan.ErrSettingsInput
			}
		}
	}
	return CapturedSettingsPairs{APIVersion: "tplaiter.dev/settings-pairs/v1", SourceInputSHA256: evidencecas.Digest(view.source), SnapshotSHA256: view.snapshotSHA256, Group: group, Pairs: append([]string(nil), pairs...)}, nil
}

// CapturePairs persists the selected intent as detached canonical data. Both
// preparation and publication still resolve the pairs against fresh state.
func CapturePairs(view *NativeView, group string, pairs []string) ([]byte, error) {
	captured, err := captureSettingsPairs(view, group, pairs)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonical(captured)
}

// RestorePairs requires a newly authenticated view and rechecks every pair.
// Completed formatter effects do not authorize a changed answer or snapshot.
func RestorePairs(view *NativeView, group string, raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > 1<<17 {
		return nil, updateplan.ErrSettingsInput
	}
	var record CapturedSettingsPairs
	if canonicaljson.DecodeStrict(raw, &record) != nil || record.APIVersion != "tplaiter.dev/settings-pairs/v1" || record.Group != group {
		return nil, updateplan.ErrSettingsInput
	}
	canonical, err := canonicaljson.Canonical(record)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, updateplan.ErrSettingsInput
	}
	fresh, err := captureSettingsPairs(view, group, record.Pairs)
	if err != nil {
		return nil, err
	}
	if fresh.SourceInputSHA256 != record.SourceInputSHA256 || fresh.SnapshotSHA256 != record.SnapshotSHA256 {
		return nil, updateplan.ErrStale
	}
	return append([]string(nil), fresh.Pairs...), nil
}

// PrepareManaged reads the authenticated current source again before preparing
// the same-version mutation with retained formatter evidence.
func (n *Native) PrepareManaged(ctx context.Context, pairs []string, transport updateplan.ManagedInput) (*projecttransaction.SettingsPlan, error) {
	view, err := n.Read(ctx)
	if err != nil {
		return nil, err
	}
	return projecttransaction.PlanManagedSettings(ctx, n.runtime, n.home, n.renderer, view.source, pairs, transport)
}

// PrepareManagedEffects exposes requests from the actual lifecycle owner;
// detached settings values and request projections do not grant execution.
func (n *Native) PrepareManagedEffects(ctx context.Context, pairs []string, transport updateplan.ManagedInput) (*updateplan.ManagedEffects, error) {
	view, err := n.Read(ctx)
	if err != nil {
		return nil, err
	}
	return projecttransaction.PrepareManagedSettingsEffects(ctx, n.runtime, n.home, n.renderer, view.source, pairs, transport)
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
