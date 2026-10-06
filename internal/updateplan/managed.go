package updateplan

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	renderengine "github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// ManagedInput is bounded operator transport. Neither selections nor choices
// grant source, formatter execution, publication or recovery authority.
type ManagedInput struct {
	ToolSource json.RawMessage `json:"toolSource"`
	Decisions  json.RawMessage `json:"decisions"`
}

// ManagedEffects retains the source-owned two-phase formatter preparation.
// Constructors read actual stable state or authenticated receipt beforeimages;
// there is no constructor accepting a caller baseline, rendered target or grant.
type ManagedEffects struct {
	backend          *Backend
	input            Input
	transport        ManagedInput
	observed         *observation
	registry         *registryObservation
	intent           *operationtrust.PreparedUpdate
	base             *renderref.Result
	clean            *formatproof.UpdateCleanPreparation
	cleanProjection  *formatproof.UpdateCleanProjection
	merged           *formatproof.UpdateMergedPreparation
	mergedProjection *formatproof.UpdateMergedProjection
	plans            map[string]managedblocks.FilePlan
	ledger           managedblocks.Baseline
	sourceLedger     managedblocks.Baseline
}

func cloneManagedInput(in ManagedInput) (ManagedInput, error) {
	if len(in.ToolSource) == 0 || len(in.ToolSource) > 1<<20 || len(in.Decisions) == 0 || len(in.Decisions) > 1<<20 {
		return ManagedInput{}, ErrInvalid
	}
	if _, err := operationtrust.DecodeSourceSelection(in.ToolSource); err != nil {
		return ManagedInput{}, err
	}
	decisions, err := managedblocks.ParseDecisions(in.Decisions)
	if err != nil {
		return ManagedInput{}, err
	}
	raw, err := canonicaljson.Canonical(decisions)
	if err != nil || !bytes.Equal(raw, in.Decisions) {
		return ManagedInput{}, ErrInvalid
	}
	return ManagedInput{ToolSource: bytes.Clone(in.ToolSource), Decisions: bytes.Clone(raw)}, nil
}

func (b *Backend) PrepareManagedEffects(ctx context.Context, in Input, transport ManagedInput) (*ManagedEffects, error) {
	if ctx == nil || b == nil || b.runtime == nil {
		return nil, ErrInvalid
	}
	if _, err := stateledger.VerifyStable(ctx, b.runtime.ProjectContext().RootPath, b.runtime.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		return nil, err
	}
	input, err := cloneSettingsInput(in)
	if err != nil {
		return nil, err
	}
	transport, err = cloneManagedInput(transport)
	if err != nil {
		return nil, err
	}
	observed, err := observe(ctx, b.runtime.ProjectContext().RootPath)
	if err != nil {
		return nil, err
	}
	registry, err := readRegistry(ctx, b.home)
	if err != nil {
		return nil, err
	}
	p, err := b.prepareManagedEffects(ctx, input, transport, observed, registry)
	if err != nil {
		return nil, err
	}
	if err := p.recheck(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (b *Backend) prepareManagedEffects(ctx context.Context, in Input, transport ManagedInput, observed *observation, registry *registryObservation) (*ManagedEffects, error) {
	var marker stateledger.ProjectV2
	if err := decodeMarker(observed.files[".tplaiter/project.yaml"], &marker); err != nil {
		return nil, err
	}
	if err := b.runtime.TrustRuntime().CheckProjectIdentity(ctx, b.runtime.ProjectContext().RootPath, marker.ID); err != nil {
		return nil, err
	}
	sourceRoot, err := provenance.DecodeRootTemplateLock(observed.files[".tplaiter/root-template.lock.json"])
	if err != nil {
		return nil, err
	}
	if marker.Template.ResolvedCommit != sourceRoot.Root.Commit || marker.Template.RequestedRef != sourceRoot.Root.RequestedRef || sourceRoot.Renderer.Version != b.rendererVersion {
		return nil, ErrUnsafe
	}
	render, err := markerRender(marker)
	if err != nil {
		return nil, err
	}
	baseIntent, err := operationtrust.PrepareSnapshot(ctx, b.runtime, operationtrust.PrepareSnapshotInput{SourceInput: in.SourceInput, Render: render, RendererVersion: b.rendererVersion})
	if err != nil {
		return nil, err
	}
	if baseIntent.RootLock() != *sourceRoot {
		return nil, ErrUnsafe
	}
	sourceProjection, err := sourceManagedProjection(ctx, b.runtime, b.home, b.rendererVersion, observed.files)
	if err != nil {
		return nil, err
	}
	base, err := sourceProjection.RenderedFor(baseIntent.Rendered())
	if err != nil {
		return nil, err
	}
	targetRender, err := b.settingsRender(ctx, in, render, marker.Answers)
	if err != nil {
		return nil, err
	}
	targetRender, answers, _, err := b.migrationRender(ctx, in, targetRender, marker.Answers, observed.files[migrations.LedgerRelPath])
	if err != nil {
		return nil, err
	}
	digest, err := bootstrap.DomainDigest(APIVersion+"/preimage", observed.images)
	if err != nil {
		return nil, err
	}
	intent, err := operationtrust.PrepareUpdate(ctx, b.runtime, operationtrust.PrepareUpdateInput{SourceInput: in.SourceInput, TargetInput: in.TargetInput, Render: targetRender, RecordedValues: answerRecordValues(answers), RendererVersion: b.rendererVersion, PreimageSHA256: digest})
	if err != nil {
		return nil, err
	}
	if intent.SourceRootLock() != *sourceRoot {
		return nil, ErrUnsafe
	}
	clean, err := formatproof.PrepareUpdateClean(ctx, b.runtime, intent, in.SourceInput, in.TargetInput, transport.ToolSource, targetRender, render, digest, evidencecas.Digest(registry.raw), transport.Decisions)
	if err != nil {
		return nil, err
	}
	return &ManagedEffects{backend: b, input: in, transport: transport, observed: observed, registry: registry, intent: intent, base: base, clean: clean, ledger: sourceProjection.Blocks(), sourceLedger: sourceProjection.Blocks(), plans: map[string]managedblocks.FilePlan{}}, nil
}

func (p *ManagedEffects) recheck(ctx context.Context) error {
	if p == nil || p.backend == nil || ctx == nil {
		return ErrInvalid
	}
	b := p.backend
	if _, err := stateledger.VerifyStable(ctx, b.runtime.ProjectContext().RootPath, b.runtime.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		return err
	}
	fresh, err := observe(ctx, b.runtime.ProjectContext().RootPath)
	if err != nil {
		return err
	}
	if !equalObservation(p.observed, fresh) {
		return ErrStale
	}
	registry, err := readRegistry(ctx, b.home)
	if err != nil {
		return err
	}
	if !bytes.Equal(registry.raw, p.registry.raw) || registry.mode != p.registry.mode || !os.SameFile(registry.identity, p.registry.identity) || !os.SameFile(registry.fileIdentity, p.registry.fileIdentity) {
		return ErrStale
	}
	return nil
}

func (p *ManagedEffects) PhaseRequests(ctx context.Context) (string, []trustverify.ExecutionRequest, error) {
	if err := p.recheck(ctx); err != nil {
		return "", nil, err
	}
	pending, err := p.clean.RequiredRequests(ctx)
	if err != nil {
		return "", nil, err
	}
	if len(pending) > 0 {
		return "clean-target", pending, nil
	}
	if err := p.prepareMerged(ctx); err != nil {
		return "", nil, err
	}
	pending, err = p.merged.RequiredRequests(ctx)
	if err != nil {
		return "", nil, err
	}
	if len(pending) > 0 {
		return "merged-candidate", pending, nil
	}
	p.mergedProjection, err = formatproof.OpenUpdateMerged(ctx, p.merged, p.merged.References())
	if err != nil {
		return "", nil, err
	}
	return "complete", []trustverify.ExecutionRequest{}, nil
}

// StageCurrentPhase executes only actual missing ordinals under exact signed
// operator approvals. It never applies an Update or changes project/registry.
func (p *ManagedEffects) StageCurrentPhase(ctx context.Context, approvals map[string]trustverify.ApprovalRefs) error {
	phase, _, err := p.PhaseRequests(ctx)
	if err != nil {
		return err
	}
	switch phase {
	case "clean-target":
		p.cleanProjection, err = formatproof.StageUpdateClean(ctx, p.clean, approvals)
	case "merged-candidate":
		p.mergedProjection, err = formatproof.StageUpdateMerged(ctx, p.merged, approvals)
	case "complete":
		if len(approvals) != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return err
}

func (p *ManagedEffects) prepareMerged(ctx context.Context) error {
	projection, err := formatproof.OpenUpdateClean(ctx, p.clean, p.clean.References())
	if err != nil {
		return err
	}
	target, err := projection.RenderedFor(ctx, p.clean)
	if err != nil {
		return err
	}
	decisions, err := managedblocks.ParseDecisions(p.transport.Decisions)
	if err != nil {
		return err
	}
	candidates := map[string][]byte{}
	ledger := p.sourceLedger.Clone()
	paths := make([]string, 0, len(p.clean.References()))
	for path := range p.clean.References() {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	seenDecisions := 0
	for _, path := range paths {
		for _, d := range decisions.Decisions {
			if d.Path == path {
				seenDecisions++
			}
		}
		prior, exists := p.sourceLedger.Files[path]
		if !exists {
			prior = managedblocks.FileBaseline{Blocks: map[string]managedblocks.BlockBaseline{}}
		}
		// Every baseline body and source identity was verified by the original
		// publication owner. Ours is the actual observed file, not a supplied map.
		ours, exists := p.observed.files[path]
		if !exists {
			return ErrUnsafe
		}
		deletes, renames, err := managedblocks.FileDecisions(decisions, path, p.intent.SourceRootLock().RootLockSHA256, p.intent.TargetRootLock().RootLockSHA256, prior, ours, target.Files[path], target.Template.ManagedBlocks)
		if err != nil {
			return err
		}
		plan, err := managedblocks.PlanFile(managedblocks.PlanInput{Path: path, Base: p.base.Files[path], Ours: ours, Theirs: target.Files[path], Baseline: prior, DeleteResolutions: deletes, Renames: renames})
		if err != nil {
			return err
		}
		if len(plan.Conflicts) > 0 {
			return ErrConflict
		}
		p.plans[path] = plan
		candidates[path] = bytes.Clone(plan.Candidate)
		// The clean target's skeleton/body becomes the upstream baseline; retained
		// local content remains only in Candidate and explicit tombstone state.
		next, err := managedblocks.SignedRootBaseline(map[string][]byte{path: target.Files[path]}, p.intent.TargetRootLock().Root)
		if err != nil {
			return err
		}
		if _, ok := next.Files[path]; !ok {
			plain, err := managedblocks.BuildBaseline(map[string][]byte{path: target.Files[path]}, nil, nil)
			if err != nil {
				return err
			}
			next.Files[path] = plain.Files[path]
		}
		if cleanBaseline, ok := next.Files[path]; ok {
			plan.Baseline.Skeleton = cleanBaseline.Skeleton
			for id, block := range plan.Baseline.Blocks {
				if cleanBlock, ok := cleanBaseline.Blocks[id]; ok && block.Tombstone == nil {
					block.Source = cleanBlock.Source
					block.Anchor = cleanBlock.Anchor
					plan.Baseline.Blocks[id] = block
				}
			}
		}
		ledger.Files[path] = plan.Baseline
	}
	if seenDecisions != len(decisions.Decisions) {
		return managedblocks.ErrDecision
	}
	if err := ledger.Validate(); err != nil {
		return err
	}
	merged, err := formatproof.PrepareUpdateMerged(ctx, p.clean, projection, candidates)
	if err != nil {
		return err
	}
	p.cleanProjection = projection
	p.merged = merged
	p.ledger = ledger
	return nil
}

// ManagedEffectReport is detached inspection data. No decoder turns it into
// Update admission or an effect receipt.
type ManagedEffectReport struct {
	CleanFiles      map[string][]byte                `json:"cleanFiles"`
	CandidateFiles  map[string][]byte                `json:"candidateFiles"`
	Blocks          managedblocks.Baseline           `json:"blocks"`
	CleanFrames     map[string]formatproof.Reference `json:"cleanFrames"`
	CandidateFrames map[string]formatproof.Reference `json:"candidateFrames"`
}

func (p *ManagedEffects) Report(ctx context.Context) (ManagedEffectReport, error) {
	phase, _, err := p.PhaseRequests(ctx)
	if err != nil {
		return ManagedEffectReport{}, err
	}
	if phase != "complete" {
		return ManagedEffectReport{}, ErrInvalid
	}
	clean, err := p.cleanProjection.RenderedFor(ctx, p.clean)
	if err != nil {
		return ManagedEffectReport{}, err
	}
	candidate, err := p.mergedProjection.FilesFor(ctx, p.merged)
	if err != nil {
		return ManagedEffectReport{}, err
	}
	return ManagedEffectReport{CleanFiles: clean.Files, CandidateFiles: candidate, Blocks: p.ledger.Clone(), CleanFrames: p.clean.References(), CandidateFrames: p.merged.References()}, nil
}

func (p *ManagedEffects) revalidatePublication(ctx context.Context) error {
	if _, err := p.Report(ctx); err != nil {
		return err
	}
	return p.mergedProjection.RevalidatePublication(ctx, p.merged)
}

func clonePlanInput(in Input) (Input, error) {
	cloned, err := cloneSettingsInput(in)
	if err != nil {
		return Input{}, err
	}
	if in.Managed != nil {
		managed, err := cloneManagedInput(*in.Managed)
		if err != nil {
			return Input{}, err
		}
		cloned.Managed = &managed
	}
	return cloned, nil
}

func cloneFileMap(in map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for path, raw := range in {
		out[path] = bytes.Clone(raw)
	}
	return out
}

func appendManagedResources(files map[string][]byte, images *resources.ResourceImages) error {
	if images == nil {
		return ErrUnsafe
	}
	for path := range files {
		if !safePath(path) || path == ".tplaiter" || strings.HasPrefix(path, ".tplaiter/") || path == ".tplater" || strings.HasPrefix(path, ".tplater/") {
			return ErrUnsafe
		}
	}
	for path, raw := range images.Files {
		if _, exists := files[path]; exists {
			return ErrUnsafe
		}
		files[path] = bytes.Clone(raw)
	}
	return nil
}

func (p *ManagedEffects) openCompleted(ctx context.Context) error {
	if p == nil || p.backend == nil {
		return ErrInvalid
	}
	if err := p.prepareMerged(ctx); err != nil {
		return err
	}
	projection, err := formatproof.OpenUpdateMerged(ctx, p.merged, p.merged.References())
	if err != nil {
		return err
	}
	p.mergedProjection = projection
	return nil
}

func (p *ManagedEffects) validateOwned(observed *observation, base map[string][]byte, result *renderref.Result, images *resources.ResourceImages, policy *adoptionpolicy.Policy) error {
	if p == nil || p.observed != observed || p.base != result {
		return ErrInvalid
	}
	expected, err := canonicaljson.Canonical(p.sourceLedger)
	if err != nil {
		return err
	}
	return validateOwnedCore(observed, base, result, images, expected, policy)
}

func managedRegistryBaseline(image RegistryImage, baseline *renderengine.Baseline, id string) (RegistryImage, error) {
	projects, err := state.DecodeProjectsRaw(image.AfterContent)
	if err != nil {
		return RegistryImage{}, err
	}
	raw, err := canonicaljson.Canonical(baseline)
	if err != nil {
		return RegistryImage{}, err
	}
	matched := false
	for i := range projects.Items {
		if projects.Items[i].ID == id {
			if matched {
				return RegistryImage{}, ErrUnsafe
			}
			matched = true
			projects.Items[i].BaselineSHA = strings.TrimPrefix(evidencecas.Digest(raw), "sha256:")
		}
	}
	if !matched {
		return RegistryImage{}, ErrUnsafe
	}
	image.AfterContent, err = state.MarshalProjects(projects)
	if err != nil {
		return RegistryImage{}, err
	}
	image.After.SHA256 = evidencecas.Digest(image.AfterContent)
	return image, nil
}

// The committed transaction owner binds this closed reconstruction data to its
// exact material afterimages. This document alone is never a receipt or grant.
type ManagedLineage struct {
	APIVersion           string                           `json:"apiVersion"`
	SourceRootLockSHA256 string                           `json:"sourceRootLockSHA256"`
	TargetRootLockSHA256 string                           `json:"targetRootLockSHA256"`
	DecisionsSHA256      string                           `json:"decisionsSHA256"`
	BaselineSHA256       string                           `json:"baselineSHA256"`
	CleanFrames          map[string]formatproof.Reference `json:"cleanFrames"`
	CandidateFrames      map[string]formatproof.Reference `json:"candidateFrames"`
}

func (p *ManagedEffects) lineage(ctx context.Context) ([]byte, error) {
	if p == nil || p.mergedProjection == nil {
		return nil, ErrInvalid
	}
	if _, err := p.mergedProjection.FilesFor(ctx, p.merged); err != nil {
		return nil, err
	}
	baseline, err := canonicaljson.Canonical(p.ledger)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonical(ManagedLineage{APIVersion: "tplaiter.dev/managed-update-lineage/v1", SourceRootLockSHA256: p.intent.SourceRootLock().RootLockSHA256, TargetRootLockSHA256: p.intent.TargetRootLock().RootLockSHA256, DecisionsSHA256: evidencecas.Digest(p.transport.Decisions), BaselineSHA256: evidencecas.Digest(baseline), CleanFrames: p.clean.References(), CandidateFrames: p.merged.References()})
}

type managedProjection interface {
	RenderedFor(*renderref.Result) (*renderref.Result, error)
	Blocks() managedblocks.Baseline
}
type managedReadDepth struct{}

func sourceManagedProjection(ctx context.Context, r *trustload.Runtime, home, renderer string, controls map[string][]byte) (managedProjection, error) {
	var header struct {
		APIVersion string `json:"apiVersion"`
	}
	if json.Unmarshal(controls[".tplaiter/managed-lineage.json"], &header) == nil && header.APIVersion == "tplaiter.dev/managed-update-lineage/v1" {
		projection, _, err := ReadManagedUpdateProjection(ctx, r, home, renderer, controls)
		return projection, err
	}
	return formatproof.ReconstructRootClean(ctx, r, home, renderer, controls)
}

// ManagedUpdateProjection retains only the clean authenticated reader view.
// Its constructor authenticates the committed owner material before any typed
// semantic reconstruction. It cannot stage effects or admit a transaction.
type ManagedUpdateProjection struct {
	clean  *renderref.Result
	blocks managedblocks.Baseline
}

func (p *ManagedUpdateProjection) Blocks() managedblocks.Baseline {
	if p == nil {
		return managedblocks.Baseline{}
	}
	return p.blocks.Clone()
}

func (p *ManagedUpdateProjection) RenderedFor(signed *renderref.Result) (*renderref.Result, error) {
	if p == nil || p.clean == nil || signed == nil || signed.Baseline == nil || signed.Baseline.ContextHash != p.clean.Baseline.ContextHash || signed.Baseline.TemplateVersion != p.clean.Baseline.TemplateVersion || len(signed.Files) != len(p.clean.Files) {
		return nil, ErrUnsafe
	}
	for path, raw := range signed.Files {
		clean, ok := p.clean.Files[path]
		if !ok || (!bytes.Contains(raw, []byte("tplater:managed-")) && !bytes.Equal(raw, clean)) {
			return nil, ErrUnsafe
		}
	}
	out := *p.clean
	out.Files = cloneFileMap(p.clean.Files)
	baseline := *p.clean.Baseline
	baseline.Files = map[string]string{}
	for path, digest := range p.clean.Baseline.Files {
		baseline.Files[path] = digest
	}
	out.Baseline = &baseline
	return &out, nil
}

func ReadManagedUpdateProjection(ctx context.Context, r *trustload.Runtime, home, renderer string, controls map[string][]byte) (*ManagedUpdateProjection, map[string][]byte, error) {
	if ctx == nil || r == nil || controls == nil {
		return nil, nil, ErrInvalid
	}
	depth, _ := ctx.Value(managedReadDepth{}).(int)
	if depth >= 32 {
		return nil, nil, ErrUnsafe
	}
	ctx = context.WithValue(ctx, managedReadDepth{}, depth+1)
	raw := controls[".tplaiter/managed-lineage.json"]
	var lineage ManagedLineage
	if canonicaljson.DecodeStrict(raw, &lineage) != nil || lineage.APIVersion != "tplaiter.dev/managed-update-lineage/v1" {
		return nil, nil, ErrUnsafe
	}
	intent, err := formatproof.CommittedUpdateIntent(ctx, r, home, raw)
	if err != nil {
		return nil, nil, err
	}
	var material UpdateMaterial
	if canonicaljson.DecodeStrict(intent, &material) != nil || material.Managed == nil || material.Home != home || material.RendererVersion != renderer {
		return nil, nil, ErrInvalid
	}
	if err := AuthenticateUpdateMaterial(ctx, r, renderer, material); err != nil {
		return nil, nil, err
	}
	observed, err := materialObservation(material.Before)
	if err != nil {
		return nil, nil, err
	}
	if material.ControlAdded {
		observed = withoutControl(observed)
	}
	backend, err := New(r, home, renderer)
	if err != nil {
		return nil, nil, err
	}
	reg := &registryObservation{raw: bytes.Clone(material.Registry.BeforeContent), mode: material.Registry.Before.Mode}
	plan, err := backend.reconstruct(ctx, Input{SourceInput: material.SourceInput, TargetInput: material.TargetInput, SettingsPairs: material.SettingsPairs, Managed: material.Managed}, observed, reg, material.Protection)
	if err != nil || plan == nil || plan.managed == nil {
		return nil, nil, ErrInvalid
	}
	expectedLineage, err := plan.managed.lineage(ctx)
	if err != nil || !bytes.Equal(raw, expectedLineage) {
		return nil, nil, ErrUnsafe
	}
	images := map[string][]byte{}
	for path, file := range material.After {
		if file.Directory {
			continue
		}
		images[path] = bytes.Clone(file.Data)
		if strings.HasPrefix(path, ".tplaiter/") && !bytes.Equal(controls[path], file.Data) {
			return nil, nil, ErrStale
		}
	}
	clean, err := plan.managed.cleanProjection.RenderedFor(ctx, plan.managed.clean)
	if err != nil {
		return nil, nil, err
	}
	return &ManagedUpdateProjection{clean: clean, blocks: plan.managed.ledger.Clone()}, images, nil
}
