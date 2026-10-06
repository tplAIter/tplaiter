package formatproof

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/stateledger"

	"github.com/tplAIter/tplaiter/internal/newtransaction/inspect"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	renderengine "github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/newimages"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// NewCleanInput is reconstruction data, not publication authority. A cold
// consumer must reopen the exact source and verify all retained effects.
type NewCleanInput struct {
	APIVersion      string                   `json:"apiVersion"`
	Home            string                   `json:"home"`
	Ref             string                   `json:"ref"`
	SourceInput     json.RawMessage          `json:"sourceInput"`
	ToolSource      json.RawMessage          `json:"toolSource"`
	Render          renderref.Input          `json:"render"`
	RendererVersion string                   `json:"rendererVersion"`
	Origins         map[string]survey.Source `json:"origins"`
	Interactive     bool                     `json:"interactive"`
}
type NewCleanPreparation struct {
	nativeIntent   *contextsource.PreparedNativeNew
	nativeSources  *sourceadapter.ContextSource
	root           provenance.RootTemplateLock
	runtime        *trustload.Runtime
	input          NewCleanInput
	context        newimages.Context
	paths          []string
	formats        map[string]*Prepared
	registrySHA256 string
	purpose        string
}
type NewCleanProjection struct {
	owner *NewCleanPreparation
	pairs map[string]*VerifiedPair
}

func PrepareNewClean(ctx context.Context, r *trustload.Runtime, in NewCleanInput) (*NewCleanPreparation, error) {
	return prepareNewClean(ctx, r, in, nil)
}

func prepareNewClean(ctx context.Context, r *trustload.Runtime, in NewCleanInput, retained *engine.ManagedPublicationRecord) (*NewCleanPreparation, error) {
	if in.APIVersion == "tplaiter.dev/managed-new-clean-input/v2" {
		return prepareContextNewClean(ctx, r, in, retained)
	}
	return prepareRootClean(ctx, r, in, retained, "new", evidencecas.Digest(nil), nil)
}

func prepareRootClean(ctx context.Context, r *trustload.Runtime, in NewCleanInput, retained *engine.ManagedPublicationRecord, purpose, observedDigest string, registryBefore []byte) (*NewCleanPreparation, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || in.APIVersion != "tplaiter.dev/managed-new-clean-input/v1" || in.Home == "" || in.Origins == nil {
		return nil, ErrUnavailable
	}
	src, err := sourceadapter.Resolve(ctx, r, in.Home, in.Ref, in.SourceInput)
	if err != nil {
		return nil, err
	}
	// The display alias is derived by the actual locator, never supplied by a
	// reconstructed request as a different render context.
	if in.Render.Repo != src.Alias {
		return nil, ErrUnavailable
	}
	prepared, err := operationtrust.PrepareNew(ctx, r, operationtrust.PrepareNewInput{SourceInput: src.Input, Render: in.Render, RendererVersion: in.RendererVersion})
	if err != nil {
		return nil, err
	}
	result := prepared.Rendered()
	if result == nil || result.Template.AIConfig.Path != "" || len(result.Template.Environment.Playbooks) != 0 || len(result.Template.Requires.Tools) != 0 || len(result.Template.Hooks.PostCreate) != 0 || len(result.Template.Hooks.PostUpdate) != 0 || operationtrust.ValidateProjectBuildSource(ctx, r.TrustRuntime(), src.Input, result.Template) != nil {
		return nil, ErrUnavailable
	}
	// A fresh root has no predecessor from which a replacement can originate.
	if result.Template.ManagedBlocks != nil && len(result.Template.ManagedBlocks.Replacements) != 0 {
		return nil, ErrUnavailable
	}
	for name, origin := range in.Origins {
		if _, exists := in.Render.Values[name]; !exists || (origin != survey.SourceDefault && origin != survey.SourceSet && origin != survey.SourceAnswer && origin != survey.SourcePrompt && origin != survey.SourceImplied) {
			return nil, ErrUnavailable
		}
	}
	source, err := operationtrust.DecodeSourceSelection(src.Input)
	if err != nil {
		return nil, err
	}
	provider, err := r.TrustRuntime().VerifySubject(ctx, source.TrustSubject(), source.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	tool, err := operationtrust.DecodeSourceSelection(in.ToolSource)
	if err != nil {
		return nil, err
	}
	toolProvider, err := r.TrustRuntime().VerifySubject(ctx, tool.TrustSubject(), tool.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	resourceImages, err := resources.PlanNativeGeneratorImages(r.TrustRuntime(), provider, prepared.RootLock())
	if err != nil {
		return nil, err
	}
	registry, _, _, err := state.ReadProjectsRaw(in.Home)
	if err != nil {
		return nil, err
	}
	if retained != nil {
		data, err := retained.DataFor(r)
		if err != nil {
			return nil, err
		}
		raw, err := canonicaljson.Canonical(in)
		if err != nil || !bytes.Equal(raw, data.Input) {
			return nil, ErrUnavailable
		}
		registry = append([]byte(nil), data.RegistryBefore...)
	}
	if purpose == "link" {
		if retained != nil || !validLinkObservationDigest(observedDigest) || len(registryBefore) > 4<<20 {
			return nil, ErrUnavailable
		}
		registry = append([]byte(nil), registryBefore...)
	} else if purpose != "new" {
		return nil, ErrUnavailable
	}
	registryDigest := evidencecas.Digest(registry)
	answers, err := canonicaljson.Canonical(in.Render.Values)
	if err != nil {
		return nil, err
	}
	emptyReplacements, err := canonicaljson.Canonical(struct {
		Version      int   `json:"version"`
		Replacements []any `json:"replacements"`
	}{1, []any{}})
	if err != nil {
		return nil, err
	}
	emptyDecisions, err := canonicaljson.Canonical(struct {
		APIVersion string `json:"apiVersion"`
		Decisions  []any  `json:"decisions"`
	}{"tplaiter.dev/managed-decisions/v1", []any{}})
	if err != nil {
		return nil, err
	}
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	if err != nil {
		return nil, err
	}
	subject := provider.Subject()
	operation := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: binding, ProjectID: r.ProjectContext().ProjectID, Scope: purpose, PreimageSHA256: observedDigest, AnswersSHA256: evidencecas.Digest(answers), Subjects: []trustverify.Provider{{Origin: subject.Origin, TemplatePath: subject.TemplatePath, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}}, Actions: []trustverify.ActionMaterial{}}
	managed := operationtrust.ManagedFormatterContext{APIVersion: "tplaiter.dev/managed-formatter-context/v1", Role: "clean-target", SourceRootLockSHA256: prepared.RootLock().RootLockSHA256, TargetRootLockSHA256: prepared.RootLock().RootLockSHA256, ReplacementDeclarationsSHA256: evidencecas.Digest(emptyReplacements), DecisionsSHA256: evidencecas.Digest(emptyDecisions), ObservedProjectSHA256: observedDigest, ObservedRegistrySHA256: registryDigest, RendererAnswersSHA256: evidencecas.Digest(answers)}
	p := &NewCleanPreparation{runtime: r, input: in, root: prepared.RootLock(), context: newimages.Context{ID: r.ProjectContext().ProjectID, Source: src, Info: in.Render.Project, Port: in.Render.Runtime.Port, Result: result, Prepared: prepared, Resources: resourceImages, Sources: in.Origins, Interactive: in.Interactive}, formats: map[string]*Prepared{}, registrySHA256: registryDigest, purpose: purpose}
	for path, input := range result.Files {
		if !bytes.Contains(input, []byte("tplater:managed-")) {
			continue
		}
		p.formats[path], err = PrepareRootGoFile(ctx, r, provider, toolProvider, path, input, managed, operation)
		if err != nil {
			return nil, err
		}
		p.paths = append(p.paths, path)
	}
	if len(p.paths) == 0 || len(p.paths) > 4096 {
		return nil, ErrUnavailable
	}
	sort.Strings(p.paths)
	// Detach the complete semantic input from any caller-owned map or slice.
	raw, err := canonicaljson.Canonical(in)
	if err != nil {
		return nil, err
	}
	if canonicaljson.DecodeStrict(raw, &p.input) != nil {
		return nil, ErrUnavailable
	}
	p.context.Sources = p.input.Origins
	return p, nil
}

func (p *NewCleanPreparation) Requests() []trustverify.ExecutionRequest {
	if p == nil {
		return nil
	}
	out := []trustverify.ExecutionRequest{}
	for _, path := range p.paths {
		out = append(out, p.formats[path].Requests()...)
	}
	return out
}

func (p *NewCleanPreparation) RequiredRequests(ctx context.Context) ([]trustverify.ExecutionRequest, error) {
	if p == nil {
		return nil, ErrUnavailable
	}
	out := []trustverify.ExecutionRequest{}
	for _, path := range p.paths {
		requests, err := p.formats[path].PendingRequests(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, requests...)
	}
	return out, nil
}

func (p *NewCleanPreparation) References() map[string]Reference {
	if p == nil {
		return nil
	}
	out := map[string]Reference{}
	for _, path := range p.paths {
		out[path] = p.formats[path].Reference()
	}
	return out
}

func OpenNewClean(ctx context.Context, p *NewCleanPreparation, references map[string]Reference) (*NewCleanProjection, error) {
	if p == nil || len(references) != len(p.paths) {
		return nil, ErrUnavailable
	}
	pairs := map[string]*VerifiedPair{}
	for _, path := range p.paths {
		reference, exists := references[path]
		if !exists {
			return nil, ErrUnavailable
		}
		pair, err := OpenPair(ctx, p.formats[path], reference)
		if err != nil {
			return nil, err
		}
		pairs[path] = pair
	}
	return &NewCleanProjection{owner: p, pairs: pairs}, nil
}

func StageNewClean(ctx context.Context, p *NewCleanPreparation, approvals map[string]trustverify.ApprovalRefs) (*NewCleanProjection, error) {
	if p == nil {
		return nil, ErrUnavailable
	}
	requests, err := p.RequiredRequests(ctx)
	if err != nil {
		return nil, err
	}
	if len(approvals) != len(requests) {
		return nil, ErrUnavailable
	}
	for _, request := range requests {
		if _, exists := approvals[request.RequestSHA256]; !exists {
			return nil, ErrUnavailable
		}
	}
	if len(requests) == 0 {
		return OpenNewClean(ctx, p, p.References())
	}
	for _, path := range p.paths {
		requests := p.formats[path].Requests()
		refs := make([]trustverify.ApprovalRefs, len(requests))
		for i, request := range requests {
			refs[i] = approvals[request.RequestSHA256]
		}
		if _, err := Stage(ctx, p.formats[path], refs); err != nil {
			return nil, err
		}
	}
	return OpenNewClean(ctx, p, p.References())
}

// ImagesFor rebuilds the entire source-owned image set. These bytes remain
// proposals until the managed transaction owner authenticates its intent and
// freshly revalidates publication approvals under the held project lease.
func (v *NewCleanProjection) ImagesFor(ctx context.Context, p *NewCleanPreparation) (map[string][]byte, error) {
	if p == nil || v == nil || v.owner != p {
		return nil, ErrUnavailable
	}
	formatted := map[string][]byte{}
	for _, path := range p.paths {
		pair, exists := v.pairs[path]
		if !exists {
			return nil, ErrUnavailable
		}
		raw, err := pair.FormattedFor(ctx, p.formats[path])
		if err != nil {
			return nil, err
		}
		formatted[path] = raw
	}
	if p.nativeIntent != nil {
		return newimages.BuildContextManaged(ctx, p.runtime, p.nativeIntent, p.context, formatted)
	}
	return newimages.BuildManaged(p.context, formatted)
}

const newLineagePath = ".tplaiter/managed-lineage.json"

type PublicationReference = inspect.PublicationReference

type newLineage struct {
	APIVersion            string               `json:"apiVersion"`
	Publication           PublicationReference `json:"publication"`
	RootLockSHA256        string               `json:"rootLockSHA256"`
	ManagedBaselineSHA256 string               `json:"managedBaselineSHA256"`
	FormatterFrames       map[string]string    `json:"formatterFrames"`
}

// NewPublication is reconstructed from actual signed source and authenticated
// formatter records. No public data field or reported receipt constructs it.
type NewPublication struct {
	runtime     *trustload.Runtime
	preparation *NewCleanPreparation
	projection  *NewCleanProjection
	record      *engine.ManagedPublicationRecord
	images      map[string][]byte
}

func imagesDigest(images map[string][]byte) (string, error) {
	raw, err := canonicaljson.Canonical(images)
	if err != nil {
		return "", err
	}
	return bootstrap.DomainDigest("tplaiter.dev/managed-image-set/v1", json.RawMessage(raw))
}

func newRegistryAfter(p *NewCleanPreparation, before []byte, stamp time.Time, baseline []byte) ([]byte, error) {
	projects := state.DefaultProjects()
	var err error
	if len(before) > 0 {
		projects, err = state.DecodeProjectsRaw(before)
		if err != nil {
			return nil, err
		}
	}
	pc := p.runtime.ProjectContext()
	for _, old := range projects.Items {
		if old.ID == pc.ProjectID || old.Path == pc.RootPath {
			return nil, ErrUnavailable
		}
	}
	src := p.context.Source
	projects.Upsert(state.ProjectRef{ID: pc.ProjectID, Path: pc.RootPath, Template: state.TemplateSelection{Repo: src.Alias, Name: src.Name, Version: src.Version}, CreatedAt: stamp, LastSeenAt: stamp, BaselineSHA: strings.TrimPrefix(evidencecas.Digest(baseline), "sha256:")})
	return state.MarshalProjects(projects)
}

func attachNewLineage(p *NewCleanPreparation, data engine.ManagedPublication, images map[string][]byte) (PublicationReference, error) {
	locator, err := data.Locator()
	if err != nil {
		return PublicationReference{}, err
	}
	reference := PublicationReference{APIVersion: publicationReferenceVersion(data.APIVersion), FrameSHA256: locator}
	raw, err := canonicaljson.Canonical(newLineage{APIVersion: publicationLineageVersion(data.APIVersion), Publication: reference, RootLockSHA256: p.root.RootLockSHA256, ManagedBaselineSHA256: evidencecas.Digest(images[".tplaiter/managed-blocks.json"]), FormatterFrames: data.FormatterFrames})
	if err != nil {
		return PublicationReference{}, err
	}
	if _, exists := images[newLineagePath]; exists {
		return PublicationReference{}, ErrUnavailable
	}
	images[newLineagePath] = raw
	return reference, nil
}

// BuildNewPublication freshly reopens source and effects, derives the exact
// registry transition, and persists integrity evidence for these complete
// afterimages. It does not mutate project/registry state or execute formatting.
func BuildNewPublication(ctx context.Context, p *NewCleanPreparation, projection *NewCleanProjection) (*NewPublication, error) {
	if p == nil || p.purpose != "new" || projection == nil || projection.owner != p {
		return nil, ErrUnavailable
	}
	fresh, err := PrepareNewClean(ctx, p.runtime, p.input)
	if err != nil {
		return nil, err
	}
	verified, err := OpenNewClean(ctx, fresh, p.References())
	if err != nil {
		return nil, err
	}
	images, err := verified.ImagesFor(ctx, fresh)
	if err != nil {
		return nil, err
	}
	before, _, _, err := state.ReadProjectsRaw(p.input.Home)
	if err != nil || evidencecas.Digest(before) != p.registrySHA256 {
		return nil, ErrUnavailable
	}
	after, err := newRegistryAfter(fresh, before, time.Now().UTC(), images[".tplaiter/baseline.json"])
	if err != nil {
		return nil, err
	}
	input, err := canonicaljson.Canonical(fresh.input)
	if err != nil {
		return nil, err
	}
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, p.runtime.TrustRuntime().Binding())
	if err != nil {
		return nil, err
	}
	frames := map[string]string{}
	for path, reference := range fresh.References() {
		frames[path] = reference.FrameSHA256
	}
	version := "tplaiter.dev/managed-publication/v1"
	if fresh.nativeIntent != nil {
		version = "tplaiter.dev/managed-publication/v2"
	}
	data := engine.ManagedPublication{APIVersion: version, Kind: "new", ProjectID: p.runtime.ProjectContext().ProjectID, Root: p.runtime.ProjectContext().RootPath, ProfileBindingSHA256: binding, Input: input, ImagesSHA256: evidencecas.Digest(nil), RegistryBefore: append(engine.Bytes{}, before...), RegistryAfter: append(engine.Bytes{}, after...), FormatterFrames: frames}
	reference, err := attachNewLineage(fresh, data, images)
	if err != nil {
		return nil, err
	}
	data.ImagesSHA256, err = imagesDigest(images)
	if err != nil {
		return nil, err
	}
	for _, path := range fresh.paths {
		if err = RevalidatePublication(ctx, fresh.formats[path], verified.pairs[path]); err != nil {
			return nil, err
		}
	}
	record, err := engine.StoreManagedPublication(ctx, p.runtime, data)
	if err != nil {
		return nil, err
	}
	if record.Locator() != reference.FrameSHA256 {
		return nil, ErrUnavailable
	}
	return &NewPublication{runtime: p.runtime, preparation: fresh, projection: verified, record: record, images: images}, nil
}

// OpenNewPublication is readonly. Historical completed effects are verified at
// owner-recorded observation times, without producing new spawn permits.
func OpenNewPublication(ctx context.Context, r *trustload.Runtime, reference PublicationReference) (*NewPublication, error) {
	if reference.APIVersion != "tplaiter.dev/managed-publication-reference/v1" && reference.APIVersion != "tplaiter.dev/managed-publication-reference/v2" {
		return nil, ErrUnavailable
	}
	record, err := engine.ReadManagedPublication(ctx, r, reference.FrameSHA256)
	if err != nil {
		return nil, err
	}
	data, err := record.DataFor(r)
	if err != nil || data.Kind != "new" || reference.APIVersion != publicationReferenceVersion(data.APIVersion) {
		return nil, ErrUnavailable
	}
	var input NewCleanInput
	if canonicaljson.DecodeStrict(data.Input, &input) != nil || (data.APIVersion == "tplaiter.dev/managed-publication/v2") != (input.APIVersion == "tplaiter.dev/managed-new-clean-input/v2") {
		return nil, ErrUnavailable
	}
	p, err := prepareNewClean(ctx, r, input, record)
	if err != nil {
		return nil, err
	}
	refs := p.References()
	if len(refs) != len(data.FormatterFrames) {
		return nil, ErrUnavailable
	}
	for path, ref := range refs {
		if data.FormatterFrames[path] != ref.FrameSHA256 {
			return nil, ErrUnavailable
		}
	}
	projection, err := OpenNewClean(ctx, p, refs)
	if err != nil {
		return nil, err
	}
	images, err := projection.ImagesFor(ctx, p)
	if err != nil {
		return nil, err
	}
	after, err := state.DecodeProjectsRaw(data.RegistryAfter)
	if err != nil {
		return nil, err
	}
	var stamp time.Time
	for _, entry := range after.Items {
		if entry.ID == r.ProjectContext().ProjectID {
			stamp = entry.CreatedAt
			if !entry.LastSeenAt.Equal(stamp) {
				return nil, ErrUnavailable
			}
		}
	}
	if stamp.IsZero() {
		return nil, ErrUnavailable
	}
	expectedAfter, err := newRegistryAfter(p, data.RegistryBefore, stamp, images[".tplaiter/baseline.json"])
	if err != nil || !bytes.Equal(expectedAfter, data.RegistryAfter) {
		return nil, ErrUnavailable
	}
	actual, err := attachNewLineage(p, data, images)
	if err != nil || actual != reference {
		return nil, ErrUnavailable
	}
	digest, err := imagesDigest(images)
	if err != nil || digest != data.ImagesSHA256 {
		return nil, ErrUnavailable
	}
	return &NewPublication{runtime: r, preparation: p, projection: projection, record: record, images: images}, nil
}

func (p *NewPublication) Reference() PublicationReference {
	if p == nil || p.record == nil {
		return PublicationReference{}
	}
	return PublicationReference{APIVersion: publicationReferenceVersion(p.recordVersion()), FrameSHA256: p.record.Locator()}
}

func (p *NewPublication) ImagesFor(ctx context.Context, r *trustload.Runtime) (map[string][]byte, error) {
	if p == nil || p.runtime != r {
		return nil, ErrUnavailable
	}
	// Reconstruct anew rather than expose a retained mutable image map as truth.
	fresh, err := OpenNewPublication(ctx, r, p.Reference())
	if err != nil {
		return nil, err
	}
	images := map[string][]byte{}
	for path, raw := range fresh.images {
		images[path] = append([]byte(nil), raw...)
	}
	return images, nil
}

func (p *NewPublication) RegistryFor(r *trustload.Runtime) (string, []byte, []byte, error) {
	if p == nil || p.runtime != r {
		return "", nil, nil, ErrUnavailable
	}
	data, err := p.record.DataFor(r)
	if err != nil {
		return "", nil, nil, err
	}
	return p.preparation.input.Home, append([]byte(nil), data.RegistryBefore...), append([]byte(nil), data.RegistryAfter...), nil
}

func (p *NewPublication) RevalidatePublication(ctx context.Context, r *trustload.Runtime) error {
	if p == nil || p.runtime != r {
		return ErrUnavailable
	}
	fresh, err := OpenNewPublication(ctx, r, p.Reference())
	if err != nil {
		return err
	}
	for _, path := range fresh.preparation.paths {
		if err = RevalidatePublication(ctx, fresh.preparation.formats[path], fresh.projection.pairs[path]); err != nil {
			return err
		}
	}
	return nil
}

// LinkCleanPreparation has a distinct purpose-bound request scope. It cannot
// become a New publication and exposes no caller-reported execution receipt.
type (
	LinkCleanPreparation struct {
		root           *NewCleanPreparation
		registryBefore []byte
		observedDigest string
	}
	LinkCleanProjection struct {
		owner *LinkCleanPreparation
		root  *NewCleanProjection
	}
)

func PrepareLinkClean(ctx context.Context, r *trustload.Runtime, in NewCleanInput, observed, registryBefore []byte) (*LinkCleanPreparation, error) {
	if len(observed) == 0 || len(observed) > 96<<20 || !json.Valid(observed) {
		return nil, ErrUnavailable
	}
	return prepareLinkDigest(ctx, r, in, evidencecas.Digest(observed), registryBefore)
}

// Only fresh actual observations or the authenticated publication reader call
// this private reconstruction helper. A digest is never a publication grant.
func prepareLinkDigest(ctx context.Context, r *trustload.Runtime, in NewCleanInput, observedDigest string, registryBefore []byte) (*LinkCleanPreparation, error) {
	p, err := prepareRootClean(ctx, r, in, nil, "link", observedDigest, registryBefore)
	if err != nil {
		return nil, err
	}
	return &LinkCleanPreparation{root: p, registryBefore: append([]byte(nil), registryBefore...), observedDigest: observedDigest}, nil
}

func (p *LinkCleanPreparation) RequiredRequests(ctx context.Context) ([]trustverify.ExecutionRequest, error) {
	if p == nil || p.root == nil || p.root.purpose != "link" {
		return nil, ErrUnavailable
	}
	return p.root.RequiredRequests(ctx)
}

func (p *LinkCleanPreparation) References() map[string]Reference {
	if p == nil || p.root == nil || p.root.purpose != "link" {
		return nil
	}
	return p.root.References()
}

func StageLinkClean(ctx context.Context, p *LinkCleanPreparation, refs map[string]trustverify.ApprovalRefs) (*LinkCleanProjection, error) {
	if p == nil || p.root == nil || p.root.purpose != "link" {
		return nil, ErrUnavailable
	}
	v, err := StageNewClean(ctx, p.root, refs)
	if err != nil {
		return nil, err
	}
	return &LinkCleanProjection{owner: p, root: v}, nil
}

func OpenLinkClean(ctx context.Context, p *LinkCleanPreparation, references map[string]Reference) (*LinkCleanProjection, error) {
	if p == nil || p.root == nil || p.root.purpose != "link" {
		return nil, ErrUnavailable
	}
	v, err := OpenNewClean(ctx, p.root, references)
	if err != nil {
		return nil, err
	}
	return &LinkCleanProjection{owner: p, root: v}, nil
}

func (v *LinkCleanProjection) ImagesFor(ctx context.Context, p *LinkCleanPreparation) (map[string][]byte, error) {
	if v == nil || p == nil || v.owner != p {
		return nil, ErrUnavailable
	}
	return v.root.ImagesFor(ctx, p.root)
}

func (v *LinkCleanProjection) RevalidatePublication(ctx context.Context, p *LinkCleanPreparation) error {
	if v == nil || p == nil || v.owner != p {
		return ErrUnavailable
	}
	for _, name := range p.root.paths {
		if err := RevalidatePublication(ctx, p.root.formats[name], v.root.pairs[name]); err != nil {
			return err
		}
	}
	return nil
}

// LinkPublicationInput is sealed reconstruction data, never a writer grant.
// BeforeSHA256 binds the exact original observation retained by the Link
// transaction owner; the integrity record does not duplicate user beforeimages.
type LinkPublicationInput struct {
	APIVersion   string        `json:"apiVersion"`
	Native       NewCleanInput `json:"native"`
	BeforeSHA256 string        `json:"beforeSHA256"`
	Stamp        string        `json:"stamp"`
}
type linkObservedFile struct {
	// The existing Link owner encodes []byte as canonical base64 JSON strings.
	Data      string `json:"data"`
	Mode      uint32 `json:"mode"`
	Directory bool   `json:"directory"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
}
type LinkPublication struct {
	runtime     *trustload.Runtime
	preparation *LinkCleanPreparation
	projection  *LinkCleanProjection
	data        engine.ManagedPublication
	reference   PublicationReference
	images      map[string][]byte
}

// ProjectLinkPublication constructs a deterministic source/effect proposal.
// It neither stores evidence nor publishes state. The Link owner must compare
// these exact observations against its actual held descriptors before sealing.
func ProjectLinkPublication(ctx context.Context, p *LinkCleanPreparation, v *LinkCleanProjection, before json.RawMessage, stamp time.Time) (*LinkPublication, error) {
	if p == nil || v == nil || v.owner != p || stamp.IsZero() || len(before) == 0 || len(before) > 96<<20 {
		return nil, fmt.Errorf("%w: Link observation shape", ErrUnavailable)
	}
	var observed map[string]linkObservedFile
	if canonicaljson.DecodeStrict(before, &observed) != nil || len(observed) == 0 || len(observed) > 4096 {
		return nil, fmt.Errorf("%w: Link observation decode", ErrUnavailable)
	}
	canonical, err := canonicaljson.Canonical(observed)
	if err != nil || !bytes.Equal(before, canonical) {
		return nil, fmt.Errorf("%w: Link observation canonical bytes", ErrUnavailable)
	}
	root, exists := observed["."]
	if !exists || !root.Directory || root.Inode == 0 || len(root.Data) != 0 {
		return nil, fmt.Errorf("%w: Link observation root identity", ErrUnavailable)
	}
	images, err := v.ImagesFor(ctx, p)
	if err != nil {
		return nil, err
	}
	total := 0
	for name, file := range observed {
		decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(file.Data)
		if decodeErr != nil || base64.StdEncoding.EncodeToString(decoded) != file.Data {
			return nil, fmt.Errorf("%w: Link observation byte encoding", ErrUnavailable)
		}
		total += len(decoded)
		if total > 64<<20 || file.Inode == 0 || file.Mode > 0o777 || (file.Directory && len(file.Data) != 0) {
			return nil, fmt.Errorf("%w: Link observation identity/mode bounds", ErrUnavailable)
		}
		if name != "." && (!fs.ValidPath(name) || name == ".tplaiter" || strings.HasPrefix(name, ".tplaiter/") || name == ".tplater" || strings.HasPrefix(name, ".tplater/") || strings.ContainsAny(name, "\\\x00\r\n")) {
			return nil, fmt.Errorf("%w: Link observation path", ErrUnavailable)
		}
	}
	for name, want := range images {
		if strings.HasPrefix(name, ".tplaiter/") {
			continue
		}
		actual, ok := observed[name]
		decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(actual.Data)
		if !ok || decodeErr != nil || actual.Directory || actual.Mode != 0o644 || !bytes.Equal(decoded, want) {
			return nil, fmt.Errorf("%w: Link observed file differs from formatted source at %s", ErrUnavailable, name)
		}
	}
	if evidencecas.Digest(before) != p.observedDigest {
		return nil, fmt.Errorf("%w: Link observation digest mismatch", ErrUnavailable)
	}
	return projectLinkImages(ctx, p, v, images, stamp)
}

func validLinkObservationDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

// The cold reader reaches this projector only after authenticating the original
// observation digest and reopening the exact source-bound formatter effects.
func projectLinkImages(ctx context.Context, p *LinkCleanPreparation, v *LinkCleanProjection, images map[string][]byte, stamp time.Time) (*LinkPublication, error) {
	if p == nil || v == nil || v.owner != p || stamp.IsZero() || !validLinkObservationDigest(p.observedDigest) {
		return nil, ErrUnavailable
	}
	// Independently bind the observation digest to every actual request frame.
	for _, name := range p.root.paths {
		frame := p.root.formats[name].frame
		if frame.Operation.Scope != "link" || frame.Operation.PreimageSHA256 != p.observedDigest {
			return nil, ErrUnavailable
		}
	}
	images[".tplaiter/update.lock"] = []byte{}
	input, err := canonicaljson.Canonical(LinkPublicationInput{APIVersion: "tplaiter.dev/managed-link-publication-input/v1", Native: p.root.input, BeforeSHA256: p.observedDigest, Stamp: stamp.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return nil, err
	}
	// Registry bytes are fixed in the verified Link preparation. The actual
	// owner checks their inode and exact current bytes before taking its lease.
	registryBefore := p.registryBefore
	after, err := newRegistryAfter(p.root, registryBefore, stamp, images[".tplaiter/baseline.json"])
	if err != nil {
		return nil, err
	}
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, p.root.runtime.TrustRuntime().Binding())
	if err != nil {
		return nil, err
	}
	frames := map[string]string{}
	for name, ref := range p.References() {
		frames[name] = ref.FrameSHA256
	}
	data := engine.ManagedPublication{APIVersion: "tplaiter.dev/managed-publication/v1", Kind: "link", ProjectID: p.root.runtime.ProjectContext().ProjectID, Root: p.root.runtime.ProjectContext().RootPath, ProfileBindingSHA256: binding, Input: input, ImagesSHA256: evidencecas.Digest(nil), RegistryBefore: append(engine.Bytes{}, registryBefore...), RegistryAfter: append(engine.Bytes{}, after...), FormatterFrames: frames}
	ref, err := attachNewLineage(p.root, data, images)
	if err != nil {
		return nil, err
	}
	data.ImagesSHA256, err = imagesDigest(images)
	if err != nil {
		return nil, err
	}
	return &LinkPublication{runtime: p.root.runtime, preparation: p, projection: v, data: data, reference: ref, images: images}, nil
}

func (p *LinkPublication) Reference() PublicationReference {
	if p == nil {
		return PublicationReference{}
	}
	return p.reference
}

func (p *LinkPublication) ImagesFor(ctx context.Context, r *trustload.Runtime) (map[string][]byte, error) {
	if p == nil || p.runtime != r || ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if _, err := p.projection.ImagesFor(ctx, p.preparation); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for name, raw := range p.images {
		out[name] = append([]byte(nil), raw...)
	}
	return out, nil
}

func (p *LinkPublication) RegistryFor(r *trustload.Runtime) (string, []byte, []byte, error) {
	if p == nil || p.runtime != r {
		return "", nil, nil, ErrUnavailable
	}
	return p.preparation.root.input.Home, append([]byte(nil), p.data.RegistryBefore...), append([]byte(nil), p.data.RegistryAfter...), nil
}

func (p *LinkPublication) Store(ctx context.Context, r *trustload.Runtime) error {
	if p == nil || p.runtime != r {
		return ErrUnavailable
	}
	if err := p.projection.RevalidatePublication(ctx, p.preparation); err != nil {
		return err
	}
	record, err := engine.StoreManagedPublication(ctx, r, p.data)
	if err != nil {
		return err
	}
	if record.Locator() != p.reference.FrameSHA256 {
		return ErrUnavailable
	}
	return nil
}

func OpenLinkPublication(ctx context.Context, r *trustload.Runtime, reference PublicationReference) (*LinkPublication, error) {
	if reference.APIVersion != "tplaiter.dev/managed-publication-reference/v1" {
		return nil, ErrUnavailable
	}
	record, err := engine.ReadManagedPublication(ctx, r, reference.FrameSHA256)
	if err != nil {
		return nil, err
	}
	data, err := record.DataFor(r)
	if err != nil || data.Kind != "link" {
		return nil, ErrUnavailable
	}
	var in LinkPublicationInput
	if canonicaljson.DecodeStrict(data.Input, &in) != nil || in.APIVersion != "tplaiter.dev/managed-link-publication-input/v1" {
		return nil, ErrUnavailable
	}
	stamp, err := time.Parse(time.RFC3339Nano, in.Stamp)
	if err != nil {
		return nil, ErrUnavailable
	}
	p, err := prepareLinkDigest(ctx, r, in.Native, in.BeforeSHA256, data.RegistryBefore)
	if err != nil {
		return nil, err
	}
	refs := map[string]Reference{}
	for name, frame := range data.FormatterFrames {
		refs[name] = Reference{APIVersion: "tplaiter.dev/formatter-reference/v1", FrameSHA256: frame}
	}
	v, err := OpenLinkClean(ctx, p, refs)
	if err != nil {
		return nil, err
	}
	images, err := v.ImagesFor(ctx, p)
	if err != nil {
		return nil, err
	}
	rebuilt, err := projectLinkImages(ctx, p, v, images, stamp)
	if err != nil {
		return nil, err
	}
	actual, err := canonicaljson.Canonical(data)
	if err != nil {
		return nil, err
	}
	want, err := canonicaljson.Canonical(rebuilt.data)
	if err != nil || !bytes.Equal(actual, want) || rebuilt.Reference() != reference {
		return nil, ErrUnavailable
	}
	return rebuilt, nil
}

func PublicationKind(ctx context.Context, r *trustload.Runtime, reference PublicationReference) (string, error) {
	if reference.APIVersion != "tplaiter.dev/managed-publication-reference/v1" && reference.APIVersion != "tplaiter.dev/managed-publication-reference/v2" {
		return "", ErrUnavailable
	}
	record, err := engine.ReadManagedPublication(ctx, r, reference.FrameSHA256)
	if err != nil {
		return "", err
	}
	data, err := record.DataFor(r)
	if err != nil {
		return "", err
	}
	if reference.APIVersion != publicationReferenceVersion(data.APIVersion) {
		return "", ErrUnavailable
	}
	return data.Kind, nil
}

// UpdateCleanPreparation retains the actual same-runtime source/target intent.
// It can prepare and verify effects, but cannot construct a transaction grant.
type UpdateCleanPreparation struct {
	runtime              *trustload.Runtime
	intent               *operationtrust.PreparedUpdate
	source, target, tool operationtrust.SourceSelection
	formats              map[string]*Prepared
	paths                []string
	operation            trustverify.OperationInputs
	managed              operationtrust.ManagedFormatterContext
}

type UpdateCleanProjection struct {
	owner *UpdateCleanPreparation
	pairs map[string]*VerifiedPair
}

// PrepareUpdateClean binds the existing opaque Update calculation's exact base
// digest before adding real per-file formatter actions. Render is the existing
// source-owned target render input, not a caller-provided operation or permit.
func PrepareUpdateClean(ctx context.Context, r *trustload.Runtime, intent *operationtrust.PreparedUpdate, sourceRaw, targetRaw, toolRaw []byte, render, sourceRender renderref.Input, observedDigest, registryDigest string, decisionsRaw []byte) (*UpdateCleanPreparation, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.TrustRuntime() == nil || intent == nil || !intent.ValidFor(r.TrustRuntime()) || !validLinkObservationDigest(observedDigest) || !validLinkObservationDigest(registryDigest) {
		return nil, ErrUnavailable
	}
	for _, raw := range [][]byte{sourceRaw, targetRaw, toolRaw} {
		if len(raw) == 0 || len(raw) > 1<<20 {
			return nil, ErrUnavailable
		}
	}
	source, err := operationtrust.DecodeSourceSelection(sourceRaw)
	if err != nil {
		return nil, err
	}
	target, err := operationtrust.DecodeSourceSelection(targetRaw)
	if err != nil {
		return nil, err
	}
	tool, err := operationtrust.DecodeSourceSelection(toolRaw)
	if err != nil {
		return nil, err
	}
	decisions, err := managedblocks.ParseDecisions(decisionsRaw)
	if err != nil {
		return nil, err
	}
	canonicalDecisions, err := canonicaljson.Canonical(decisions)
	if err != nil || !bytes.Equal(canonicalDecisions, decisionsRaw) {
		return nil, ErrUnavailable
	}
	resolutions := make([]*trustverify.VerifiedResolution, 3)
	for i, selection := range []*operationtrust.SourceSelection{source, target, tool} {
		resolutions[i], err = r.TrustRuntime().VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
		if err != nil {
			return nil, err
		}
	}
	if !updateSelectionMatchesRoot(*source, intent.SourceRootLock()) || !updateSelectionMatchesRoot(*target, intent.TargetRootLock()) {
		return nil, ErrUnavailable
	}
	provider := func(resolution *trustverify.VerifiedResolution) trustverify.Provider {
		s := resolution.Subject()
		return trustverify.Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
	}
	subjects := []trustverify.Provider{provider(resolutions[0]), provider(resolutions[1])}
	key := func(p trustverify.Provider) string { return p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit }
	if key(subjects[1]) < key(subjects[0]) {
		subjects[0], subjects[1] = subjects[1], subjects[0]
	}
	if subjects[0] == subjects[1] {
		subjects = subjects[:1]
	}
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	if err != nil {
		return nil, err
	}
	answers, err := canonicaljson.Canonical(render.Values)
	if err != nil {
		return nil, err
	}
	operation := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: binding, ProjectID: r.ProjectContext().ProjectID, Scope: "update", PreimageSHA256: observedDigest, AnswersSHA256: evidencecas.Digest(answers), Subjects: subjects, Actions: []trustverify.ActionMaterial{}}
	baseDigest, err := trustverify.ComputeOperationInputsSHA256(operation)
	if err != nil || baseDigest != intent.OperationInputsSHA256() {
		return nil, ErrUnavailable
	}
	// The calculation base contains source and target. The action-bearing
	// formatter operation additionally binds an independent admitted tool.
	toolSubject := provider(resolutions[2])
	foundTool := false
	for _, subject := range operation.Subjects {
		if key(subject) == key(toolSubject) && subject != toolSubject {
			return nil, ErrUnavailable
		}
		if subject == toolSubject {
			foundTool = true
		}
	}
	if !foundTool {
		operation.Subjects = append(operation.Subjects, toolSubject)
	}
	sort.Slice(operation.Subjects, func(i, j int) bool { return key(operation.Subjects[i]) < key(operation.Subjects[j]) })
	result := intent.Rendered()
	if result == nil || result.Template == nil {
		return nil, ErrUnavailable
	}
	targetFS, err := operationtrust.SnapshotFS(r.TrustRuntime(), resolutions[1])
	if err != nil {
		return nil, err
	}
	signedTemplate, err := renderref.LoadTemplate(targetFS)
	if err != nil {
		return nil, err
	}
	replacements := signedTemplate.ManagedBlocks
	if replacements == nil {
		replacements = &manifest.ManagedBlocks{Version: 1, Replacements: []manifest.ManagedReplacement{}}
	}
	replacementBytes, err := canonicaljson.Canonical(replacements)
	if err != nil {
		return nil, err
	}
	managed := operationtrust.ManagedFormatterContext{APIVersion: "tplaiter.dev/managed-formatter-context/v1", Role: "clean-target", SourceRootLockSHA256: intent.SourceRootLock().RootLockSHA256, TargetRootLockSHA256: intent.TargetRootLock().RootLockSHA256, ReplacementDeclarationsSHA256: evidencecas.Digest(replacementBytes), DecisionsSHA256: evidencecas.Digest(canonicalDecisions), ObservedProjectSHA256: observedDigest, ObservedRegistrySHA256: registryDigest, RendererAnswersSHA256: evidencecas.Digest(answers)}
	p := &UpdateCleanPreparation{runtime: r, intent: intent, source: *source, target: *target, tool: *tool, formats: map[string]*Prepared{}, operation: operation, managed: managed}
	// An authenticated source render determines whether a marker-free target is
	// a managed deletion. Caller paths cannot enroll an ordinary file here.
	sourceIntent, err := operationtrust.PrepareSnapshot(ctx, r, operationtrust.PrepareSnapshotInput{SourceInput: sourceRaw, Render: sourceRender, RendererVersion: intent.SourceRootLock().Renderer.Version})
	if err != nil || sourceIntent.RootLock() != intent.SourceRootLock() {
		return nil, ErrUnavailable
	}
	sourceFiles := sourceIntent.Rendered().Files
	for path, input := range result.Files {
		if !bytes.Contains(input, []byte("tplater:managed-")) && !bytes.Contains(sourceFiles[path], []byte("tplater:managed-")) {
			continue
		}
		p.formats[path], err = prepareRootGoFormat(ctx, r, resolutions[1], resolutions[2], path, input, managed, operation)
		if err != nil {
			return nil, err
		}
		p.paths = append(p.paths, path)
	}
	if len(p.paths) == 0 || len(p.paths) > 4096 {
		return nil, ErrUnavailable
	}
	sort.Strings(p.paths)
	return p, nil
}

func updateSelectionMatchesRoot(selection operationtrust.SourceSelection, lock provenance.RootTemplateLock) bool {
	s, e := selection.TrustSubject(), selection.EvidenceRefs()
	return lock.Root == (provenance.RootSubject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256, StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint, CheckpointCAS: e.CheckpointCAS, InclusionProofCAS: e.InclusionProofCAS})
}

func (p *UpdateCleanPreparation) recheck(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || p == nil || p.runtime == nil || p.intent == nil || !p.intent.ValidFor(p.runtime.TrustRuntime()) {
		return ErrUnavailable
	}
	for _, selection := range []operationtrust.SourceSelection{p.source, p.target, p.tool} {
		if _, err := p.runtime.TrustRuntime().VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs()); err != nil {
			return err
		}
	}
	return nil
}

func (p *UpdateCleanPreparation) RequiredRequests(ctx context.Context) ([]trustverify.ExecutionRequest, error) {
	if err := p.recheck(ctx); err != nil {
		return nil, err
	}
	out := []trustverify.ExecutionRequest{}
	for _, path := range p.paths {
		requests, err := p.formats[path].PendingRequests(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, requests...)
	}
	return out, nil
}

func (p *UpdateCleanPreparation) References() map[string]Reference {
	if p == nil {
		return nil
	}
	refs := map[string]Reference{}
	for _, path := range p.paths {
		refs[path] = p.formats[path].Reference()
	}
	return refs
}

func OpenUpdateClean(ctx context.Context, p *UpdateCleanPreparation, refs map[string]Reference) (*UpdateCleanProjection, error) {
	if err := p.recheck(ctx); err != nil {
		return nil, err
	}
	if len(refs) != len(p.paths) {
		return nil, ErrUnavailable
	}
	v := &UpdateCleanProjection{owner: p, pairs: map[string]*VerifiedPair{}}
	for _, path := range p.paths {
		ref, ok := refs[path]
		if !ok {
			return nil, ErrUnavailable
		}
		pair, err := OpenPair(ctx, p.formats[path], ref)
		if err != nil {
			return nil, err
		}
		v.pairs[path] = pair
	}
	return v, nil
}

func StageUpdateClean(ctx context.Context, p *UpdateCleanPreparation, approvals map[string]trustverify.ApprovalRefs) (*UpdateCleanProjection, error) {
	requests, err := p.RequiredRequests(ctx)
	if err != nil {
		return nil, err
	}
	if len(approvals) != len(requests) {
		return nil, ErrUnavailable
	}
	for _, request := range requests {
		if _, ok := approvals[request.RequestSHA256]; !ok {
			return nil, ErrUnavailable
		}
	}
	for _, path := range p.paths {
		pending, err := p.formats[path].PendingRequests(ctx)
		if err != nil {
			return nil, err
		}
		if len(pending) == 0 {
			continue
		}
		refs := make([]trustverify.ApprovalRefs, 2)
		for i, request := range p.formats[path].Requests() {
			refs[i] = approvals[request.RequestSHA256]
		}
		if _, err := Stage(ctx, p.formats[path], refs); err != nil {
			return nil, err
		}
	}
	return OpenUpdateClean(ctx, p, p.References())
}

func (v *UpdateCleanProjection) RenderedFor(ctx context.Context, p *UpdateCleanPreparation) (*renderref.Result, error) {
	if v == nil || p == nil || v.owner != p {
		return nil, ErrUnavailable
	}
	if err := p.recheck(ctx); err != nil {
		return nil, err
	}
	result := p.intent.Rendered()
	// Re-read declarations from the original verified target. Rendered() is a
	// detached data projection, not authority for a replacement declaration.
	resolution, err := p.runtime.TrustRuntime().VerifySubject(ctx, p.target.TrustSubject(), p.target.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	snapshot, err := operationtrust.SnapshotFS(p.runtime.TrustRuntime(), resolution)
	if err != nil {
		return nil, err
	}
	signedTemplate, err := renderref.LoadTemplate(snapshot)
	if err != nil {
		return nil, err
	}
	if result == nil || result.Baseline == nil {
		return nil, ErrUnavailable
	}
	result.Template = signedTemplate
	result.Resolved.Values = result.Resolved.Values.Clone()
	result.Resolved.ActiveValues = result.Resolved.ActiveValues.Clone()
	baseline := *result.Baseline
	baseline.Files = map[string]string{}
	for path, digest := range result.Baseline.Files {
		baseline.Files[path] = digest
	}
	for _, path := range p.paths {
		pair := v.pairs[path]
		if pair == nil {
			return nil, ErrUnavailable
		}
		output, err := pair.FormattedFor(ctx, p.formats[path])
		if err != nil {
			return nil, err
		}
		result.Files[path] = output
		baseline.Files[path] = strings.TrimPrefix(evidencecas.Digest(output), "sha256:")
	}
	result.Baseline = &baseline
	return result, nil
}

func (v *UpdateCleanProjection) RevalidatePublication(ctx context.Context, p *UpdateCleanPreparation) error {
	if _, err := v.RenderedFor(ctx, p); err != nil {
		return err
	}
	for _, path := range p.paths {
		if err := RevalidatePublication(ctx, p.formats[path], v.pairs[path]); err != nil {
			return err
		}
	}
	return nil
}

// UpdateMergedPreparation retains candidate transport under the actual clean
// effect predecessor. It is not a publication grant: the Update plan owner must
// derive and revalidate these candidates from authenticated baseline and Ours.
type UpdateMergedPreparation struct {
	clean      *UpdateCleanPreparation
	projection *UpdateCleanProjection
	formats    *UpdateCleanPreparation
}

type UpdateMergedProjection struct {
	owner      *UpdateMergedPreparation
	projection *UpdateCleanProjection
}

func PrepareUpdateMerged(ctx context.Context, clean *UpdateCleanPreparation, verified *UpdateCleanProjection, candidates map[string][]byte) (*UpdateMergedPreparation, error) {
	if verified == nil || clean == nil || verified.owner != clean || len(candidates) != len(clean.paths) {
		return nil, ErrUnavailable
	}
	if _, err := verified.RenderedFor(ctx, clean); err != nil {
		return nil, err
	}
	r := clean.runtime
	target, err := r.TrustRuntime().VerifySubject(ctx, clean.target.TrustSubject(), clean.target.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	tool, err := r.TrustRuntime().VerifySubject(ctx, clean.tool.TrustSubject(), clean.tool.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	formats := &UpdateCleanPreparation{runtime: r, intent: clean.intent, source: clean.source, target: clean.target, tool: clean.tool, paths: append([]string(nil), clean.paths...), formats: map[string]*Prepared{}, operation: clean.operation}
	for _, path := range clean.paths {
		input, ok := candidates[path]
		if !ok || len(input) == 0 || len(input) > 16<<20 {
			return nil, ErrUnavailable
		}
		context := clean.managed
		context.Role = "merged-candidate"
		// The exact retained frame binds both native passes, source material,
		// operator approvals, clean input and action-bearing operation digest.
		context.PredecessorCleanProofSHA256 = clean.formats[path].Reference().FrameSHA256
		formats.formats[path], err = prepareRootGoFormat(ctx, r, target, tool, path, input, context, clean.operation)
		if err != nil {
			return nil, err
		}
	}
	return &UpdateMergedPreparation{clean: clean, projection: verified, formats: formats}, nil
}

func (p *UpdateMergedPreparation) RequiredRequests(ctx context.Context) ([]trustverify.ExecutionRequest, error) {
	if p == nil || p.projection == nil {
		return nil, ErrUnavailable
	}
	if _, err := p.projection.RenderedFor(ctx, p.clean); err != nil {
		return nil, err
	}
	return p.formats.RequiredRequests(ctx)
}

func (p *UpdateMergedPreparation) References() map[string]Reference {
	if p == nil {
		return nil
	}
	return p.formats.References()
}

func StageUpdateMerged(ctx context.Context, p *UpdateMergedPreparation, approvals map[string]trustverify.ApprovalRefs) (*UpdateMergedProjection, error) {
	if _, err := p.RequiredRequests(ctx); err != nil {
		return nil, err
	}
	projection, err := StageUpdateClean(ctx, p.formats, approvals)
	if err != nil {
		return nil, err
	}
	return &UpdateMergedProjection{owner: p, projection: projection}, nil
}

func OpenUpdateMerged(ctx context.Context, p *UpdateMergedPreparation, refs map[string]Reference) (*UpdateMergedProjection, error) {
	if _, err := p.RequiredRequests(ctx); err != nil {
		return nil, err
	}
	projection, err := OpenUpdateClean(ctx, p.formats, refs)
	if err != nil {
		return nil, err
	}
	return &UpdateMergedProjection{owner: p, projection: projection}, nil
}

func (v *UpdateMergedProjection) FilesFor(ctx context.Context, p *UpdateMergedPreparation) (map[string][]byte, error) {
	if v == nil || p == nil || v.owner != p || v.projection == nil {
		return nil, ErrUnavailable
	}
	if _, err := p.RequiredRequests(ctx); err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, path := range p.formats.paths {
		pair := v.projection.pairs[path]
		if pair == nil {
			return nil, ErrUnavailable
		}
		output, err := pair.FormattedFor(ctx, p.formats.formats[path])
		if err != nil {
			return nil, err
		}
		files[path] = output
	}
	return files, nil
}

func (v *UpdateMergedProjection) RevalidatePublication(ctx context.Context, p *UpdateMergedPreparation) error {
	if _, err := v.FilesFor(ctx, p); err != nil {
		return err
	}
	if err := p.projection.RevalidatePublication(ctx, p.clean); err != nil {
		return err
	}
	for _, path := range p.formats.paths {
		if err := RevalidatePublication(ctx, p.formats.formats[path], v.projection.pairs[path]); err != nil {
			return err
		}
	}
	return nil
}

func publicationReferenceVersion(version string) string {
	if version == "tplaiter.dev/managed-publication/v2" {
		return "tplaiter.dev/managed-publication-reference/v2"
	}
	return "tplaiter.dev/managed-publication-reference/v1"
}

func publicationLineageVersion(version string) string {
	if version == "tplaiter.dev/managed-publication/v2" {
		return "tplaiter.dev/managed-lineage/v2"
	}
	return "tplaiter.dev/managed-lineage/v1"
}

func (p *NewPublication) recordVersion() string {
	if p != nil && p.preparation != nil && p.preparation.nativeIntent != nil {
		return "tplaiter.dev/managed-publication/v2"
	}
	return "tplaiter.dev/managed-publication/v1"
}

func prepareContextNewClean(ctx context.Context, r *trustload.Runtime, in NewCleanInput, retained *engine.ManagedPublicationRecord) (*NewCleanPreparation, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || in.APIVersion != "tplaiter.dev/managed-new-clean-input/v2" || in.Home == "" || in.Origins == nil {
		return nil, ErrUnavailable
	}
	src, err := sourceadapter.ResolveContextSources(ctx, r, in.Home, in.Ref, in.SourceInput)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			src.Close()
		}
	}()
	rootSource, err := src.Root(ctx, r)
	if err != nil || in.Render.Repo != rootSource.Alias {
		return nil, ErrUnavailable
	}
	sources, err := src.Sources(ctx, r)
	if err != nil {
		return nil, err
	}
	intent, err := contextsource.PrepareManagedNativeNew(ctx, r, sources, contextsource.NativeNewInput{Render: in.Render, RendererVersion: in.RendererVersion})
	if err != nil {
		return nil, err
	}
	defer func() {
		if !complete {
			intent.Close()
		}
	}()
	result, err := intent.Rendered(ctx, r)
	if err != nil {
		return nil, err
	}
	for name, origin := range in.Origins {
		if _, exists := in.Render.Values[name]; !exists || (origin != survey.SourceDefault && origin != survey.SourceSet && origin != survey.SourceAnswer && origin != survey.SourcePrompt && origin != survey.SourceImplied) {
			return nil, ErrUnavailable
		}
	}
	tool, err := operationtrust.DecodeSourceSelection(in.ToolSource)
	if err != nil {
		return nil, err
	}
	toolProvider, err := r.TrustRuntime().VerifySubject(ctx, tool.TrustSubject(), tool.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	resourceImages, err := resources.PlanContextNativeGeneratorImages(ctx, r, intent)
	if err != nil {
		return nil, err
	}
	registry, _, _, err := state.ReadProjectsRaw(in.Home)
	if err != nil {
		return nil, err
	}
	if retained != nil {
		data, err := retained.DataFor(r)
		if err != nil || data.APIVersion != "tplaiter.dev/managed-publication/v2" || data.Kind != "new" {
			return nil, ErrUnavailable
		}
		raw, err := canonicaljson.Canonical(in)
		if err != nil || !bytes.Equal(raw, data.Input) {
			return nil, ErrUnavailable
		}
		registry = append([]byte(nil), data.RegistryBefore...)
	}
	root, err := intent.RootLock(ctx, r)
	if err != nil {
		return nil, err
	}
	p := &NewCleanPreparation{runtime: r, input: in, nativeSources: src, nativeIntent: intent, root: root, purpose: "new", registrySHA256: evidencecas.Digest(registry), formats: map[string]*Prepared{}, context: newimages.Context{ID: r.ProjectContext().ProjectID, Source: rootSource, Info: in.Render.Project, Port: in.Render.Runtime.Port, Result: result, Resources: resourceImages, Sources: in.Origins, Interactive: in.Interactive}}
	inventory, err := intent.ManagedFiles(ctx, r)
	if err != nil || len(inventory) == 0 || len(inventory) > 4096 {
		return nil, ErrUnavailable
	}
	for _, file := range inventory {
		p.formats[file.Path], err = PrepareContextNativeNewFile(ctx, r, intent, toolProvider, file.Path, p.registrySHA256, in.Render, in.RendererVersion)
		if err != nil {
			return nil, err
		}
		p.paths = append(p.paths, file.Path)
	}
	sort.Strings(p.paths)
	raw, err := canonicaljson.Canonical(in)
	if err != nil || canonicaljson.DecodeStrict(raw, &p.input) != nil {
		return nil, ErrUnavailable
	}
	p.context.Sources = p.input.Origins
	complete = true
	return p, nil
}

var ErrRootLineage = errors.New("managed clean projection: invalid or unavailable authenticated lineage")

type RootCleanProjection struct {
	files    map[string][]byte
	baseline renderengine.Baseline
	blocks   managedblocks.Baseline
}

func (p *RootCleanProjection) RenderedFor(signed *renderref.Result) (*renderref.Result, error) {
	if p == nil || signed == nil || signed.Baseline == nil || signed.Baseline.ContextHash != p.baseline.ContextHash || signed.Baseline.TemplateVersion != p.baseline.TemplateVersion || len(signed.Files) != len(p.files) {
		return nil, ErrRootLineage
	}
	files := map[string][]byte{}
	for name, raw := range signed.Files {
		clean, ok := p.files[name]
		if !ok {
			return nil, ErrRootLineage
		}
		if !bytes.Contains(raw, []byte("tplater:managed-")) && !bytes.Equal(raw, clean) {
			return nil, ErrRootLineage
		}
		files[name] = append([]byte(nil), clean...)
	}
	result := *signed
	result.Files = files
	baseline := p.baseline
	baseline.Files = map[string]string{}
	for name, digest := range p.baseline.Files {
		baseline.Files[name] = digest
	}
	result.Baseline = &baseline
	return &result, nil
}

func (p *RootCleanProjection) Blocks() managedblocks.Baseline {
	if p == nil {
		return managedblocks.Baseline{}
	}
	return p.blocks.Clone()
}

func ReconstructRootPublication(ctx context.Context, r *trustload.Runtime, home, renderer string, raw []byte, requiredKind string) (*RootCleanProjection, map[string][]byte, error) {
	var locator struct {
		APIVersion            string               `json:"apiVersion"`
		Publication           PublicationReference `json:"publication"`
		RootLockSHA256        string               `json:"rootLockSHA256"`
		ManagedBaselineSHA256 string               `json:"managedBaselineSHA256"`
		FormatterFrames       map[string]string    `json:"formatterFrames"`
	}
	if canonicaljson.DecodeStrict(raw, &locator) != nil || (locator.APIVersion != "tplaiter.dev/managed-lineage/v1" && locator.APIVersion != "tplaiter.dev/managed-lineage/v2") || locator.FormatterFrames == nil {
		return nil, nil, ErrRootLineage
	}
	if (locator.APIVersion == "tplaiter.dev/managed-lineage/v2") != (locator.Publication.APIVersion == "tplaiter.dev/managed-publication-reference/v2") {
		return nil, nil, ErrRootLineage
	}
	kind, err := PublicationKind(ctx, r, locator.Publication)
	if err != nil {
		return nil, nil, err
	}
	if requiredKind != "" && kind != requiredKind {
		return nil, nil, ErrRootLineage
	}
	var pub interface {
		ImagesFor(context.Context, *trustload.Runtime) (map[string][]byte, error)
		RegistryFor(*trustload.Runtime) (string, []byte, []byte, error)
	}
	switch kind {
	case "new":
		pub, err = OpenNewPublication(ctx, r, locator.Publication)
	case "link":
		pub, err = OpenLinkPublication(ctx, r, locator.Publication)
	default:
		return nil, nil, ErrRootLineage
	}
	if err != nil {
		return nil, nil, err
	}
	actualHome, _, _, err := pub.RegistryFor(r)
	if err != nil || actualHome != home {
		return nil, nil, ErrRootLineage
	}
	images, err := pub.ImagesFor(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(raw, images[newLineagePath]) {
		return nil, nil, ErrRootLineage
	}
	lock, err := provenance.DecodeRootTemplateLock(images[".tplaiter/root-template.lock.json"])
	if err != nil || lock.Renderer.Version != renderer || lock.RootLockSHA256 != locator.RootLockSHA256 {
		return nil, nil, ErrRootLineage
	}
	var baseline renderengine.Baseline
	if canonicaljson.DecodeStrict(images[renderengine.BaselineRelPath], &baseline) != nil || baseline.Schema != renderengine.BaselineSchema || baseline.Files == nil {
		return nil, nil, ErrRootLineage
	}
	blocks, err := managedblocks.ParseBaseline(images[".tplaiter/managed-blocks.json"])
	if err != nil {
		return nil, nil, err
	}
	files := map[string][]byte{}
	for name := range baseline.Files {
		data, ok := images[name]
		if !ok {
			return nil, nil, ErrRootLineage
		}
		files[name] = append([]byte(nil), data...)
	}
	return &RootCleanProjection{files: files, baseline: baseline, blocks: blocks}, images, nil
}

// ReconstructRootClean checks all immutable control images against the original
// authenticated New/Link publication. It creates no writer or execution grant.
func ReconstructRootClean(ctx context.Context, r *trustload.Runtime, home, renderer string, controls map[string][]byte) (*RootCleanProjection, error) {
	if controls == nil {
		return nil, ErrRootLineage
	}
	projection, images, err := ReconstructRootPublication(ctx, r, home, renderer, controls[newLineagePath], "")
	if err != nil {
		return nil, err
	}
	for name, want := range images {
		if strings.HasPrefix(name, ".tplaiter/") && !bytes.Equal(controls[name], want) {
			return nil, ErrRootLineage
		}
	}
	return projection, nil
}

// ReadRootNew is the purpose-bound New reader used by the upper lifecycle
// facade and the New owner. It creates no evidence, approval or execution grant.
func ReadRootNew(ctx context.Context, r *trustload.Runtime, home, renderer string) (*RootCleanProjection, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || renderer == "" {
		return nil, ErrRootLineage
	}
	root := r.ProjectContext().RootPath
	snapshot, err := stateledger.VerifyStable(ctx, root, r.TrustRuntime(), stateledger.StableVerifyOptions{})
	if err != nil {
		return nil, err
	}
	obs, err := projectverify.OpenObservation(ctx, root)
	if err != nil {
		return nil, err
	}
	defer obs.Close()
	raw, err := obs.ReadVerified(ctx, snapshot, newLineagePath)
	if err != nil {
		return nil, err
	}
	projection, images, err := ReconstructRootPublication(ctx, r, home, renderer, raw, "new")
	if err != nil {
		return nil, err
	}
	for name, want := range images {
		if !strings.HasPrefix(name, ".tplaiter/") {
			continue
		}
		got, err := obs.ReadVerified(ctx, snapshot, name)
		if err != nil || !bytes.Equal(got, want) {
			return nil, ErrRootLineage
		}
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
		return nil, ErrRootLineage
	}
	return projection, nil
}

// ReconstructRootNew preserves the immutable beforeimage checks and literal
// New purpose. Caller maps cannot become receipts or publication authority.
func ReconstructRootNew(ctx context.Context, r *trustload.Runtime, home, renderer string, controls map[string][]byte) (*RootCleanProjection, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || renderer == "" || len(controls) > 16384 {
		return nil, ErrRootLineage
	}
	projection, images, err := ReconstructRootPublication(ctx, r, home, renderer, controls[newLineagePath], "new")
	if err != nil {
		return nil, err
	}
	for name, want := range images {
		if strings.HasPrefix(name, ".tplaiter/") && !bytes.Equal(controls[name], want) {
			return nil, ErrRootLineage
		}
	}
	return projection, nil
}

// NewPublicationProjection is detached calculation data, not a writer grant.
// The transaction owner still holds an opaque NewPublication and freshly
// compares the complete sealed output tree and exact registry pair at its gate.
type NewPublicationProjection struct {
	Images                        map[string][]byte
	Home                          string
	RegistryBefore, RegistryAfter []byte
}

func (p *NewPublication) ReadProjectionFor(ctx context.Context, r *trustload.Runtime) (NewPublicationProjection, error) {
	return p.readProjection(ctx, r, false)
}

func (p *NewPublication) PublicationProjectionFor(ctx context.Context, r *trustload.Runtime) (NewPublicationProjection, error) {
	return p.readProjection(ctx, r, true)
}

func (p *NewPublication) readProjection(ctx context.Context, r *trustload.Runtime, currentApproval bool) (NewPublicationProjection, error) {
	if p == nil || p.runtime != r {
		return NewPublicationProjection{}, ErrUnavailable
	}
	return newPublicationProjection(ctx, r, p.Reference(), currentApproval)
}

func ReadNewPublicationProjection(ctx context.Context, r *trustload.Runtime, reference PublicationReference) (NewPublicationProjection, error) {
	return newPublicationProjection(ctx, r, reference, false)
}

func CurrentNewPublicationProjection(ctx context.Context, r *trustload.Runtime, reference PublicationReference) (NewPublicationProjection, error) {
	return newPublicationProjection(ctx, r, reference, true)
}

func newPublicationProjection(ctx context.Context, r *trustload.Runtime, reference PublicationReference, currentApproval bool) (NewPublicationProjection, error) {
	fresh, err := OpenNewPublication(ctx, r, reference)
	if err != nil {
		return NewPublicationProjection{}, err
	}
	if currentApproval {
		for _, path := range fresh.preparation.paths {
			if err := RevalidatePublication(ctx, fresh.preparation.formats[path], fresh.projection.pairs[path]); err != nil {
				return NewPublicationProjection{}, err
			}
		}
	}
	home, before, after, err := fresh.RegistryFor(r)
	if err != nil {
		return NewPublicationProjection{}, err
	}
	images := map[string][]byte{}
	for path, raw := range fresh.images {
		images[path] = bytes.Clone(raw)
	}
	return NewPublicationProjection{Images: images, Home: home, RegistryBefore: before, RegistryAfter: after}, nil
}

// CommittedUpdateIntent is readonly transport obtained from the actual native
// MAC/phase/inode owner. Its caller must still reconstruct the typed intent.
func CommittedUpdateIntent(ctx context.Context, r *trustload.Runtime, home string, lineage []byte) (json.RawMessage, error) {
	receipt, err := engine.FindCommittedUpdateForLineage(ctx, r, home, lineage)
	if err != nil {
		return nil, err
	}
	material, err := receipt.MaterialFor(ctx, r)
	if err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), material.Intent...), nil
}
