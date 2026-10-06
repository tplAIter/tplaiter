package formatproof

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/newtransaction/inspect"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/newimages"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
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
	p := &NewCleanPreparation{runtime: r, input: in, context: newimages.Context{ID: r.ProjectContext().ProjectID, Source: src, Info: in.Render.Project, Port: in.Render.Runtime.Port, Result: result, Prepared: prepared, Resources: resourceImages, Sources: in.Origins, Interactive: in.Interactive}, formats: map[string]*Prepared{}, registrySHA256: registryDigest, purpose: purpose}
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
	reference := PublicationReference{APIVersion: "tplaiter.dev/managed-publication-reference/v1", FrameSHA256: locator}
	raw, err := canonicaljson.Canonical(newLineage{APIVersion: "tplaiter.dev/managed-lineage/v1", Publication: reference, RootLockSHA256: p.context.Prepared.RootLock().RootLockSHA256, ManagedBaselineSHA256: evidencecas.Digest(images[".tplaiter/managed-blocks.json"]), FormatterFrames: data.FormatterFrames})
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
	data := engine.ManagedPublication{APIVersion: "tplaiter.dev/managed-publication/v1", Kind: "new", ProjectID: p.runtime.ProjectContext().ProjectID, Root: p.runtime.ProjectContext().RootPath, ProfileBindingSHA256: binding, Input: input, ImagesSHA256: evidencecas.Digest(nil), RegistryBefore: append(engine.Bytes{}, before...), RegistryAfter: append(engine.Bytes{}, after...), FormatterFrames: frames}
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
	if reference.APIVersion != "tplaiter.dev/managed-publication-reference/v1" {
		return nil, ErrUnavailable
	}
	record, err := engine.ReadManagedPublication(ctx, r, reference.FrameSHA256)
	if err != nil {
		return nil, err
	}
	data, err := record.DataFor(r)
	if err != nil || data.Kind != "new" {
		return nil, ErrUnavailable
	}
	var input NewCleanInput
	if canonicaljson.DecodeStrict(data.Input, &input) != nil {
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
	return PublicationReference{APIVersion: "tplaiter.dev/managed-publication-reference/v1", FrameSHA256: p.record.Locator()}
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
	if reference.APIVersion != "tplaiter.dev/managed-publication-reference/v1" {
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
	return data.Kind, nil
}
