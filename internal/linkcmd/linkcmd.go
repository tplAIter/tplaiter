// Package linkcmd prepares state-only adoption from concrete installed authority.
package linkcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/newimages"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"gopkg.in/yaml.v3"
)

var (
	ErrInput     = errors.New("link: invalid bounded input")
	ErrConflict  = errors.New("link: explicit ownership choice required")
	ErrState     = errors.New("link: existing or unsafe managed state")
	ErrExclusion = errors.New("link: user-owned template exclusions unsupported by native consumers")
)

// Input is untrusted intent, never installed authority or a publication plan.
type Input struct {
	Managed *ManagedInput     `json:"managed,omitempty"`
	Action  string            `json:"action"`
	Ref     string            `json:"ref"`
	Name    string            `json:"name"`
	Module  string            `json:"module"`
	Sets    []string          `json:"sets"`
	Port    int               `json:"port"`
	Source  json.RawMessage   `json:"source"`
	Choices map[string]string `json:"choices"`
}
type Conflict struct {
	Path   string `json:"path"`
	State  string `json:"state"`
	Choice string `json:"choice"`
}
type Report struct {
	Action    string
	Conflicts []Conflict
	Paths     []string
}

// Plan is an opaque in-memory proposal. It has no decoder or Apply method.
type Plan struct {
	publication    *formatproof.LinkPublication
	runtime        *trustload.Runtime
	home           string
	input          Input
	stamp          time.Time
	before         map[string]File
	missing        []string
	images         map[string][]byte
	registryBefore File
	registryAfter  []byte
	fingerprint    string
	report         Report
}

func Prepare(ctx context.Context, r *trustload.Runtime, home string, in Input, renderer string) (*Plan, error) {
	return prepare(ctx, r, home, in, renderer, time.Now().UTC())
}

func prepare(ctx context.Context, r *trustload.Runtime, home string, in Input, renderer string, stamp time.Time) (*Plan, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, ErrInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pc := r.ProjectContext()
	if err := r.TrustRuntime().CheckProjectIdentity(ctx, pc.RootPath, pc.ProjectID); err != nil {
		return nil, err
	}
	if in.Action != "link" && in.Action != "adopt" || in.Name == "" || len(in.Choices) > 4096 || in.Port < 0 || in.Port > 65535 {
		return nil, ErrInput
	}
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || home == pc.RootPath || strings.HasPrefix(home, pc.RootPath+"/") || strings.HasPrefix(pc.RootPath, home+"/") {
		return nil, ErrInput
	}
	sel, err := operationtrust.DecodeSourceSelection(in.Source)
	if err != nil {
		return nil, err
	}
	if in.Ref != sel.Subject.Commit || sel.Subject.RequestedRef != sel.Subject.Commit {
		return nil, ErrInput
	}
	// No mutable catalog, hooks, answers-file, shell or execution input.
	var images map[string][]byte
	var before map[string]File
	var missing []string
	var publication *formatproof.LinkPublication
	if in.Managed != nil {
		staged, e := PrepareManaged(ctx, r, home, in, renderer)
		if e != nil {
			return nil, e
		}
		in = staged.Input()
		projection, e := formatproof.OpenLinkClean(ctx, staged.prepared, in.Managed.References)
		if e != nil {
			return nil, fmt.Errorf("link completed effects: %w", e)
		}
		before, missing = staged.before, staged.missing
		beforeRaw, e := canonicaljson.Canonical(before)
		if e != nil {
			return nil, e
		}
		publication, e = formatproof.ProjectLinkPublication(ctx, staged.prepared, projection, beforeRaw, stamp)
		if e != nil {
			return nil, fmt.Errorf("link source/effect projection: %w", e)
		}
		images, e = publication.ImagesFor(ctx, r)
		if e != nil {
			return nil, e
		}
	} else {
		images, err = newcmd.PrepareNativeImage(ctx, newcmd.Options{Ref: in.Ref, ProjectName: in.Name, Dir: pc.RootPath, Module: in.Module, Port: in.Port, Sets: in.Sets, Defaults: true, CLIVersion: renderer}, newcmd.Deps{Runtime: r, Home: home, SourceInput: in.Source})
		if err != nil {
			return nil, err
		}
		before, missing, err = Observe(ctx, pc.RootPath, images)
		if err != nil {
			return nil, err
		}
	}
	for _, name := range []string{".tplaiter", ".tplater"} {
		if _, err := ObservePath(pc.RootPath, name); !errors.Is(err, fs.ErrNotExist) {
			return nil, ErrState
		}
	}
	report := Report{Action: in.Action, Conflicts: []Conflict{}, Paths: []string{}}
	expected := map[string]bool{}
	names := make([]string, 0, len(images))
	for name := range images {
		names = append(names, name)
	}
	sort.Strings(names)
	managed := map[string][]byte{}
	for _, name := range names {
		if strings.HasPrefix(name, ".tplaiter/") {
			managed[name] = images[name]
			report.Paths = append(report.Paths, name)
			continue
		}
		if !SafeUserPath(name) {
			return nil, ErrInput
		}
		actual, exists := before[name]
		if exists && bytes.Equal(actual.Data, images[name]) && actual.Mode == 0o644 {
			continue
		}
		status := "modified"
		if !exists {
			status = "missing"
		}
		choice := in.Choices[name]
		expected[name] = true
		if in.Action != "adopt" || choice != "track" && choice != "user-owned" {
			return nil, fmt.Errorf("%w: %s (%s)", ErrConflict, name, status)
		}
		report.Conflicts = append(report.Conflicts, Conflict{name, status, choice})
	}
	for name, choice := range in.Choices {
		if !expected[name] || choice != "track" && choice != "user-owned" {
			return nil, ErrInput
		}
	}
	projected, err := ProjectAdoption(images, in, renderer, stamp, before)
	if err != nil {
		return nil, err
	}
	for path, raw := range projected {
		if strings.HasPrefix(path, ".tplaiter/") {
			managed[path] = raw
		}
	}
	managed[".tplaiter/update.lock"] = []byte{}
	report.Paths = append(report.Paths, ".tplaiter/update.lock")
	sort.Strings(report.Paths)
	reg, err := ObservePath(home, "projects.yaml")
	if errors.Is(err, fs.ErrNotExist) {
		reg = File{}
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	projects := state.DefaultProjects()
	if reg.Inode != 0 {
		projects, err = state.DecodeProjectsRaw(reg.Data)
		if err != nil {
			return nil, err
		}
	}
	for _, p := range projects.Items {
		if p.ID == pc.ProjectID || p.Path == pc.RootPath {
			return nil, ErrState
		}
	}
	var marker stateledger.ProjectV2
	if err = yaml.Unmarshal(managed[".tplaiter/project.yaml"], &marker); err != nil {
		return nil, err
	}
	projects.Upsert(state.ProjectRef{ID: pc.ProjectID, Path: pc.RootPath, Template: state.TemplateSelection{Repo: marker.Template.Repo, Name: marker.Template.Name, Version: in.Ref}, CreatedAt: stamp, LastSeenAt: stamp, BaselineSHA: strings.TrimPrefix(evidencecas.Digest(managed[".tplaiter/baseline.json"]), "sha256:")})
	after, err := state.MarshalProjects(projects)
	if err != nil {
		return nil, err
	}
	if publication != nil {
		actualHome, actualBefore, actualAfter, e := publication.RegistryFor(r)
		if e != nil || actualHome != home || !bytes.Equal(actualBefore, reg.Data) || !bytes.Equal(actualAfter, after) {
			return nil, ErrState
		}
	}
	p := &Plan{publication: publication, runtime: r, home: home, input: cloneInput(in), stamp: stamp, before: before, missing: missing, images: managed, registryBefore: reg, registryAfter: after, report: report}
	p.fingerprint, err = p.seal()
	if err != nil {
		return nil, err
	}
	fresh, absent, err := Observe(ctx, pc.RootPath, images)
	if err != nil || !reflect.DeepEqual(before, fresh) || !reflect.DeepEqual(missing, absent) {
		return nil, ErrState
	}
	if err = r.TrustRuntime().CheckProjectIdentity(ctx, pc.RootPath, pc.ProjectID); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Plan) seal() (string, error) {
	if p.runtime == nil || p.runtime.TrustRuntime() == nil {
		return "", ErrInput
	}
	raw, err := canonicaljson.Canonical(struct {
		Domain                string
		Root, Home, ProjectID string
		Binding               any
		Input                 Input
		Stamp                 time.Time
		Before                map[string]File
		Missing               []string
		Images                map[string][]byte
		RegistryBefore        File
		RegistryAfter         []byte
	}{"tplaiter.dev/native-link-plan/v1", p.runtime.ProjectContext().RootPath, p.home, p.runtime.ProjectContext().ProjectID, p.runtime.TrustRuntime().Binding(), p.input, p.stamp, p.before, p.missing, p.images, p.registryBefore, p.registryAfter})
	if err != nil {
		return "", err
	}
	return evidencecas.Digest(raw), nil
}

func (p *Plan) Fingerprint() string {
	if p == nil {
		return ""
	}
	return p.fingerprint
}

func (p *Plan) Report() Report {
	v := p.report
	v.Paths = append([]string{}, v.Paths...)
	v.Conflicts = append([]Conflict{}, v.Conflicts...)
	return v
}
func (p *Plan) Runtime() *trustload.Runtime { return p.runtime }
func (p *Plan) Home() string                { return p.home }
func (p *Plan) Input() Input                { return cloneInput(p.input) }
func (p *Plan) Stamp() time.Time            { return p.stamp }
func (p *Plan) Images() map[string][]byte {
	v := map[string][]byte{}
	for k, b := range p.images {
		v[k] = bytes.Clone(b)
	}
	return v
}

func (p *Plan) Before() map[string]File {
	v := map[string]File{}
	for k, b := range p.before {
		b.Data = bytes.Clone(b.Data)
		v[k] = b
	}
	return v
}
func (p *Plan) Missing() []string { return append([]string{}, p.missing...) }
func (p *Plan) Registry() (File, []byte) {
	b := p.registryBefore
	b.Data = bytes.Clone(b.Data)
	return b, bytes.Clone(p.registryAfter)
}

// Reprepare is used by the concrete adapter after taking its leases.
func (p *Plan) Reprepare(ctx context.Context, renderer string) (*Plan, error) {
	fresh, err := prepare(ctx, p.runtime, p.home, p.input, renderer, p.stamp)
	if err != nil {
		return nil, err
	}
	if fresh.fingerprint != p.fingerprint {
		return nil, ErrState
	}
	if fresh.publication != nil {
		if err := fresh.publication.Store(ctx, p.runtime); err != nil {
			return nil, err
		}
	}
	return fresh, nil
}

// Reconstruct regenerates only signed managed images for authenticated recovery.
// It does not observe/admit a target or confer a publication capability.
func Reconstruct(ctx context.Context, r *trustload.Runtime, home string, in Input, renderer string) (map[string][]byte, error) {
	sel, err := operationtrust.DecodeSourceSelection(in.Source)
	if err != nil {
		return nil, err
	}
	if in.Ref != sel.Subject.Commit || sel.Subject.RequestedRef != in.Ref {
		return nil, ErrInput
	}
	images, err := newcmd.PrepareNativeImage(ctx, newcmd.Options{Ref: in.Ref, ProjectName: in.Name, Dir: r.ProjectContext().RootPath, Module: in.Module, Port: in.Port, Sets: in.Sets, Defaults: true, CLIVersion: renderer}, newcmd.Deps{Runtime: r, Home: home, SourceInput: in.Source})
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for p, b := range images {
		if strings.HasPrefix(p, ".tplaiter/") {
			out[p] = b
		}
	}
	out[".tplaiter/update.lock"] = []byte{}
	return out, nil
}

func cloneInput(in Input) Input {
	if in.Managed != nil {
		m := *in.Managed
		m.ToolSource = bytes.Clone(m.ToolSource)
		m.RegistryBefore = bytes.Clone(m.RegistryBefore)
		m.References = map[string]formatproof.Reference{}
		for name, ref := range in.Managed.References {
			m.References[name] = ref
		}
		in.Managed = &m
	}
	in.Source = bytes.Clone(in.Source)
	in.Sets = append([]string{}, in.Sets...)
	v := map[string]string{}
	for k, c := range in.Choices {
		v[k] = c
	}
	in.Choices = v
	return in
}

// ReconstructProjected uses authenticated original observations, never a partial tree.
func ReconstructProjected(ctx context.Context, r *trustload.Runtime, home string, in Input, renderer string, stamp time.Time, before map[string]File) (map[string][]byte, error) {
	if in.Managed != nil {
		return reconstructManagedLink(ctx, r, home, in, renderer, stamp, before)
	}

	sel, err := operationtrust.DecodeSourceSelection(in.Source)
	if err != nil {
		return nil, err
	}
	if in.Ref != sel.Subject.Commit || sel.Subject.RequestedRef != in.Ref {
		return nil, ErrInput
	}
	images, err := newcmd.PrepareNativeImage(ctx, newcmd.Options{Ref: in.Ref, ProjectName: in.Name, Dir: r.ProjectContext().RootPath, Module: in.Module, Port: in.Port, Sets: in.Sets, Defaults: true, CLIVersion: renderer}, newcmd.Deps{Runtime: r, Home: home, SourceInput: in.Source})
	if err != nil {
		return nil, err
	}
	projected, err := ProjectAdoption(images, in, renderer, stamp, before)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for p, b := range projected {
		if strings.HasPrefix(p, ".tplaiter/") {
			out[p] = b
		}
	}
	out[".tplaiter/update.lock"] = []byte{}
	return out, nil
}

// ManagedInput is source/effect reconstruction transport. Approval document
// locations and execution permissions never enter Link's sealed semantic input.
type ManagedInput struct {
	APIVersion     string                           `json:"apiVersion"`
	ToolSource     json.RawMessage                  `json:"toolSource"`
	ObservedSHA256 string                           `json:"observedSHA256"`
	RegistryBefore managedLinkBytes                 `json:"registryBefore"`
	References     map[string]formatproof.Reference `json:"references"`
}

// managedLinkBytes uses the existing cold owner's array byte convention,
// including an explicit empty array for an absent original registry.
// This is reconstruction transport; it does not carry registry authority.
type managedLinkBytes []byte

func (b managedLinkBytes) MarshalJSON() ([]byte, error) {
	values := make([]uint16, len(b))
	for i, value := range b {
		values[i] = uint16(value)
	}
	return json.Marshal(values)
}

func (b *managedLinkBytes) UnmarshalJSON(raw []byte) error {
	var values []byte
	if err := canonicaljson.DecodeStrict(raw, &values); err != nil {
		return err
	}
	if len(values) > 4<<20 {
		return ErrInput
	}
	*b = append(managedLinkBytes{}, values...)
	return nil
}

// ManagedPreparation exposes requests only; it has no writer or public decoder.
type ManagedPreparation struct {
	runtime        *trustload.Runtime
	home, renderer string
	input          Input
	before         map[string]File
	missing        []string
	rawImages      map[string][]byte
	registry       File
	prepared       *formatproof.LinkCleanPreparation
}

func (p *ManagedPreparation) Input() Input {
	if p == nil {
		return Input{}
	}
	return cloneInput(p.input)
}

func (p *ManagedPreparation) Requests(ctx context.Context) ([]trustverify.ExecutionRequest, error) {
	if p == nil {
		return nil, ErrInput
	}
	return p.prepared.RequiredRequests(ctx)
}

func (p *ManagedPreparation) References() map[string]formatproof.Reference {
	if p == nil {
		return nil
	}
	return p.prepared.References()
}

func linkNativeContext(ctx context.Context, r *trustload.Runtime, home string, in Input, renderer string) (*newimages.Context, error) {
	if r == nil || r.TrustRuntime() == nil || in.Managed == nil || in.Managed.APIVersion != "tplaiter.dev/managed-link-input/v1" || len(in.Choices) != 0 || in.Action != "link" || len(in.Managed.ToolSource) == 0 || len(in.Managed.ToolSource) > 1<<20 {
		return nil, ErrInput
	}
	if _, err := operationtrust.DecodeSourceSelection(in.Managed.ToolSource); err != nil {
		return nil, err
	}
	selection, err := operationtrust.DecodeSourceSelection(in.Source)
	if err != nil || in.Ref != selection.Subject.Commit || selection.Subject.RequestedRef != in.Ref {
		return nil, ErrInput
	}
	return newcmd.PrepareNativeContext(ctx, newcmd.Options{Ref: in.Ref, ProjectName: in.Name, Dir: r.ProjectContext().RootPath, Module: in.Module, Port: in.Port, Sets: in.Sets, Defaults: true, CLIVersion: renderer}, newcmd.Deps{Runtime: r, Home: home, SourceInput: in.Source})
}

func linkClean(ctx context.Context, r *trustload.Runtime, home string, in Input, renderer string, c *newimages.Context, before map[string]File) (*formatproof.LinkCleanPreparation, error) {
	raw, err := canonicaljson.Canonical(before)
	if err != nil {
		return nil, err
	}
	if evidencecas.Digest(raw) != in.Managed.ObservedSHA256 {
		return nil, ErrState
	}
	origins := map[string]survey.Source{}
	for key := range c.Result.Resolved.Values {
		origins[key] = survey.SourceDefault
		if origin, exists := c.Sources[key]; exists {
			origins[key] = origin
		}
	}
	native := formatproof.NewCleanInput{APIVersion: "tplaiter.dev/managed-new-clean-input/v1", Home: home, Ref: in.Ref, SourceInput: c.Source.Input, ToolSource: in.Managed.ToolSource, Render: renderref.Input{Repo: c.Source.Alias, Values: c.Result.Resolved.Values, Project: c.Info, Runtime: manifest.ProjectRuntime{Port: c.Port}}, RendererVersion: renderer, Origins: origins}
	return formatproof.PrepareLinkClean(ctx, r, native, raw, in.Managed.RegistryBefore)
}

func PrepareManaged(ctx context.Context, r *trustload.Runtime, home string, in Input, renderer string) (*ManagedPreparation, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || !filepath.IsAbs(home) || filepath.Clean(home) != home || home == r.ProjectContext().RootPath || strings.HasPrefix(home, r.ProjectContext().RootPath+"/") || strings.HasPrefix(r.ProjectContext().RootPath, home+"/") {
		return nil, ErrInput
	}
	c, err := linkNativeContext(ctx, r, home, in, renderer)
	if err != nil {
		return nil, err
	}
	images, err := newimages.Build(*c)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{".tplaiter", ".tplater"} {
		if _, err := ObservePath(r.ProjectContext().RootPath, name); !errors.Is(err, fs.ErrNotExist) {
			return nil, ErrState
		}
	}
	before, missing, err := Observe(ctx, r.ProjectContext().RootPath, images)
	if err != nil {
		return nil, err
	}
	reg, err := ObservePath(home, "projects.yaml")
	if errors.Is(err, fs.ErrNotExist) {
		reg = File{}
	} else if err != nil {
		return nil, err
	}
	raw, err := canonicaljson.Canonical(before)
	if err != nil {
		return nil, err
	}
	observed := evidencecas.Digest(raw)
	if in.Managed.ObservedSHA256 != "" && in.Managed.ObservedSHA256 != observed {
		return nil, ErrState
	}
	if in.Managed.RegistryBefore != nil && !bytes.Equal(in.Managed.RegistryBefore, reg.Data) {
		return nil, ErrState
	}
	in = cloneInput(in)
	in.Managed.ObservedSHA256 = observed
	in.Managed.RegistryBefore = bytes.Clone(reg.Data)
	prepared, err := linkClean(ctx, r, home, in, renderer, c, before)
	if err != nil {
		return nil, err
	}
	if len(in.Managed.References) != 0 && !reflect.DeepEqual(in.Managed.References, prepared.References()) {
		return nil, ErrState
	}
	in.Managed.References = prepared.References()
	return &ManagedPreparation{runtime: r, home: home, renderer: renderer, input: in, before: before, missing: missing, rawImages: images, registry: reg, prepared: prepared}, nil
}

func (p *ManagedPreparation) Stage(ctx context.Context, refs map[string]trustverify.ApprovalRefs) error {
	if p == nil {
		return ErrInput
	}
	recheck := func() error {
		before, missing, err := Observe(ctx, p.runtime.ProjectContext().RootPath, p.rawImages)
		if err != nil || !reflect.DeepEqual(before, p.before) || !reflect.DeepEqual(missing, p.missing) {
			return ErrState
		}
		reg, err := ObservePath(p.home, "projects.yaml")
		if errors.Is(err, fs.ErrNotExist) {
			reg = File{}
		} else if err != nil {
			return err
		}
		if !reflect.DeepEqual(reg, p.registry) {
			return ErrState
		}
		return nil
	}
	if err := recheck(); err != nil {
		return err
	}
	if _, err := formatproof.StageLinkClean(ctx, p.prepared, refs); err != nil {
		return err
	}
	return recheck()
}

func reconstructManagedLink(ctx context.Context, r *trustload.Runtime, home string, in Input, renderer string, stamp time.Time, before map[string]File) (map[string][]byte, error) {
	c, err := linkNativeContext(ctx, r, home, in, renderer)
	if err != nil {
		return nil, err
	}
	prepared, err := linkClean(ctx, r, home, in, renderer, c, before)
	if err != nil {
		return nil, err
	}
	projection, err := formatproof.OpenLinkClean(ctx, prepared, in.Managed.References)
	if err != nil {
		return nil, err
	}
	raw, err := canonicaljson.Canonical(before)
	if err != nil {
		return nil, err
	}
	publication, err := formatproof.ProjectLinkPublication(ctx, prepared, projection, raw, stamp)
	if err != nil {
		return nil, err
	}
	retained, err := formatproof.OpenLinkPublication(ctx, r, publication.Reference())
	if err != nil {
		return nil, err
	}
	if err := projection.RevalidatePublication(ctx, prepared); err != nil {
		return nil, err
	}
	images, err := retained.ImagesFor(ctx, r)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for name, data := range images {
		if strings.HasPrefix(name, ".tplaiter/") {
			out[name] = data
		}
	}
	return out, nil
}
