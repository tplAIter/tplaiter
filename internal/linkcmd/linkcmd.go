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
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
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
	images, err := newcmd.PrepareNativeImage(ctx, newcmd.Options{Ref: in.Ref, ProjectName: in.Name, Dir: pc.RootPath, Module: in.Module, Port: in.Port, Sets: in.Sets, Defaults: true, CLIVersion: renderer}, newcmd.Deps{Runtime: r, Home: home, SourceInput: in.Source})
	if err != nil {
		return nil, err
	}
	before, missing, err := Observe(ctx, pc.RootPath, images)
	if err != nil {
		return nil, err
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
		if choice == "user-owned" {
			return nil, ErrExclusion
		}
		if in.Action != "adopt" || choice != "track" {
			return nil, fmt.Errorf("%w: %s (%s)", ErrConflict, name, status)
		}
		report.Conflicts = append(report.Conflicts, Conflict{name, status, choice})
	}
	for name, choice := range in.Choices {
		if !expected[name] || choice != "track" {
			return nil, ErrInput
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
	p := &Plan{runtime: r, home: home, input: cloneInput(in), stamp: stamp, before: before, missing: missing, images: managed, registryBefore: reg, registryAfter: after, report: report}
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
	return prepare(ctx, p.runtime, p.home, p.input, renderer, p.stamp)
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
	in.Source = bytes.Clone(in.Source)
	in.Sets = append([]string{}, in.Sets...)
	v := map[string]string{}
	for k, c := range in.Choices {
		v[k] = c
	}
	in.Choices = v
	return in
}
