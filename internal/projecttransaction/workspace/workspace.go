// Package workspace admits one signed service and go.work/registry transition
// beneath an authenticated existing workspace. Plans and reports are distinct:
// no caller-supplied material, callbacks or serialized plan grants a writer.
package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ownership"
	physical "github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

var ErrInput = errors.New("workspace: invalid native service input")

const domain = "tplaiter.dev/native-workspace-plan/v1"

type Input struct {
	Name            string         `json:"name"`
	Module          string         `json:"module"`
	Port            int            `json:"port"`
	Sets            []string       `json:"sets"`
	Defaults        bool           `json:"defaults"`
	WorkspaceSource physical.Bytes `json:"workspaceSource"`
	ServiceSource   physical.Bytes `json:"serviceSource"`
}
type intent struct {
	Input    Input                    `json:"input"`
	Renderer string                   `json:"renderer"`
	Service  trustload.ProjectContext `json:"service"`
}
type Plan struct {
	workspace, service *trustload.Runtime
	material           physical.Material
	input              Input
	renderer           string
}
type Report struct {
	Service string   `json:"service"`
	Module  string   `json:"module"`
	Paths   []string `json:"paths"`
}

func (p *Plan) Fingerprint() string {
	if p == nil {
		return ""
	}
	return p.material.Fingerprint
}

func (p *Plan) Report() Report {
	if p == nil {
		return Report{}
	}
	var marker stateledger.ProjectV2
	_ = yaml.Unmarshal(p.material.After[path.Join("services", mustSlug(p.input.Name), ".tplaiter/project.yaml")].Data, &marker)
	paths := []string{"go.work"}
	for name := range p.material.After {
		if _, exists := p.material.Before[name]; !exists {
			paths = append(paths, name)
		}
	}
	slices.Sort(paths)
	moduleName, _ := marker.Project["module"].(string)
	return Report{Service: mustSlug(p.input.Name), Module: moduleName, Paths: paths}
}
func mustSlug(name string) string { slug, _ := newcmd.Slugify(name); return slug }

func Prepare(ctx context.Context, wr, sr *trustload.Runtime, home, renderer string, input Input) (*Plan, error) {
	if wr == nil || sr == nil || wr.TrustRuntime() == nil || sr.TrustRuntime() == nil || renderer == "" || !filepath.IsAbs(home) {
		return nil, ErrInput
	}
	if _, err := stateledger.VerifyStable(ctx, wr.ProjectContext().RootPath, wr.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		return nil, err
	}
	before, err := physical.WorkspaceSnapshot(ctx, wr.ProjectContext().RootPath)
	if err != nil {
		return nil, err
	}
	registry, err := physical.WorkspaceRegistrySnapshot(home)
	if err != nil {
		return nil, err
	}
	input.Sets = append([]string{}, input.Sets...)
	input.WorkspaceSource = bytes.Clone(input.WorkspaceSource)
	input.ServiceSource = bytes.Clone(input.ServiceSource)
	m, err := construct(ctx, wr, sr, home, renderer, input, before, registry)
	if err != nil {
		return nil, err
	}
	after, err := physical.WorkspaceSnapshot(ctx, wr.ProjectContext().RootPath)
	if err != nil || !equal(before, after) {
		return nil, errors.Join(physical.ErrConflict, err)
	}
	regAfter, err := physical.WorkspaceRegistrySnapshot(home)
	if err != nil || !equal(registry, regAfter) {
		return nil, errors.Join(physical.ErrConflict, err)
	}
	return &Plan{workspace: wr, service: sr, material: m, input: input, renderer: renderer}, nil
}

func equal(a, b any) bool {
	x, e := canonicaljson.Canonical(a)
	y, f := canonicaljson.Canonical(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

func construct(ctx context.Context, wr, sr *trustload.Runtime, home, renderer string, in Input, before map[string]physical.File, registry physical.File) (physical.Material, error) {
	fail := func(err error) (physical.Material, error) { return physical.Material{}, err }
	wc, sc := wr.ProjectContext(), sr.ProjectContext()
	slug, err := newcmd.Slugify(in.Name)
	if err != nil || in.Port < 0 || in.Port > 65535 {
		return fail(fmt.Errorf("%w: invalid service name or port", ErrInput))
	}
	prefix := "services/" + slug
	if sc.WorkspaceContext != wc.Key || sc.RootPath != filepath.Join(wc.RootPath, filepath.FromSlash(prefix)) || sc.ProjectID == wc.ProjectID || wr.ScratchRoot() != sr.ScratchRoot() || !wr.SharesInstallation(sr) {
		return fail(fmt.Errorf("%w: service context must link to the exact installed workspace/services/slug root and authority", ErrInput))
	}
	if err := sr.TrustRuntime().CheckProjectIdentity(ctx, sc.RootPath, sc.ProjectID); err != nil {
		return fail(err)
	}
	for name := range before {
		if strings.EqualFold(strings.Split(name, "/")[0], "services") && strings.Split(name, "/")[0] != "services" {
			return fail(physical.ErrConflict)
		}
		if strings.EqualFold(name, prefix) || strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)+"/") {
			return fail(physical.ErrConflict)
		}
	}
	if dir, exists := before["services"]; exists && !dir.Directory {
		return fail(physical.ErrConflict)
	}
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(before[".tplaiter/project.yaml"].Data, &marker); err != nil {
		return fail(err)
	}
	if err := wr.TrustRuntime().CheckProjectIdentity(ctx, wc.RootPath, marker.ID); err != nil {
		return fail(err)
	}
	// Recreate the registered workspace's signed metadata. Neither the local
	// manifest nor a plaintext ownership inventory determines workspace authority.
	src, err := sourceadapter.Resolve(ctx, wr, home, sourceCommit(in.WorkspaceSource), in.WorkspaceSource)
	if err != nil {
		return fail(err)
	}
	tpl, err := renderref.LoadTemplate(src.Snapshot)
	if err != nil || !slices.Contains(tpl.Metadata.Labels["type"], "workspace") {
		return fail(fmt.Errorf("%w: signed workspace source requires type=workspace", ErrInput))
	}
	text := func(k string) string { v, _ := marker.Project[k].(string); return v }
	workspaceOpts := newcmd.Options{Ref: sourceCommit(in.WorkspaceSource), ProjectName: text("name"), Module: text("module"), System: text("system"), Domain: text("domain"), Dir: wc.RootPath, Defaults: true, CLIVersion: renderer}
	if port, ok := marker.Runtime["port"].(int); ok {
		workspaceOpts.Port = port
	}
	for key, a := range marker.Answers {
		workspaceOpts.Sets = append(workspaceOpts.Sets, fmt.Sprintf("%s=%v", key, a.Value))
	}
	slices.Sort(workspaceOpts.Sets)
	workspaceImages, err := newcmd.PrepareNativeImage(ctx, workspaceOpts, newcmd.Deps{Runtime: wr, Home: home, SourceInput: in.WorkspaceSource})
	if err != nil {
		return fail(err)
	}
	for _, name := range []string{".tplaiter/root-template.lock.json", ".tplaiter/template.lock.json", engine.BaselineRelPath, ownership.InventoryRelPath, resources.NativeResourceLockPath, ".tplaiter/manifest.snapshot.yaml"} {
		if !bytes.Equal(before[name].Data, workspaceImages[name]) {
			return fail(physical.ErrAuthentication)
		}
	}
	ss, err := sourceadapter.Resolve(ctx, sr, home, sourceCommit(in.ServiceSource), in.ServiceSource)
	if err != nil {
		return fail(err)
	}
	serviceTemplate, err := renderref.LoadTemplate(ss.Snapshot)
	if err != nil || !slices.Contains(serviceTemplate.Metadata.Labels["type"], "service") {
		return fail(fmt.Errorf("%w: signed service source requires type=service", ErrInput))
	}
	mod := in.Module
	if mod == "" {
		mod = text("module") + "/" + prefix
	}
	if module.CheckPath(mod) != nil {
		return fail(fmt.Errorf("%w: invalid Go module path", ErrInput))
	}
	sets := append([]string{}, in.Sets...)
	for _, group := range serviceTemplate.Settings {
		if group.Group == "workflow" {
			sets = append(sets, "workflow=true")
		}
	}
	images, err := newcmd.PrepareNativeImage(ctx, newcmd.Options{Ref: ss.Version, ProjectName: in.Name, Module: mod, System: text("system"), Domain: text("domain"), Dir: sc.RootPath, Port: in.Port, Sets: sets, Defaults: in.Defaults, CLIVersion: renderer}, newcmd.Deps{Runtime: sr, Home: home, SourceInput: in.ServiceSource})
	if err != nil {
		return fail(err)
	}
	// A service must actually be a Go module with the requested identity.
	gm, err := modfile.Parse("go.mod", images["go.mod"], nil)
	if err != nil || gm.Module == nil || gm.Module.Mod.Path != mod {
		return fail(fmt.Errorf("%w: signed service go.mod must declare the requested module", ErrInput))
	}
	work, ok := before["go.work"]
	if !ok || work.Directory {
		return fail(fmt.Errorf("%w: workspace requires a regular go.work", ErrInput))
	}
	wf, err := modfile.ParseWork("go.work", work.Data, nil)
	if err != nil || wf.Go == nil {
		return fail(fmt.Errorf("%w: invalid workspace go.work", ErrInput))
	}
	seen := map[string]bool{}
	for _, use := range wf.Use {
		clean := path.Clean(use.Path)
		if filepath.IsAbs(use.Path) || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(use.Path, "\\") || seen[strings.ToLower(clean)] || strings.EqualFold(clean, prefix) {
			return fail(fmt.Errorf("%w: unsafe, duplicate or existing service go.work registration", ErrInput))
		}
		seen[strings.ToLower(clean)] = true
	}
	if err := wf.AddUse("./"+prefix, ""); err != nil {
		return fail(err)
	}
	wf.Cleanup()
	projects, err := state.DecodeProjectsRaw(registry.Data)
	if err != nil {
		return fail(err)
	}
	var workspaceEntry *state.ProjectRef
	for i := range projects.Items {
		p := &projects.Items[i]
		if p.Path == wc.RootPath && p.ID != wc.ProjectID {
			return fail(physical.ErrAuthentication)
		}
		if p.ID == sc.ProjectID || p.Path == sc.RootPath {
			return fail(physical.ErrConflict)
		}
		if p.ID == wc.ProjectID {
			if workspaceEntry != nil || p.Path != wc.RootPath || p.Template.Version != marker.Template.ResolvedCommit || p.BaselineSHA != strings.TrimPrefix(evidencecas.Digest(before[engine.BaselineRelPath].Data), "sha256:") {
				return fail(physical.ErrAuthentication)
			}
			workspaceEntry = p
		}
	}
	if workspaceEntry == nil {
		return fail(physical.ErrAuthentication)
	}
	projects.Items = append(projects.Items, state.ProjectRef{ID: sc.ProjectID, Path: sc.RootPath, Template: state.TemplateSelection{Repo: ss.Alias, Name: ss.Name, Version: ss.Version}, CreatedAt: workspaceEntry.CreatedAt, LastSeenAt: workspaceEntry.LastSeenAt, BaselineSHA: strings.TrimPrefix(evidencecas.Digest(images[engine.BaselineRelPath]), "sha256:")})
	registryAfter, err := state.MarshalProjects(projects)
	if err != nil {
		return fail(err)
	}
	after := map[string]physical.File{}
	for name, f := range before {
		after[name] = f
	}
	work.Data = modfile.Format(wf.Syntax)
	after["go.work"] = work
	for name, raw := range images {
		target := path.Join(prefix, name)
		if !pathSafe(name) {
			return fail(fmt.Errorf("%w: unsafe signed service output path", ErrInput))
		}
		after[target] = physical.File{Data: raw, Mode: 0o644}
		for parent := path.Dir(target); parent != "."; parent = path.Dir(parent) {
			if f, exists := after[parent]; exists {
				if !f.Directory {
					return fail(physical.ErrConflict)
				}
				continue
			}
			mode := uint32(0o755)
			if parent == prefix+"/.tplaiter" {
				mode = 0o700
			}
			after[parent] = physical.File{Data: physical.Bytes{}, Directory: true, Mode: mode}
		}
	}
	rawIntent, err := canonicaljson.Canonical(intent{Input: in, Renderer: renderer, Service: sc})
	if err != nil {
		return fail(err)
	}
	m := physical.Material{Root: wc.RootPath, Home: home, ProjectID: wc.ProjectID, Binding: wr.TrustRuntime().Binding(), Before: before, After: after, Registry: &physical.RegistryPair{Before: registry, After: physical.File{Data: registryAfter, Mode: registry.Mode}}, ReadOnlyPaths: []string{}, Intent: rawIntent}
	m.Fingerprint, err = bootstrap.DomainDigest(domain, m)
	return m, err
}

func pathSafe(name string) bool {
	return name != "." && filepath.IsLocal(name) && !strings.ContainsAny(name, "\\\x00\r\n") && name != ".tplater" && !strings.HasPrefix(name, ".tplater/")
}

func sourceCommit(raw []byte) string {
	s, e := operationtrust.DecodeSourceSelection(raw)
	if e != nil {
		return ""
	}
	return s.Subject.Commit
}
