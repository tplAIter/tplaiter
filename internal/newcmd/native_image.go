package newcmd

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/survey"
)

// PrepareNativeImage reuses native creation's signed renderer and ledger image
// builder without creating a target, lock, journal or registry. Returned bytes
// are proposals; the workspace adapter freshly rebuilds them under its leases.
func PrepareNativeImage(ctx context.Context, opts Options, d Deps) (map[string][]byte, error) {
	if d.Runtime == nil || d.Runtime.TrustRuntime() == nil {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	slug, err := Slugify(opts.ProjectName)
	if err != nil {
		return nil, err
	}
	pc := d.Runtime.ProjectContext()
	if opts.Dir != pc.RootPath {
		return nil, errors.New("TRUST_PROJECT_CONTEXT_MISMATCH")
	}
	if err := d.Runtime.TrustRuntime().CheckProjectIdentity(ctx, pc.RootPath, pc.ProjectID); err != nil {
		return nil, err
	}
	src, err := sourceadapter.Resolve(ctx, d.Runtime, d.Home, opts.Ref, d.SourceInput)
	if err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(src.Snapshot)
	if err != nil {
		return nil, err
	}
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || len(tpl.Commands) != 0 || tpl.AIConfig.Path != "" || opts.EnvSetup != nil && *opts.EnvSetup {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	constraint := tpl.Requires.Tplaiter
	if constraint == "" {
		constraint = tpl.Requires.Tplater
	}
	if tpl.Requires.Tplaiter != "" && tpl.Requires.Tplater != "" && tpl.Requires.Tplaiter != tpl.Requires.Tplater {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	if err := checkTplaterVersion(constraint, opts.CLIVersion); err != nil {
		return nil, err
	}
	r := &run{opts: opts, d: d}
	preset, sources, err := r.buildPreset(tpl)
	if err != nil {
		return nil, err
	}
	answers, err := survey.AskFlow(tpl, preset, survey.FlowOptions{Defaults: opts.Defaults, PresetSources: sources}, nil, io.Discard, d.Palette)
	if err != nil {
		return nil, err
	}
	info := manifest.ProjectInfo{Name: opts.ProjectName, Slug: slug, Module: r.moduleOrDefault(slug), System: opts.System, Domain: opts.Domain}
	port := opts.Port
	if port == 0 {
		port = defaultPort
	}
	p, err := Prepare(ctx, d.Runtime, operationtrust.PrepareNewInput{SourceInput: src.Input, Render: renderref.Input{Values: answers.Values, Project: info, Runtime: manifest.ProjectRuntime{Port: port}, Repo: src.Alias}, RendererVersion: opts.CLIVersion})
	if err != nil {
		return nil, err
	}
	if !p.ValidFor(d.Runtime.TrustRuntime()) {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	sel, err := operationtrust.DecodeSourceSelection(src.Input)
	if err != nil {
		return nil, err
	}
	resolution, err := d.Runtime.TrustRuntime().VerifySubject(ctx, sel.TrustSubject(), sel.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	images, err := resources.PlanNativeGeneratorImages(d.Runtime.TrustRuntime(), resolution, p.RootLock())
	if err != nil {
		return nil, err
	}
	result := p.Rendered()
	for name, raw := range result.Files {
		if !fs.ValidPath(name) || name == "." || name == ".tplaiter" || strings.HasPrefix(name, ".tplaiter/") || name == ".tplater" || strings.HasPrefix(name, ".tplater/") || strings.Contains(string(raw), "tplater:managed-") {
			return nil, operationtrust.ErrSourceAdapterUnsupported
		}
	}
	return liveTreeImages(pc.ProjectID, src, info, port, result, p, images, sources, false)
}
