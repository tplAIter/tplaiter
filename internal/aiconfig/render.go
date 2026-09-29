package aiconfig

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// Target tools.
const (
	TargetCursor   = "cursor"
	TargetClaude   = "claude"
	TargetAgentsMD = "agents_md"
	TargetGemini   = "gemini"
)

// Template names in the targets/ directory.
const (
	tmplCursorrules = "cursorrules.tmpl"
	tmplCursorMDC   = "cursor_mdc.tmpl"
	tmplClaude      = "claude.tmpl"
	tmplAgents      = "agents.tmpl"
	tmplGemini      = "gemini.tmpl"
)

// RenderOptions controls generation.
type RenderOptions struct {
	// TargetRoot — project root where artifacts are written.
	TargetRoot string
	// Values — resolved project settings (module gating through
	// [Source.Filter]).
	Values settings.Values
	// Targets — tools to generate; empty means config.targets is used.
	Targets []string
	// Project — project metadata for artifact headers.
	Project manifest.ProjectInfo
}

// Result — generation result: relative paths of written and skipped files.
type Result struct {
	// Written — written files (relative to TargetRoot), sorted.
	Written []string
	// SkippedProtected — 99-* / 99-project.* files left untouched by the generator.
	SkippedProtected []string
}

// aggregateCtx — data for aggregate templates (CLAUDE.md/AGENTS.md/GEMINI.md/.cursorrules).
type aggregateCtx struct {
	Config  Config
	Project manifest.ProjectInfo
	Modules []LoadedModule
	Base    *LoadedModule
}

// moduleCtx — data for the per-module .mdc template.
type moduleCtx struct {
	Config  Config
	Project manifest.ProjectInfo
	Module  LoadedModule
}

// funcMap — template helper functions.
var funcMap = template.FuncMap{
	"joinComma": func(items []string) string { return strings.Join(items, ", ") },
	"trimSpace": strings.TrimSpace,
}

// Render renders selected targets into TargetRoot. Existing 99-project.* and
// .cursor/rules/99-*.mdc files are not overwritten (project additions).
func (s *Source) Render(opts RenderOptions) (*Result, error) {
	targets := opts.Targets
	if len(targets) == 0 {
		targets = s.Config.Targets
	}

	tmpl, err := s.parseTargets()
	if err != nil {
		return nil, err
	}

	modules, err := s.Filter(opts.Values)
	if err != nil {
		return nil, err
	}
	agg := aggregateCtx{
		Config:  s.Config,
		Project: opts.Project,
		Modules: modules,
		Base:    findBase(modules),
	}

	res := &Result{}
	for _, target := range targets {
		if !knownTargets[target] {
			return nil, fmt.Errorf("aiconfig: unknown target %q", target)
		}
		if err := s.renderTarget(target, tmpl, agg, opts, res); err != nil {
			return nil, err
		}
	}

	sort.Strings(res.Written)
	sort.Strings(res.SkippedProtected)
	return res, nil
}

// renderTarget renders one tool.
func (s *Source) renderTarget(target string, tmpl *template.Template, agg aggregateCtx, opts RenderOptions, res *Result) error {
	switch target {
	case TargetCursor:
		return s.renderCursor(tmpl, agg, opts, res)
	case TargetClaude:
		return renderAggregate(tmpl, tmplClaude, "CLAUDE.md", agg, opts, res)
	case TargetAgentsMD:
		return renderAggregate(tmpl, tmplAgents, "AGENTS.md", agg, opts, res)
	case TargetGemini:
		return renderAggregate(tmpl, tmplGemini, "GEMINI.md", agg, opts, res)
	default:
		return fmt.Errorf("aiconfig: unknown target %q", target)
	}
}

// renderCursor writes .cursorrules, .cursor/rules/<NN-name>.mdc, and .cursor/docs/<name>.md.
func (s *Source) renderCursor(tmpl *template.Template, agg aggregateCtx, opts RenderOptions, res *Result) error {
	if err := renderAggregate(tmpl, tmplCursorrules, ".cursorrules", agg, opts, res); err != nil {
		return err
	}
	for _, m := range agg.Modules {
		mdcPath := filepath.Join(".cursor", "rules", m.RuleName+".mdc")
		ctx := moduleCtx{Config: agg.Config, Project: agg.Project, Module: m}
		if err := renderTemplate(tmpl, tmplCursorMDC, mdcPath, ctx, opts, res); err != nil {
			return err
		}
		docPath := filepath.Join(".cursor", "docs", m.DocBase)
		if err := writeFile(docPath, []byte(m.Doc), opts, res); err != nil {
			return err
		}
	}
	return nil
}

// renderAggregate renders one aggregate file from a named template.
func renderAggregate(tmpl *template.Template, name, rel string, agg aggregateCtx, opts RenderOptions, res *Result) error {
	return renderTemplate(tmpl, name, rel, agg, opts, res)
}

// renderTemplate executes template name with data and writes the result to rel.
func renderTemplate(tmpl *template.Template, name, rel string, data any, opts RenderOptions, res *Result) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return fmt.Errorf("aiconfig: rendering %s: %w", name, err)
	}
	return writeFile(rel, buf.Bytes(), opts, res)
}

// writeFile creates directories and writes a file, skipping protected 99 paths.
func writeFile(rel string, content []byte, opts RenderOptions, res *Result) error {
	if isProtected(rel) {
		res.SkippedProtected = append(res.SkippedProtected, rel)
		return nil
	}
	abs := filepath.Join(opts.TargetRoot, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return fmt.Errorf("aiconfig: mkdir for %s: %w", rel, err)
	}
	if err := os.WriteFile(abs, content, 0o600); err != nil {
		return fmt.Errorf("aiconfig: writing %s: %w", rel, err)
	}
	res.Written = append(res.Written, rel)
	return nil
}

// isProtected reports whether a path is a project addition (99-*), which the
// generator never overwrites.
func isProtected(rel string) bool {
	base := filepath.Base(rel)
	return strings.HasPrefix(base, "99-")
}

// parseTargets parses all templates from targets/ into one set.
func (s *Source) parseTargets() (*template.Template, error) {
	pattern := filepath.Join(s.Dir, "targets", "*.tmpl")
	tmpl, err := template.New("targets").Funcs(funcMap).ParseGlob(pattern)
	if err != nil {
		return nil, fmt.Errorf("aiconfig: parsing targets (%s): %w", pattern, err)
	}
	return tmpl, nil
}

// findBase returns the 00-base module (for aggregate templates), if present in the set.
func findBase(modules []LoadedModule) *LoadedModule {
	for i := range modules {
		if modules[i].ID == "00-base" {
			return &modules[i]
		}
	}
	return nil
}
