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

// Целевые инструменты.
const (
	TargetCursor   = "cursor"
	TargetClaude   = "claude"
	TargetAgentsMD = "agents_md"
	TargetGemini   = "gemini"
)

// Имена шаблонов в каталоге targets/.
const (
	tmplCursorrules = "cursorrules.tmpl"
	tmplCursorMDC   = "cursor_mdc.tmpl"
	tmplClaude      = "claude.tmpl"
	tmplAgents      = "agents.tmpl"
	tmplGemini      = "gemini.tmpl"
)

// RenderOptions управляет генерацией.
type RenderOptions struct {
	// TargetRoot — корень проекта, куда пишутся артефакты.
	TargetRoot string
	// Values — разрешённые настройки проекта (гейтинг модулей через
	// [Source.Filter]).
	Values settings.Values
	// Targets — какие инструменты генерировать; пусто → берётся config.targets.
	Targets []string
	// Project — метаданные проекта для шапок артефактов.
	Project manifest.ProjectInfo
}

// Result — итог генерации: относительные пути записанных и пропущенных файлов.
type Result struct {
	// Written — записанные файлы (относительно TargetRoot), отсортированы.
	Written []string
	// SkippedProtected — файлы 99-* / 99-project.*, которые генератор не трогает.
	SkippedProtected []string
}

// aggregateCtx — данные для «сводных» шаблонов (CLAUDE.md/AGENTS.md/GEMINI.md/.cursorrules).
type aggregateCtx struct {
	Config  Config
	Project manifest.ProjectInfo
	Modules []LoadedModule
	Base    *LoadedModule
}

// moduleCtx — данные для per-module шаблона .mdc.
type moduleCtx struct {
	Config  Config
	Project manifest.ProjectInfo
	Module  LoadedModule
}

// funcMap — вспомогательные функции шаблонов.
var funcMap = template.FuncMap{
	"joinComma": func(items []string) string { return strings.Join(items, ", ") },
	"trimSpace": strings.TrimSpace,
}

// Render рендерит выбранные targets в TargetRoot. Существующие 99-project.*
// и .cursor/rules/99-*.mdc не перезаписываются (проектные дополнения).
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
			return nil, fmt.Errorf("aiconfig: неизвестный target %q", target)
		}
		if err := s.renderTarget(target, tmpl, agg, opts, res); err != nil {
			return nil, err
		}
	}

	sort.Strings(res.Written)
	sort.Strings(res.SkippedProtected)
	return res, nil
}

// renderTarget рендерит один инструмент.
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
		return fmt.Errorf("aiconfig: неизвестный target %q", target)
	}
}

// renderCursor пишет .cursorrules, .cursor/rules/<NN-name>.mdc и .cursor/docs/<name>.md.
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

// renderAggregate рендерит один сводный файл из именованного шаблона.
func renderAggregate(tmpl *template.Template, name, rel string, agg aggregateCtx, opts RenderOptions, res *Result) error {
	return renderTemplate(tmpl, name, rel, agg, opts, res)
}

// renderTemplate исполняет шаблон name с данными data и пишет результат в rel.
func renderTemplate(tmpl *template.Template, name, rel string, data any, opts RenderOptions, res *Result) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return fmt.Errorf("aiconfig: рендер %s: %w", name, err)
	}
	return writeFile(rel, buf.Bytes(), opts, res)
}

// writeFile создаёт каталоги и пишет файл, пропуская защищённые 99-пути.
func writeFile(rel string, content []byte, opts RenderOptions, res *Result) error {
	if isProtected(rel) {
		res.SkippedProtected = append(res.SkippedProtected, rel)
		return nil
	}
	abs := filepath.Join(opts.TargetRoot, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return fmt.Errorf("aiconfig: mkdir для %s: %w", rel, err)
	}
	if err := os.WriteFile(abs, content, 0o600); err != nil {
		return fmt.Errorf("aiconfig: запись %s: %w", rel, err)
	}
	res.Written = append(res.Written, rel)
	return nil
}

// isProtected сообщает, относится ли путь к проектным дополнениям (99-*),
// которые генератор никогда не перезаписывает.
func isProtected(rel string) bool {
	base := filepath.Base(rel)
	return strings.HasPrefix(base, "99-")
}

// parseTargets парсит все шаблоны из targets/ в единый набор.
func (s *Source) parseTargets() (*template.Template, error) {
	pattern := filepath.Join(s.Dir, "targets", "*.tmpl")
	tmpl, err := template.New("targets").Funcs(funcMap).ParseGlob(pattern)
	if err != nil {
		return nil, fmt.Errorf("aiconfig: разбор targets (%s): %w", pattern, err)
	}
	return tmpl, nil
}

// findBase возвращает модуль 00-base (для сводных шаблонов), если он в наборе.
func findBase(modules []LoadedModule) *LoadedModule {
	for i := range modules {
		if modules[i].ID == "00-base" {
			return &modules[i]
		}
	}
	return nil
}
