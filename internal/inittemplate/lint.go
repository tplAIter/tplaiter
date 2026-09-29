package inittemplate

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"text/template"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/aiconfig"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

const (
	templateManifestFileName = "template.manifest.yaml"
	repoManifestFileName     = "repo.manifest.yaml"
	partialsDirName          = "partials"
)

// lintProject — synthetic project coordinates for trial combo rendering.
// Slug is valid (^[a-z][a-z0-9_]*$) so case helpers and __slug__ work.
var lintProject = manifest.ProjectInfo{
	Name:   "Lint Probe",
	Slug:   "lint_probe",
	Module: "example.com/lint_probe",
	System: "lint",
	Domain: "lint",
}

// LintOptions — parameters for one [Lint] invocation.
type LintOptions struct {
	// Path — template-repository root. Templates are discovered with the same
	// rules as repository indexing (see repo.DiscoverTemplatePaths): the
	// repo.manifest.yaml roots, or the root template plus nested templates.
	// Empty → ".".
	Path string
	// ComboName — exact combination-name filter; empty means all.
	ComboName string
	// Out — result-table output stream.
	Out io.Writer
	// Palette — message palette (nil-safe; zero value is used).
	Palette ui.Palette
}

// LintRow — one result-table cell (template × combo × status).
type LintRow struct {
	Template string
	Combo    string
	OK       bool
	Detail   string
}

// LintResult — lint-template result.
type LintResult struct {
	Rows   []LintRow
	Failed bool
}

// discovered — one discovered template: name and its on-disk root directory.
type discovered struct {
	name string
	root string
}

// Lint — generic template-repository self-test (analogous to gotmpl selftest):
// finds manifests, validates each template, and trial-renders all corner-case
// settings combinations while checking NOTES/generators/ai-config/environment.
// Returns [LintResult] with a table; Failed=true on any failure (caller maps it to exit 1).
func Lint(opts LintOptions) (*LintResult, error) {
	root := opts.Path
	if root == "" {
		root = "."
	}

	templates, err := discoverTemplates(root)
	if err != nil {
		return nil, err
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("inittemplate: template manifests not found in %q "+
			"(expected %s at root, %s, or a nested directory with %s)",
			root, templateManifestFileName, repoManifestFileName, templateManifestFileName)
	}

	res := &LintResult{}
	res.checkDuplicateNames(templates)
	for _, tmpl := range templates {
		res.lintOne(tmpl, opts.ComboName)
	}
	renderTable(opts.Out, opts.Palette, res)
	return res, nil
}

// lintOne checks one template and appends result rows.
func (res *LintResult) lintOne(d discovered, comboFilter string) {
	manifestPath := filepath.Join(d.root, templateManifestFileName)
	tpl, err := manifest.LoadTemplate(manifestPath)
	if err != nil {
		res.fail(d.name, "load", err)
		return
	}
	if verr := tpl.Validate(); verr != nil {
		res.fail(d.name, "validate", verr)
		return
	}
	res.ok(d.name, "validate", "manifest is valid")

	// ai-config is loaded and validated once (independent of combo); per-combo
	// processing only runs Filter.
	aiSrc, aiErr := loadAIConfig(d.root, tpl)
	if aiErr != nil {
		res.fail(d.name, "ai-config", aiErr)
		aiSrc = nil // skip later Filter — source is invalid
	}

	combos := Combos(tpl)
	filtered, known := FilterCombos(combos, comboFilter)
	if comboFilter != "" && len(filtered) == 0 {
		res.fail(d.name, comboFilter, fmt.Errorf("unknown combination; available: %v", known))
		return
	}

	for _, c := range filtered {
		if cerr := checkCombo(d.root, tpl, aiSrc, c); cerr != nil {
			res.fail(d.name, c.Name, cerr)
			continue
		}
		res.ok(d.name, c.Name, "ok")
	}
}

// checkCombo runs one template through one combo: Resolve → Render → NOTES →
// generator parsing → ai-config Filter → environment YAML parsing → arch-lint
// (optional; see checkArchLint).
func checkCombo(root string, tpl *manifest.Template, aiSrc *aiconfig.Source, c Combo) error {
	resolved, err := settings.Resolve(tpl, c.Explicit)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	renderRes, outDir, cleanup, err := renderCombo(root, tpl, resolved)
	if err != nil {
		return err // engine catches leftover markers/broken conditions
	}
	defer cleanup()

	if err := checkNotes(root, tpl, renderRes); err != nil {
		return err
	}
	if err := checkGenerators(root, tpl, resolved); err != nil {
		return err
	}
	if aiSrc != nil {
		if _, ferr := aiSrc.Filter(resolved.ActiveValues); ferr != nil {
			return fmt.Errorf("ai-config filter: %w", ferr)
		}
	}
	if err := checkEnvironment(root, tpl); err != nil {
		return err
	}
	return checkArchLint(tpl, outDir, renderRes.Files)
}

// renderCombo performs a trial atomic render into a temporary directory. The
// render directory is NOT removed before returning (checkArchLint needs to read
// .go files); the caller owns cleanup through the returned cleanup function.
func renderCombo(root string, tpl *manifest.Template, resolved settings.Resolved) (renderRes *engine.Result, outDir string, cleanup func(), err error) {
	tmp, err := os.MkdirTemp("", "tplater-lint-")
	if err != nil {
		return nil, "", func() {}, fmt.Errorf("temp: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tmp) }
	outDir = filepath.Join(tmp, "out")

	renderRes, err = engine.Render(engine.Options{
		Source:   os.DirFS(root),
		Target:   outDir,
		Template: tpl,
		Resolved: resolved,
		Project:  lintProject,
		Runtime:  manifest.ProjectRuntime{Port: 8080},
		Repo:     "lint",
		Partials: loadPartials(root),
	})
	if err != nil {
		cleanup()
		return nil, "", func() {}, fmt.Errorf("render: %w", err)
	}
	return renderRes, outDir, cleanup, nil
}

// loadPartials returns the partials source (partials/ directory), when present.
func loadPartials(root string) []fs.FS {
	dir := filepath.Join(root, partialsDirName)
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return []fs.FS{os.DirFS(dir)}
	}
	return nil
}

// checkNotes verifies that metadata.notes is read, parsed, and rendered with the
// same context as the tree (symmetric with newcmd.printNotes).
func checkNotes(root string, tpl *manifest.Template, renderRes *engine.Result) error {
	if tpl.Metadata.Notes == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(tpl.Metadata.Notes)))
	if err != nil {
		return fmt.Errorf("notes: reading %s: %w", tpl.Metadata.Notes, err)
	}
	t, err := template.New("notes").Funcs(engine.FuncMap(renderRes.Context.Settings)).Parse(string(data))
	if err != nil {
		return fmt.Errorf("notes: parsing: %w", err)
	}
	if err := t.Execute(io.Discard, renderRes.Context); err != nil {
		return fmt.Errorf("notes: rendering: %w", err)
	}
	return nil
}

// checkGenerators parses each snippet and anchor insertion as text/template with
// the engine's full FuncMap (the "snippets parse as text/template" contract).
func checkGenerators(root string, tpl *manifest.Template, resolved settings.Resolved) error {
	fm := engine.FuncMap(settings.View(resolved.ActiveValues))
	for i := range tpl.Generators {
		g := &tpl.Generators[i]
		if g.Snippet != "" {
			if err := parseSnippetFile(root, g.Snippet, fm); err != nil {
				return fmt.Errorf("generator %q snippet: %w", g.Kind, err)
			}
		}
		for _, t := range g.Targets { // multifile form
			if err := parseSnippetFile(root, t.Snippet, fm); err != nil {
				return fmt.Errorf("generator %q targets snippet %q: %w", g.Kind, t.Snippet, err)
			}
		}
		for _, a := range g.Anchors {
			if a.Insert == "" {
				continue
			}
			if err := parseSnippetFile(root, a.Insert, fm); err != nil {
				return fmt.Errorf("generator %q anchor insert: %w", g.Kind, err)
			}
		}
	}
	return nil
}

// parseSnippetFile reads and parses (without executing) snippet rel relative to
// the template root.
func parseSnippetFile(root, rel string, fm template.FuncMap) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", rel, err)
	}
	if _, err := template.New(filepath.Base(rel)).Funcs(fm).Parse(string(data)); err != nil {
		return fmt.Errorf("parsing %s: %w", rel, err)
	}
	return nil
}

// checkEnvironment verifies that every playbook exists and parses as YAML.
func checkEnvironment(root string, tpl *manifest.Template) error {
	for _, pb := range tpl.Environment.Playbooks {
		if pb.File == "" {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(pb.File))
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("environment playbook %q (%s): %w", pb.Name, pb.File, err)
		}
		var doc any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("environment playbook %q (%s): invalid YAML: %w", pb.Name, pb.File, err)
		}
	}
	return nil
}

// loadAIConfig loads and validates the ai-config source when declared by the
// manifest. Returns (nil, nil) when aiConfig.path is empty.
func loadAIConfig(root string, tpl *manifest.Template) (*aiconfig.Source, error) {
	if tpl.AIConfig.Path == "" {
		return nil, nil
	}
	dir := filepath.Join(root, filepath.FromSlash(tpl.AIConfig.Path))
	src, err := aiconfig.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	if err := src.Validate(tpl); err != nil {
		return nil, err
	}
	return src, nil
}

// discoverTemplates uses the same confined, recursive declared-root discovery
// as repository indexing ([repo.DiscoverTemplatePaths]): a provider root
// template and nested templates (for example templates/service) are all
// linted, and path escapes are rejected with the same typed errors. The root
// template keeps the directory base name as its display name; nested
// templates are named by their repository-relative path.
func discoverTemplates(root string) ([]discovered, error) {
	paths, err := repo.DiscoverTemplatePaths(root)
	if err != nil {
		return nil, fmt.Errorf("inittemplate: template discovery: %w", err)
	}
	out := make([]discovered, 0, len(paths))
	for _, rel := range paths {
		name := rel
		if rel == "." {
			name = filepath.Base(mustAbs(root))
		}
		out = append(out, discovered{name: name, root: filepath.Join(root, filepath.FromSlash(rel))})
	}
	return out, nil
}

// checkDuplicateNames fails the lint when two discovered templates declare
// the same metadata.name: repository indexing would reject the repository
// with the same typed error (TPL-E-REPO-DUP-NAME). Templates whose manifest
// does not load are reported by lintOne and ignored here.
func (res *LintResult) checkDuplicateNames(templates []discovered) {
	byName := make(map[string]string, len(templates))
	for _, d := range templates {
		tpl, err := manifest.LoadTemplate(filepath.Join(d.root, templateManifestFileName))
		if err != nil || tpl.Metadata.Name == "" {
			continue
		}
		if prior, dup := byName[tpl.Metadata.Name]; dup {
			res.fail(d.name, "discovery", manifest.NewRepositoryError(manifest.CodeRepoDupName, d.name,
				fmt.Sprintf("template name %q is declared by both %q and %q", tpl.Metadata.Name, prior, d.name)))
			continue
		}
		byName[tpl.Metadata.Name] = d.name
	}
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func (res *LintResult) ok(tmpl, combo, detail string) {
	res.Rows = append(res.Rows, LintRow{Template: tmpl, Combo: combo, OK: true, Detail: detail})
}

func (res *LintResult) fail(tmpl, combo string, err error) {
	res.Failed = true
	res.Rows = append(res.Rows, LintRow{Template: tmpl, Combo: combo, OK: false, Detail: err.Error()})
}

// renderTable prints the results table.
func renderTable(out io.Writer, pal ui.Palette, res *LintResult) {
	if out == nil {
		return
	}
	t := ui.NewTable("TEMPLATE", "COMBO", "STATUS", "DETAIL")
	for _, r := range res.Rows {
		status := "ok"
		if !r.OK {
			status = "FAIL"
		}
		t.AddRow(r.Template, r.Combo, colorStatus(pal, r.OK, status), r.Detail)
	}
	fmt.Fprintln(out, t.RenderStyled(pal))
	if res.Failed {
		fmt.Fprintln(out, pal.Error("lint-template: failures detected"))
	} else {
		fmt.Fprintln(out, pal.Success("lint-template: all combinations are green"))
	}
}

func colorStatus(pal ui.Palette, ok bool, s string) string {
	if ok {
		return pal.Success(s)
	}
	return pal.Error(s)
}
