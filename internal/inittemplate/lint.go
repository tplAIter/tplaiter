package inittemplate

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"text/template"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/aiconfig"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

const (
	templateManifestFileName = "template.manifest.yaml"
	repoManifestFileName     = "repo.manifest.yaml"
	partialsDirName          = "partials"
)

// lintProject — синтетические координаты проекта для пробного рендера комбо.
// Slug валиден (^[a-z][a-z0-9_]*$), чтобы кейс-хелперы и __slug__ отработали.
var lintProject = manifest.ProjectInfo{
	Name:   "Lint Probe",
	Slug:   "lint_probe",
	Module: "example.com/lint_probe",
	System: "lint",
	Domain: "lint",
}

// LintOptions — параметры одного запуска [Lint].
type LintOptions struct {
	// Path — корень репозитория шаблона (single) или репозитория с
	// repo.manifest.yaml/подкаталогами шаблонов (multi). Пусто → ".".
	Path string
	// ComboName — фильтр по имени комбинации (точное совпадение); пусто — все.
	ComboName string
	// Out — поток вывода таблицы результатов.
	Out io.Writer
	// Palette — палитра сообщений (nil-safe: используется zero-значение).
	Palette ui.Palette
}

// LintRow — одна ячейка таблицы результатов (шаблон × комбо × статус).
type LintRow struct {
	Template string
	Combo    string
	OK       bool
	Detail   string
}

// LintResult — итог lint-template.
type LintResult struct {
	Rows   []LintRow
	Failed bool
}

// discovered — один найденный шаблон: имя и его корневой каталог на диске.
type discovered struct {
	name string
	root string
}

// Lint — generic-селфтест репозитория шаблона ( аналог gotmpl
// selftest): находит манифест(ы), валидирует каждый шаблон и прогоняет пробный
// рендер по всем «угловым» комбинациям настроек с проверками NOTES/generators/
// ai-config/environment. Возвращает [LintResult] с таблицей; Failed=true при
// любом провале (вызывающий транслирует в exit 1).
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
		return nil, fmt.Errorf("inittemplate: манифесты шаблонов не найдены в %q "+
			"(ожидался %s в корне, %s, или подкаталог с %s)",
			root, templateManifestFileName, repoManifestFileName, templateManifestFileName)
	}

	res := &LintResult{}
	for _, tmpl := range templates {
		res.lintOne(tmpl, opts.ComboName)
	}
	renderTable(opts.Out, opts.Palette, res)
	return res, nil
}

// lintOne проверяет один шаблон и добавляет строки результата.
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
	res.ok(d.name, "validate", "манифест валиден")

	// ai-config загружается и валидируется один раз (комбо-независимо);
	// per-combo выполняется только Filter.
	aiSrc, aiErr := loadAIConfig(d.root, tpl)
	if aiErr != nil {
		res.fail(d.name, "ai-config", aiErr)
		aiSrc = nil // дальнейший Filter пропускаем — источник невалиден
	}

	combos := Combos(tpl)
	filtered, known := FilterCombos(combos, comboFilter)
	if comboFilter != "" && len(filtered) == 0 {
		res.fail(d.name, comboFilter, fmt.Errorf("неизвестная комбинация; доступны: %v", known))
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

// checkCombo прогоняет один шаблон через одну комбо: Resolve → Render → NOTES →
// generators-парс → ai-config Filter → environment yaml-парс → arch-lint
// (проверку, опционально — см. checkArchLint).
func checkCombo(root string, tpl *manifest.Template, aiSrc *aiconfig.Source, c Combo) error {
	resolved, err := settings.Resolve(tpl, c.Explicit)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	renderRes, outDir, cleanup, err := renderCombo(root, tpl, resolved)
	if err != nil {
		return err // engine сам ловит маркеры-остатки/битые условия
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

// renderCombo делает пробный атомарный рендер шаблона во временный каталог.
// Каталог рендера НЕ удаляется до возврата вызывающему (нужен checkArchLint
// для чтения содержимого .go-файлов) — очистка на ответственности вызывающего
// через возвращённый cleanup.
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

// loadPartials возвращает источник партиалов (каталог partials/), если он есть.
func loadPartials(root string) []fs.FS {
	dir := filepath.Join(root, partialsDirName)
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return []fs.FS{os.DirFS(dir)}
	}
	return nil
}

// checkNotes проверяет, что metadata.notes читается, парсится и рендерится тем
// же контекстом, что и дерево (симметрично newcmd.printNotes).
func checkNotes(root string, tpl *manifest.Template, renderRes *engine.Result) error {
	if tpl.Metadata.Notes == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(tpl.Metadata.Notes)))
	if err != nil {
		return fmt.Errorf("notes: чтение %s: %w", tpl.Metadata.Notes, err)
	}
	t, err := template.New("notes").Funcs(engine.FuncMap(renderRes.Context.Settings)).Parse(string(data))
	if err != nil {
		return fmt.Errorf("notes: разбор: %w", err)
	}
	if err := t.Execute(io.Discard, renderRes.Context); err != nil {
		return fmt.Errorf("notes: рендер: %w", err)
	}
	return nil
}

// checkGenerators парсит каждый сниппет и вставку якоря как text/template с
// полным FuncMap движка (: «сниппеты парсятся text/template»).
func checkGenerators(root string, tpl *manifest.Template, resolved settings.Resolved) error {
	fm := engine.FuncMap(settings.View(resolved.ActiveValues))
	for i := range tpl.Generators {
		g := &tpl.Generators[i]
		if g.Snippet != "" {
			if err := parseSnippetFile(root, g.Snippet, fm); err != nil {
				return fmt.Errorf("generator %q snippet: %w", g.Kind, err)
			}
		}
		for _, t := range g.Targets { // мультифайловая форма (проверку)
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

// parseSnippetFile читает и парсит (без исполнения) файл-сниппет rel
// относительно корня шаблона.
func parseSnippetFile(root, rel string, fm template.FuncMap) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", rel, err)
	}
	if _, err := template.New(filepath.Base(rel)).Funcs(fm).Parse(string(data)); err != nil {
		return fmt.Errorf("разбор %s: %w", rel, err)
	}
	return nil
}

// checkEnvironment проверяет, что каждый плейбук существует и парсится как YAML.
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
			return fmt.Errorf("environment playbook %q (%s): невалидный YAML: %w", pb.Name, pb.File, err)
		}
	}
	return nil
}

// loadAIConfig загружает и валидирует источник ai-config, если манифест его
// объявляет. Возвращает (nil, nil), если aiConfig.path пуст.
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

// discoverTemplates находит шаблоны репозитория: multi (repo.manifest.yaml с
// перечнем путей), single (template.manifest.yaml в корне) или скан подкаталогов
// первого уровня на наличие template.manifest.yaml.
func discoverTemplates(root string) ([]discovered, error) {
	if _, err := os.Stat(filepath.Join(root, repoManifestFileName)); err == nil {
		return discoverMulti(root)
	}
	if _, err := os.Stat(filepath.Join(root, templateManifestFileName)); err == nil {
		return []discovered{{name: filepath.Base(mustAbs(root)), root: root}}, nil
	}
	return scanSubdirs(root)
}

// discoverMulti читает repo.manifest.yaml и разворачивает его templates[].path.
func discoverMulti(root string) ([]discovered, error) {
	repo, err := manifest.LoadRepository(filepath.Join(root, repoManifestFileName))
	if err != nil {
		return nil, fmt.Errorf("inittemplate: %s: %w", repoManifestFileName, err)
	}
	out := make([]discovered, 0, len(repo.Templates))
	for _, ref := range repo.Templates {
		p := filepath.FromSlash(ref.Path)
		out = append(out, discovered{name: ref.Path, root: filepath.Join(root, p)})
	}
	return out, nil
}

// scanSubdirs ищет template.manifest.yaml в подкаталогах первого уровня.
func scanSubdirs(root string) ([]discovered, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("inittemplate: чтение %q: %w", root, err)
	}
	var out []discovered
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(sub, templateManifestFileName)); err == nil {
			out = append(out, discovered{name: e.Name(), root: sub})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
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

// renderTable печатает таблицу результатов.
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
		fmt.Fprintln(out, pal.Error("lint-template: обнаружены провалы"))
	} else {
		fmt.Fprintln(out, pal.Success("lint-template: все комбинации зелёные"))
	}
}

func colorStatus(pal ui.Palette, ok bool, s string) string {
	if ok {
		return pal.Success(s)
	}
	return pal.Error(s)
}
