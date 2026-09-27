// Package contribute реализует `tplater upgrade`: разработчик,
// доработавший код в сгенерированном проекте, предлагает эти изменения самому
// шаблону — обратной параметризацией (де-рендер) правок и открытием MR/PR в
// репозитории шаблона (либо серией git-патчей в --patch-режиме).
//
// Флоу: диф work↔эталонный рендер (переиспользуется ядро internal/stats и
// internal/renderref) → кандидаты (изменённые файлы эталона + extra по --files)
// → интерактивный выбор (huh-мультиселект) → де-рендер (slug/module/... →
// плейсхолдеры) → ветка в кеш-клоне репозитория шаблона → commit →
// push + glab/gh MR (по типу репо) ИЛИ git format-patch (--patch/plain git).
// Кеш-клон после операции возвращается на исходный ref — кеш не портится.
package contribute

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stats"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// defaultRoot — каталог дерева генерируемых файлов внутри шаблона по умолчанию
// (совпадает с engine.defaultRoot; тот не экспортирован).
const defaultRoot = "files"

// tmplSuffix — суффикс исходников, рендерящихся движком (engine.tmplSuffix).
const tmplSuffix = ".tmpl"

// excludedFromCandidates — файлы, всегда исключаемые из кандидатов дрейфа
//: go.mod/go.sum шумят локальными replace'ами и версиями и
// почти никогда не являются осмысленным вкладом в шаблон.
var excludedFromCandidates = map[string]struct{}{
	"go.mod": {},
	"go.sum": {},
}

// Options — параметры запуска [Upgrade].
type Options struct {
	// StartDir — рабочий каталог для поиска проекта (обычно os.Getwd).
	StartDir string
	// Files — glob-паттерны extra-файлов (отсутствующих в эталоне), которые
	// добавляются к кандидатам. Непустой список также обходит интерактив.
	Files []string
	// Title — заголовок MR/PR (по умолчанию генерируется из проекта).
	Title string
	// Draft — открыть MR/PR черновиком.
	Draft bool
	// Patch — форсировать patch-режим (git format-patch вместо push+MR).
	Patch bool
	// Yes — не задавать интерактивных вопросов (выбрать всех кандидатов).
	Yes bool
}

// Deps — внешние зависимости [Upgrade], инъектируемые слоем cobra и тестами.
type Deps struct {
	// Manager — резолюция/checkout версий шаблона и git-операции в кеш-клоне.
	Manager *repo.Manager
	// Runner — запуск glab/gh (в тестах — execx.RecordingRunner). Отделён от
	// git-раннера менеджера, чтобы e2e мог гонять реальный git, но мокать MR-CLI.
	Runner execx.Runner
	// Home — домашний каталог tplater (для чтения реестра репозиториев).
	Home string
	// Out, Err — потоки основного вывода и предупреждений.
	Out io.Writer
	Err io.Writer
	// Palette — палитра сообщений.
	Palette ui.Palette
	// Picker — интерактивный выбор файлов (huh в проде, scripted в тестах).
	Picker FilePicker
	// Now — источник времени для имени ветки/каталога патчей (тесты фиксируют).
	Now func() time.Time
}

// Result — итог `tplater upgrade` (для тестов и печати).
type Result struct {
	// Mode — "mr" (push+MR/PR) либо "patch" (git format-patch).
	Mode string
	// Branch — созданная ветка вклада.
	Branch string
	// Files — де-параметризованные исходные пути шаблона (в порядке применения).
	Files []string
	// PatchDir — каталог с патчами (только для Mode=="patch").
	PatchDir string
	// MRArgs — аргументы вызванной MR-CLI (glab/gh; только для Mode=="mr").
	MRArgs []string
}

// modeMR/modePatch — значения Result.Mode.
const (
	modeMR    = "mr"
	modePatch = "patch"
)

// fileChange — один файл, применяемый к дереву шаблона.
type fileChange struct {
	logical    string // логический путь в проекте (churned.txt)
	sourceRel  string // путь исходника в шаблоне относительно каталога шаблона (files/churned.txt.tmpl)
	content    []byte // де-параметризованное содержимое
	condition  string // условие вертикали, если файл к ней принадлежит
	reviewDesc bool   // пометку ревью не удалось поставить в файл — уходит в описание MR
}

// reference — результат резолюции+рендера эталонной версии шаблона проекта.
type reference struct {
	res      repo.Resolved
	rendered *renderref.Result
	// srcMap — логический путь эталона → путь исходника в дереве шаблона
	// (относительно каталога шаблона, с .tmpl-суффиксом для рендерящихся файлов).
	srcMap map[string]string
}

// Upgrade исполняет `tplater upgrade`: находит проект, вычисляет кандидатов
// дрейфа, выбирает файлы, де-параметризует их и открывает MR/PR (или формирует
// патчи). Инвариант: кеш-клон репозитория шаблона возвращается на исходный ref
// независимо от исхода после создания ветки.
func Upgrade(ctx context.Context, d Deps, opts Options) (*Result, error) {
	if d.Now == nil {
		d.Now = time.Now
	}

	root, proj, err := project.FindRoot(opts.StartDir)
	if err != nil {
		return nil, err
	}

	ref, err := renderReference(ctx, d.Manager, proj)
	if err != nil {
		return nil, err
	}

	report, err := stats.Analyze(stats.AnalyzeInput{
		RefFiles:   ref.rendered.Files,
		WorkDir:    root,
		CopyGlobs:  ref.rendered.Template.Engine.CopyWithoutRender,
		Generators: ref.rendered.Template.Generators,
	})
	if err != nil {
		return nil, err
	}

	candidates := selectCandidates(report, opts.Files)
	if len(candidates) == 0 {
		fmt.Fprintln(d.Out, "Нет изменений для вклада: рабочее дерево совпадает с эталоном шаблона.")
		return &Result{}, nil
	}

	selected, err := chooseFiles(d, opts, candidates)
	if err != nil {
		return nil, err
	}
	if len(selected) == 0 {
		fmt.Fprintln(d.Out, "Файлы не выбраны — вклад отменён.")
		return &Result{}, nil
	}

	changes, err := buildChanges(root, proj.Project, ref, selected)
	if err != nil {
		return nil, err
	}

	// Реестр: URL и тип репозитория (для выбора push+MR vs patch и auth push).
	repoEntry, err := repoRef(d.Home, ref.res.RepoAlias)
	if err != nil {
		return nil, err
	}

	out := &Result{
		Branch: branchName(proj.Project.Slug, d.Now()),
		Files:  changeSourcePaths(changes),
	}
	if opts.Patch || repoEntry.Type == state.RepoKindGit {
		out.Mode = modePatch
	} else {
		out.Mode = modeMR
	}

	if err := applyInClone(ctx, d, repoEntry, changes, out, opts, proj, ref, root); err != nil {
		return nil, err
	}
	printSummary(d, out, repoEntry)
	return out, nil
}

// renderReference резолвит версию шаблона проекта, рендерит эталон и строит
// srcMap (логический путь → путь исходника) обходом дерева checkout, пока тот
// жив. Checkout очищается перед возвратом — байты эталона и карта исходников
// уже в памяти.
func renderReference(ctx context.Context, mgr *repo.Manager, proj *manifest.Project) (reference, error) {
	in := renderref.Input{
		Values:  renderref.Values(proj.Settings),
		Project: proj.Project,
		Runtime: proj.Runtime,
		Repo:    proj.Template.Repo,
	}
	coord := proj.Template.Repo + "/" + proj.Template.Name
	res, err := mgr.ResolveRef(coord + "@" + proj.Template.Version)
	if err != nil {
		return reference{}, fmt.Errorf("upgrade: версия %s: %w", proj.Template.Version, err)
	}

	src, cleanup, err := mgr.Checkout(ctx, res.RepoAlias, res.GitRef, res.Entry.Path)
	if err != nil {
		return reference{}, err
	}
	defer func() { _ = cleanup() }()

	rendered, err := renderref.Render(src, in)
	if err != nil {
		return reference{}, fmt.Errorf("upgrade: рендер эталона: %w", err)
	}

	srcMap := buildSourceMap(src, normalizeRoot(rendered.Template.Engine.Root))
	return reference{res: res, rendered: rendered, srcMap: srcMap}, nil
}

// buildSourceMap обходит дерево генерируемых файлов checkout (engineRoot) и
// строит карту: логический путь (без .tmpl) → фактический путь исходника
// относительно каталога шаблона. Это точное определение «.tmpl vs byte-copy»
// по реальному дереву, а не по эвристике содержимого.
func buildSourceMap(src fs.FS, engineRoot string) map[string]string {
	out := map[string]string{}
	if info, err := fs.Stat(src, engineRoot); err != nil || !info.IsDir() {
		return out
	}
	_ = fs.WalkDir(src, engineRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // сбойный файл просто не попадёт в карту.
		}
		rel := strings.TrimPrefix(p, engineRoot+"/")
		logical := strings.TrimSuffix(rel, tmplSuffix)
		out[logical] = p
		return nil
	})
	return out
}

// selectCandidates строит список путей-кандидатов: изменённые файлы эталона
// (StatusModified/ModifiedBinary) кроме go.mod/go.sum + extra-файлы, попавшие
// под --files глобы. Результат отсортирован и без дублей.
func selectCandidates(report *stats.Report, fileGlobs []string) []string {
	out := make([]string, 0, len(report.Files))
	for _, f := range report.Files {
		if f.Status != stats.StatusModified && f.Status != stats.StatusModifiedBinary {
			continue
		}
		if _, skip := excludedFromCandidates[f.Path]; skip {
			continue
		}
		out = append(out, f.Path)
	}
	if len(fileGlobs) > 0 {
		gm := newGlobMatcher(fileGlobs)
		for _, extra := range report.Extras {
			if gm.match(extra) {
				out = append(out, extra)
			}
		}
	}
	sort.Strings(out)
	return dedupStrings(out)
}

// chooseFiles выбирает подмножество кандидатов: неинтерактивно (--yes/--files)
// берёт всех; иначе показывает мультиселект (все предвыбраны).
func chooseFiles(d Deps, opts Options, candidates []string) ([]string, error) {
	if opts.Yes || len(opts.Files) > 0 || d.Picker == nil {
		return candidates, nil
	}
	return d.Picker.Pick(candidates)
}

// buildChanges превращает выбранные логические пути в fileChange: определяет
// исходный путь в шаблоне (по srcMap; для новых extra-файлов — эвристикой),
// читает содержимое из рабочего дерева, применяет де-рендер и, для файлов
// условной вертикали, пометку ревью.
func buildChanges(root string, proj manifest.ProjectInfo, ref reference, selected []string) ([]fileChange, error) {
	engineRoot := normalizeRoot(ref.rendered.Template.Engine.Root)
	subs := buildSubstitutions(proj)

	changes := make([]fileChange, 0, len(selected))
	for _, rel := range selected {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("upgrade: чтение %s: %w", rel, err)
		}

		derendered, changed := derender(content, subs)
		sourceRel := sourceRelFor(ref.srcMap, engineRoot, rel, changed)

		cond, isVertical := conditionForPath(ref.rendered.Template.Files, rel)
		reviewDesc := false
		if isVertical {
			var ok bool
			derendered, ok = markReview(derendered, sourceRel, cond)
			reviewDesc = !ok
		}

		changes = append(changes, fileChange{
			logical:    rel,
			sourceRel:  sourceRel,
			content:    derendered,
			condition:  cond,
			reviewDesc: reviewDesc,
		})
	}
	return changes, nil
}

// sourceRelFor вычисляет путь исходника в шаблоне для логического пути rel.
// Если rel есть в srcMap (файл входит в дерево эталона) — берётся точный путь
// исходника (.tmpl или byte-copy). Иначе rel — новый extra-файл: пишем как
// .tmpl, только если де-рендер вставил плейсхолдеры (иначе plain, чтобы не
// прогонять статический файл через движок зря).
func sourceRelFor(srcMap map[string]string, engineRoot, rel string, derenderChanged bool) string {
	if src, ok := srcMap[rel]; ok {
		return src
	}
	plain := path.Join(engineRoot, rel)
	if derenderChanged {
		return plain + tmplSuffix
	}
	return plain
}

// applyInClone ведёт всю git-часть в кеш-клоне: ветка от ref проекта, запись
// файлов, commit, затем push+MR или format-patch. Кеш-клон гарантированно
// возвращается на исходную ветку, а созданная ветка удаляется локально.
func applyInClone(ctx context.Context, d Deps, repoEntry state.RepoRef, changes []fileChange, out *Result, opts Options, proj *manifest.Project, ref reference, root string) error {
	clone := d.Manager.CloneDir(repoEntry.Alias)

	orig, err := currentBranch(ctx, d.Manager, clone)
	if err != nil {
		return err
	}
	startPoint := resolveStartPoint(ctx, d.Manager, clone, ref.res.GitRef)

	if err := runGit(ctx, d.Manager, clone, "switch", "-c", out.Branch, startPoint); err != nil {
		return fmt.Errorf("upgrade: создание ветки %s: %w", out.Branch, err)
	}
	// Инвариант: вернуть клон на исходный ref и удалить ветку в любом исходе.
	defer func() {
		_ = runGit(ctx, d.Manager, clone, "switch", orig)
		_ = runGit(ctx, d.Manager, clone, "branch", "-D", out.Branch)
	}()

	templateDir := filepath.FromSlash(normalizeTemplatePath(ref.res.Entry.Path))
	for _, ch := range changes {
		dest := filepath.Join(clone, templateDir, filepath.FromSlash(ch.sourceRel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("upgrade: подготовка каталога для %s: %w", ch.sourceRel, err)
		}
		if err := os.WriteFile(dest, ch.content, 0o644); err != nil { //nolint:gosec // G306: исходники шаблона — обычные файлы 0644 (уходят в git, режим не секрет).
			return fmt.Errorf("upgrade: запись %s: %w", ch.sourceRel, err)
		}
	}

	if err := runGit(ctx, d.Manager, clone, "add", "-A"); err != nil {
		return fmt.Errorf("upgrade: git add: %w", err)
	}
	if err := runGit(ctx, d.Manager, clone, "commit", "-m", commitMessage(proj, ref.res)); err != nil {
		return fmt.Errorf("upgrade: git commit: %w", err)
	}

	if out.Mode == modePatch {
		return formatPatch(ctx, d, clone, startPoint, out, root)
	}
	return pushAndOpenMR(ctx, d, repoEntry, out, opts, proj, ref, changes)
}

// formatPatch формирует серию патчей (startPoint..HEAD) в ./tplater-upgrade-<date>/.
func formatPatch(ctx context.Context, d Deps, clone, startPoint string, out *Result, root string) error {
	dir := filepath.Join(root, "tplater-upgrade-"+d.Now().Format("20060102-1504"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("upgrade: каталог патчей: %w", err)
	}
	if err := runGit(ctx, d.Manager, clone, "format-patch", startPoint, "-o", dir); err != nil {
		return fmt.Errorf("upgrade: git format-patch: %w", err)
	}
	out.PatchDir = dir
	return nil
}

// pushAndOpenMR пушит ветку в origin и открывает MR/PR через glab/gh.
func pushAndOpenMR(ctx context.Context, d Deps, repoEntry state.RepoRef, out *Result, opts Options, proj *manifest.Project, ref reference, changes []fileChange) error {
	clone := d.Manager.CloneDir(repoEntry.Alias)
	pushEnv := auth.HelperEnv(repoEntry.URL)
	if res, err := d.Manager.RunGit(ctx, clone, []string{"push", "-u", "origin", out.Branch}, pushEnv); err != nil {
		return fmt.Errorf(
			"upgrade: push ветки %s: %s: %w\nпроверьте доступ к репозиторию шаблона: `tplater auth add %s`",
			out.Branch, strings.TrimSpace(res.Stderr), err, hostOf(repoEntry.URL),
		)
	}

	title := opts.Title
	if title == "" {
		title = defaultTitle(proj)
	}
	desc := buildDescription(proj, ref.res, changes)

	args := mrArgs(repoEntry.Type, out.Branch, title, desc, opts.Draft)
	bin := mrBinary(repoEntry.Type)
	if _, err := d.Runner.Run(ctx, bin, args, execx.Options{Dir: clone, Env: pushEnv}); err != nil {
		return fmt.Errorf("upgrade: %s %s: %w", bin, strings.Join(args, " "), err)
	}
	out.MRArgs = args
	return nil
}

// runGit — обёртка над Manager.RunGit без доп-окружения (для операций в клоне).
func runGit(ctx context.Context, mgr *repo.Manager, clone string, args ...string) error {
	res, err := mgr.RunGit(ctx, clone, args, nil)
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// currentBranch возвращает текущую символическую ветку клона (для восстановления).
func currentBranch(ctx context.Context, mgr *repo.Manager, clone string) (string, error) {
	res, err := mgr.RunGit(ctx, clone, []string{"symbolic-ref", "--short", "-q", "HEAD"}, nil)
	b := strings.TrimSpace(res.Stdout)
	if err != nil || b == "" {
		return "", errors.New("upgrade: кеш-клон в состоянии detached HEAD — не могу безопасно вести ветку (выполните `tplater repo update`)")
	}
	return b, nil
}

// resolveStartPoint выбирает точку ветвления: origin/<ref>, если такая ссылка
// есть (актуальный @latest после fetch живёт в origin/<branch>), иначе <ref>
// (тег/коммит). Повторяет логику repo.Manager.Checkout.
func resolveStartPoint(ctx context.Context, mgr *repo.Manager, clone, gitRef string) string {
	if _, err := mgr.RunGit(ctx, clone, []string{"rev-parse", "--verify", "--quiet", "origin/" + gitRef}, nil); err == nil {
		return "origin/" + gitRef
	}
	return gitRef
}

// repoRef достаёт запись реестра репозитория alias из config.yaml.
func repoRef(home, alias string) (state.RepoRef, error) {
	cfg, err := state.LoadConfig(home)
	if err != nil {
		return state.RepoRef{}, err
	}
	for _, r := range cfg.Repos {
		if r.Alias == alias {
			return r, nil
		}
	}
	return state.RepoRef{}, fmt.Errorf("upgrade: репозиторий %q не найден в реестре", alias)
}

// --- вспомогательные ---

// normalizeRoot приводит Engine.Root к каноническому виду (копия
// engine.normalizeRoot — не экспортирована).
func normalizeRoot(root string) string {
	root = strings.Trim(strings.TrimSpace(root), "/")
	if root == "" {
		return defaultRoot
	}
	return root
}

// normalizeTemplatePath приводит Entry.Path к каталогу без ведущих/замыкающих
// слэшей; "." и "" означают корень репозитория.
func normalizeTemplatePath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "." {
		return ""
	}
	return p
}

// branchName формирует имя ветки вклада: tplater/upgrade-<slug>-<YYYYMMDD-HHmm>.
func branchName(slug string, now time.Time) string {
	return fmt.Sprintf("tplater/upgrade-%s-%s", slug, now.Format("20060102-1504"))
}

// defaultTitle — заголовок MR по умолчанию.
func defaultTitle(proj *manifest.Project) string {
	return "tplater: вклад из проекта " + proj.Project.Slug
}

// commitMessage — сообщение коммита.
func commitMessage(proj *manifest.Project, res repo.Resolved) string {
	return fmt.Sprintf("tplater upgrade: вклад из %s (%s/%s@%s)",
		proj.Project.Slug, res.RepoAlias, res.Entry.Name, res.Version)
}

// mrBinary возвращает CLI открытия MR/PR по типу репозитория.
func mrBinary(kind state.RepoKind) string {
	if kind == state.RepoKindGitHub {
		return "gh"
	}
	return "glab"
}

// mrArgs формирует аргументы glab/gh для создания MR/PR.
func mrArgs(kind state.RepoKind, branch, title, desc string, draft bool) []string {
	if kind == state.RepoKindGitHub {
		args := []string{"pr", "create", "--head", branch, "--title", title, "--body", desc}
		if draft {
			args = append(args, "--draft")
		}
		return args
	}
	args := []string{"mr", "create", "--source-branch", branch, "--title", title, "--description", desc}
	if draft {
		args = append(args, "--draft")
	}
	return args
}

// buildDescription собирает описание MR: автоблок метаданных (шаблон+версия,
// проект, снимок настроек, список файлов, пометки TPLATER-REVIEW).
func buildDescription(proj *manifest.Project, res repo.Resolved, changes []fileChange) string {
	var b strings.Builder
	b.WriteString("## tplater upgrade\n\n")
	fmt.Fprintf(&b, "- Шаблон: `%s/%s@%s`\n", res.RepoAlias, res.Entry.Name, res.Version)
	fmt.Fprintf(&b, "- Проект: `%s` (модуль `%s`)\n", proj.Project.Slug, proj.Project.Module)

	if len(proj.Settings) > 0 {
		fmt.Fprintf(&b, "- Настройки: %s\n", settingsSnapshot(proj.Settings))
	}

	b.WriteString("- Файлы:\n")
	for _, ch := range changes {
		line := "  - `" + ch.sourceRel + "`"
		if ch.condition != "" {
			line += fmt.Sprintf(" — условная вертикаль `%s`", ch.condition)
		}
		b.WriteString(line + "\n")
	}

	var reviewNotes []string
	for _, ch := range changes {
		if ch.reviewDesc {
			reviewNotes = append(reviewNotes,
				fmt.Sprintf("`%s` (условие `%s`)", ch.sourceRel, ch.condition))
		}
	}
	if len(reviewNotes) > 0 {
		b.WriteString("\n> " + reviewMarker + ": для файлов ниже пометку не удалось вставить в тело (нет стиля комментария) — проверьте условные блоки вручную: ")
		b.WriteString(strings.Join(reviewNotes, ", ") + "\n")
	}

	b.WriteString("\n_Сгенерировано `tplater upgrade`. Обратная параметризация не восстанавливает условные блоки — проверьте пометки TPLATER-REVIEW._\n")
	return b.String()
}

// settingsSnapshot форматирует снимок настроек проекта в стабильную строку
// key=value (ключи отсортированы).
func settingsSnapshot(s map[string]any) string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, s[k]))
	}
	return strings.Join(parts, ", ")
}

// printSummary печатает итог операции пользователю.
func printSummary(d Deps, out *Result, repoEntry state.RepoRef) {
	switch out.Mode {
	case modePatch:
		fmt.Fprintln(d.Out, d.Palette.Success("Патчи сформированы: ")+out.PatchDir)
		fmt.Fprintf(d.Out, "Передайте их мейнтейнеру шаблона (%s) — например, `git am %s/*.patch`.\n",
			repoEntry.Alias, out.PatchDir)
	case modeMR:
		fmt.Fprintln(d.Out, d.Palette.Success("Ветка запушена и запрос открыт: ")+out.Branch)
		fmt.Fprintf(d.Out, "MR/PR создан через `%s` (репозиторий %s).\n", mrBinary(repoEntry.Type), repoEntry.Alias)
	}
	if len(out.Files) > 0 {
		fmt.Fprintf(d.Out, "Файлов во вкладе: %d.\n", len(out.Files))
	}
}

func changeSourcePaths(changes []fileChange) []string {
	out := make([]string, 0, len(changes))
	for _, ch := range changes {
		out = append(out, ch.sourceRel)
	}
	return out
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// hostOf извлекает host из git-URL для подсказки про auth.
func hostOf(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		if slash := strings.IndexAny(rest, "/:"); slash >= 0 {
			return rest[:slash]
		}
		return rest
	}
	return raw
}
