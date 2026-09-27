// Package newcmd оркестрирует сборочную команду `tplaiter new`:
// резолюция и checkout шаблона, версия-гейт и проверка инструментов окружения,
// опрос настроек, атомарный рендер проекта, копирование ресурсов в .tplaiter/,
// снимок манифеста и проектный маркер, постсоздание (hooks/AI/env setup),
// регистрация в реестре проектов и печать NOTES.
//
// Пакет назван newcmd, а не new: last — зарезервированное имя во многих
// контекстах и путает соседством с ключевым словом. Оркестрация вынесена из
// internal/cmd, чтобы её можно было тестировать без cobra, подставляя
// [survey.Prompter] и [execx.Runner]; тонкая обёртка живёт в
// internal/cmd/new.go.
package newcmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/aiconfig"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/envsetup"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// templateManifestFileName — имя манифеста шаблона в корне checkout'а (та же
// приватная константа, что и в internal/repo/scan.go и internal/cmd/template.go).
const templateManifestFileName = "template.manifest.yaml"

// partialsDirName — каталог ассоциированных {{ define }}-шаблонов внутри
// checkout'а шаблона (см. фикстуру single-basic/partials).
const partialsDirName = "partials"

// defaultPort — порт по умолчанию для .Runtime.Port, если --port не задан.
const defaultPort = 8080

// Options — параметры одного запуска [Run], разобранные из флагов `tplaiter new`
//. Слой cobra (internal/cmd/new.go) заполняет их и добавляет
// runtime-контекст (Interactive, CLIVersion).
type Options struct {
	// Ref — ссылка на шаблон `<repo>/<name>[@version]`.
	Ref string
	// ProjectName — человекочитаемое имя проекта (источник slug).
	ProjectName string
	// Dir — целевой каталог (пусто → ./<slug>).
	Dir string
	// Module — go-module проекта (пусто → git.example.test/<slug>).
	Module string
	// System, Domain — необязательные координаты проекта (.Project.System/Domain).
	System string
	Domain string
	// Sets — значения --set (повторяемый флаг), формат group=value.
	Sets []string
	// AnswersFile — путь файла --answers (YAML).
	AnswersFile string
	// Defaults — --defaults: не опрашивать, взять дефолты (+ preset).
	Defaults bool
	// NoHooks — --no-hooks: пропустить hooks.postCreate.
	NoHooks bool
	// NoDepsCheck — --no-deps-check: пропустить проверку инструментов окружения.
	NoDepsCheck bool
	// EnvSetup управляет предложением env setup после постсоздания: nil — спросить
	// интерактивно, &true — запустить (--env-setup), &false — пропустить
	// (--no-env-setup).
	EnvSetup *bool
	// Yes — --yes: авто-подтверждение (установка инструментов + env setup).
	Yes bool
	// Port — --port: .Runtime.Port (0 → defaultPort).
	Port int
	// Interactive — доступен ли TTY на stdin (детект вызывающим слоем). При false
	// опрос запрещён (CI): незаданные настройки берут дефолт.
	Interactive bool
	// CLIVersion — версия самого tplaiter (resolveVersion в cmd) для версия-гейта
	// requires.tplaiter.
	CLIVersion string
}

// Deps — внешние зависимости [Run], инъектируемые вызывающим слоем для
// тестируемости (боевые реализации — в internal/cmd/new.go, тестовые дублёры —
// в тестах пакета).
type Deps struct {
	// Manager — резолюция/checkout шаблона (repo).
	Manager *repo.Manager
	// Runner — запуск внешних процессов (deps-check, hooks, ansible/env setup).
	Runner execx.Runner
	// Home — домашний каталог tplaiter (state.Home) для реестра проектов и лока.
	Home string
	// Prompter — интерактивный опрос настроек (survey). В неинтерактивном режиме
	// не вызывается, но должен быть не nil (используется только при Interactive).
	Prompter survey.Prompter
	// Confirm — интерактивное подтверждение (env setup). nil трактуется как
	// «нет» — предложение пропускается, если только не задан --env-setup/--yes.
	Confirm func(prompt string) (bool, error)
	// Out, Err — потоки основного вывода и предупреждений/ошибок.
	Out io.Writer
	Err io.Writer
	// Palette — палитра сообщений.
	Palette ui.Palette
	// Now — источник времени регистрации (переопределяется в тестах).
	Now func() time.Time
}

// Run исполняет полный флоу `tplaiter new`. Все шаги ДО создания
// целевого каталога (резолюция, checkout, гейты, опрос) при ошибке/прерывании
// ничего не создают. После успешного рендера любой провал обязательного шага
// (копирование ресурсов, снимок, маркер, обязательный hook, регистрация) удаляет
// целевой каталог целиком (атомарность); провалы опциональных шагов
// (optional-hook, AI-таргеты, env setup, NOTES) понижаются до предупреждения.
func Run(ctx context.Context, opts Options, d Deps) (err error) {
	// Live creation has no authorized lifecycle consumer in T5. This guard is
	// deliberately the first observable action: legacy inputs must not select a
	// target, inspect the filesystem, resolve a source, initialise HOME, or run
	// a tool before the later lifecycle owner takes responsibility.
	return ErrLifecycleUnavailable
}

// run держит рабочее состояние одного вызова [Run].
type run struct {
	opts Options
	d    Deps
	now  func() time.Time
}

func (r *run) execute(ctx context.Context) error {
	// --- фаза 1: подготовка (ничего не создаётся) ---
	slug, err := Slugify(r.opts.ProjectName)
	if err != nil {
		return err
	}
	target := r.opts.Dir
	if target == "" {
		target = "./" + slug
	}
	// Ранняя проверка занятости каталога — до опроса, чтобы повторный `new`
	// падал сразу, не тратя ввод пользователя и не трогая существующий каталог.
	if err := ensureVacant(target); err != nil {
		return err
	}

	resolved, err := r.d.Manager.ResolveRef(r.opts.Ref)
	if err != nil {
		return err
	}

	src, cleanup, err := r.d.Manager.Checkout(ctx, resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			r.warnf("очистка checkout шаблона: %v", cerr)
		}
	}()

	tpl, err := loadTemplateFromFS(src)
	if err != nil {
		return err
	}

	constraint := tpl.Requires.Tplaiter
	if constraint == "" {
		constraint = tpl.Requires.Tplater
	}
	if tpl.Requires.Tplaiter != "" && tpl.Requires.Tplater != "" && tpl.Requires.Tplaiter != tpl.Requires.Tplater {
		return errors.New("newcmd: conflicting requires.tplaiter and requires.tplater")
	}
	if err := checkTplaterVersion(constraint, r.opts.CLIVersion); err != nil {
		return err
	}
	if !r.opts.NoDepsCheck {
		if err := r.ensureTools(ctx, tpl); err != nil {
			return err
		}
	}

	preset, presetSrc, err := r.buildPreset(tpl)
	if err != nil {
		return err
	}

	res, err := survey.AskFlow(tpl, preset, survey.FlowOptions{
		Defaults:      r.opts.Defaults,
		Interactive:   r.opts.Interactive,
		PresetSources: presetSrc,
	}, r.d.Prompter, r.d.Out, r.d.Palette)
	if err != nil {
		return err
	}

	projInfo := manifest.ProjectInfo{
		Name:   r.opts.ProjectName,
		Slug:   slug,
		Module: r.moduleOrDefault(slug),
		System: r.opts.System,
		Domain: r.opts.Domain,
	}
	port := r.opts.Port
	if port == 0 {
		port = defaultPort
	}

	// --- фаза 2: создание (атомарный рендер + пост-шаги) ---
	renderRes, err := r.render(src, target, tpl, res, projInfo, port, resolved.RepoAlias)
	if err != nil {
		return err
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("newcmd: определение абсолютного пути %s: %w", target, err)
	}

	// С этого момента каталог создан: любой провал обязательного шага удаляет его.
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(absTarget)
		}
	}()

	if err := copyResources(src, absTarget, tpl); err != nil {
		return err
	}
	if err := manifest.SaveSnapshot(filepath.Join(absTarget, manifest.SnapshotRelPath), tpl); err != nil {
		return fmt.Errorf("newcmd: сохранение снимка манифеста: %w", err)
	}
	projMarker, err := r.writeProjectMarker(absTarget, tpl, res, projInfo, port, resolved)
	if err != nil {
		return err
	}

	// hooks.postCreate: обязательные хуки при провале удаляют каталог; optional —
	// понижаются до предупреждения (см. runHooks).
	if !r.opts.NoHooks {
		if err := r.runHooks(ctx, absTarget, tpl, res, projInfo); err != nil {
			return err
		}
	}

	if err := r.register(absTarget, tpl, resolved, projMarker.ID); err != nil {
		return err
	}
	committed = true

	// --- фаза 3: пост-создание (только предупреждения, каталог уже зафиксирован) ---
	r.renderAITargets(absTarget, tpl, res, projInfo)
	r.offerEnvSetup(ctx, absTarget, tpl, res, projInfo)
	r.printNotes(src, tpl, renderRes)

	r.infof("Проект %s создан в %s (шаблон %s/%s@%s)\n",
		projInfo.Slug, target, resolved.RepoAlias, tpl.Metadata.Name, resolved.Version)
	return nil
}

// ensureTools прогоняет проверку/установку инструментов окружения.
func (r *run) ensureTools(ctx context.Context, tpl *manifest.Template) error {
	if len(tpl.Requires.Tools) == 0 {
		return nil
	}
	out := deps.NewUI(r.d.Out, r.d.Palette)
	return deps.EnsureTools(ctx, r.d.Runner, out, tpl.Requires.Tools, deps.EnsureOptions{AutoYes: r.opts.Yes})
}

// buildPreset собирает preset настроек из --answers (базовый слой) и --set
// (перекрывает), попутно размечая источники для сводки опроса. --set и
// --answers приоритетнее интерактивного ввода.
func (r *run) buildPreset(tpl *manifest.Template) (settings.Values, map[string]survey.Source, error) {
	preset := settings.Values{}
	presetSrc := map[string]survey.Source{}

	if r.opts.AnswersFile != "" {
		answers, err := settings.LoadAnswersFile(tpl, r.opts.AnswersFile)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range answers {
			preset[k] = v
			presetSrc[k] = survey.SourceAnswer
		}
	}
	for _, expr := range r.opts.Sets {
		group, value, err := settings.ParseSet(tpl, expr)
		if err != nil {
			return nil, nil, err
		}
		preset[group] = value
		presetSrc[group] = survey.SourceSet
	}
	return preset, presetSrc, nil
}

// moduleOrDefault возвращает заданный --module либо нейтральный default <slug>.
func (r *run) moduleOrDefault(slug string) string {
	if r.opts.Module != "" {
		return r.opts.Module
	}
	return "example.com/" + slug
}

// render запускает атомарный рендер движка, собирая partials из checkout'а.
func (r *run) render(
	src fs.FS, target string, tpl *manifest.Template, res settings.Resolved,
	projInfo manifest.ProjectInfo, port int, repoAlias string,
) (*engine.Result, error) {
	partials, err := templatePartials(src)
	if err != nil {
		return nil, err
	}

	sp := ui.NewSpinner(r.d.Err, r.d.Palette)
	sp.Start("Рендерю проект %s", target)
	renderRes, err := engine.Render(engine.Options{
		Source:   src,
		Target:   target,
		Template: tpl,
		Resolved: res,
		Project:  projInfo,
		Runtime:  manifest.ProjectRuntime{Port: port},
		Repo:     repoAlias,
		Partials: partials,
	})
	sp.Stop()
	if err != nil {
		return nil, fmt.Errorf("newcmd: рендер проекта: %w", err)
	}
	return renderRes, nil
}

// projectMarker — данные, нужные [run.register] после записи маркера.
type projectMarker struct {
	ID string
}

// writeProjectMarker строит и пишет .tplaiter/project.yaml: id-UUID,
// координаты шаблона, идентификация проекта, ПОЛНЫЙ снимок настроек (не Active —
// основа для update/переопроса), runtime и путь baseline.
func (r *run) writeProjectMarker(
	target string, tpl *manifest.Template, res settings.Resolved,
	projInfo manifest.ProjectInfo, port int, resolved repo.Resolved,
) (projectMarker, error) {
	id, err := newUUIDv4()
	if err != nil {
		return projectMarker{}, err
	}
	proj := manifest.Project{
		APIVersion: manifest.APIVersion,
		Kind:       manifest.KindProject,
		ID:         id,
		Template: manifest.ProjectTemplate{
			Repo:    resolved.RepoAlias,
			Name:    tpl.Metadata.Name,
			Version: resolved.Version,
		},
		Project:  projInfo,
		Settings: map[string]any(res.Values),
		Runtime:  manifest.ProjectRuntime{Port: port},
		Baseline: engine.BaselineRelPath,
	}

	data, err := yaml.Marshal(proj)
	if err != nil {
		return projectMarker{}, fmt.Errorf("newcmd: сериализация project.yaml: %w", err)
	}
	markerPath := filepath.Join(target, project.MarkerRelPath)
	if err := os.MkdirAll(filepath.Dir(markerPath), 0o755); err != nil {
		return projectMarker{}, fmt.Errorf("newcmd: создание каталога .tplaiter: %w", err)
	}
	if err := os.WriteFile(markerPath, data, 0o644); err != nil { //nolint:gosec // G306: маркер не секрет.
		return projectMarker{}, fmt.Errorf("newcmd: запись project.yaml: %w", err)
	}
	return projectMarker{ID: id}, nil
}

// register регистрирует проект в ~/.tplaiter/projects.yaml под межпроцессным
// локом. BaselineSHA — sha256 файла baseline.json.
func (r *run) register(target string, tpl *manifest.Template, resolved repo.Resolved, id string) error {
	baselineSHA, err := hashFile(filepath.Join(target, engine.BaselineRelPath))
	if err != nil {
		return fmt.Errorf("newcmd: хеш baseline: %w", err)
	}
	now := r.now()
	ref := state.ProjectRef{
		ID:   id,
		Path: target,
		Template: state.TemplateSelection{
			Repo:    resolved.RepoAlias,
			Name:    tpl.Metadata.Name,
			Version: resolved.Version,
		},
		CreatedAt:   now,
		LastSeenAt:  now,
		BaselineSHA: baselineSHA,
	}
	return state.WithLock(r.d.Home, func() error {
		projects, err := state.LoadProjects(r.d.Home)
		if err != nil {
			return err
		}
		projects.Upsert(ref)
		return state.SaveProjects(r.d.Home, projects)
	})
}

// runHooks исполняет hooks.postCreate по порядку: run-хуки через
// $SHELL -c в каталоге проекта со стримингом вывода; ansible-хуки — через
// envsetup.RunPlaybook. Провал обязательного (optional=false) хука прерывает
// создание; провал optional-хука понижается до предупреждения.
func (r *run) runHooks(
	ctx context.Context, target string, tpl *manifest.Template,
	res settings.Resolved, projInfo manifest.ProjectInfo,
) error {
	for i := range tpl.Hooks.PostCreate {
		h := tpl.Hooks.PostCreate[i]
		var err error
		switch {
		case h.Run != "":
			err = r.runShellHook(ctx, target, h.Run)
		case h.Ansible != "":
			err = r.runAnsibleHook(ctx, target, h, res, projInfo)
		default:
			continue
		}
		if err == nil {
			continue
		}
		if h.Optional {
			r.warnf("postCreate-хук пропущен (optional): %v", err)
			continue
		}
		return fmt.Errorf("newcmd: postCreate-хук: %w", err)
	}
	return nil
}

// runShellHook исполняет run-хук через $SHELL -c в каталоге проекта.
func (r *run) runShellHook(ctx context.Context, target, script string) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	r.infof("postCreate: %s\n", script)
	_, err := r.d.Runner.Run(ctx, shell, []string{"-c", script}, execx.Options{
		Dir:    target,
		Stdout: r.d.Out,
		Stderr: r.d.Err,
	})
	return err
}

// runAnsibleHook исполняет ansible-хук через envsetup.RunPlaybook. Файл хука
// адресуется относительно .tplaiter/environment (должен быть скопирован
// copyResources как часть каталога окружения).
func (r *run) runAnsibleHook(
	ctx context.Context, target string, h manifest.Hook,
	res settings.Resolved, projInfo manifest.ProjectInfo,
) error {
	runner := envsetup.NewRunner(r.d.Runner, r.d.Out, r.d.Palette)
	return runner.RunPlaybook(ctx, envsetup.Options{
		TemplateDir: filepath.Join(target, envsetup.EnvironmentRelPath),
		ProjectRoot: target,
		Playbook:    manifest.Playbook{Name: "postCreate", File: h.Ansible},
		Values:      res.Values,
		Project:     projInfo,
		AutoYes:     r.opts.Yes,
	})
}

// renderAITargets рендерит AI-артефакты из скопированного .tplaiter/ai-config
//, если шаблон объявляет aiConfig. Любая ошибка — предупреждение
// (не фейл) с подсказкой `tplaiter ai gen`.
func (r *run) renderAITargets(target string, tpl *manifest.Template, res settings.Resolved, projInfo manifest.ProjectInfo) {
	if tpl.AIConfig.Path == "" {
		return
	}
	src, err := aiconfig.Load(filepath.Join(target, aiconfig.AIConfigRelPath))
	if err != nil {
		r.warnAI(err)
		return
	}
	if _, err := src.Render(aiconfig.RenderOptions{
		TargetRoot: target,
		Values:     res.ActiveValues,
		Project:    projInfo,
	}); err != nil {
		r.warnAI(err)
	}
}

func (r *run) warnAI(err error) {
	r.warnf("AI-таргеты не сгенерированы: %v — можно повторить `tplaiter ai gen`", err)
}

// offerEnvSetup после постсоздания предлагает прогнать playbook "setup"
//. --no-env-setup пропускает; --env-setup/--yes запускают сразу;
// иначе — интерактивное подтверждение. Провал — предупреждение (не фейл):
// каталог уже зафиксирован.
func (r *run) offerEnvSetup(ctx context.Context, target string, tpl *manifest.Template, res settings.Resolved, projInfo manifest.ProjectInfo) {
	pb, ok := findSetupPlaybook(tpl.Environment.Playbooks)
	if !ok {
		return
	}
	if r.opts.EnvSetup != nil && !*r.opts.EnvSetup {
		return // --no-env-setup
	}

	run := false
	switch {
	case r.opts.Yes || (r.opts.EnvSetup != nil && *r.opts.EnvSetup):
		run = true
	case r.opts.Interactive && r.d.Confirm != nil:
		ok, err := r.d.Confirm(fmt.Sprintf("Запустить настройку окружения (env setup: %s)?", pb.Name))
		if err != nil {
			r.warnf("подтверждение env setup: %v", err)
			return
		}
		run = ok
	}
	if !run {
		return
	}

	runner := envsetup.NewRunner(r.d.Runner, r.d.Out, r.d.Palette)
	if err := runner.RunPlaybook(ctx, envsetup.Options{
		TemplateDir: filepath.Join(target, envsetup.EnvironmentRelPath),
		ProjectRoot: target,
		Playbook:    pb,
		Values:      res.Values,
		Project:     projInfo,
		AutoYes:     r.opts.Yes,
	}); err != nil {
		r.warnf("env setup не выполнен: %v — можно повторить `tplaiter env setup`", err)
	}
}

// printNotes рендерит и печатает metadata.notes (helm-стиль «что дальше»),
// используя тот же контекст, что и рендер дерева. Notes короткий и plain —
// печатается как есть, без glamour. Ошибки — предупреждение.
func (r *run) printNotes(src fs.FS, tpl *manifest.Template, renderRes *engine.Result) {
	if tpl.Metadata.Notes == "" {
		return
	}
	data, err := fs.ReadFile(src, filepath.ToSlash(tpl.Metadata.Notes))
	if err != nil {
		r.warnf("NOTES не прочитан (%s): %v", tpl.Metadata.Notes, err)
		return
	}
	tmpl, err := template.New("notes").Funcs(engine.FuncMap(renderRes.Context.Settings)).Parse(string(data))
	if err != nil {
		r.warnf("NOTES не разобран: %v", err)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, renderRes.Context); err != nil {
		r.warnf("NOTES не отрендерен: %v", err)
		return
	}
	fmt.Fprintln(r.d.Out)
	fmt.Fprintln(r.d.Out, buf.String())
}

func (r *run) infof(format string, a ...any) {
	if r.d.Out != nil {
		fmt.Fprintf(r.d.Out, format, a...)
	}
}

func (r *run) warnf(format string, a ...any) {
	if r.d.Err == nil {
		return
	}
	fmt.Fprint(r.d.Err, r.d.Palette.Warn("предупреждение: "))
	fmt.Fprintf(r.d.Err, format+"\n", a...)
}

// findSetupPlaybook ищет playbook с именем "setup" среди environment.playbooks.
func findSetupPlaybook(playbooks []manifest.Playbook) (manifest.Playbook, bool) {
	for _, pb := range playbooks {
		if pb.Name == "setup" {
			return pb, true
		}
	}
	return manifest.Playbook{}, false
}

// loadTemplateFromFS читает и валидирует манифест из корня checkout'а шаблона.
func loadTemplateFromFS(src fs.FS) (*manifest.Template, error) {
	data, err := fs.ReadFile(src, templateManifestFileName)
	if err != nil {
		return nil, fmt.Errorf("newcmd: чтение %s: %w", templateManifestFileName, err)
	}
	tpl, err := manifest.ParseTemplate(data)
	if err != nil {
		return nil, fmt.Errorf("newcmd: %w", err)
	}
	if err := tpl.Validate(); err != nil {
		return nil, fmt.Errorf("newcmd: манифест шаблона невалиден: %w", err)
	}
	return tpl, nil
}

// templatePartials собирает partials-источник из checkout'а, если каталог
// partials/ существует (иначе — nil, движок обходится без него).
func templatePartials(src fs.FS) ([]fs.FS, error) {
	info, err := fs.Stat(src, partialsDirName)
	if err != nil || !info.IsDir() {
		return nil, nil //nolint:nilerr // отсутствие partials/ — норма, не ошибка.
	}
	sub, err := fs.Sub(src, partialsDirName)
	if err != nil {
		return nil, fmt.Errorf("newcmd: подкаталог partials: %w", err)
	}
	return []fs.FS{sub}, nil
}

// ensureVacant проверяет, что target пригоден для создания проекта: не
// существует либо пустой каталог. Непустой каталог или файл —
// ошибка (повторный `new` — только `tplaiter update`).
func ensureVacant(target string) error {
	info, err := os.Stat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("newcmd: проверка целевого каталога %s: %w", target, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("newcmd: %s существует и не является каталогом", target)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return fmt.Errorf("newcmd: чтение целевого каталога %s: %w", target, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("newcmd: каталог %s не пуст — повторное создание не поддерживается (используйте `tplaiter update`)", target)
	}
	return nil
}

// hashFile возвращает hex-представление sha256 содержимого файла.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
