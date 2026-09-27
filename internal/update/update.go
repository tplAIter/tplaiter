package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/envsetup"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// Options — параметры одного запуска [Run].
type Options struct {
	// StartDir — рабочий каталог для поиска проекта (обычно os.Getwd) в режиме
	// одного проекта; игнорируется при All.
	StartDir string
	// To — явная целевая версия шаблона (`--to`); пусто — старший стабильный тег.
	To string
	// DryRun — вычислить план и отчёт, ничего не менять (`--dry-run`).
	DryRun bool
	// Check — только просканировать рабочее дерево на маркеры конфликта
	// (`--check`); при находке exit 1.
	Check bool
	// All — обновить все проекты реестра со статусом ok (`--all`).
	All bool
	// Verbose — печатать унифицированные diff'ы «локальных отклонений».
	Verbose bool
}

// Deps — внешние зависимости [Run], инъектируемые слоем cobra (боевые) и тестами.
type Deps struct {
	// Manager — резолюция/checkout версий шаблона (repo-кеш).
	Manager *repo.Manager
	// Runner — запуск postUpdate-хуков (shell/ansible).
	Runner execx.Runner
	// Home — домашний каталог tplater (реестр проектов, лок).
	Home string
	// Out, Err — потоки основного вывода и предупреждений.
	Out io.Writer
	Err io.Writer
	// Palette — палитра сообщений.
	Palette ui.Palette
	// Now — источник времени регистрации (переопределяется в тестах).
	Now func() time.Time
}

// Result — итог обновления одного проекта.
type Result struct {
	ID         string
	Path       string
	OldVersion string
	NewVersion string
	// Report — структурированный отчёт по 5 категориям (nil в режиме --check).
	Report *Report
	// Conflicts — файлы с маркерами: план (обычный режим) или ScanConflicts
	// (--check).
	Conflicts []string
	// NoOp — план ничего не меняет (обновление на ту же версию с теми же values).
	NoOp bool
	// Applied — план был применён (не DryRun/Check).
	Applied bool
	// DryRun — план вычислен, но не применён.
	DryRun bool
}

// ExitCodeError несёт нестандартный код выхода: 1 (--check нашёл маркеры) или 2
// (update оставил конфликт-маркеры). Слой cobra транслирует его в
// process-exit-код. Отдельный от internal/cmd тип — пакет update не должен
// зависеть от cobra-слоя.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("update: exit %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitCodeError) Unwrap() error { return e.Err }

// Run exposes only the bounded local conflict inspection in T5. Live update
// remains unavailable until the downstream lifecycle owner is installed.
func Run(ctx context.Context, d Deps, opts Options) error {
	// --all has no bounded local-only interpretation. Refuse it before loading
	// the registry or inspecting any project.
	if opts.All {
		return ErrLifecycleUnavailable
	}
	// --check is the sole legacy read-only exception: it scans precisely the
	// supplied tree and never resolves, checks out, initialises, or publishes.
	if opts.Check {
		return inspectAllowed(d, opts)
	}
	// Ordinary and --dry-run legacy routes have no T5 lifecycle owner. This is
	// deliberately before FindRoot, manager use, source reads, or HOME access.
	return ErrLifecycleUnavailable
}

func inspectAllowed(d Deps, opts Options) error {
	found, err := ScanConflicts(opts.StartDir, nil)
	if err != nil {
		return err
	}
	res := &Result{Path: opts.StartDir, Conflicts: found}
	printSingle(d, opts, res)
	return exitFor(res, opts)
}

// runCurrent обновляет проект, найденный от StartDir вверх по дереву.
func runCurrent(ctx context.Context, d Deps, opts Options) error {
	return ErrLifecycleUnavailable
}

// updateOne — ядро обновления одного проекта (без печати). root — корень
// проекта, proj — его разобранный маркер.
func updateOne(ctx context.Context, d Deps, opts Options, root string, proj *manifest.Project) (*Result, error) {
	return nil, ErrLifecycleUnavailable
}

// applyUpdate материализует план и фиксирует новую версию: пишет файлы,
// поднимает версию в маркере, сохраняет снимок нового манифеста, чистый
// target-baseline, перекопирует ресурсы .tplaiter/, гоняет postUpdate-хуки и
// обновляет baselineSHA в реестре проектов.
func applyUpdate(
	ctx context.Context, d Deps, root string, proj *manifest.Project,
	plan *Plan, tgt *renderref.Result, tgtSrc fs.FS, targetRef repo.Resolved,
) error {
	return ErrLifecycleUnavailable
}

// applyLegacyUpdate preserves the former live sequence for the downstream
// lifecycle owner. T5 never calls it and cannot use it as an apply bypass.
func applyLegacyUpdate(
	ctx context.Context, d Deps, root string, proj *manifest.Project,
	plan *Plan, tgt *renderref.Result, tgtSrc fs.FS, targetRef repo.Resolved,
) error {
	if _, err := plan.applyLegacy(root); err != nil {
		return err
	}
	if err := writeUpdatedMarker(root, proj, targetRef.Version); err != nil {
		return err
	}
	if err := manifest.SaveSnapshot(filepath.Join(root, manifest.SnapshotRelPath), tgt.Template); err != nil {
		return fmt.Errorf("update: сохранение снимка манифеста: %w", err)
	}
	// baseline = чистый рендер target (НЕ смерженные файлы с маркерами).
	if err := tgt.Baseline.Save(root); err != nil {
		return err
	}
	if err := resources.Copy(tgtSrc, root, tgt.Template); err != nil {
		return err
	}
	if err := runPostUpdateHooks(ctx, d, root, tgt.Template, tgt.Resolved, proj.Project); err != nil {
		return err
	}
	return updateRegistry(d, root, proj, targetRef)
}

// ThreeWay — план и отчёт одной 3-way-операции: общее ядро `tplater update`
// (две версии шаблона) и `tplater settings set/edit` (одна версия, старые vs
// новые значения — реализация ). Выделено из [updateOne] аддитивно, без изменения
// поведения update.
type ThreeWay struct {
	// Plan — набор файловых решений (см. [Plan]).
	Plan *Plan
	// Report — структурированный отчёт по 5 категориям (см. [Report]).
	Report *Report
}

// ComputeThreeWay строит 3-way-план и отчёт по чистым рендерам base (общий
// предок) и target (цель) и baseline-хешам рабочего дерева workDir. Это ровно та
// связка [Compute]+buildReport, что исполняет [updateOne]; вынесена, чтобы
// `tplater settings set` (реализация ) переиспользовал механику без дублирования:
// settings подставляет base = рендер СТАРЫХ значений, target = рендер НОВЫХ на
// ОДНОЙ версии шаблона (у update это две разные версии).
func ComputeThreeWay(baseFiles, targetFiles map[string][]byte, baseline map[string]string, workDir string) (*ThreeWay, error) {
	plan, err := Compute(baseFiles, targetFiles, baseline, workDir)
	if err != nil {
		return nil, err
	}
	return &ThreeWay{Plan: plan, Report: buildReport(plan, baseFiles, workDir)}, nil
}

// LoadBaselineHashes читает карту sha256 файлов из .tplaiter/baseline.json
// проекта projectDir (отсутствие файла — пустая карта, не ошибка). Экспорт
// [loadBaselineHashes] для settings-команды (реализация ), которой нужен тот же
// baseline для детекта пользовательских правок.
func LoadBaselineHashes(projectDir string) (map[string]string, error) {
	return loadBaselineHashes(projectDir)
}

// RenderVersion выкачивает версию шаблона по резолву res и рендерит её в память
// с координатами/значениями проекта in. checkout очищается перед возвратом —
// вызывающему нужны только байты (для base-предка 3-way; target рендерится
// отдельно, потому что его checkout нужен ещё и для копирования ресурсов).
func RenderVersion(ctx context.Context, mgr *repo.Manager, res repo.Resolved, in renderref.Input) (*renderref.Result, error) {
	src, cleanup, err := mgr.Checkout(ctx, res.RepoAlias, res.GitRef, res.Entry.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	return renderref.Render(src, in)
}

// writeUpdatedMarker поднимает template.version в .tplaiter/project.yaml до
// newVersion, сохраняя остальной снимок (settings/runtime/id) без изменений.
func writeUpdatedMarker(root string, proj *manifest.Project, newVersion string) error {
	proj.Template.Version = newVersion
	data, err := yaml.Marshal(proj)
	if err != nil {
		return fmt.Errorf("update: сериализация project.yaml: %w", err)
	}
	path := filepath.Join(root, project.MarkerRelPath)
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: маркер не секрет.
		return fmt.Errorf("update: запись project.yaml: %w", err)
	}
	return nil
}

// updateRegistry обновляет baselineSHA/path/lastSeenAt записи проекта в реестре
//; Template/CreatedAt существующей записи сохраняет Upsert.
func updateRegistry(d Deps, root string, proj *manifest.Project, targetRef repo.Resolved) error {
	baselineSHA, err := hashFile(filepath.Join(root, engine.BaselineRelPath))
	if err != nil {
		return fmt.Errorf("update: хеш baseline: %w", err)
	}
	now := nowFn(d)()
	ref := state.ProjectRef{
		ID:   proj.ID,
		Path: root,
		Template: state.TemplateSelection{
			Repo:    proj.Template.Repo,
			Name:    proj.Template.Name,
			Version: targetRef.Version,
		},
		CreatedAt:   now,
		LastSeenAt:  now,
		BaselineSHA: baselineSHA,
	}
	return state.WithLock(d.Home, func() error {
		projects, lerr := state.LoadProjects(d.Home)
		if lerr != nil {
			return lerr
		}
		projects.Upsert(ref)
		return state.SaveProjects(d.Home, projects)
	})
}

// loadBaselineHashes читает карту sha256 из .tplaiter/baseline.json проекта.
// Отсутствие файла — не ошибка (пустая карта; детект правок опирается на base).
func loadBaselineHashes(projectDir string) (map[string]string, error) {
	path := filepath.Join(projectDir, filepath.FromSlash(engine.BaselineRelPath))
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update: чтение baseline: %w", err)
	}
	var b engine.Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("update: разбор baseline: %w", err)
	}
	if b.Files == nil {
		return map[string]string{}, nil
	}
	return b.Files, nil
}

// hashFile возвращает hex(sha256) содержимого файла.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

// runPostUpdateHooks исполняет hooks.postUpdate по порядку: run —
// через $SHELL -c в корне проекта, ansible — через envsetup.RunPlaybook. Провал
// обязательного хука прерывает; optional — понижается до предупреждения.
func runPostUpdateHooks(
	ctx context.Context, d Deps, root string, tpl *manifest.Template,
	res settings.Resolved, projInfo manifest.ProjectInfo,
) error {
	for i := range tpl.Hooks.PostUpdate {
		h := tpl.Hooks.PostUpdate[i]
		var err error
		switch {
		case h.Run != "":
			err = runShellHook(ctx, d, root, h.Run)
		case h.Ansible != "":
			err = runAnsibleHook(ctx, d, root, h, res, projInfo)
		default:
			continue
		}
		if err == nil {
			continue
		}
		if h.Optional {
			warnf(d, "postUpdate-хук пропущен (optional): %v", err)
			continue
		}
		return fmt.Errorf("update: postUpdate-хук: %w", err)
	}
	return nil
}

func runShellHook(ctx context.Context, d Deps, root, script string) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	infof(d, "postUpdate: %s\n", script)
	_, err := d.Runner.Run(ctx, shell, []string{"-c", script}, execx.Options{
		Dir:    root,
		Stdout: d.Out,
		Stderr: d.Err,
	})
	return err
}

func runAnsibleHook(
	ctx context.Context, d Deps, root string, h manifest.Hook,
	res settings.Resolved, projInfo manifest.ProjectInfo,
) error {
	runner := envsetup.NewRunner(d.Runner, d.Out, d.Palette)
	return runner.RunPlaybook(ctx, envsetup.Options{
		TemplateDir: filepath.Join(root, envsetup.EnvironmentRelPath),
		ProjectRoot: root,
		Playbook:    manifest.Playbook{Name: "postUpdate", File: h.Ansible},
		Values:      res.Values,
		Project:     projInfo,
		AutoYes:     true,
	})
}

func nowFn(d Deps) func() time.Time {
	if d.Now != nil {
		return d.Now
	}
	return time.Now
}

func infof(d Deps, format string, a ...any) {
	if d.Out != nil {
		fmt.Fprintf(d.Out, format, a...)
	}
}

func warnf(d Deps, format string, a ...any) {
	if d.Err == nil {
		return
	}
	fmt.Fprint(d.Err, d.Palette.Warn("предупреждение: "))
	fmt.Fprintf(d.Err, format+"\n", a...)
}
