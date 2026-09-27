// Package settingscmd оркеструет команду `tplater settings`:
// просмотр текущих настроек проекта (list), их изменение через --set (set) и
// интерактивный переопрос отдельной группы (edit).
//
// Ключевая идея set/edit — та же 3-way-механика, что и у `tplater update`
// (реализация ), но на ОДНОЙ версии шаблона: base — чистый рендер СТАРЫХ значений
// проекта, target — рендер НОВЫХ. Смена значения select удаляет старую вертикаль
// файлов (hash==baseline → удаление, изменённые локально — предупреждение) и
// добавляет новую. Ядро вычисления переиспользуется из internal/update
// ([update.ComputeThreeWay], [update.LoadBaselineHashes]) — здесь только сборка
// base/target-рендеров, доклад и фиксация нового состояния проекта.
//
// В отличие от update смена настроек НЕ трогает версию шаблона, НЕ пишет снимок
// манифеста и НЕ гоняет хуки (ни postUpdate, ни postCreate) — это изменение
// параметров того же рендера, а не обновление шаблона; пользователю выдаётся
// только доклад об изменениях (и предупреждение перегенерировать ai-config, если
// его состав мог смениться).
package settingscmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
	"github.com/tplAIter/tplaiter/internal/update"
)

// Options — параметры одного запуска команды settings.
type Options struct {
	// StartDir — рабочий каталог для поиска проекта (обычно os.Getwd).
	StartDir string
	// Pairs — значения `group=value` для set (повторяемый флаг --set-стиля).
	Pairs []string
	// Group — целевая группа для edit (пусто — вывести список групп-подсказку).
	Group string
	// DryRun — вычислить план и отчёт, ничего не менять (--dry-run).
	DryRun bool
	// Yes — не запрашивать подтверждение перед применением (--yes).
	Yes bool
	// Verbose — печатать унифицированные diff'ы «локальных отклонений».
	Verbose bool
}

// Deps — внешние зависимости команды settings, инъектируемые слоем cobra и
// тестами.
type Deps struct {
	// Manager — резолюция/checkout версии шаблона (repo-кеш).
	Manager *repo.Manager
	// Home — домашний каталог tplater (реестр проектов, лок).
	Home string
	// Out, Err — потоки основного вывода и предупреждений.
	Out io.Writer
	Err io.Writer
	// Palette — палитра сообщений.
	Palette ui.Palette
	// Now — источник времени регистрации (переопределяется в тестах).
	Now func() time.Time
	// Prompter — интерактивный опрос для edit и подтверждения set. В
	// неинтерактивном режиме для set не вызывается.
	Prompter survey.Prompter
	// Interactive — доступен ли TTY (управляет опросом edit и подтверждением set).
	Interactive bool
}

// List печатает текущие значения настроек проекта: таблица
// GROUP/VALUE/ACTIVE, где неактивные вложенные группы (родительская опция не
// выбрана) приглушены.
func List(d Deps, opts Options) error {
	root, proj, err := project.FindRoot(opts.StartDir)
	if err != nil {
		return err
	}
	tpl, _, err := project.LoadManifestForProject(root, proj, d.Home)
	if err != nil {
		return err
	}
	resolved, err := settings.Resolve(tpl, renderref.Values(proj.Settings))
	if err != nil {
		return fmt.Errorf("settings list: %w", err)
	}
	printResolveReport(d, resolved.Report)
	printSettingsTable(d.Out, d.Palette, tpl, resolved.Values)
	return nil
}

// Set применяет новые значения настроек к проекту той же 3-way-механикой, что и
// update: парсит `group=value`, доразрешает requires, рендерит
// старое и новое состояние на текущей версии шаблона и сливает деревом.
func Set(ctx context.Context, d Deps, opts Options) error {
	if len(opts.Pairs) == 0 {
		return errors.New("settings set: укажите хотя бы одно значение group=value")
	}
	ch, cleanup, err := openChange(ctx, d, opts.StartDir)
	if err != nil {
		return err
	}
	defer cleanup()

	// explicit — только осмысленно заданные (отличные от дефолта) текущие
	// значения плюс новые пары. Значения, совпадающие с дефолтом группы,
	// НЕ считаются явными: иначе requires новой опции (напр. oauth ⇒
	// database=postgres) конфликтовал бы с дефолтным database=none вместо
	// довключения ( — требования довключают дефолтные значения,
	// но не перезаписывают явный пользовательский выбор).
	defaults := settings.DefaultValues(ch.tpl)
	explicit := nonDefaultExplicit(ch.oldValues, defaults, nil)
	for _, pair := range opts.Pairs {
		group, value, perr := settings.ParseSet(ch.tpl, pair)
		if perr != nil {
			return fmt.Errorf("settings set: %w", perr)
		}
		explicit[group] = value
	}

	resolved, rerr := settings.Resolve(ch.tpl, explicit)
	if rerr != nil {
		return fmt.Errorf("settings set: %w", rerr)
	}
	ch.resolved = resolved

	return applyChange(ctx, d, ch, opts, d.Interactive && !opts.Yes)
}

// Edit переопрашивает одну группу настроек: без аргумента печатает
// список групп-подсказку; с группой — ведёт [survey.AskFlow] по дереву только
// этой группы (preset — остальные текущие значения) и применяет результат тем же
// set-путём.
func Edit(ctx context.Context, d Deps, opts Options) error {
	ch, cleanup, err := openChange(ctx, d, opts.StartDir)
	if err != nil {
		return err
	}
	defer cleanup()

	if opts.Group == "" {
		resolved, rerr := settings.Resolve(ch.tpl, ch.oldValues)
		if rerr != nil {
			return fmt.Errorf("settings edit: %w", rerr)
		}
		printSettingsTable(d.Out, d.Palette, ch.tpl, resolved.Values)
		fmt.Fprintln(d.Out, d.Palette.Muted("укажите группу для переопроса: tplater settings edit <group>"))
		return nil
	}

	if !groupExists(ch.tpl, opts.Group) {
		return fmt.Errorf("settings edit: неизвестная группа %q", opts.Group)
	}

	// preset — все текущие значения, КРОМЕ переопрашиваемой группы и её вложенных
	// уточнений: их AskFlow задаст заново (динамически, по новому выбору родителя).
	drop := groupWithDescendants(ch.tpl, opts.Group)
	preset := settings.Values{}
	for k, v := range ch.oldValues {
		if !drop[k] {
			preset[k] = v
		}
	}

	resolved, err := survey.AskFlow(
		ch.tpl, preset,
		survey.FlowOptions{Interactive: d.Interactive},
		d.Prompter, d.Out, d.Palette,
	)
	if err != nil {
		return err
	}
	ch.resolved = resolved

	// AskFlow уже показал сводку и запросил подтверждение — повторно не спрашиваем.
	return applyChange(ctx, d, ch, opts, false)
}

// change — общий контекст изменения настроек (set/edit): найденный проект,
// манифест и checkout его версии, старые значения и (после разрешения) новые.
type change struct {
	root      string
	proj      *manifest.Project
	tpl       *manifest.Template
	src       fs.FS
	oldValues settings.Values
	resolved  settings.Resolved
}

// openChange находит проект от startDir, резолвит и выкачивает ЕГО ТЕКУЩУЮ версию
// шаблона (settings работают на одной версии) и загружает манифест. Возвращает
// контекст и cleanup checkout'а (держится открытым до копирования ресурсов).
func openChange(ctx context.Context, d Deps, startDir string) (*change, func(), error) {
	root, proj, err := project.FindRoot(startDir)
	if err != nil {
		return nil, nil, err
	}

	coord := proj.Template.Repo + "/" + proj.Template.Name
	ref, err := d.Manager.ResolveRef(coord + "@" + proj.Template.Version)
	if err != nil {
		return nil, nil, fmt.Errorf("settings: версия шаблона %s недоступна в кеше репозитория: %w", proj.Template.Version, err)
	}
	src, cleanup, err := d.Manager.Checkout(ctx, ref.RepoAlias, ref.GitRef, ref.Entry.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("settings: checkout версии шаблона: %w", err)
	}
	tpl, err := renderref.LoadTemplate(src)
	if err != nil {
		_ = cleanup()
		return nil, nil, err
	}

	return &change{
		root:      root,
		proj:      proj,
		tpl:       tpl,
		src:       src,
		oldValues: renderref.Values(proj.Settings),
	}, func() { _ = cleanup() }, nil
}

// applyChange — общий хвост set/edit: рендерит base (старые значения) и target
// (новые), вычисляет 3-way-план и отчёт (переиспользуя [update.ComputeThreeWay]),
// печатает доклад и — если не --dry-run и подтверждено — материализует план,
// пишет новые значения в project.yaml, пересчитывает baseline, перекопирует
// ресурсы и освежает реестр. Конфликты → код выхода 2 ([update.ExitCodeError]).
func applyChange(_ context.Context, d Deps, ch *change, opts Options, confirm bool) error {
	base := renderref.Input{
		Values:  ch.oldValues,
		Project: ch.proj.Project,
		Runtime: ch.proj.Runtime,
		Repo:    ch.proj.Template.Repo,
	}
	baseRendered, err := renderref.Render(ch.src, base)
	if err != nil {
		return fmt.Errorf("settings: рендер текущих значений: %w", err)
	}

	target := base
	target.Values = ch.resolved.Values
	tgtRendered, err := renderref.Render(ch.src, target)
	if err != nil {
		return fmt.Errorf("settings: рендер новых значений: %w", err)
	}

	baseline, err := update.LoadBaselineHashes(ch.root)
	if err != nil {
		return err
	}
	tw, err := update.ComputeThreeWay(baseRendered.Files, tgtRendered.Files, baseline, ch.root)
	if err != nil {
		return err
	}

	printResolveReport(d, ch.resolved.Report)
	changed := changedGroups(ch.tpl, ch.oldValues, ch.resolved.Values)

	if !tw.Plan.HasChanges() && len(changed) == 0 {
		fmt.Fprintln(d.Out, "изменений настроек нет — всё уже как задано")
		return nil
	}

	fmt.Fprintln(d.Out, "изменение настроек проекта:")
	fmt.Fprintln(d.Out)
	tw.Report.Render(d.Out, d.Palette, opts.Verbose)
	printChangedGroups(d.Out, d.Palette, changed)

	conflicts := tw.Plan.Conflicts()

	if opts.DryRun {
		fmt.Fprintln(d.Out, d.Palette.Muted("(--dry-run — изменения не записаны)"))
		return exitForConflicts(conflicts)
	}

	if confirm && d.Prompter != nil {
		ok, cerr := d.Prompter.Confirm("Применить изменения настроек?")
		if cerr != nil {
			return cerr
		}
		if !ok {
			fmt.Fprintln(d.Out, "отменено — изменения не записаны")
			return nil
		}
	}

	if applyErr := commit(d, ch, tw.Plan, tgtRendered); applyErr != nil {
		return applyErr
	}

	if ch.tpl.AIConfig.Path != "" {
		fmt.Fprintln(d.Err, d.Palette.Warn("предупреждение: ")+
			"состав ai-config мог измениться со сменой настроек — перегенерируйте: tplater ai gen")
	}
	fmt.Fprintln(d.Out, d.Palette.Success("настройки применены"))
	if len(conflicts) > 0 {
		fmt.Fprintln(d.Out, d.Palette.Warn("часть файлов содержит конфликт-маркеры — разрешите их и закоммитьте"))
	}
	return exitForConflicts(conflicts)
}

// commit материализует план изменения настроек и фиксирует новое состояние
// проекта: пишет файлы, обновляет project.yaml.settings (полные новые значения),
// сохраняет чистый target-baseline, перекопирует ресурсы .tplaiter/ и освежает
// baselineSHA в реестре (версия шаблона неизменна — снимок манифеста и хуки не
// трогаются).
func commit(d Deps, ch *change, plan *update.Plan, tgtRendered *renderref.Result) error {
	if _, err := plan.Apply(ch.root); err != nil {
		return err
	}
	ch.proj.Settings = map[string]any(ch.resolved.Values)
	if err := saveMarker(ch.root, ch.proj); err != nil {
		return err
	}
	if err := tgtRendered.Baseline.Save(ch.root); err != nil {
		return err
	}
	if err := resources.Copy(ch.src, ch.root, ch.tpl); err != nil {
		return err
	}
	return refreshRegistry(d, ch.root, ch.proj)
}
