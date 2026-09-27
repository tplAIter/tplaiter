// Package stats реализует отчёт дрейфа сгенерированного проекта от шаблона
// (`tplater stats`): чистый рендер зафиксированной версии+ответов
// (эталон, через internal/renderref — то же ядро, что у update) сравнивается с
// рабочим деревом. По каждому файлу — статус (identical/modified/deleted/extra),
// метрика % изменённых строк (LCS) и класс обновляемости (auto/conflict-prone/
// manual-only). Итог — drift-score 0..100, топ по дрейфу, сломанные якоря;
// `--json` даёт стабильную машиночитаемую схему для дашбордов.
//
// Пакет НЕ импортирует internal/update: эталон рендерится напрямую через
// renderref (checkout из кеша + рендер), historical-эвристика — рендер последних
// N тегов и сравнение результатов. Это исключает связанность с update (его
// параллельно рефакторит реализация ) и повторяет ту же оркестрацию рендера.
package stats

import (
	"context"
	"fmt"
	"io"

	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// historicalTags — сколько последних стабильных тегов шаблона учитывается в
// эвристике conflict-prone (: «diff последних N версий шаблона»).
const historicalTags = 3

// Options — параметры запуска [Run].
type Options struct {
	// StartDir — рабочий каталог для поиска проекта (обычно os.Getwd).
	StartDir string
	// JSON — печатать машиночитаемый отчёт вместо человекочитаемого.
	JSON bool
}

// Deps — внешние зависимости [Run], инъектируемые слоем cobra и тестами.
type Deps struct {
	// Manager — резолюция/checkout версий шаблона (repo-кеш).
	Manager *repo.Manager
	// Home — домашний каталог tplater (не используется напрямую, задел под
	// сверку реестра; оставлен для симметрии с update.Deps).
	Home string
	// Out, Err — потоки основного вывода и предупреждений.
	Out io.Writer
	Err io.Writer
	// Palette — палитра сообщений.
	Palette ui.Palette
}

// Run исполняет `tplater stats`: находит проект от StartDir, собирает отчёт
// дрейфа и печатает его (текстом либо JSON). Ошибок с нестандартным кодом
// выхода не порождает — stats только читает.
func Run(ctx context.Context, d Deps, opts Options) error {
	rep, err := Collect(ctx, d, opts.StartDir)
	if err != nil {
		return err
	}
	if opts.JSON {
		return rep.WriteJSON(d.Out)
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(d.Err, d.Palette.Warn("предупреждение: ")+w)
	}
	rep.Render(d.Out, d.Palette)
	return nil
}

// Collect находит проект от startDir, рендерит эталон зафиксированной версии,
// собирает историческую эвристику и анализирует дрейф рабочего дерева.
func Collect(ctx context.Context, d Deps, startDir string) (*Report, error) {
	root, proj, err := project.FindRoot(startDir)
	if err != nil {
		return nil, err
	}

	in := renderref.Input{
		Values:  renderref.Values(proj.Settings),
		Project: proj.Project,
		Runtime: proj.Runtime,
		Repo:    proj.Template.Repo,
	}
	coord := proj.Template.Repo + "/" + proj.Template.Name

	ref, err := d.Manager.ResolveRef(coord + "@" + proj.Template.Version)
	if err != nil {
		return nil, fmt.Errorf("stats: версия %s: %w", proj.Template.Version, err)
	}

	rendered, err := renderVersion(ctx, d.Manager, ref, in)
	if err != nil {
		return nil, fmt.Errorf("stats: рендер эталона: %w", err)
	}

	churn, histAvailable := historicalChurn(ctx, d.Manager, ref, in)

	rep, err := Analyze(AnalyzeInput{
		RefFiles:      rendered.Files,
		WorkDir:       root,
		CopyGlobs:     rendered.Template.Engine.CopyWithoutRender,
		Generators:    rendered.Template.Generators,
		Churn:         churn,
		HistAvailable: histAvailable,
	})
	if err != nil {
		return nil, err
	}
	rep.OldVersion = proj.Template.Version
	if !histAvailable {
		rep.Warnings = append(rep.Warnings,
			"историческая эвристика недоступна (<2 стабильных тегов) — все правки классифицированы как auto")
	}
	return rep, nil
}

// renderVersion выкачивает версию шаблона по резолву res и рендерит её в память
// с координатами/значениями проекта in. Checkout очищается перед возвратом.
// Дублирует update.RenderVersion (пакет update намеренно не импортируется).
func renderVersion(ctx context.Context, mgr *repo.Manager, res repo.Resolved, in renderref.Input) (*renderref.Result, error) {
	src, cleanup, err := mgr.Checkout(ctx, res.RepoAlias, res.GitRef, res.Entry.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	return renderref.Render(src, in)
}

// historicalChurn собирает множество эталонных путей, которые шаблон менял между
// последними N стабильными тегами (эвристика conflict-prone):
// рендерит каждый из последних N тегов теми же значениями и относит к churn
// путь, содержимое которого различается между любыми двумя рендерами (в т.ч.
// появление/исчезновение файла). Возвращает множество и признак доступности
// эвристики (>=2 успешно отрендеренных тегов). Best-effort: не отрендерившийся
// тег пропускается, не роняя stats.
func historicalChurn(ctx context.Context, mgr *repo.Manager, ref repo.Resolved, in renderref.Input) (map[string]struct{}, bool) {
	tags := ref.Entry.Tags
	if len(tags) > historicalTags {
		tags = tags[:historicalTags]
	}
	if len(tags) < 2 {
		return nil, false
	}

	renders := make([]map[string][]byte, 0, len(tags))
	for _, tag := range tags {
		src, cleanup, err := mgr.Checkout(ctx, ref.RepoAlias, tag, ref.Entry.Path)
		if err != nil {
			continue
		}
		res, rerr := renderref.Render(src, in)
		_ = cleanup()
		if rerr != nil {
			continue
		}
		renders = append(renders, res.Files)
	}
	if len(renders) < 2 {
		return nil, false
	}

	churn := map[string]struct{}{}
	paths := map[string]struct{}{}
	for _, r := range renders {
		for p := range r {
			paths[p] = struct{}{}
		}
	}
	for p := range paths {
		if pathVaries(renders, p) {
			churn[p] = struct{}{}
		}
	}
	return churn, true
}

// pathVaries сообщает, различается ли содержимое пути p между рендерами (включая
// отсутствие файла в части рендеров).
func pathVaries(renders []map[string][]byte, p string) bool {
	first := renders[0][p]
	firstHas := hasKey(renders[0], p)
	for _, r := range renders[1:] {
		has := hasKey(r, p)
		if has != firstHas {
			return true
		}
		if has && string(r[p]) != string(first) {
			return true
		}
	}
	return false
}

func hasKey(m map[string][]byte, k string) bool {
	_, ok := m[k]
	return ok
}
