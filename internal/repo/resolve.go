package repo

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/state"
)

// Resolved — результат резолюции ссылки на шаблон.
type Resolved struct {
	RepoAlias string
	Entry     state.TemplateEntry
	// GitRef — git-ссылка, пригодная для checkout (тег `vX.Y.Z`/`name/vX.Y.Z`
	// либо ветка/HEAD для @latest).
	GitRef string
	// Version — человекочитаемая выбранная версия (`v1.2.0` или `latest`).
	Version string
}

// ResolveRef разбирает ссылку `<repo>/<name>[@<version>]` или короткую
// `<name>[@<version>]` и выбирает конкретную версию:
//   - `repo/` можно опустить, если имя уникально среди всех репозиториев; иначе
//     — ошибка со списком кандидатов;
//   - `@<vX.Y.Z>` — конкретный стабильный тег (должен существовать);
//   - `@latest` — HEAD отслеживаемой ветки;
//   - без `@` — старший стабильный тег; при отсутствии тегов — HEAD ветки с
//     предупреждением.
func (m *Manager) ResolveRef(ref string) (Resolved, error) {
	idx, err := m.loadIndex()
	if err != nil {
		return Resolved{}, err
	}

	coord, version := splitVersion(ref)
	repoPart, namePart := splitRepoName(coord)
	if namePart == "" {
		return Resolved{}, fmt.Errorf("repo: пустое имя шаблона в ссылке %q", ref)
	}

	alias, entry, err := m.findTemplate(idx, repoPart, namePart)
	if err != nil {
		return Resolved{}, err
	}

	gitRef, chosen, err := selectVersion(entry, version)
	if err != nil {
		return Resolved{}, err
	}
	if version == "" && len(entry.Tags) == 0 {
		m.warnf("шаблон %s/%s не имеет стабильных тегов — использую %s (@latest)\n", alias, namePart, entry.Ref)
	}
	return Resolved{RepoAlias: alias, Entry: entry, GitRef: gitRef, Version: chosen}, nil
}

// findTemplate находит (alias, entry) по опциональному repoPart и имени.
func (m *Manager) findTemplate(idx state.Index, repoPart, name string) (string, state.TemplateEntry, error) {
	if repoPart != "" {
		entries, ok := idx.Repos[repoPart]
		if !ok {
			return "", state.TemplateEntry{}, fmt.Errorf("repo: репозиторий %q не найден в индексе", repoPart)
		}
		for _, e := range entries {
			if e.Name == name {
				return repoPart, e, nil
			}
		}
		return "", state.TemplateEntry{}, fmt.Errorf("repo: шаблон %q не найден в репозитории %q", name, repoPart)
	}

	// Короткая форма: ищем по всем репозиториям, требуем уникальности.
	type hit struct {
		alias string
		entry state.TemplateEntry
	}
	var hits []hit
	for _, alias := range sortedKeys(idx.Repos) {
		for _, e := range idx.Repos[alias] {
			if e.Name == name {
				hits = append(hits, hit{alias, e})
			}
		}
	}
	switch len(hits) {
	case 0:
		return "", state.TemplateEntry{}, fmt.Errorf("repo: шаблон %q не найден ни в одном репозитории", name)
	case 1:
		return hits[0].alias, hits[0].entry, nil
	default:
		var cands []string
		for _, h := range hits {
			cands = append(cands, h.alias+"/"+name)
		}
		return "", state.TemplateEntry{}, fmt.Errorf(
			"repo: имя %q неоднозначно — уточните репозиторий (%s)", name, strings.Join(cands, ", "),
		)
	}
}

// selectVersion выбирает git-ref и человекочитаемую версию для entry.
func selectVersion(entry state.TemplateEntry, version string) (gitRef, chosen string, err error) {
	switch version {
	case "":
		if len(entry.Tags) > 0 {
			return entry.Tags[0], tagVersionSuffix(entry.Tags[0], entry.Name), nil
		}
		return entry.Ref, "latest", nil
	case "latest":
		return entry.Ref, "latest", nil
	default:
		for _, tag := range entry.Tags {
			if tagVersionSuffix(tag, entry.Name) == version {
				return tag, version, nil
			}
		}
		if len(entry.Tags) == 0 {
			return "", "", fmt.Errorf("repo: у шаблона %q нет стабильных тегов (запрошена версия %q)", entry.Name, version)
		}
		return "", "", fmt.Errorf("repo: версия %q не найдена у шаблона %q (доступны: %s)",
			version, entry.Name, strings.Join(versionSuffixes(entry), ", "))
	}
}

// Checkout материализует дерево шаблона на нужной ссылке в отдельный git
// worktree и возвращает fs.FS, укоренённую в каталоге шаблона, функцию очистки
// и ошибку.
//
// Выбор worktree (а не `git archive`): worktree add --detach атомарно создаёт
// рабочую копию нужного ref, корректно применяя .gitattributes и — что важно
// для клонов с --filter=blob:none — лениво до-загружая ровно те blob'ы, которые
// нужны для этого ref (archive потребовал бы тех же объектов, но давал бы tar,
// который пришлось бы распаковывать во временный каталог отдельным шагом).
// Очистка через `git worktree remove --force` возвращает git в согласованное
// состояние (плюс RemoveAll на случай, если каталог уже отвязан).
func (m *Manager) Checkout(ctx context.Context, alias, gitRef, templatePath string) (fs.FS, func() error, error) {
	clone := m.cloneDir(alias)
	if _, err := os.Stat(clone); err != nil {
		return nil, nil, fmt.Errorf("repo: клон %q отсутствует: %w", alias, err)
	}

	wt, err := os.MkdirTemp("", "tplater-checkout-"+alias+"-")
	if err != nil {
		return nil, nil, fmt.Errorf("repo: временный каталог для checkout: %w", err)
	}

	// Ветки после `repo update` живут в origin/<ref> (fetch в не-bare клоне не
	// двигает локальную ветку) — для актуального @latest используем origin-реф.
	checkoutRef := gitRef
	if _, err := m.git(ctx, clone, []string{"rev-parse", "--verify", "--quiet", "origin/" + gitRef}, nil); err == nil {
		checkoutRef = "origin/" + gitRef
	}

	if _, err := m.git(ctx, clone, []string{"worktree", "add", "--detach", wt, checkoutRef}, nil); err != nil {
		_ = os.RemoveAll(wt)
		return nil, nil, fmt.Errorf("repo: checkout %s@%s: %w", alias, gitRef, err)
	}

	cleanup := func() error {
		// worktree remove отвязывает рабочий каталог и удаляет его; RemoveAll —
		// подстраховка (например, если git оставил каталог из-за грязного дерева).
		_, rmErr := m.git(ctx, clone, []string{"worktree", "remove", "--force", wt}, nil)
		if err := os.RemoveAll(wt); err != nil && rmErr == nil {
			return err
		}
		return rmErr
	}

	root := wt
	if p := normalizeTemplatePath(templatePath); p != "." {
		root = filepath.Join(wt, filepath.FromSlash(p))
	}
	return os.DirFS(root), cleanup, nil
}

// splitVersion делит ссылку на координату и версию по последнему '@'.
func splitVersion(ref string) (coord, version string) {
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

// splitRepoName делит координату `repo/name` на части; без '/' — только имя.
func splitRepoName(coord string) (repo, name string) {
	if i := strings.Index(coord, "/"); i >= 0 {
		return coord[:i], coord[i+1:]
	}
	return "", coord
}

func versionSuffixes(entry state.TemplateEntry) []string {
	out := make([]string, 0, len(entry.Tags))
	for _, t := range entry.Tags {
		out = append(out, tagVersionSuffix(t, entry.Name))
	}
	return out
}

func sortedKeys(m map[string][]state.TemplateEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
