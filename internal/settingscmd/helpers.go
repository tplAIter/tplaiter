package settingscmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
	"github.com/tplAIter/tplaiter/internal/update"
)

// groupChange — изменение одной группы для сводки set/edit.
type groupChange struct {
	Group string
	Old   string
	New   string
}

// exitForConflicts возвращает [update.ExitCodeError] с кодом 2, если план
// оставил конфликт-маркеры (симметрично `tplater update`). Слой cmd
// транслирует его в exit-код процесса.
func exitForConflicts(conflicts []string) error {
	if len(conflicts) == 0 {
		return nil
	}
	return &update.ExitCodeError{
		Code: 2,
		Err:  fmt.Errorf("settings: %d конфликт(ов) требуют ручного разрешения", len(conflicts)),
	}
}

// printResolveReport печатает доклад резолвера: довключённые значения (requires)
// и предупреждения (напр. сброс неактивной вложенной группы).
func printResolveReport(d Deps, rep settings.Report) {
	if len(rep.Implied) > 0 {
		fmt.Fprintln(d.Out, d.Palette.Warn("довключено автоматически (требуется выбранными опциями):"))
		for _, im := range rep.Implied {
			fmt.Fprintf(d.Out, "  %s=%s (требует %s)\n", im.Group, im.Value, im.RequiredBy)
		}
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(d.Err, d.Palette.Warn("предупреждение: ")+w)
	}
}

// printSettingsTable печатает таблицу GROUP/VALUE/ACTIVE по всему дереву групп.
// Неактивные вложенные группы (родительская опция не выбрана) приглушаются
// целиком; вложенность отражается отступом имени группы.
func printSettingsTable(out io.Writer, pal ui.Palette, tpl *manifest.Template, values settings.Values) {
	tbl := ui.NewTable("GROUP", "VALUE", "ACTIVE")
	walkGroups(tpl.Settings, values, true, 0, func(g *manifest.SettingGroup, active bool, depth int) {
		name := strings.Repeat("  ", depth) + g.Group
		val := formatValue(values[g.Group])
		activeCell := "да"
		if !active {
			activeCell = "нет"
		}
		if active {
			tbl.AddRow(name, val, activeCell)
			return
		}
		// Неактивная вложенная группа — приглушаем всю строку.
		tbl.AddRow(pal.Muted(name), pal.Muted(val), pal.Muted(activeCell))
	})
	fmt.Fprintln(out, tbl.RenderStyled(pal))
}

// printChangedGroups печатает сводку изменённых групп (старое→новое).
func printChangedGroups(out io.Writer, pal ui.Palette, changed []groupChange) {
	if len(changed) == 0 {
		return
	}
	fmt.Fprintln(out, "изменённые группы:")
	for _, c := range changed {
		fmt.Fprintf(out, "  %s: %s → %s\n", c.Group, pal.Muted(c.Old), pal.Success(c.New))
	}
}

// changedGroups сравнивает старые и новые значения по всем группам дерева и
// возвращает изменившиеся (в порядке объявления).
func changedGroups(tpl *manifest.Template, oldV, newV settings.Values) []groupChange {
	var out []groupChange
	walkGroups(tpl.Settings, newV, true, 0, func(g *manifest.SettingGroup, _ bool, _ int) {
		o := formatValue(oldV[g.Group])
		n := formatValue(newV[g.Group])
		if o != n {
			out = append(out, groupChange{Group: g.Group, Old: o, New: n})
		}
	})
	return out
}

// walkGroups обходит дерево групп в порядке объявления, вызывая fn для каждой
// группы с флагом активности и глубиной вложенности. Корневые группы активны
// всегда; вложенная активна, когда активен родитель И в нём выбрана
// активирующая опция (по values).
func walkGroups(
	groups []manifest.SettingGroup, values settings.Values, active bool, depth int,
	fn func(g *manifest.SettingGroup, active bool, depth int),
) {
	for i := range groups {
		g := &groups[i]
		fn(g, active, depth)
		for j := range g.Options {
			opt := &g.Options[j]
			childActive := active && optionSelected(g.Type, values[g.Group], opt.ID)
			walkGroups(opt.Settings, values, childActive, depth+1, fn)
		}
	}
}

// optionSelected сообщает, выбрана ли опция optID в группе типа select/
// multiselect при значении val.
func optionSelected(typ string, val any, optID string) bool {
	switch typ {
	case manifest.TypeSelect:
		s, _ := val.(string)
		return s == optID
	case manifest.TypeMultiselect:
		list, _ := val.([]string)
		for _, s := range list {
			if s == optID {
				return true
			}
		}
	}
	return false
}

// groupExists сообщает, есть ли в дереве группа с данным id.
func groupExists(tpl *manifest.Template, id string) bool {
	found := false
	walkGroups(tpl.Settings, nil, true, 0, func(g *manifest.SettingGroup, _ bool, _ int) {
		if g.Group == id {
			found = true
		}
	})
	return found
}

// groupWithDescendants возвращает множество id целевой группы и всех групп,
// вложенных под её опции (её субдерево). Нужно, чтобы edit <group> переопросил
// саму группу и её уточнения, а не тянул их из preset.
func groupWithDescendants(tpl *manifest.Template, id string) map[string]bool {
	out := map[string]bool{}
	var find func(groups []manifest.SettingGroup)
	find = func(groups []manifest.SettingGroup) {
		for i := range groups {
			g := &groups[i]
			if g.Group == id {
				out[id] = true
				markSubtree(g, out)
				return
			}
			for j := range g.Options {
				find(g.Options[j].Settings)
			}
		}
	}
	find(tpl.Settings)
	return out
}

// markSubtree помечает в set id всех групп, вложенных под опции g.
func markSubtree(g *manifest.SettingGroup, out map[string]bool) {
	for j := range g.Options {
		for k := range g.Options[j].Settings {
			sub := &g.Options[j].Settings[k]
			out[sub.Group] = true
			markSubtree(sub, out)
		}
	}
}

// saveMarker сериализует проектный маркер и перезаписывает .tplaiter/project.yaml
// (значения settings уже обновлены вызывающим). Версия/id/runtime сохраняются.
func saveMarker(root string, proj *manifest.Project) error {
	data, err := yaml.Marshal(proj)
	if err != nil {
		return fmt.Errorf("settings: сериализация project.yaml: %w", err)
	}
	path := filepath.Join(root, project.MarkerRelPath)
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: маркер не секрет.
		return fmt.Errorf("settings: запись project.yaml: %w", err)
	}
	return nil
}

// refreshRegistry освежает baselineSHA/path/lastSeenAt записи проекта в реестре
//: baseline пересчитан сменой настроек, версия шаблона не менялась.
func refreshRegistry(d Deps, root string, proj *manifest.Project) error {
	baselineSHA, err := hashFile(filepath.Join(root, engine.BaselineRelPath))
	if err != nil {
		return fmt.Errorf("settings: хеш baseline: %w", err)
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	ts := now()
	ref := state.ProjectRef{
		ID:   proj.ID,
		Path: root,
		Template: state.TemplateSelection{
			Repo:    proj.Template.Repo,
			Name:    proj.Template.Name,
			Version: proj.Template.Version,
		},
		CreatedAt:   ts,
		LastSeenAt:  ts,
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

// hashFile возвращает hex(sha256) содержимого файла.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// nonDefaultExplicit возвращает подмножество values, отличающихся от defaults и
// не входящих в drop (последнее — субдерево переопрашиваемой группы для edit).
// Это восстановление «явно заданных» групп из плоского снимка project.yaml, где
// различие explicit/дефолт не сохраняется: значение, равное дефолту, считаем
// неявным, чтобы requires могли его довключить.
func nonDefaultExplicit(values, defaults settings.Values, drop map[string]bool) settings.Values {
	out := settings.Values{}
	for group, val := range values {
		if drop[group] {
			continue
		}
		if valuesEqual(val, defaults[group]) {
			continue
		}
		out[group] = val
	}
	return out
}

// valuesEqual сравнивает значения настроек с поддержкой []string.
func valuesEqual(a, b any) bool {
	as, aok := a.([]string)
	bs, bok := b.([]string)
	if aok || bok {
		if !aok || !bok || len(as) != len(bs) {
			return false
		}
		for i := range as {
			if as[i] != bs[i] {
				return false
			}
		}
		return true
	}
	return a == b
}

// formatValue форматирует значение группы для таблиц/сводок.
func formatValue(v any) string {
	switch x := v.(type) {
	case []string:
		if len(x) == 0 {
			return "-"
		}
		return strings.Join(x, ",")
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case string:
		if x == "" {
			return "-"
		}
		return x
	case nil:
		return "-"
	default:
		return fmt.Sprintf("%v", x)
	}
}
