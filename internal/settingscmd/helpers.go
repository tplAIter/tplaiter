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

// groupChange — one group change for the set/edit summary.
type groupChange struct {
	Group string
	Old   string
	New   string
}

// exitForConflicts returns [update.ExitCodeError] with code 2 when the plan
// leaves conflict markers (symmetric with `tplaiter update`). The cmd layer maps
// it to the process exit code.
func exitForConflicts(conflicts []string) error {
	if len(conflicts) == 0 {
		return nil
	}
	return &update.ExitCodeError{
		Code: 2,
		Err:  fmt.Errorf("settings: %d conflict(s) require manual resolution", len(conflicts)),
	}
}

// printResolveReport prints resolver output: implied values (requires) and
// warnings (for example, clearing an inactive nested group).
func printResolveReport(d Deps, rep settings.Report) {
	if len(rep.Implied) > 0 {
		fmt.Fprintln(d.Out, d.Palette.Warn("auto-enabled (required by selected options):"))
		for _, im := range rep.Implied {
			fmt.Fprintf(d.Out, "  %s=%s (required by %s)\n", im.Group, im.Value, im.RequiredBy)
		}
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(d.Err, d.Palette.Warn("warning: ")+w)
	}
}

// printSettingsTable prints GROUP/VALUE/ACTIVE for the entire group tree.
// Inactive nested groups (parent option not selected) are muted; nesting is
// represented by indentation of the group name.
func printSettingsTable(out io.Writer, pal ui.Palette, tpl *manifest.Template, values settings.Values) {
	tbl := ui.NewTable("GROUP", "VALUE", "ACTIVE")
	walkGroups(tpl.Settings, values, true, 0, func(g *manifest.SettingGroup, active bool, depth int) {
		name := strings.Repeat("  ", depth) + g.Group
		if g.Deprecated {
			name += " (deprecated, retained read-only)"
		}
		val := formatValue(values[g.Group])
		activeCell := "yes"
		if !active {
			activeCell = "no"
		}
		if active {
			tbl.AddRow(name, val, activeCell)
			return
		}
		// Inactive nested group — mute the entire row.
		tbl.AddRow(pal.Muted(name), pal.Muted(val), pal.Muted(activeCell))
	})
	fmt.Fprintln(out, tbl.RenderStyled(pal))
}

// printChangedGroups prints changed groups (old→new).
func printChangedGroups(out io.Writer, pal ui.Palette, changed []groupChange) {
	if len(changed) == 0 {
		return
	}
	fmt.Fprintln(out, "changed groups:")
	for _, c := range changed {
		fmt.Fprintf(out, "  %s: %s → %s\n", c.Group, pal.Muted(c.Old), pal.Success(c.New))
	}
}

// changedGroups compares old and new values across the group tree and returns
// changed groups in declaration order.
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

// walkGroups traverses groups in declaration order, calling fn with activity and
// nesting depth. Root groups are always active; a nested group is active when its
// parent is active and its activating option is selected in values.
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

// optionSelected reports whether optID is selected in a select/multiselect group
// with value val.
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

// groupExists reports whether the tree contains a group with the given ID.
func groupExists(tpl *manifest.Template, id string) bool {
	found := false
	walkGroups(tpl.Settings, nil, true, 0, func(g *manifest.SettingGroup, _ bool, _ int) {
		if g.Group == id {
			found = true
		}
	})
	return found
}

// groupWithDescendants returns the target group ID and all groups nested under
// its options (its subtree). edit <group> uses it to re-ask the group and its
// refinements rather than pulling them from the preset.
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

// markSubtree marks IDs of all groups nested under g's options in set.
func markSubtree(g *manifest.SettingGroup, out map[string]bool) {
	for j := range g.Options {
		for k := range g.Options[j].Settings {
			sub := &g.Options[j].Settings[k]
			out[sub.Group] = true
			markSubtree(sub, out)
		}
	}
}

// saveMarker serializes the project marker and rewrites .tplaiter/project.yaml
// (settings values were already updated by the caller). Version/id/runtime remain.
func saveMarker(root string, proj *manifest.Project) error {
	data, err := yaml.Marshal(proj)
	if err != nil {
		return fmt.Errorf("settings: serializing project.yaml: %w", err)
	}
	path := filepath.Join(root, project.MarkerRelPath)
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: the marker is not secret.
		return fmt.Errorf("settings: writing project.yaml: %w", err)
	}
	return nil
}

// refreshRegistry refreshes baselineSHA/path/lastSeenAt in the project registry:
// the baseline changed with settings, while the template version did not.
func refreshRegistry(d Deps, root string, proj *manifest.Project) error {
	baselineSHA, err := hashFile(filepath.Join(root, engine.BaselineRelPath))
	if err != nil {
		return fmt.Errorf("settings: baseline hash: %w", err)
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

// hashFile returns hex(sha256) of file contents.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// nonDefaultExplicit returns values differing from defaults and outside drop
// (the latter is the re-asked group's subtree for edit). It reconstructs
// "explicit" groups from the flat project.yaml snapshot, where explicit/default
// provenance is lost: default-equal values are treated as implicit so requires
// can imply them.
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

// valuesEqual compares setting values, including []string.
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

// formatValue formats a group value for tables/summaries.
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
