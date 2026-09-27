package templateview

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// indentUnit is the indent for one level of the settings-group tree.
const indentUnit = "  "

// RenderSettings writes the template settings-group tree (`settings`) in a
// Helm-catalog style: each group shows its id/title, type and default, followed
// by options (planned options use muted pal color) and recursively nested detail
// groups (Option.Settings) with increased indentation. depth is the initial
// indent level, usually 0.
func RenderSettings(w io.Writer, pal ui.Palette, groups []manifest.SettingGroup, depth int) {
	if len(groups) == 0 {
		fmt.Fprintln(w, strings.Repeat(indentUnit, depth)+"манифест не объявляет settings")
		return
	}
	for i := range groups {
		renderGroup(w, pal, &groups[i], depth)
	}
}

func renderGroup(w io.Writer, pal ui.Palette, g *manifest.SettingGroup, depth int) {
	pad := strings.Repeat(indentUnit, depth)
	label := g.Group
	if g.Title != "" {
		label += " — " + g.Title
	}
	fmt.Fprintf(w, "%s- %s [%s, default=%s]\n", pad, label, g.Type, formatDefault(g.Default))
	if g.Description != "" {
		fmt.Fprintf(w, "%s%s%s\n", pad, indentUnit, g.Description)
	}
	for i := range g.Options {
		renderOption(w, pal, &g.Options[i], depth+1)
	}
}

func renderOption(w io.Writer, pal ui.Palette, opt *manifest.Option, depth int) {
	pad := strings.Repeat(indentUnit, depth)
	body := "* " + opt.ID
	if opt.Title != "" {
		body += " — " + opt.Title
	}
	line := pad + body
	if opt.Status == manifest.StatusPlanned {
		line = pad + ui.StatusIcon(pal, ui.StatusPlanned) + " " + pal.Muted(body+" [planned]")
	}
	fmt.Fprintln(w, line)
	if opt.Description != "" {
		fmt.Fprintf(w, "%s%s%s\n", pad, indentUnit, opt.Description)
	}
	if len(opt.Settings) > 0 {
		RenderSettings(w, pal, opt.Settings, depth+1)
	}
}

// formatDefault converts SettingGroup.Default (whose type depends on group Type;
// see [manifest.SettingGroup]) to printable form.
func formatDefault(v any) string {
	switch d := v.(type) {
	case nil:
		return "-"
	case string:
		return d
	case bool:
		return strconv.FormatBool(d)
	case int:
		return strconv.Itoa(d)
	case []any:
		parts := make([]string, 0, len(d))
		for _, el := range d {
			if s, ok := el.(string); ok {
				parts = append(parts, s)
			} else {
				parts = append(parts, fmt.Sprint(el))
			}
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(d)
	}
}
