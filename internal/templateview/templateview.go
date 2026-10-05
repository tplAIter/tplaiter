// Package templateview renders a template's catalog view (`tplaiter template show`
// and future `tplaiter new --help-template`): metadata header, settings-group tree,
// and template documentation. It is pure rendering to io.Writer with no repository
// or template-filesystem access: the caller (internal/cmd) resolves the reference,
// checks it out, and passes the parsed [manifest.Template] and documentation bytes.
package templateview

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// HeaderInfo is `template show` header data: displayName/name, repository,
// selected version (and available stable versions), description, maintainers, labels.
type HeaderInfo struct {
	Repo        string
	Name        string
	DisplayName string
	// Version is the human-readable selected version (see [repo.Resolved.Version]).
	Version string
	// Versions contains all available stable template versions (version suffix with
	// no repository/name prefix), in descending order; empty if the template has no
	// stable tags.
	Versions    []string
	Description string
	Maintainers []manifest.Maintainer
	Labels      map[string][]string
}

// RenderHeader writes the template metadata header to w: a title (bold with
// color; see [ui.Palette.Header]) and a "key: value" [ui.KeyValue] block for
// nonempty repository/version/description/maintainers/labels fields.
func RenderHeader(w io.Writer, pal ui.Palette, h HeaderInfo) {
	title := h.Name
	if h.DisplayName != "" && h.DisplayName != h.Name {
		title = fmt.Sprintf("%s (%s)", h.DisplayName, h.Name)
	}
	fmt.Fprintln(w, pal.Header(title))

	kv := ui.NewKeyValue().Add("repository", h.Repo)
	if len(h.Versions) > 0 {
		kv.Add("version", h.Version+"  (available: "+strings.Join(h.Versions, ", ")+")")
	} else {
		kv.Add("version", h.Version)
	}
	if h.Description != "" {
		kv.Add("description", h.Description)
	}
	if m := formatMaintainers(h.Maintainers); m != "" {
		kv.Add("maintainers", m)
	}
	if l := FormatLabels(h.Labels); l != "" {
		kv.Add("labels", l)
	}
	kv.Render(w)
}

// FormatLabels formats template labels flatly: groups sort by name, values within
// a group are comma-separated, and groups are separated by "; ".
func FormatLabels(labels map[string][]string) string {
	if len(labels) == 0 {
		return ""
	}
	groups := make([]string, 0, len(labels))
	for g := range labels {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	parts := make([]string, 0, len(groups))
	for _, g := range groups {
		values := append([]string(nil), labels[g]...)
		sort.Strings(values)
		parts = append(parts, g+"="+strings.Join(values, ","))
	}
	return strings.Join(parts, "; ")
}

func formatMaintainers(ms []manifest.Maintainer) string {
	if len(ms) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		s := m.Name
		if m.Email != "" {
			s += " <" + m.Email + ">"
		}
		if s == "" {
			s = m.Telegram
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// RenderCommands writes manifest commands (`commands`) as a name-sorted
// COMMAND/DESCRIPTION table. An empty command list is not an error; it writes
// an explanatory line.
func RenderCommands(w io.Writer, pal ui.Palette, commands map[string]manifest.Command) {
	fmt.Fprintln(w, pal.Header("commands:"))
	if len(commands) == 0 {
		fmt.Fprintln(w, "  manifest does not declare commands")
		return
	}

	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)

	t := ui.NewTable("COMMAND", "DESCRIPTION")
	for _, name := range names {
		t.AddRow(name, commands[name].Description)
	}
	fmt.Fprintln(w, indentLines(t.RenderStyled(pal), "  "))
}

// indentLines prefixes every line of s with pad.
func indentLines(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}
