package update

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/tplAIter/tplaiter/internal/ui"
)

// FileDelta is a file with added/deleted line counts relative to the reference.
type FileDelta struct {
	Path    string
	Added   int
	Removed int
}

// Report is the structured five-category update report, built from the plan
// before application so it reads the current work tree.
type Report struct {
	// Updated: files overwritten by target (hash==baseline; only the template changed).
	Updated []string
	// KeptYours: files unchanged by the template but edited by the user.
	KeptYours []string
	// Merged: files cleanly 3-way merged, with +/- line counts.
	Merged []FileDelta
	// Conflicts: files with conflict markers.
	Conflicts []string
	// LocalDeviations: work differs from the base render and the template also
	// changed the file (merge and conflict categories). Shows work↔baseline diff.
	LocalDeviations []FileDelta
	// Deleted: files removed with the template.
	Deleted []string
	// Created: new target-version files.
	Created []string
	// Warnings: plan warnings (for example, deleted upstream but edited locally).
	Warnings []string
	// diffs are work↔baseline unified diffs for LocalDeviations (for --verbose).
	diffs map[string]string
}

// buildReport classifies plan actions into report categories. baseFiles is the
// old clean render (reference for non-template diff); workDir is the project
// root before the plan changes the work tree.
func buildReport(plan *Plan, baseFiles map[string][]byte, workDir string) *Report {
	r := &Report{diffs: map[string]string{}}
	r.Warnings = append(r.Warnings, plan.Warnings...)

	for _, a := range plan.Actions {
		switch {
		case a.Conflict:
			r.Conflicts = append(r.Conflicts, a.Path)
			r.addDeviation(a.Path, baseFiles, workDir)
		case a.Op == OpDelete:
			r.Deleted = append(r.Deleted, a.Path)
		case a.Op == OpWrite && a.Reason == "merge":
			work, _, _ := readWork(workDir, a.Path)
			add, rm := lineDelta(work, a.Content)
			r.Merged = append(r.Merged, FileDelta{Path: a.Path, Added: add, Removed: rm})
			r.addDeviation(a.Path, baseFiles, workDir)
		case a.Op == OpWrite && a.Reason == "create":
			r.Created = append(r.Created, a.Path)
		case a.Op == OpWrite: // update / recreate
			r.Updated = append(r.Updated, a.Path)
		case a.Op == OpKeep && a.Reason == "unchanged":
			// Keep without a user edit: stay quiet (file matches the reference).
			work, _, _ := readWork(workDir, a.Path)
			if base, ok := baseFiles[a.Path]; ok && !bytes.Equal(work, base) {
				r.KeptYours = append(r.KeptYours, a.Path)
			}
		case a.Op == OpKeep && a.Reason == "kept (modified locally, removed upstream)":
			r.KeptYours = append(r.KeptYours, a.Path)
		}
	}

	sort.Strings(r.Updated)
	sort.Strings(r.KeptYours)
	sort.Strings(r.Conflicts)
	sort.Strings(r.Deleted)
	sort.Strings(r.Created)
	sort.Slice(r.Merged, func(i, j int) bool { return r.Merged[i].Path < r.Merged[j].Path })
	sort.Slice(r.LocalDeviations, func(i, j int) bool { return r.LocalDeviations[i].Path < r.LocalDeviations[j].Path })
	return r
}

// addDeviation records a local deviation (work != base render), retaining the
// work↔baseline unified diff for --verbose.
func (r *Report) addDeviation(path string, baseFiles map[string][]byte, workDir string) {
	base, ok := baseFiles[path]
	if !ok {
		return
	}
	work, _, _ := readWork(workDir, path)
	if bytes.Equal(work, base) {
		return
	}
	add, rm := lineDelta(base, work)
	r.LocalDeviations = append(r.LocalDeviations, FileDelta{Path: path, Added: add, Removed: rm})
	r.diffs[path] = unifiedDiff(base, work)
}

// HasConflicts reports whether any files contain conflict markers.
func (r *Report) HasConflicts() bool { return len(r.Conflicts) > 0 }

// Render prints the report to out using pal. verbose adds a unified diff for each
// local deviation.
func (r *Report) Render(out io.Writer, pal ui.Palette, verbose bool) {
	section := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintln(out, title)
		for _, it := range items {
			fmt.Fprintf(out, "  %s\n", it)
		}
	}

	// Categories with explicit semantics use matching palette colors (updated=success,
	// conflict=error, deviations=warn); neutral categories use a bold header.
	section(pal.Success("updated:"), r.Updated)
	section(pal.Header("created:"), r.Created)
	section(pal.Header("deleted:"), r.Deleted)
	section(pal.Header("kept yours:"), r.KeptYours)

	if len(r.Merged) > 0 {
		fmt.Fprintln(out, pal.Header("merged:"))
		for _, d := range r.Merged {
			fmt.Fprintf(out, "  %s (%s)\n", d.Path, deltaStr(pal, d))
		}
	}
	if len(r.Conflicts) > 0 {
		fmt.Fprintln(out, pal.Error("CONFLICT (markers in files, manual resolution required):"))
		for _, c := range r.Conflicts {
			fmt.Fprintf(out, "  %s\n", c)
		}
	}
	if len(r.LocalDeviations) > 0 {
		fmt.Fprintln(out, pal.Warn("local deviations (made outside template, work↔baseline):"))
		for _, d := range r.LocalDeviations {
			fmt.Fprintf(out, "  %s (%s)\n", d.Path, deltaStr(pal, d))
			if verbose {
				fmt.Fprint(out, indent(r.diffs[d.Path]))
			}
		}
		if !verbose {
			fmt.Fprintln(out, pal.Muted("  (--verbose — show unified diff)"))
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintln(out, pal.Warn("warning: ")+w)
	}
}

// deltaStr formats "+A -R lines" using the palette.
func deltaStr(pal ui.Palette, d FileDelta) string {
	return fmt.Sprintf("%s %s", pal.Success(fmt.Sprintf("+%d", d.Added)), pal.Warn(fmt.Sprintf("-%d", d.Removed)))
}

// lineDelta counts added/deleted lines between oldB and newB using LCS.
func lineDelta(oldB, newB []byte) (added, removed int) {
	a := splitLines(oldB)
	b := splitLines(newB)
	common := len(lcsPairs(a, b))
	return len(b) - common, len(a) - common
}

// unifiedDiff builds a compact line diff oldB->newB using LCS: old-only lines
// get "-", new-only lines "+", and common lines a space.
func unifiedDiff(oldB, newB []byte) string {
	a := splitLines(oldB)
	b := splitLines(newB)
	pairs := lcsPairs(a, b)

	var sb []byte
	emit := func(prefix byte, lines []string) {
		for _, ln := range lines {
			sb = append(sb, prefix)
			sb = append(sb, ln...)
			sb = append(sb, '\n')
		}
	}

	ai, bi := 0, 0
	for _, p := range pairs {
		emit('-', a[ai:p.a])
		emit('+', b[bi:p.b])
		emit(' ', a[p.a:p.a+1])
		ai, bi = p.a+1, p.b+1
	}
	emit('-', a[ai:])
	emit('+', b[bi:])
	return string(sb)
}

// indent adds indentation to each line of a diff block.
func indent(s string) string {
	if s == "" {
		return ""
	}
	out := make([]byte, 0, len(s)+8)
	lineStart := true
	for i := 0; i < len(s); i++ {
		if lineStart {
			out = append(out, ' ', ' ', ' ', ' ')
			lineStart = false
		}
		out = append(out, s[i])
		if s[i] == '\n' {
			lineStart = true
		}
	}
	return string(out)
}
