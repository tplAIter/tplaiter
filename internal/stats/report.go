package stats

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/ui"
)

// topN is how many files to show in the top-drift table.
const topN = 10

// WriteJSON serializes the report in the stable {score, files, extras,
// brokenAnchors} schema with two-space indentation and a final \n. extras and
// brokenAnchors are always non-nil slices (JSON `[]`, not `null`) for stable goldens.
func (r *Report) WriteJSON(w io.Writer) error {
	out := *r
	if out.Files == nil {
		out.Files = []FileStat{}
	}
	if out.Extras == nil {
		out.Extras = []string{}
	}
	if out.BrokenAnchors == nil {
		out.BrokenAnchors = []string{}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("stats: сериализация JSON: %w", err)
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("stats: запись JSON: %w", err)
	}
	return nil
}

// Render prints a human-readable report: category and score summary, top 10 by
// drift, extra-file count, and broken anchors. Zero drift is summarized as
// "project matches the template".
func (r *Report) Render(w io.Writer, p ui.Palette) {
	counts := r.countByStatus()

	fmt.Fprintln(w, p.Header(fmt.Sprintf("дрейф проекта от шаблона (версия %s)", r.OldVersion)))
	fmt.Fprintln(w)

	if r.isClean() {
		fmt.Fprintln(w, p.Success("drift-score: 0 — проект соответствует шаблону"))
		return
	}

	scoreLine := fmt.Sprintf("drift-score: %d / 100", r.Score)
	fmt.Fprintln(w, scoreColor(p, r.Score)(scoreLine))
	fmt.Fprintf(w, "файлов эталона: %d  (identical %d, modified %d, deleted %d)\n",
		len(r.Files), counts[StatusIdentical], counts[StatusModified]+counts[StatusModifiedBinary], counts[StatusDeleted])
	fmt.Fprintf(w, "extra-файлов (вне шаблона): %d\n", len(r.Extras))
	fmt.Fprintf(w, "сломанные якоря: %d", len(r.BrokenAnchors))
	if len(r.BrokenAnchors) > 0 {
		fmt.Fprintf(w, " (%s)", joinPaths(r.BrokenAnchors))
	}
	fmt.Fprint(w, "\n\n")

	r.renderTop(w, p)
}

// renderTop prints the top-N files by drift.
func (r *Report) renderTop(w io.Writer, p ui.Palette) {
	ranked := r.rankedByDrift()
	if len(ranked) == 0 {
		return
	}
	if len(ranked) > topN {
		ranked = ranked[:topN]
	}
	fmt.Fprintln(w, p.Header(fmt.Sprintf("топ-%d по дрейфу:", topN)))
	table := ui.NewTable("FILE", "STATUS", "CLASS", "±", "%")
	for _, f := range ranked {
		table.AddRow(f.Path, statusColor(p, f.Status), f.Class, plusMinus(f), pctCell(f))
	}
	fmt.Fprintln(w, table.RenderStyled(p))
}

// rankedByDrift sorts files by descending score contribution, then by path;
// identical files (zero contribution) are discarded.
func (r *Report) rankedByDrift() []FileStat {
	drifted := make([]FileStat, 0, len(r.Files))
	for _, f := range r.Files {
		if f.Status == StatusIdentical {
			continue
		}
		drifted = append(drifted, f)
	}
	sort.SliceStable(drifted, func(i, j int) bool {
		si, sj := scoreFor(drifted[i]), scoreFor(drifted[j])
		if si != sj {
			return si > sj
		}
		return drifted[i].Path < drifted[j].Path
	})
	return drifted
}

func (r *Report) countByStatus() map[string]int {
	m := map[string]int{}
	for _, f := range r.Files {
		m[f.Status]++
	}
	return m
}

// isClean reports zero drift: score 0, no extras, and no broken anchors.
func (r *Report) isClean() bool {
	return r.Score == 0 && len(r.Extras) == 0 && len(r.BrokenAnchors) == 0
}

func plusMinus(f FileStat) string {
	if f.Status == StatusModifiedBinary || f.Status == StatusDeleted {
		return "—"
	}
	return "+" + strconv.Itoa(f.AddedLines) + "/-" + strconv.Itoa(f.RemovedLines)
}

func pctCell(f FileStat) string {
	switch f.Status {
	case StatusModifiedBinary:
		return "bin"
	case StatusDeleted:
		return "100"
	}
	return strconv.FormatFloat(f.Percent, 'f', -1, 64)
}

// scoreColor chooses score color: 0 success, <34 muted, <67 warn, otherwise error.
func scoreColor(p ui.Palette, score int) func(string) string {
	switch {
	case score == 0:
		return p.Success
	case score < 34:
		return p.Muted
	case score < 67:
		return p.Warn
	default:
		return p.Error
	}
}

func statusColor(p ui.Palette, status string) string {
	switch status {
	case StatusIdentical:
		return p.Success(status)
	case StatusDeleted:
		return p.Error(status)
	default:
		return p.Warn(status)
	}
}

func joinPaths(paths []string) string {
	return strings.Join(paths, ", ")
}
