package stats_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/stats"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// writeTree materializes a relative-path-to-content map in dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func refFiles(m map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = []byte(v)
	}
	return out
}

// findFile returns FileStat by path (or fails the test).
func findFile(t *testing.T, rep *stats.Report, path string) stats.FileStat {
	t.Helper()
	for _, f := range rep.Files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("file %q missing from the report", path)
	return stats.FileStat{}
}

func analyze(t *testing.T, in stats.AnalyzeInput) *stats.Report {
	t.Helper()
	rep, err := stats.Analyze(in)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return rep
}

// Zero drift: work == reference -> score 0, all identical.
func TestAnalyze_ZeroDrift(t *testing.T) {
	work := t.TempDir()
	tree := map[string]string{"a.txt": "x\n", "dir/b.txt": "y\n"}
	writeTree(t, work, tree)

	rep := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(tree), WorkDir: work})

	if rep.Score != 0 {
		t.Errorf("score = %d, expected 0", rep.Score)
	}
	for _, f := range rep.Files {
		if f.Status != stats.StatusIdentical {
			t.Errorf("%s: status %q, expected identical", f.Path, f.Status)
		}
	}
	if len(rep.Extras) != 0 || len(rep.BrokenAnchors) != 0 {
		t.Errorf("extras=%v brokenAnchors=%v, expected empty", rep.Extras, rep.BrokenAnchors)
	}
}

// One file changed: status/+/-% are correct, score > 0.
func TestAnalyze_ModifiedFile(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{"m.txt": "a\nb\nc\nd"}
	writeTree(t, work, map[string]string{"m.txt": "a\nb\nc\nX"}) // 1 of 4 lines changed

	rep := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work, HistAvailable: false})

	f := findFile(t, rep, "m.txt")
	if f.Status != stats.StatusModified {
		t.Errorf("status = %q, expected modified", f.Status)
	}
	if f.Class != stats.ClassAuto {
		t.Errorf("class = %q, expected auto (heuristic unavailable)", f.Class)
	}
	if f.AddedLines != 1 || f.RemovedLines != 1 {
		t.Errorf("± = +%d/-%d, expected +1/-1", f.AddedLines, f.RemovedLines)
	}
	if f.Percent != 50 {
		t.Errorf("percent = %v, expected 50", f.Percent)
	}
	// auto: 50 * 0.5 = 25 -> rounded 25.
	if rep.Score != 25 {
		t.Errorf("score = %d, expected 25", rep.Score)
	}
}

// Reference file deleted: manual-only, contribution 100.
func TestAnalyze_DeletedFile(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{"keep.txt": "x\n", "gone.txt": "bye\n"}
	writeTree(t, work, map[string]string{"keep.txt": "x\n"}) // gone.txt is absent

	rep := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work})

	f := findFile(t, rep, "gone.txt")
	if f.Status != stats.StatusDeleted || f.Class != stats.ClassManualOnly {
		t.Errorf("gone.txt: %q/%q, expected deleted/manual-only", f.Status, f.Class)
	}
	// (0 + 100)/2 = 50.
	if rep.Score != 50 {
		t.Errorf("score = %d, expected 50", rep.Score)
	}
}

// Extra file: appears in extras and does not affect score.
func TestAnalyze_ExtraFile(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{"a.txt": "x\n"}
	writeTree(t, work, map[string]string{"a.txt": "x\n", "extra/new.txt": "z\n"})

	rep := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work})

	if len(rep.Extras) != 1 || rep.Extras[0] != "extra/new.txt" {
		t.Errorf("extras = %v, expected [extra/new.txt]", rep.Extras)
	}
	if rep.Score != 0 {
		t.Errorf("score = %d, expected 0 (extra is not counted)", rep.Score)
	}
	for _, f := range rep.Files {
		if f.Path == "extra/new.txt" {
			t.Errorf("an extra file must not be in files")
		}
	}
}

// Service directories .tplaiter/ and .git/ are excluded from extras.
func TestAnalyze_ExcludesServiceDirs(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{"a.txt": "x\n"}
	writeTree(t, work, map[string]string{
		"a.txt":                   "x\n",
		".tplaiter/baseline.json": "{}",
		".git/config":             "[core]",
	})

	rep := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work})
	if len(rep.Extras) != 0 {
		t.Errorf("extras = %v, expected empty (service directories excluded)", rep.Extras)
	}
}

// Broken CODEGEN anchor: file is manual-only and appears in brokenAnchors.
func TestAnalyze_BrokenAnchor(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{"wiring.txt": "pre\n// CODEGEN:WIRING\npost\n"}
	writeTree(t, work, map[string]string{"wiring.txt": "pre\npost\n"}) // anchor removed

	gens := []manifest.Generator{{
		Kind:    "handler",
		Snippet: "s.tmpl",
		Target:  "x",
		Anchors: []manifest.Anchor{{File: "wiring.txt", Anchor: "// CODEGEN:WIRING", Insert: "i.tmpl"}},
	}}

	rep := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work, Generators: gens})

	if len(rep.BrokenAnchors) != 1 || rep.BrokenAnchors[0] != "wiring.txt" {
		t.Errorf("brokenAnchors = %v, expected [wiring.txt]", rep.BrokenAnchors)
	}
	f := findFile(t, rep, "wiring.txt")
	if f.Class != stats.ClassManualOnly {
		t.Errorf("class = %q, expected manual-only (broken anchor)", f.Class)
	}
	if rep.Score != 100 {
		t.Errorf("score = %d, expected 100 (manual-only)", rep.Score)
	}
}

// An intact anchor (present in work) is not broken.
func TestAnalyze_IntactAnchor(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{"wiring.txt": "pre\n// CODEGEN:WIRING\npost\n"}
	writeTree(t, work, map[string]string{"wiring.txt": "pre\n// CODEGEN:WIRING\npost\nUSER\n"})

	gens := []manifest.Generator{{
		Anchors: []manifest.Anchor{{File: "wiring.txt", Anchor: "// CODEGEN:WIRING"}},
	}}

	rep := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work, Generators: gens, HistAvailable: false})
	if len(rep.BrokenAnchors) != 0 {
		t.Errorf("brokenAnchors = %v, expected empty", rep.BrokenAnchors)
	}
	f := findFile(t, rep, "wiring.txt")
	if f.Class != stats.ClassAuto {
		t.Errorf("class = %q, expected auto (anchor intact)", f.Class)
	}
}

// conflict-prone vs auto: churn file -> conflict-prone, outside churn -> auto.
func TestAnalyze_ConflictProneVsAuto(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{"churned.txt": "a\nb", "stable.txt": "a\nb"}
	writeTree(t, work, map[string]string{"churned.txt": "a\nX", "stable.txt": "a\nX"})

	rep := analyze(t, stats.AnalyzeInput{
		RefFiles:      refFiles(ref),
		WorkDir:       work,
		Churn:         map[string]struct{}{"churned.txt": {}},
		HistAvailable: true,
	})

	if c := findFile(t, rep, "churned.txt").Class; c != stats.ClassConflictProne {
		t.Errorf("churned.txt class = %q, expected conflict-prone", c)
	}
	if c := findFile(t, rep, "stable.txt").Class; c != stats.ClassAuto {
		t.Errorf("stable.txt class = %q, expected auto", c)
	}
}

// copyWithoutRender artifact: an edit -> manual-only.
func TestAnalyze_CopyWithoutRenderManualOnly(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{"dashboards/app.json": "{\"a\":1}"}
	writeTree(t, work, map[string]string{"dashboards/app.json": "{\"a\":2}"})

	rep := analyze(t, stats.AnalyzeInput{
		RefFiles:      refFiles(ref),
		WorkDir:       work,
		CopyGlobs:     []string{"**/dashboards/*.json"},
		HistAvailable: true,
	})
	if c := findFile(t, rep, "dashboards/app.json").Class; c != stats.ClassManualOnly {
		t.Errorf("class = %q, expected manual-only (copyWithoutRender)", c)
	}
}

// Modified binary file: modified-binary without a line metric.
func TestAnalyze_ModifiedBinary(t *testing.T) {
	work := t.TempDir()
	ref := map[string][]byte{"bin.dat": {0x00, 0x01, 0x02}}
	writeTree(t, work, nil)
	if err := os.WriteFile(filepath.Join(work, "bin.dat"), []byte{0x00, 0x01, 0xFF}, 0o644); err != nil {
		t.Fatal(err)
	}

	rep := analyze(t, stats.AnalyzeInput{RefFiles: ref, WorkDir: work, HistAvailable: false})
	f := findFile(t, rep, "bin.dat")
	if f.Status != stats.StatusModifiedBinary {
		t.Errorf("status = %q, expected modified-binary", f.Status)
	}
	if f.AddedLines != 0 || f.RemovedLines != 0 || f.Percent != 0 {
		t.Errorf("a binary file must not have line metrics: %+v", f)
	}
	// modified-binary auto: base 100 * 0.5 = 50.
	if rep.Score != 50 {
		t.Errorf("score = %d, expected 50", rep.Score)
	}
}

// Monotonicity: more edits -> higher score.
func TestAnalyze_ScoreMonotonic(t *testing.T) {
	ref := map[string]string{"m.txt": "a\nb\nc\nd"}

	work1 := t.TempDir()
	writeTree(t, work1, map[string]string{"m.txt": "a\nb\nc\nX"}) // 1 line
	rep1 := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work1})

	work2 := t.TempDir()
	writeTree(t, work2, map[string]string{"m.txt": "a\nb\nY\nX"}) // 2 lines
	rep2 := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work2})

	if rep2.Score <= rep1.Score {
		t.Errorf("monotonicity violated: score1=%d, score2=%d (expected score2 > score1)", rep1.Score, rep2.Score)
	}
}

// --json golden: stable schema.
func TestAnalyze_JSONGolden(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{
		"keep.txt": "same\n",
		"mod.txt":  "a\nb\nc\nd",
		"gone.txt": "bye\n",
	}
	writeTree(t, work, map[string]string{
		"keep.txt":      "same\n",
		"mod.txt":       "a\nb\nc\nX",
		"extra/new.txt": "z\n",
	})

	rep := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work, HistAvailable: false})

	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	want := `{
  "score": 42,
  "files": [
    {
      "path": "gone.txt",
      "status": "deleted",
      "class": "manual-only",
      "addedLines": 0,
      "removedLines": 0,
      "percent": 0
    },
    {
      "path": "keep.txt",
      "status": "identical",
      "class": "",
      "addedLines": 0,
      "removedLines": 0,
      "percent": 0
    },
    {
      "path": "mod.txt",
      "status": "modified",
      "class": "auto",
      "addedLines": 1,
      "removedLines": 1,
      "percent": 50
    }
  ],
  "extras": [
    "extra/new.txt"
  ],
  "brokenAnchors": []
}
`
	if buf.String() != want {
		t.Errorf("JSON golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", buf.String(), want)
	}
}

// Text Render on a drifting report: top-N table with all sections.
func TestReport_RenderText(t *testing.T) {
	work := t.TempDir()
	ref := map[string]string{
		"keep.txt": "same\n",
		"mod.txt":  "a\nb\nc\nd",
		"gone.txt": "bye\n",
	}
	writeTree(t, work, map[string]string{
		"keep.txt":      "same\n",
		"mod.txt":       "a\nb\nc\nX",
		"extra/new.txt": "z\n",
	})
	rep := analyze(t, stats.AnalyzeInput{RefFiles: refFiles(ref), WorkDir: work, HistAvailable: true})
	rep.OldVersion = "v0.3.0"

	var buf bytes.Buffer
	rep.Render(&buf, ui.NewPalette(false))
	got := buf.String()

	for _, want := range []string{"drift-score", "top-", "mod.txt", "gone.txt", "extra files (outside template): 1"} {
		if !strings.Contains(got, want) {
			t.Errorf("text report does not contain %q:\n%s", want, got)
		}
	}
}
