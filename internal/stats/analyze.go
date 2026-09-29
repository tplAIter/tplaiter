package stats

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// File statuses relative to the reference render.
const (
	// StatusIdentical means the work file matches the reference byte-for-byte.
	StatusIdentical = "identical"
	// StatusModified means the work file differs (with a line metric).
	StatusModified = "modified"
	// StatusModifiedBinary means the work file differs but is binary (no line
	// metric: added/removed=0, percent=0).
	StatusModifiedBinary = "modified-binary"
	// StatusDeleted means the file exists in the reference but not in the work tree.
	StatusDeleted = "deleted"
	// StatusExtra means the file exists in the work tree but not in the reference
	// (excluded from drift-score and shown separately).
	StatusExtra = "extra"
)

// File updateability classes.
const (
	// ClassNone is used for identical files (no class applies).
	ClassNone = ""
	// ClassAuto means update can cleanly 3-way merge user edits: the template has
	// not historically changed this file.
	ClassAuto = "auto"
	// ClassConflictProne means edits to a file historically changed by the template
	// (overlap with the last N tag diffs), so update may conflict.
	ClassConflictProne = "conflict-prone"
	// ClassManualOnly means update cannot bring the file to the template itself:
	// deleted reference file, broken CODEGEN anchor, or edit to a copyWithoutRender artifact.
	ClassManualOnly = "manual-only"
)

// FileStat describes one file's drift.
type FileStat struct {
	Path         string  `json:"path"`
	Status       string  `json:"status"`
	Class        string  `json:"class"`
	AddedLines   int     `json:"addedLines"`
	RemovedLines int     `json:"removedLines"`
	Percent      float64 `json:"percent"`
}

// Report is the comparison result (the `--json` schema is stable:
// {score, files, extras, brokenAnchors}; fields outside the schema are marked
// json:"-").
type Report struct {
	// Score is total drift-score 0..100 (weighted average over reference files;
	// extras are excluded).
	Score int `json:"score"`
	// Files are reference files (identical/modified/deleted), sorted by path.
	Files []FileStat `json:"files"`
	// Extras are work-file paths absent from the reference (excluded from score).
	Extras []string `json:"extras"`
	// BrokenAnchors are paths where a reference CODEGEN anchor is absent in work.
	BrokenAnchors []string `json:"brokenAnchors"`
	// Warnings are warnings (for example, unavailable historical heuristic); they
	// are outside the JSON schema.
	Warnings []string `json:"-"`
	// OldVersion is the project template version (for the text report heading).
	OldVersion string `json:"-"`
}

// AnalyzeInput is the pure [Analyze] input: reference render plus historical
// context. It is separate from [Collect] so analysis can be tested without git
// (score monotonicity, classification, and JSON schema).
type AnalyzeInput struct {
	// RefFiles is the reference render: relative slash path -> content.
	RefFiles map[string][]byte
	// WorkDir is the project work-tree root.
	WorkDir string
	// CopyGlobs are the template's engine.copyWithoutRender globs (manual-only files).
	CopyGlobs []string
	// Generators are manifest generators (the source of CODEGEN anchors).
	Generators []manifest.Generator
	// Churn contains reference paths changed by the template across the last N tags
	// (the historical conflict-prone heuristic).
	Churn map[string]struct{}
	// HistAvailable says whether the historical heuristic is available (>=2 tags).
	// When false, all modified files are classified as auto.
	HistAvailable bool
}

// stdExcludes are work-tree directories excluded from traversal: .tplaiter/
// (baseline/snapshot/registry are not reference files) and .git/.
var stdExcludes = map[string]struct{}{
	".tplaiter": {},
	".git":      {},
}

// Analyze compares the reference render with the work tree and builds a drift
// report. Pure function over prepared inputs.
func Analyze(in AnalyzeInput) (*Report, error) {
	copyMatcher := newGlobMatcher(in.CopyGlobs)

	broken, err := brokenAnchors(in.RefFiles, in.WorkDir, in.Generators)
	if err != nil {
		return nil, err
	}

	workExtras, err := walkExtras(in.WorkDir, in.RefFiles)
	if err != nil {
		return nil, err
	}

	files := make([]FileStat, 0, len(in.RefFiles))
	refPaths := sortedRefPaths(in.RefFiles)
	for _, rel := range refPaths {
		refContent := in.RefFiles[rel]
		workContent, exists, rerr := readWork(in.WorkDir, rel)
		if rerr != nil {
			return nil, rerr
		}
		files = append(files, classify(rel, refContent, workContent, exists, classifyCtx{
			copyMatcher:   copyMatcher,
			broken:        broken,
			churn:         in.Churn,
			histAvailable: in.HistAvailable,
		}))
	}

	rep := &Report{
		Files:         files,
		Extras:        workExtras,
		BrokenAnchors: sortedKeys(broken),
	}
	rep.Score = int(math.Round(averageScore(files)))
	return rep, nil
}

// classifyCtx is the classification context for one file.
type classifyCtx struct {
	copyMatcher   *globMatcher
	broken        map[string]struct{}
	churn         map[string]struct{}
	histAvailable bool
}

// classify computes status, class, and metric for one reference file.
func classify(rel string, refContent, workContent []byte, exists bool, ctx classifyCtx) FileStat {
	fsStat := FileStat{Path: rel}

	if !exists {
		fsStat.Status = StatusDeleted
		fsStat.Class = ClassManualOnly
		return fsStat
	}
	if bytes.Equal(refContent, workContent) {
		fsStat.Status = StatusIdentical
		fsStat.Class = ClassNone
		return fsStat
	}

	// The file changed. The metric applies only to text files.
	if isBinary(refContent) || isBinary(workContent) {
		fsStat.Status = StatusModifiedBinary
	} else {
		fsStat.Status = StatusModified
		added, removed, percent := lineMetric(refContent, workContent)
		fsStat.AddedLines = added
		fsStat.RemovedLines = removed
		fsStat.Percent = roundPct(percent)
	}

	fsStat.Class = classifyModified(rel, ctx)
	return fsStat
}

// classifyModified determines the updateability class of a modified file.
func classifyModified(rel string, ctx classifyCtx) string {
	if _, ok := ctx.broken[rel]; ok {
		return ClassManualOnly
	}
	if ctx.copyMatcher.match(rel) {
		return ClassManualOnly
	}
	if !ctx.histAvailable {
		// Historical heuristic unavailable (<2 tags): all edits are auto.
		return ClassAuto
	}
	if _, ok := ctx.churn[rel]; ok {
		return ClassConflictProne
	}
	return ClassAuto
}

// scoreFor is a file's drift-score contribution: identical=0; deleted and
// other manual-only=100; modified auto=%*0.5, conflict-prone=%*1.0. For a
// modified binary, % cannot be measured, so 100 is used as the fully drifting base.
func scoreFor(f FileStat) float64 {
	switch f.Status {
	case StatusIdentical, StatusExtra:
		return 0
	case StatusDeleted:
		return 100
	}
	if f.Class == ClassManualOnly {
		return 100
	}
	base := f.Percent
	if f.Status == StatusModifiedBinary {
		base = 100
	}
	if f.Class == ClassConflictProne {
		return base * 1.0
	}
	return base * 0.5
}

// averageScore is the mean scoreFor over reference files (Analyze excludes
// extras, so they do not reach this function). Empty list -> 0.
func averageScore(files []FileStat) float64 {
	if len(files) == 0 {
		return 0
	}
	var sum float64
	for _, f := range files {
		sum += scoreFor(f)
	}
	return sum / float64(len(files))
}

// brokenAnchors collects paths where a reference CODEGEN anchor (Generator.
// Anchors[].Anchor in Anchors[].File) is absent from the work file. It considers
// only anchors actually present in the reference (the file was generated and
// contains the anchor); otherwise that configuration does not expect the anchor.
func brokenAnchors(refFiles map[string][]byte, workDir string, gens []manifest.Generator) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	for i := range gens {
		for _, a := range gens[i].Anchors {
			if a.File == "" || a.Anchor == "" {
				continue
			}
			refContent, ok := refFiles[a.File]
			if !ok || !bytes.Contains(refContent, []byte(a.Anchor)) {
				continue // The anchor is not expected for this configuration.
			}
			workContent, exists, err := readWork(workDir, a.File)
			if err != nil {
				return nil, err
			}
			if !exists || !bytes.Contains(workContent, []byte(a.Anchor)) {
				out[a.File] = struct{}{}
			}
		}
	}
	return out, nil
}

// walkExtras traverses the work tree (excluding .tplaiter/ and .git/) and
// returns sorted slash paths absent from the reference.
func walkExtras(workDir string, refFiles map[string][]byte) ([]string, error) {
	var extras []string
	root := filepath.Clean(workDir)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, skip := stdExcludes[d.Name()]; skip && path != root {
				return fs.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		if _, ok := refFiles[slash]; !ok {
			extras = append(extras, slash)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("stats: walk work tree: %w", err)
	}
	sort.Strings(extras)
	return extras, nil
}

// readWork reads a work-tree file by slash path rel.
func readWork(workDir, rel string) ([]byte, bool, error) {
	full := filepath.Join(workDir, filepath.FromSlash(rel))
	data, err := os.ReadFile(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("stats: read %s: %w", rel, err)
	}
	return data, true, nil
}

// isBinary heuristically detects a binary file by a NUL byte in the first 8000
// bytes (the same heuristic as git). An empty file is not binary.
func isBinary(data []byte) bool {
	n := len(data)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

// roundPct rounds a percentage to 2 places for stable JSON.
func roundPct(p float64) float64 {
	return math.Round(p*100) / 100
}

func sortedRefPaths(refFiles map[string][]byte) []string {
	out := make([]string, 0, len(refFiles))
	for k := range refFiles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
