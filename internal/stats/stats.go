// Package stats reports drift of a generated project from its template
// (`tplaiter stats`): a clean render of the pinned version and answers
// (the reference from internal/renderref, shared with update) against the work
// tree. Each file gets a status (identical/modified/deleted/extra), a changed
// line percentage (LCS), and an updateability class (auto/conflict-prone/
// manual-only). The result is drift-score 0..100, top drift files, and broken anchors.
// `--json` provides a stable machine-readable schema for dashboards.
//
// The package does not import internal/update: it renders the reference directly
// through renderref (cache checkout plus render), and the historical heuristic
// renders the last N tags and compares results. This avoids coupling to update
// and repeats the same render orchestration.
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

// historicalTags is the number of latest stable template tags used by the
// conflict-prone heuristic ("diff of the last N template versions").
const historicalTags = 3

// Options contains [Run] parameters.
type Options struct {
	// StartDir is the work directory for project lookup (usually os.Getwd).
	StartDir string
	// JSON prints a machine-readable report instead of a human-readable one.
	JSON bool
}

// Deps contains [Run]'s external dependencies, injected by cobra and tests.
type Deps struct {
	// Manager resolves and checks out template versions (repository cache).
	Manager *repo.Manager
	// Home is the tplaiter home directory (reserved for registry checks; retained
	// for symmetry with update.Deps).
	Home string
	// Out and Err are the main output and warning streams.
	Out io.Writer
	Err io.Writer
	// Palette is the message palette.
	Palette ui.Palette
}

// Run executes `tplaiter stats`: finds the project from StartDir, collects a drift
// report, and prints it as text or JSON. It only reads and produces no special exit errors.
func Run(ctx context.Context, d Deps, opts Options) error {
	rep, err := Collect(ctx, d, opts.StartDir)
	if err != nil {
		return err
	}
	if opts.JSON {
		return rep.WriteJSON(d.Out)
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(d.Err, d.Palette.Warn("warning: ")+w)
	}
	rep.Render(d.Out, d.Palette)
	return nil
}

// Collect finds the project from startDir, renders the pinned reference version,
// gathers the historical heuristic, and analyzes work-tree drift.
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
		return nil, fmt.Errorf("stats: version %s: %w", proj.Template.Version, err)
	}

	rendered, err := renderVersion(ctx, d.Manager, ref, in)
	if err != nil {
		return nil, fmt.Errorf("stats: render reference: %w", err)
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
			"historical heuristic unavailable (<2 stable tags) — all edits classified as auto")
	}
	return rep, nil
}

// renderVersion checks out the template version resolved by res and renders it
// in memory with project coordinates/values from in. Checkout is cleaned up
// before return. Duplicates update.RenderVersion (update is intentionally not imported).
func renderVersion(ctx context.Context, mgr *repo.Manager, res repo.Resolved, in renderref.Input) (*renderref.Result, error) {
	src, cleanup, err := mgr.Checkout(ctx, res.RepoAlias, res.GitRef, res.Entry.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	return renderref.Render(ctx, src, in)
}

// historicalChurn collects reference paths changed by the template among the
// latest N stable tags (the conflict-prone heuristic). It renders each tag with
// the same values and marks paths whose content differs between any renders,
// including file appearance/disappearance. It returns the set and whether the
// heuristic is available (>=2 successful renders). Best effort: failed tags are skipped.
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
		res, rerr := renderref.Render(ctx, src, in)
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

// pathVaries reports whether path p's content differs between renders, including
// absence from some renders.
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
