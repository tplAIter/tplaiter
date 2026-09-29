package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/envsetup"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// Options contains parameters for one [Run].
type Options struct {
	// StartDir is the project lookup directory (usually os.Getwd) for single-project mode; ignored with All.
	StartDir string
	// To is the explicit target template version (`--to`); empty means highest stable tag.
	To string
	// DryRun computes the plan and report without changing anything (`--dry-run`).
	DryRun bool
	// Check only scans the work tree for conflict markers
	// (`--check`); exits 1 when a marker is found.
	Check bool
	// All updates all registry projects with status ok (`--all`).
	All bool
	// Verbose prints unified diffs for local deviations.
	Verbose bool
}

// Deps contains [Run]'s external dependencies, injected by cobra and tests.
type Deps struct {
	// Manager resolves and checks out template versions (repository cache).
	Manager *repo.Manager
	// Runner runs postUpdate hooks (shell/ansible).
	Runner execx.Runner
	// Home is the tplater home directory (project registry and lock).
	Home string
	// Out and Err are the main output and warning streams.
	Out io.Writer
	Err io.Writer
	// Palette is the message palette.
	Palette ui.Palette
	// Now supplies registration time (overridden in tests).
	Now func() time.Time
}

// Result is the result of updating one project.
type Result struct {
	ID         string
	Path       string
	OldVersion string
	NewVersion string
	// Report is the five-category report (nil in --check mode).
	Report *Report
	// Conflicts are files with markers: from the plan (normal mode) or ScanConflicts
	// (--check).
	Conflicts []string
	// NoOp means the plan changes nothing (same version and values).
	NoOp bool
	// Applied means the plan was applied (not DryRun/Check).
	Applied bool
	// DryRun means the plan was computed but not applied.
	DryRun bool
}

// ExitCodeError carries a nonstandard exit code: 1 when --check finds markers or
// 2 when update leaves conflicts. The cobra layer converts it to a process exit
// code; this package does not depend on cobra.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("update: exit %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitCodeError) Unwrap() error { return e.Err }

// Run exposes only the bounded local conflict inspection in T5. Live update
// remains unavailable until the downstream lifecycle owner is installed.
func Run(ctx context.Context, d Deps, opts Options) error {
	// --all has no bounded local-only interpretation. Refuse it before loading
	// the registry or inspecting any project.
	if opts.All {
		return ErrLifecycleUnavailable
	}
	// --check is the sole legacy read-only exception: it scans precisely the
	// supplied tree and never resolves, checks out, initialises, or publishes.
	if opts.Check {
		return inspectAllowed(d, opts)
	}
	// Ordinary and --dry-run legacy routes have no T5 lifecycle owner. This is
	// deliberately before FindRoot, manager use, source reads, or HOME access.
	return ErrLifecycleUnavailable
}

func inspectAllowed(d Deps, opts Options) error {
	found, err := ScanConflicts(opts.StartDir, nil)
	if err != nil {
		return err
	}
	res := &Result{Path: opts.StartDir, Conflicts: found}
	printSingle(d, opts, res)
	return exitFor(res, opts)
}

// runCurrent updates the project found by walking upward from StartDir.
func runCurrent(ctx context.Context, d Deps, opts Options) error {
	return ErrLifecycleUnavailable
}

// updateOne is the core update for one project (without printing). root is the
// project root and proj its parsed marker.
func updateOne(ctx context.Context, d Deps, opts Options, root string, proj *manifest.Project) (*Result, error) {
	return nil, ErrLifecycleUnavailable
}

// applyUpdate materializes the plan and commits the new version: writes files,
// updates the marker, saves the new manifest snapshot and clean target baseline,
// recopies .tplaiter resources, runs postUpdate hooks, and updates registry baselineSHA.
func applyUpdate(
	ctx context.Context, d Deps, root string, proj *manifest.Project,
	plan *Plan, tgt *renderref.Result, tgtSrc fs.FS, targetRef repo.Resolved,
) error {
	return ErrLifecycleUnavailable
}

// applyLegacyUpdate preserves the former live sequence for the downstream
// lifecycle owner. T5 never calls it and cannot use it as an apply bypass.
func applyLegacyUpdate(
	ctx context.Context, d Deps, root string, proj *manifest.Project,
	plan *Plan, tgt *renderref.Result, tgtSrc fs.FS, targetRef repo.Resolved,
) error {
	if _, err := plan.applyLegacy(root); err != nil {
		return err
	}
	if err := writeUpdatedMarker(root, proj, targetRef.Version); err != nil {
		return err
	}
	if err := manifest.SaveSnapshot(filepath.Join(root, manifest.SnapshotRelPath), tgt.Template); err != nil {
		return fmt.Errorf("update: сохранение снимка манифеста: %w", err)
	}
	// baseline is the clean target render (NOT merged files containing markers).
	if err := tgt.Baseline.Save(root); err != nil {
		return err
	}
	if err := resources.Copy(tgtSrc, root, tgt.Template); err != nil {
		return err
	}
	if err := runPostUpdateHooks(ctx, d, root, tgt.Template, tgt.Resolved, proj.Project); err != nil {
		return err
	}
	return updateRegistry(d, root, proj, targetRef)
}

// ThreeWay is the plan and report for one 3-way operation: shared by `tplater update`
// (two template versions) and `tplater settings set/edit` (one version, old vs new values).
// Extracted from [updateOne] additively without changing update behavior.
type ThreeWay struct {
	// Plan is the set of file decisions (see [Plan]).
	Plan *Plan
	// Report is the five-category report (see [Report]).
	Report *Report
}

// ComputeThreeWay builds a 3-way plan and report from clean base and target
// renders plus baseline hashes for workDir. It is the [Compute]+buildReport
// sequence used by [updateOne], extracted so
// `tplater settings set` (the implementation) reuses the mechanism without duplication:
// settings can use base = old-values render and target = new-values render at one
// template version (update uses two different versions).
func ComputeThreeWay(baseFiles, targetFiles map[string][]byte, baseline map[string]string, workDir string) (*ThreeWay, error) {
	plan, err := Compute(baseFiles, targetFiles, baseline, workDir)
	if err != nil {
		return nil, err
	}
	return &ThreeWay{Plan: plan, Report: buildReport(plan, baseFiles, workDir)}, nil
}

// LoadBaselineHashes reads file sha256 values from .tplaiter/baseline.json
// projectDir (a missing file is an empty map, not an error). Exported for the
// settings command, which needs the same baseline to detect user edits.
func LoadBaselineHashes(projectDir string) (map[string]string, error) {
	return loadBaselineHashes(projectDir)
}

// RenderVersion checks out the template version in res and renders it in memory
// with project coordinates/values from in. Checkout is cleaned up before return;
// callers need only bytes (for the 3-way base; target is rendered separately
// because its checkout is also needed for copying resources).
func RenderVersion(ctx context.Context, mgr *repo.Manager, res repo.Resolved, in renderref.Input) (*renderref.Result, error) {
	src, cleanup, err := mgr.Checkout(ctx, res.RepoAlias, res.GitRef, res.Entry.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	return renderref.Render(ctx, src, in)
}

// writeUpdatedMarker raises template.version in .tplaiter/project.yaml to
// newVersion while preserving the rest of the snapshot (settings/runtime/id).
func writeUpdatedMarker(root string, proj *manifest.Project, newVersion string) error {
	proj.Template.Version = newVersion
	data, err := yaml.Marshal(proj)
	if err != nil {
		return fmt.Errorf("update: сериализация project.yaml: %w", err)
	}
	path := filepath.Join(root, project.MarkerRelPath)
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: marker is not secret.
		return fmt.Errorf("update: запись project.yaml: %w", err)
	}
	return nil
}

// updateRegistry updates baselineSHA/path/lastSeenAt in the project registry;
// Upsert preserves Template/CreatedAt of an existing entry.
func updateRegistry(d Deps, root string, proj *manifest.Project, targetRef repo.Resolved) error {
	baselineSHA, err := hashFile(filepath.Join(root, engine.BaselineRelPath))
	if err != nil {
		return fmt.Errorf("update: хеш baseline: %w", err)
	}
	now := nowFn(d)()
	ref := state.ProjectRef{
		ID:   proj.ID,
		Path: root,
		Template: state.TemplateSelection{
			Repo:    proj.Template.Repo,
			Name:    proj.Template.Name,
			Version: targetRef.Version,
		},
		CreatedAt:   now,
		LastSeenAt:  now,
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

// loadBaselineHashes reads sha256 values from the project's .tplaiter/baseline.json.
// A missing file is not an error (empty map; edit detection uses base).
func loadBaselineHashes(projectDir string) (map[string]string, error) {
	path := filepath.Join(projectDir, filepath.FromSlash(engine.BaselineRelPath))
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update: чтение baseline: %w", err)
	}
	var b engine.Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("update: разбор baseline: %w", err)
	}
	if b.Files == nil {
		return map[string]string{}, nil
	}
	return b.Files, nil
}

// hashFile returns hex(sha256) of file content.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

// runPostUpdateHooks executes hooks.postUpdate in order: run through $SHELL -c
// at the project root, ansible through envsetup.RunPlaybook. Required-hook
// failure aborts; optional failure becomes a warning.
func runPostUpdateHooks(
	ctx context.Context, d Deps, root string, tpl *manifest.Template,
	res settings.Resolved, projInfo manifest.ProjectInfo,
) error {
	for i := range tpl.Hooks.PostUpdate {
		h := tpl.Hooks.PostUpdate[i]
		var err error
		switch {
		case h.Run != "":
			err = runShellHook(ctx, d, root, h.Run)
		case h.Ansible != "":
			err = runAnsibleHook(ctx, d, root, h, res, projInfo)
		default:
			continue
		}
		if err == nil {
			continue
		}
		if h.Optional {
			warnf(d, "postUpdate-хук пропущен (optional): %v", err)
			continue
		}
		return fmt.Errorf("update: postUpdate-хук: %w", err)
	}
	return nil
}

func runShellHook(ctx context.Context, d Deps, root, script string) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	infof(d, "postUpdate: %s\n", script)
	_, err := d.Runner.Run(ctx, shell, []string{"-c", script}, execx.Options{
		Dir:    root,
		Stdout: d.Out,
		Stderr: d.Err,
	})
	return err
}

func runAnsibleHook(
	ctx context.Context, d Deps, root string, h manifest.Hook,
	res settings.Resolved, projInfo manifest.ProjectInfo,
) error {
	runner := envsetup.NewRunner(d.Runner, d.Out, d.Palette)
	return runner.RunPlaybook(ctx, envsetup.Options{
		TemplateDir: filepath.Join(root, envsetup.EnvironmentRelPath),
		ProjectRoot: root,
		Playbook:    manifest.Playbook{Name: "postUpdate", File: h.Ansible},
		Values:      res.Values,
		Project:     projInfo,
		AutoYes:     true,
	})
}

func nowFn(d Deps) func() time.Time {
	if d.Now != nil {
		return d.Now
	}
	return time.Now
}

func infof(d Deps, format string, a ...any) {
	if d.Out != nil {
		fmt.Fprintf(d.Out, format, a...)
	}
}

func warnf(d Deps, format string, a ...any) {
	if d.Err == nil {
		return
	}
	fmt.Fprint(d.Err, d.Palette.Warn("предупреждение: "))
	fmt.Fprintf(d.Err, format+"\n", a...)
}
