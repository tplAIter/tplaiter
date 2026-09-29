// Package settingscmd orchestrates `tplater settings`: viewing current project
// settings (list), changing them through --set (set), and interactively re-asking
// one group (edit).
//
// set/edit use the same 3-way mechanics as `tplater update`, but on ONE template
// version: base is a clean render of OLD project values, target a render of NEW
// values. Changing a select removes the old file vertical (hash==baseline →
// deletion; locally changed files warn) and adds the new one. Computation is
// reused from internal/update ([update.ComputeThreeWay], [update.LoadBaselineHashes]);
// this package builds base/target renders, reports, and persists new project state.
//
// Unlike update, changing settings does not touch the template version, write a
// manifest snapshot, or run hooks (postUpdate or postCreate): it changes the same
// render's parameters rather than updating the template. The user receives only
// a change report (and a warning to regenerate ai-config if its composition may change).
package settingscmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
	"github.com/tplAIter/tplaiter/internal/update"
)

// Options — parameters for one settings command invocation.
type Options struct {
	// StartDir — working directory for finding the project (usually os.Getwd).
	StartDir string
	// Pairs — `group=value` values for set (repeatable --set-style flag).
	Pairs []string
	// Group — target group for edit (empty prints a group hint list).
	Group string
	// DryRun — compute plan/report without changing anything (--dry-run).
	DryRun bool
	// Yes — do not ask for confirmation before applying (--yes).
	Yes bool
	// Verbose — print unified diffs of local deviations.
	Verbose bool
}

// Deps — external settings-command dependencies injected by cobra and tests.
type Deps struct {
	// Manager — template-version resolution/checkout (repository cache).
	Manager *repo.Manager
	// Home — tplater home directory (project registry, lock).
	Home string
	// Out, Err — main output and warning streams.
	Out io.Writer
	Err io.Writer
	// Palette — message palette.
	Palette ui.Palette
	// Now — registry timestamp source (overridden in tests).
	Now func() time.Time
	// Prompter — interactive questionnaire for edit and set confirmation. It is
	// not called for set in non-interactive mode.
	Prompter survey.Prompter
	// Interactive — whether TTY is available (controls edit asking and set confirmation).
	Interactive bool
}

// List prints current project settings as GROUP/VALUE/ACTIVE; inactive nested
// groups (parent option not selected) are muted.
func List(d Deps, opts Options) error {
	root, proj, err := project.FindRoot(opts.StartDir)
	if err != nil {
		return err
	}
	tpl, _, err := project.LoadManifestForProject(root, proj, d.Home)
	if err != nil {
		return err
	}
	resolved, err := settings.Resolve(tpl, renderref.Values(proj.Settings))
	if err != nil {
		return fmt.Errorf("settings list: %w", err)
	}
	printResolveReport(d, resolved.Report)
	printSettingsTable(d.Out, d.Palette, tpl, resolved.Values)
	return nil
}

// Set applies new project settings with update's 3-way mechanics: parses
// `group=value`, resolves requires, renders old/new state on the current template
// version, and merges the tree.
func Set(ctx context.Context, d Deps, opts Options) error {
	if len(opts.Pairs) == 0 {
		return errors.New("settings set: provide at least one group=value")
	}
	ch, cleanup, err := openChange(ctx, d, opts.StartDir)
	if err != nil {
		return err
	}
	defer cleanup()

	// explicit — current values meaningfully set (different from defaults) plus
	// new pairs. Default-equal values are NOT explicit: otherwise a new option's
	// requires (e.g. oauth ⇒ database=postgres) would conflict with default
	// database=none instead of being implied (requirements imply defaults but do
	// not overwrite an explicit user choice).
	defaults := settings.DefaultValues(ch.tpl)
	explicit := nonDefaultExplicit(ch.oldValues, defaults, nil)
	for _, pair := range opts.Pairs {
		group, value, perr := settings.ParseSet(ch.tpl, pair)
		if perr != nil {
			return fmt.Errorf("settings set: %w", perr)
		}
		explicit[group] = value
	}

	resolved, rerr := settings.Resolve(ch.tpl, explicit)
	if rerr != nil {
		return fmt.Errorf("settings set: %w", rerr)
	}
	ch.resolved = resolved

	return applyChange(ctx, d, ch, opts, d.Interactive && !opts.Yes)
}

// Edit re-asks one settings group: without an argument it prints a group hint
// list; with a group it runs [survey.AskFlow] over that group's tree (preset is
// the other current values) and applies the result through the same set path.
func Edit(ctx context.Context, d Deps, opts Options) error {
	ch, cleanup, err := openChange(ctx, d, opts.StartDir)
	if err != nil {
		return err
	}
	defer cleanup()

	if opts.Group == "" {
		resolved, rerr := settings.Resolve(ch.tpl, ch.oldValues)
		if rerr != nil {
			return fmt.Errorf("settings edit: %w", rerr)
		}
		printSettingsTable(d.Out, d.Palette, ch.tpl, resolved.Values)
		fmt.Fprintln(d.Out, d.Palette.Muted("specify group to re-ask: tplater settings edit <group>"))
		return nil
	}

	if !groupExists(ch.tpl, opts.Group) {
		return fmt.Errorf("settings edit: unknown group %q", opts.Group)
	}

	// preset — all current values EXCEPT the re-asked group and nested refinements;
	// AskFlow asks those again dynamically based on the new parent choice.
	drop := groupWithDescendants(ch.tpl, opts.Group)
	preset := settings.Values{}
	for k, v := range ch.oldValues {
		if !drop[k] {
			preset[k] = v
		}
	}

	resolved, err := survey.AskFlow(
		ch.tpl, preset,
		survey.FlowOptions{Interactive: d.Interactive},
		d.Prompter, d.Out, d.Palette,
	)
	if err != nil {
		return err
	}
	ch.resolved = resolved

	// AskFlow already showed the summary and requested confirmation; do not ask again.
	return applyChange(ctx, d, ch, opts, false)
}

// change — shared set/edit context: discovered project, manifest and checkout of
// its version, old values, and new values after resolution.
type change struct {
	root      string
	proj      *manifest.Project
	tpl       *manifest.Template
	src       fs.FS
	oldValues settings.Values
	resolved  settings.Resolved
}

// openChange finds the project from startDir, resolves/checks out its CURRENT
// template version (settings operate on one version), and loads the manifest.
// Returns context and checkout cleanup, held until resources are copied.
func openChange(ctx context.Context, d Deps, startDir string) (*change, func(), error) {
	root, proj, err := project.FindRoot(startDir)
	if err != nil {
		return nil, nil, err
	}

	coord := proj.Template.Repo + "/" + proj.Template.Name
	ref, err := d.Manager.ResolveRef(coord + "@" + proj.Template.Version)
	if err != nil {
		return nil, nil, fmt.Errorf("settings: template version %s not available in repository cache: %w", proj.Template.Version, err)
	}
	src, cleanup, err := d.Manager.Checkout(ctx, ref.RepoAlias, ref.GitRef, ref.Entry.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("settings: template version checkout: %w", err)
	}
	tpl, err := renderref.LoadTemplate(src)
	if err != nil {
		_ = cleanup()
		return nil, nil, err
	}

	return &change{
		root:      root,
		proj:      proj,
		tpl:       tpl,
		src:       src,
		oldValues: renderref.Values(proj.Settings),
	}, func() { _ = cleanup() }, nil
}

// applyChange is the shared set/edit tail: renders base (old values) and target
// (new), computes a 3-way plan/report (reusing [update.ComputeThreeWay]), prints
// it, and when not --dry-run and confirmed materializes the plan, writes new
// project.yaml values, recalculates the baseline, recopies resources, and refreshes
// the registry. Conflicts → exit code 2 ([update.ExitCodeError]).
func applyChange(ctx context.Context, d Deps, ch *change, opts Options, confirm bool) error {
	base := renderref.Input{
		Values:  ch.oldValues,
		Project: ch.proj.Project,
		Runtime: ch.proj.Runtime,
		Repo:    ch.proj.Template.Repo,
	}
	baseRendered, err := renderref.Render(ctx, ch.src, base)
	if err != nil {
		return fmt.Errorf("settings: rendering current values: %w", err)
	}

	target := base
	target.Values = ch.resolved.Values
	tgtRendered, err := renderref.Render(ctx, ch.src, target)
	if err != nil {
		return fmt.Errorf("settings: rendering new values: %w", err)
	}

	baseline, err := update.LoadBaselineHashes(ch.root)
	if err != nil {
		return err
	}
	tw, err := update.ComputeThreeWay(baseRendered.Files, tgtRendered.Files, baseline, ch.root)
	if err != nil {
		return err
	}

	printResolveReport(d, ch.resolved.Report)
	changed := changedGroups(ch.tpl, ch.oldValues, ch.resolved.Values)

	if !tw.Plan.HasChanges() && len(changed) == 0 {
		fmt.Fprintln(d.Out, "no settings changes — already as set")
		return nil
	}

	fmt.Fprintln(d.Out, "changing project settings:")
	fmt.Fprintln(d.Out)
	tw.Report.Render(d.Out, d.Palette, opts.Verbose)
	printChangedGroups(d.Out, d.Palette, changed)

	conflicts := tw.Plan.Conflicts()

	if opts.DryRun {
		fmt.Fprintln(d.Out, d.Palette.Muted("(--dry-run — changes not written)"))
		return exitForConflicts(conflicts)
	}

	if confirm && d.Prompter != nil {
		ok, cerr := d.Prompter.Confirm("Apply settings changes?")
		if cerr != nil {
			return cerr
		}
		if !ok {
			fmt.Fprintln(d.Out, "cancelled — changes not written")
			return nil
		}
	}

	if applyErr := commit(d, ch, tw.Plan, tgtRendered); applyErr != nil {
		return applyErr
	}

	if ch.tpl.AIConfig.Path != "" {
		fmt.Fprintln(d.Err, d.Palette.Warn("warning: ")+
			"ai-config composition may have changed with settings — regenerate: tplater ai gen")
	}
	fmt.Fprintln(d.Out, d.Palette.Success("settings applied"))
	if len(conflicts) > 0 {
		fmt.Fprintln(d.Out, d.Palette.Warn("some files contain conflict markers — resolve them and commit"))
	}
	return exitForConflicts(conflicts)
}

// commit materializes the settings-change plan and records new project state:
// writes files, updates project.yaml.settings (complete new values), stores a
// clean target baseline, recopies .tplaiter/ resources, and refreshes registry
// baselineSHA. The template version is unchanged; manifest snapshot and hooks are untouched.
func commit(d Deps, ch *change, plan *update.Plan, tgtRendered *renderref.Result) error {
	if _, err := plan.Apply(ch.root); err != nil {
		return err
	}
	ch.proj.Settings = map[string]any(ch.resolved.Values)
	if err := saveMarker(ch.root, ch.proj); err != nil {
		return err
	}
	if err := tgtRendered.Baseline.Save(ch.root); err != nil {
		return err
	}
	if err := resources.Copy(ch.src, ch.root, ch.tpl); err != nil {
		return err
	}
	return refreshRegistry(d, ch.root, ch.proj)
}
