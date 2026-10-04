// Package newcmd orchestrates the `tplaiter new` command:
// template resolution and checkout, the version gate and environment-tool
// checks, settings prompts, atomic project rendering, resource copying into
// .tplaiter/, the manifest snapshot and project marker, post-creation
// (hooks/AI/env setup), project-registry registration, and NOTES output.
//
// The package is named newcmd rather than new: new is reserved in many
// contexts and is easy to confuse with the keyword. Orchestration lives
// outside internal/cmd so it can be tested without cobra by injecting
// [survey.Prompter] and [execx.Runner]; the thin wrapper lives in
// internal/cmd/new.go.
package newcmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/aiconfig"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/envsetup"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// templateManifestFileName is the template manifest name at the checkout root
// (the same private constant as in internal/repo/scan.go and internal/cmd/template.go).
const templateManifestFileName = "template.manifest.yaml"

// partialsDirName is the directory of associated {{ define }} templates inside
// the template checkout (see the single-basic/partials fixture).
const partialsDirName = "partials"

// defaultPort is the default value for .Runtime.Port when --port is omitted.
const defaultPort = 8080

// Options contains parameters for one [Run], parsed from `tplaiter new` flags.
// The cobra layer (internal/cmd/new.go) fills them and adds runtime context
// (Interactive, CLIVersion).
type Options struct {
	// DryRun prepares a verified result without publishing project or registry state.
	DryRun bool
	// Ref is a template reference: `<repo>/<name>[@version]`.
	Ref string
	// ProjectName is the human-readable project name and slug source.
	ProjectName string
	// Dir is the target directory (empty means ./<slug>).
	Dir string
	// Module is the project's Go module (empty means git.example.test/<slug>).
	Module string
	// System and Domain are optional project coordinates (.Project.System/Domain).
	System string
	Domain string
	// Sets contains --set values (a repeatable flag) in group=value format.
	Sets []string
	// AnswersFile is the path passed to --answers (YAML).
	AnswersFile string
	// Defaults means --defaults: skip prompts and use defaults (+ preset).
	Defaults bool
	// NoHooks means --no-hooks: skip hooks.postCreate.
	NoHooks bool
	// NoDepsCheck means --no-deps-check: skip environment-tool checks.
	NoDepsCheck bool
	// EnvSetup controls the post-creation env setup prompt: nil asks
	// interactively, &true runs it (--env-setup), and &false skips it
	// (--no-env-setup).
	EnvSetup *bool
	// Yes means --yes: automatically confirm tool installation and env setup.
	Yes bool
	// Port is --port: .Runtime.Port (0 means defaultPort).
	Port int
	// Interactive reports whether stdin has a TTY (detected by the caller).
	// When false, prompting is forbidden (CI) and unset settings use defaults.
	Interactive bool
	// CLIVersion is the tplaiter version (resolveVersion in cmd) used for the
	// requires.tplaiter version gate.
	CLIVersion string
}

// Deps contains [Run]'s external dependencies, injected by the caller for
// testability (production implementations are in internal/cmd/new.go and
// test doubles are in package tests).
type Deps struct {
	// Runtime is the authenticated installed runtime; legacy dependencies cannot replace it.
	Runtime *trustload.Runtime
	// SourceInput contains bounded, untrusted pinned selection and evidence locators.
	SourceInput []byte
	// Manager resolves and checks out templates (repo).
	Manager *repo.Manager
	// Runner starts external processes (deps-check, hooks, ansible/env setup).
	Runner execx.Runner
	// Home is the tplaiter home directory (state.Home) for the project registry
	// and location lookup.
	Home string
	// Prompter performs the interactive settings survey (survey). It is not
	// called in non-interactive mode, but must be non-nil when Interactive.
	Prompter survey.Prompter
	// Confirm performs interactive confirmation (env setup). nil means “no”, so
	// the offer is skipped unless --env-setup or --yes is set.
	Confirm func(prompt string) (bool, error)
	// Out and Err are the main output and warning/error streams.
	Out io.Writer
	Err io.Writer
	// Palette is the message palette.
	Palette ui.Palette
	// Now supplies registration time (overridden in tests).
	Now func() time.Time
}

// Run verifies and renders a signed native, action-free template, then publishes
// project ledgers and registry state through a recoverable new transaction.
// An authenticated runtime is mandatory; legacy managers and runners never
// authorize creation. Publication failures retain the recovery journal.
func Run(ctx context.Context, opts Options, d Deps) (err error) {
	if d.Runtime == nil {
		return ErrLifecycleUnavailable
	}
	return runLive(ctx, opts, d, nil)
}

// run holds the working state for one [Run] call.
type run struct {
	opts Options
	d    Deps
	now  func() time.Time
}

func (r *run) execute(ctx context.Context) error {
	// --- phase 1: preparation (nothing is created) ---
	slug, err := Slugify(r.opts.ProjectName)
	if err != nil {
		return err
	}
	target := r.opts.Dir
	if target == "" {
		target = "./" + slug
	}
	// Check directory occupancy before prompting so a repeated `new` fails
	// immediately without consuming user input or touching the existing directory.
	if err := ensureVacant(target); err != nil {
		return err
	}

	resolved, err := r.d.Manager.ResolveRef(r.opts.Ref)
	if err != nil {
		return err
	}

	src, cleanup, err := r.d.Manager.Checkout(ctx, resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			r.warnf("template checkout cleanup: %v", cerr)
		}
	}()

	tpl, err := loadTemplateFromFS(src)
	if err != nil {
		return err
	}

	constraint := tpl.Requires.Tplaiter
	if constraint == "" {
		constraint = tpl.Requires.Tplater
	}
	if tpl.Requires.Tplaiter != "" && tpl.Requires.Tplater != "" && tpl.Requires.Tplaiter != tpl.Requires.Tplater {
		return errors.New("newcmd: conflicting requires.tplaiter and requires.tplater")
	}
	if err := checkTplaterVersion(constraint, r.opts.CLIVersion); err != nil {
		return err
	}
	if !r.opts.NoDepsCheck {
		if err := r.ensureTools(ctx, tpl); err != nil {
			return err
		}
	}

	preset, presetSrc, err := r.buildPreset(tpl)
	if err != nil {
		return err
	}

	res, err := survey.AskFlow(tpl, preset, survey.FlowOptions{
		Defaults:      r.opts.Defaults,
		Interactive:   r.opts.Interactive,
		PresetSources: presetSrc,
	}, r.d.Prompter, r.d.Out, r.d.Palette)
	if err != nil {
		return err
	}

	projInfo := manifest.ProjectInfo{
		Name:   r.opts.ProjectName,
		Slug:   slug,
		Module: r.moduleOrDefault(slug),
		System: r.opts.System,
		Domain: r.opts.Domain,
	}
	port := r.opts.Port
	if port == 0 {
		port = defaultPort
	}

	// --- phase 2: creation (atomic render + post-steps) ---
	renderRes, err := r.render(src, target, tpl, res, projInfo, port, resolved.RepoAlias)
	if err != nil {
		return err
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("newcmd: determine absolute path %s: %w", target, err)
	}

	// From this point the directory exists: any required-step failure removes it.
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(absTarget)
		}
	}()

	if err := copyResources(src, absTarget, tpl); err != nil {
		return err
	}
	if err := manifest.SaveSnapshot(filepath.Join(absTarget, manifest.SnapshotRelPath), tpl); err != nil {
		return fmt.Errorf("newcmd: save manifest snapshot: %w", err)
	}
	projMarker, err := r.writeProjectMarker(absTarget, tpl, res, projInfo, port, resolved)
	if err != nil {
		return err
	}

	// hooks.postCreate: required-hook failures remove the directory; optional
	// failures are downgraded to warnings (see runHooks).
	if !r.opts.NoHooks {
		if err := r.runHooks(ctx, absTarget, tpl, res, projInfo); err != nil {
			return err
		}
	}

	if err := r.register(absTarget, tpl, resolved, projMarker.ID); err != nil {
		return err
	}
	committed = true

	// --- phase 3: post-creation (warnings only; the directory is committed) ---
	r.renderAITargets(absTarget, tpl, res, projInfo)
	r.offerEnvSetup(ctx, absTarget, tpl, res, projInfo)
	r.printNotes(src, tpl, renderRes)

	r.infof("Project %s created in %s (template %s/%s@%s)\n",
		projInfo.Slug, target, resolved.RepoAlias, tpl.Metadata.Name, resolved.Version)
	return nil
}

// ensureTools checks and installs environment tools.
func (r *run) ensureTools(ctx context.Context, tpl *manifest.Template) error {
	if len(tpl.Requires.Tools) == 0 {
		return nil
	}
	out := deps.NewUI(r.d.Out, r.d.Palette)
	return deps.EnsureTools(ctx, r.d.Runner, out, tpl.Requires.Tools, deps.EnsureOptions{AutoYes: r.opts.Yes})
}

// buildPreset builds a settings preset from --answers (base layer) and --set
// (overrides), while recording sources for the survey summary. --set and
// --answers take precedence over interactive input.
func (r *run) buildPreset(tpl *manifest.Template) (settings.Values, map[string]survey.Source, error) {
	preset := settings.Values{}
	presetSrc := map[string]survey.Source{}

	if r.opts.AnswersFile != "" {
		answers, err := settings.LoadAnswersFile(tpl, r.opts.AnswersFile)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range answers {
			preset[k] = v
			presetSrc[k] = survey.SourceAnswer
		}
	}
	for _, expr := range r.opts.Sets {
		group, value, err := settings.ParseSet(tpl, expr)
		if err != nil {
			return nil, nil, err
		}
		preset[group] = value
		presetSrc[group] = survey.SourceSet
	}
	return preset, presetSrc, nil
}

// moduleOrDefault returns the supplied --module or the neutral default <slug>.
func (r *run) moduleOrDefault(slug string) string {
	if r.opts.Module != "" {
		return r.opts.Module
	}
	return "example.com/" + slug
}

// render runs the engine's atomic render, collecting partials from the checkout.
func (r *run) render(
	src fs.FS, target string, tpl *manifest.Template, res settings.Resolved,
	projInfo manifest.ProjectInfo, port int, repoAlias string,
) (*engine.Result, error) {
	partials, err := templatePartials(src)
	if err != nil {
		return nil, err
	}

	sp := ui.NewSpinner(r.d.Err, r.d.Palette)
	sp.Start("Rendering project %s", target)
	renderRes, err := engine.Render(engine.Options{
		Source:   src,
		Target:   target,
		Template: tpl,
		Resolved: res,
		Project:  projInfo,
		Runtime:  manifest.ProjectRuntime{Port: port},
		Repo:     repoAlias,
		Partials: partials,
	})
	sp.Stop()
	if err != nil {
		return nil, fmt.Errorf("newcmd: rendering project: %w", err)
	}
	return renderRes, nil
}

// projectMarker contains the data needed by [run.register] after writing the marker.
type projectMarker struct {
	ID string
}

// writeProjectMarker builds and writes .tplaiter/project.yaml: a UUID, template
// coordinates, project identity, the FULL settings snapshot (not Active, which
// is the basis for update and re-prompting), runtime, and the baseline path.
func (r *run) writeProjectMarker(
	target string, tpl *manifest.Template, res settings.Resolved,
	projInfo manifest.ProjectInfo, port int, resolved repo.Resolved,
) (projectMarker, error) {
	id, err := newUUIDv4()
	if err != nil {
		return projectMarker{}, err
	}
	proj := manifest.Project{
		APIVersion: manifest.APIVersion,
		Kind:       manifest.KindProject,
		ID:         id,
		Template: manifest.ProjectTemplate{
			Repo:    resolved.RepoAlias,
			Name:    tpl.Metadata.Name,
			Version: resolved.Version,
		},
		Project:  projInfo,
		Settings: map[string]any(res.Values),
		Runtime:  manifest.ProjectRuntime{Port: port},
		Baseline: engine.BaselineRelPath,
	}

	data, err := yaml.Marshal(proj)
	if err != nil {
		return projectMarker{}, fmt.Errorf("newcmd: marshal project.yaml: %w", err)
	}
	markerPath := filepath.Join(target, project.MarkerRelPath)
	if err := os.MkdirAll(filepath.Dir(markerPath), 0o755); err != nil {
		return projectMarker{}, fmt.Errorf("newcmd: create .tplaiter directory: %w", err)
	}
	if err := os.WriteFile(markerPath, data, 0o644); err != nil { //nolint:gosec // G306: the marker is not secret.
		return projectMarker{}, fmt.Errorf("newcmd: write project.yaml: %w", err)
	}
	return projectMarker{ID: id}, nil
}

// register adds the project to ~/.tplaiter/projects.yaml under an interprocess
// lock. BaselineSHA is the sha256 of baseline.json.
func (r *run) register(target string, tpl *manifest.Template, resolved repo.Resolved, id string) error {
	baselineSHA, err := hashFile(filepath.Join(target, engine.BaselineRelPath))
	if err != nil {
		return fmt.Errorf("newcmd: hash baseline: %w", err)
	}
	now := r.now()
	ref := state.ProjectRef{
		ID:   id,
		Path: target,
		Template: state.TemplateSelection{
			Repo:    resolved.RepoAlias,
			Name:    tpl.Metadata.Name,
			Version: resolved.Version,
		},
		CreatedAt:   now,
		LastSeenAt:  now,
		BaselineSHA: baselineSHA,
	}
	return state.WithLock(r.d.Home, func() error {
		projects, err := state.LoadProjects(r.d.Home)
		if err != nil {
			return err
		}
		projects.Upsert(ref)
		return state.SaveProjects(r.d.Home, projects)
	})
}

// runHooks executes hooks.postCreate in order: run hooks through $SHELL -c in
// the project directory with streamed output, and ansible hooks through
// envsetup.RunPlaybook. A required hook failure (optional=false) aborts
// creation; an optional hook failure is downgraded to a warning.
func (r *run) runHooks(
	ctx context.Context, target string, tpl *manifest.Template,
	res settings.Resolved, projInfo manifest.ProjectInfo,
) error {
	for i := range tpl.Hooks.PostCreate {
		h := tpl.Hooks.PostCreate[i]
		var err error
		switch {
		case h.Run != "":
			err = r.runShellHook(ctx, target, h.Run)
		case h.Ansible != "":
			err = r.runAnsibleHook(ctx, target, h, res, projInfo)
		default:
			continue
		}
		if err == nil {
			continue
		}
		if h.Optional && !interrupted(ctx, err) {
			r.warnf("postCreate hook skipped (optional): %v", err)
			continue
		}
		return fmt.Errorf("newcmd: postCreate hook: %w", err)
	}
	return nil
}

// interrupted reports whether a hook failed because the operation was
// cancelled or tplaiter received SIGINT/SIGTERM. Such a failure aborts the
// hook sequence even for an optional hook.
func interrupted(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, execx.ErrInterrupted)
}

// runShellHook executes a run hook through $SHELL -c in the project directory.
func (r *run) runShellHook(ctx context.Context, target, script string) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	r.infof("postCreate: %s\n", script)
	// Hooks run in their own process group so that cancellation stops the
	// whole `$SHELL -c` tree (SIGTERM, grace, SIGKILL). RunInterruptible also
	// turns SIGINT/SIGTERM received by tplaiter into that cancellation, so a
	// Ctrl+C never leaves the hook group running as an orphan.
	_, err := execx.RunInterruptible(ctx, r.d.Runner, shell, []string{"-c", script}, execx.Options{
		Dir:    target,
		Stdout: r.d.Out,
		Stderr: r.d.Err,
	})
	return err
}

// runAnsibleHook executes an ansible hook through envsetup.RunPlaybook. The
// hook file is addressed relative to .tplaiter/environment and must have been
// copied by copyResources as part of the environment directory.
func (r *run) runAnsibleHook(
	ctx context.Context, target string, h manifest.Hook,
	res settings.Resolved, projInfo manifest.ProjectInfo,
) error {
	runner := envsetup.NewRunner(r.d.Runner, r.d.Out, r.d.Palette)
	return runner.RunPlaybook(ctx, envsetup.Options{
		TemplateDir: filepath.Join(target, envsetup.EnvironmentRelPath),
		ProjectRoot: target,
		Playbook:    manifest.Playbook{Name: "postCreate", File: h.Ansible},
		Values:      res.Values,
		Project:     projInfo,
		AutoYes:     r.opts.Yes,
	})
}

// renderAITargets renders AI artifacts from the copied .tplaiter/ai-config
// when the template declares aiConfig. Any error is a warning, not a failure,
// with a hint to run `tplaiter ai gen`.
func (r *run) renderAITargets(target string, tpl *manifest.Template, res settings.Resolved, projInfo manifest.ProjectInfo) {
	if tpl.AIConfig.Path == "" {
		return
	}
	src, err := aiconfig.Load(filepath.Join(target, aiconfig.AIConfigRelPath))
	if err != nil {
		r.warnAI(err)
		return
	}
	if _, err := src.Render(aiconfig.RenderOptions{
		TargetRoot: target,
		Values:     res.ActiveValues,
		Project:    projInfo,
	}); err != nil {
		r.warnAI(err)
	}
}

func (r *run) warnAI(err error) {
	r.warnf("AI targets not generated: %v — you can retry `tplaiter ai gen`", err)
}

// offerEnvSetup offers to run the "setup" playbook after creation.
// --no-env-setup skips it; --env-setup/--yes run it immediately; otherwise
// the user is asked interactively. Failure is a warning, not a failure:
// the directory has already been committed.
func (r *run) offerEnvSetup(ctx context.Context, target string, tpl *manifest.Template, res settings.Resolved, projInfo manifest.ProjectInfo) {
	pb, ok := findSetupPlaybook(tpl.Environment.Playbooks)
	if !ok {
		return
	}
	if r.opts.EnvSetup != nil && !*r.opts.EnvSetup {
		return // --no-env-setup
	}

	run := false
	switch {
	case r.opts.Yes || (r.opts.EnvSetup != nil && *r.opts.EnvSetup):
		run = true
	case r.opts.Interactive && r.d.Confirm != nil:
		ok, err := r.d.Confirm(fmt.Sprintf("Run environment setup (env setup: %s)?", pb.Name))
		if err != nil {
			r.warnf("env setup confirmation: %v", err)
			return
		}
		run = ok
	}
	if !run {
		return
	}

	runner := envsetup.NewRunner(r.d.Runner, r.d.Out, r.d.Palette)
	if err := runner.RunPlaybook(ctx, envsetup.Options{
		TemplateDir: filepath.Join(target, envsetup.EnvironmentRelPath),
		ProjectRoot: target,
		Playbook:    pb,
		Values:      res.Values,
		Project:     projInfo,
		AutoYes:     r.opts.Yes,
	}); err != nil {
		r.warnf("env setup not completed: %v — you can retry `tplaiter env setup`", err)
	}
}

// printNotes renders and prints metadata.notes (Helm-style "what next") using
// the same context as the tree render. Notes are short and plain, printed as
// is without glamour. Errors are warnings.
func (r *run) printNotes(src fs.FS, tpl *manifest.Template, renderRes *engine.Result) {
	if tpl.Metadata.Notes == "" {
		return
	}
	data, err := fs.ReadFile(src, filepath.ToSlash(tpl.Metadata.Notes))
	if err != nil {
		r.warnf("NOTES not read (%s): %v", tpl.Metadata.Notes, err)
		return
	}
	tmpl, err := template.New("notes").Funcs(engine.FuncMap(renderRes.Context.Settings)).Parse(string(data))
	if err != nil {
		r.warnf("NOTES not parsed: %v", err)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, renderRes.Context); err != nil {
		r.warnf("NOTES not rendered: %v", err)
		return
	}
	fmt.Fprintln(r.d.Out)
	fmt.Fprintln(r.d.Out, buf.String())
}

func (r *run) infof(format string, a ...any) {
	if r.d.Out != nil {
		fmt.Fprintf(r.d.Out, format, a...)
	}
}

func (r *run) warnf(format string, a ...any) {
	if r.d.Err == nil {
		return
	}
	fmt.Fprint(r.d.Err, r.d.Palette.Warn("warning: "))
	fmt.Fprintf(r.d.Err, format+"\n", a...)
}

// findSetupPlaybook finds the playbook named "setup" among environment.playbooks.
func findSetupPlaybook(playbooks []manifest.Playbook) (manifest.Playbook, bool) {
	for _, pb := range playbooks {
		if pb.Name == "setup" {
			return pb, true
		}
	}
	return manifest.Playbook{}, false
}

// loadTemplateFromFS reads and validates the manifest from the template checkout root.
func loadTemplateFromFS(src fs.FS) (*manifest.Template, error) {
	data, err := fs.ReadFile(src, templateManifestFileName)
	if err != nil {
		return nil, fmt.Errorf("newcmd: read %s: %w", templateManifestFileName, err)
	}
	tpl, err := manifest.ParseTemplate(data)
	if err != nil {
		return nil, fmt.Errorf("newcmd: %w", err)
	}
	if err := tpl.Validate(); err != nil {
		return nil, fmt.Errorf("newcmd: template manifest is invalid: %w", err)
	}
	return tpl, nil
}

// templatePartials builds a partials source from the checkout when partials/
// exists (otherwise nil, and the engine runs without it).
func templatePartials(src fs.FS) ([]fs.FS, error) {
	info, err := fs.Stat(src, partialsDirName)
	if err != nil || !info.IsDir() {
		return nil, nil //nolint:nilerr // Missing partials/ is normal, not an error.
	}
	sub, err := fs.Sub(src, partialsDirName)
	if err != nil {
		return nil, fmt.Errorf("newcmd: partials subdirectory: %w", err)
	}
	return []fs.FS{sub}, nil
}

// ensureVacant checks that target is suitable for project creation: it must be
// absent or an empty directory. A non-empty directory or file is an error
// (repeat creation requires `tplaiter update`).
func ensureVacant(target string) error {
	info, err := os.Stat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("newcmd: check target directory %s: %w", target, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("newcmd: %s exists and is not a directory", target)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return fmt.Errorf("newcmd: read target directory %s: %w", target, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("newcmd: directory %s is not empty — re-creation not supported (use `tplaiter update`)", target)
	}
	return nil
}

// hashFile returns the hex representation of a file's sha256 contents.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
