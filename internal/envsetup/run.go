// Package envsetup executes environment Ansible playbooks declared by the
// template in its manifest (environment.playbooks, SPEC-01 §2, SPEC-03 §4).
// tplaiter does not try to understand every possible project-environment setup;
// it installs the single universal tool (Ansible) and delegates to a playbook
// carried by the template.
//
// The package is named envsetup rather than env: the latter is too closely
// associated with the standard library (os.Environ, etc.) and would be
// misleading beside internal/cmd/env.go (the `tplaiter env` CLI command that wraps this package).
//
// # .tplaiter/environment contract (for C2 — `tplaiter new`)
//
// A created project has no template checkout: rendering (engine) leaves only
// the gotemplate result over the settings tree, while playbook files
// (environment.playbooks[].file, usually "environment/setup.yml", etc.) are
// addressed relative to the TEMPLATE ROOT, not the project. For `tplaiter env`
// to run playbooks after the template checkout has been removed or updated,
// C2 (`tplaiter new`) MUST copy (not render — verbatim, including .yml/.j2/vars
// and any Ansible-specific files) the directories referenced by the template's
// environment.playbooks[].file paths into the project at:
//
//	<project root>/.tplaiter/environment/
//
// preserving relative paths: if the manifest declares file:
// "environment/setup.yml", the project must contain
// ".tplaiter/environment/environment/setup.yml". The simplest approach is to
// copy the entire template directory under .tplaiter/environment/, preserving
// its 1:1 structure; then Playbook.File can be joined with TemplateDir without
// path renormalization. [EnvironmentRelPath] is the canonical relative path so
// both contract parties (C2 and `tplaiter env`) use one constant. Package tests
// place playbook files manually (without a real C2/checkout pass).
package envsetup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// EnvironmentRelPath — project environment-directory path relative to the
// project root. `tplaiter new` (C2) copies template playbook files there (see the
// package docs); [Options].TemplateDir is built with filepath.Join(root, EnvironmentRelPath).
const EnvironmentRelPath = ".tplaiter/environment"

// ansibleTool — environment requirement for executing playbooks (SPEC-01 §2:
// `{ name: ansible, required: false, install: { brew: ansible, apt: ansible } }`).
// required is true here not in the template-manifest sense (Ansible is not
// globally required there), but as a local requirement of this operation:
// without ansible-playbook, `tplaiter env setup` simply cannot run.
var ansibleTool = manifest.Tool{
	Name:     "ansible",
	Required: true,
	Install: manifest.ToolInstall{
		Brew: "ansible",
		Apt:  "ansible",
	},
}

// ansiblePlaybookBinary — actual binary launched by Runner. It differs from the
// package name ansibleTool.Name ("ansible"): the formula/package is named
// ansible, while the executable needed here is ansible-playbook (installed by
// the same package, but a different PATH name).
const ansiblePlaybookBinary = "ansible-playbook"

// ErrAnsibleMissing reports that ansible-playbook was not found in PATH and (if
// attempted) installation did not solve the problem. errors.Is distinguishes
// this [Runner.RunPlaybook] failure from others (missing playbook file or an
// ansible-playbook error).
var ErrAnsibleMissing = errors.New("envsetup: ansible-playbook not found in PATH")

// ErrPlaybookFileNotFound reports that the playbook file is absent at the
// expected path (TemplateDir/Playbook.File).
var ErrPlaybookFileNotFound = errors.New("envsetup: playbook file not found")

// ErrAnsibleAdapterUnavailable is returned before inspecting a playbook,
// resolving a tool, creating extra-vars, or invoking an installer. Generic
// Ansible imports, plugins, inventory and variable closure are not an
// approved executable adapter.
var ErrAnsibleAdapterUnavailable = errors.New("TRUST_ANSIBLE_ADAPTER_UNAVAILABLE")

// PlaybookInfo — one environment playbook for the `tplaiter env list` report.
type PlaybookInfo struct {
	// Name — playbook identifier (environment.playbooks[].name).
	Name string
	// Description — human-readable description from the manifest.
	Description string
	// Available reports whether When (or an empty When) is true for current
	// values. A parse error or unknown group also yields false: the playbook is
	// honestly unavailable rather than "unknown".
	Available bool
	// WhenStr — original When string (empty when there is no condition), used to
	// show in the report why the playbook is unavailable.
	WhenStr string
}

// ListPlaybooks returns template-environment playbooks with availability based
// on the when condition for current values (SPEC-03 §4), in manifest order.
func ListPlaybooks(tpl *manifest.Template, values settings.Values) []PlaybookInfo {
	playbooks := tpl.Environment.Playbooks
	infos := make([]PlaybookInfo, 0, len(playbooks))
	for _, pb := range playbooks {
		info := PlaybookInfo{Name: pb.Name, Description: pb.Description, WhenStr: pb.When, Available: true}
		if pb.When != "" {
			ok, err := evalWhen(pb.When, values)
			info.Available = err == nil && ok
		}
		infos = append(infos, info)
	}
	return infos
}

// evalWhen parses and evaluates a when-condition string (SPEC-01 §3.2). The
// caller treats parse/evaluation errors (including an unknown-group reference)
// as "condition not met", rather than panicking, consistent with
// [manifest.ParseCondition]/[settings.Eval].
func evalWhen(when string, values settings.Values) (bool, error) {
	cond, err := manifest.ParseCondition(when)
	if err != nil {
		return false, err
	}
	return settings.Eval(cond, values)
}

// Runner executes environment playbooks. The zero value is unusable; use
// [NewRunner]. Fields are exported so tests can construct Runner directly (for
// example with [execx.RecordingRunner]) without the constructor.
type Runner struct {
	// Exec — external-command execution layer (ansible-playbook, brew through
	// [deps.Install]). Always execx.Runner, never os/exec directly; the package is
	// fully mockable through execx.RecordingRunner.
	Exec execx.Runner
	// UI — Runner's own messages (which playbook runs and where to look on error)
	// and the stdout/stderr streaming sink for ansible-playbook.
	UI deps.UI
	// DepsUI — UI passed to deps.Install for automatic Ansible installation
	// (SPEC-03 §4). Separate from UI by task design; in practice [NewRunner] sets
	// both to the same value. They are separate so callers can deliberately mute
	// only dependency-subflow output without affecting the main UI.
	DepsUI deps.UI
}

// NewRunner builds a Runner over exec (the command layer), writing to out with
// palette pal. UI and DepsUI point to the same deps.UI; separate fields exist
// for targeted replacement in special scenarios (see DepsUI), not because they
// must differ.
func NewRunner(exec execx.Runner, out io.Writer, pal ui.Palette) *Runner {
	u := deps.NewUI(out, pal)
	return &Runner{Exec: exec, UI: u, DepsUI: u}
}

// Options — parameters for one [Runner.RunPlaybook] invocation.
type Options struct {
	// TemplateDir — directory containing playbook files (usually
	// <project root>/.tplaiter/environment; see [EnvironmentRelPath] and the
	// package contract with `tplaiter new`). Playbook.File resolves via
	// filepath.Join(TemplateDir, Playbook.File).
	TemplateDir string
	// ProjectRoot — project root: ansible-playbook working directory and source
	// for the tplater_project_root extra-var.
	ProjectRoot string
	// Playbook — playbook to run from manifest environment.playbooks.
	Playbook manifest.Playbook
	// Values — current project settings (.tplaiter/project.yaml), passed as
	// tplaiter.settings in extra-vars.
	Values settings.Values
	// Project — project identity (.tplaiter/project.yaml: project), passed as
	// tplaiter.project in extra-vars.
	Project manifest.ProjectInfo
	// AutoYes — confirms Ansible installation without an interactive question
	// (`--yes`, SPEC-03 §4). When false and ansible-playbook is missing,
	// [Runner.RunPlaybook] returns [ErrAnsibleMissing] with an installation recipe
	// without installing anything.
	AutoYes bool
}

// RunPlaybook executes one environment playbook (SPEC-03 §4):
//  1. checks that the playbook file exists (TemplateDir/Playbook.File);
//  2. ensures ansible-playbook is available in PATH, offering installation
//     through [deps.Install] if not (see [ensureAnsiblePlaybook]);
//  3. serializes Values+Project as JSON extra-vars into a mode-0600 temporary
//     file (safer than a long command line: settings secrets enter neither the
//     process argv nor shell history);
//  4. runs `ansible-playbook <file> --extra-vars @<tmp> -e
//     tplater_project_root=<ProjectRoot>` in ProjectRoot, streaming output to
//     UI.Out; the temporary file is removed after completion regardless of outcome.
//
// An ansible-playbook error (non-zero exit code) is returned as-is, containing
// *execx.ExitError; errors.As lets the calling command layer
// (internal/cmd/env.go) propagate the same exit code through tplaiter (see the
// same technique in execRunCommand in run.go).
func (r *Runner) RunPlaybook(ctx context.Context, opts Options) error {
	return ErrAnsibleAdapterUnavailable
	/*
		playbookPath := filepath.Join(opts.TemplateDir, opts.Playbook.File)
		if _, err := os.Stat(playbookPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf(
					"%w: %s (playbook %q from manifest environment.playbooks) — check that "+
						"`tplaiter new` copied the template environment directory to %s",
					ErrPlaybookFileNotFound, playbookPath, opts.Playbook.Name, EnvironmentRelPath,
				)
			}
			return fmt.Errorf("envsetup: checking playbook file %s: %w", playbookPath, err)
		}

		if err := ensureAnsiblePlaybook(ctx, r.Exec, r.DepsUI, opts.AutoYes); err != nil {
			return err
		}

		extraVarsJSON, err := buildExtraVars(opts.Values, opts.Project)
		if err != nil {
			return err
		}

		tmpPath, err := writeExtraVarsFile(extraVarsJSON)
		if err != nil {
			return err
		}
		defer os.Remove(tmpPath)

			r.UI.Info(fmt.Sprintf("envsetup: running playbook %s (%s)", opts.Playbook.Name, playbookPath))

		args := []string{
			playbookPath,
			"--extra-vars", "@" + tmpPath,
			"-e", "tplater_project_root=" + opts.ProjectRoot,
		}
		_, err = r.Exec.Run(ctx, ansiblePlaybookBinary, args, execx.Options{
			Dir:    opts.ProjectRoot,
			Stdout: r.UI.Out,
			Stderr: r.UI.Out,
		})
		return err
	*/
}

// ensureAnsiblePlaybook checks that ansible-playbook is available in PATH and,
// if not, runs the Ansible auto-install flow (SPEC-03 §4): [deps.Install] with
// confirm=autoYes, followed by another PATH check. It deliberately checks
// "ansible-playbook" itself (rather than "ansible" through [deps.Check]) because
// that is exactly the binary [Runner.RunPlaybook] launches; they are commonly
// installed by one ansible package, but the actual executable must be checked.
func ensureAnsiblePlaybook(ctx context.Context, exec execx.Runner, out deps.UI, autoYes bool) error {
	return ErrAnsibleAdapterUnavailable
	/*
		if _, err := exec.LookPath(ansiblePlaybookBinary); err == nil {
			return nil
		}

		confirm := func() bool { return autoYes }
		if _, err := deps.Install(ctx, exec, out, ansibleTool, confirm); err != nil {
			return fmt.Errorf("envsetup: Ansible installation: %w", err)
		}

		if _, err := exec.LookPath(ansiblePlaybookBinary); err == nil {
			return nil
		}

		recipe := installRecipe(exec)
		return fmt.Errorf(
			"%w — install ansible (%s) and retry, or pass --yes for automatic installation",
			ErrAnsibleMissing, recipe,
		)
	*/
}

// installRecipe builds a human-readable Ansible installation recipe for the
// [ensureAnsiblePlaybook] error when auto-installation failed or was not requested.
func installRecipe(exec execx.Runner) string {
	action := deps.InstallPlan(ansibleTool, deps.DetectPlatform(exec))
	if action.Kind != deps.ActionNone {
		return action.Command
	}
	return "brew install " + ansibleTool.Install.Brew + " (or " + ansibleTool.Install.Apt + " via apt on linux)"
}

// projectVars — tplaiter.project portion of extra-vars (SPEC-03 §4: JSON
// {"tplaiter": {"project": {...}, "settings": {...}}}). Explicit lowercase
// json tags are required externally (Ansible expects snake/lower case), rather
// than Go's convention for exported [manifest.ProjectInfo] fields.
type projectVars struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Module string `json:"module"`
	System string `json:"system"`
	Domain string `json:"domain"`
}

// extraVarsTplater — body of the "tplaiter" extra-vars field.
type extraVarsTplater struct {
	Project  projectVars     `json:"project"`
	Settings settings.Values `json:"settings"`
}

// extraVarsPayload — root of the JSON extra-vars passed to ansible-playbook.
type extraVarsPayload struct {
	Tplater extraVarsTplater `json:"tplaiter"`
}

// buildExtraVars serializes values and project as JSON extra-vars (SPEC-03 §4):
// {"tplaiter": {"project": {name,slug,module,system,domain}, "settings":
// {...values}}}. It is intentionally separate from [Runner.RunPlaybook] so unit
// tests can verify the JSON shape without running real ansible-playbook or using
// temporary files.
func buildExtraVars(values settings.Values, proj manifest.ProjectInfo) (string, error) {
	if values == nil {
		values = settings.Values{}
	}
	payload := extraVarsPayload{
		Tplater: extraVarsTplater{
			Project: projectVars{
				Name:   proj.Name,
				Slug:   proj.Slug,
				Module: proj.Module,
				System: proj.System,
				Domain: proj.Domain,
			},
			Settings: values,
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("envsetup: serialize extra-vars: %w", err)
	}
	return string(data), nil
}

// writeExtraVarsFile writes content to a mode-0600 temporary file (SPEC-03 §4:
// passing extra-vars through a file is safer than a long command line because
// settings secrets do not enter argv or shell history) and returns its path. The
// caller is responsible for removal (see defer os.Remove in [Runner.RunPlaybook]).
func writeExtraVarsFile(content string) (string, error) {
	f, err := os.CreateTemp("", "tplater-extravars-*.json")
	if err != nil {
		return "", fmt.Errorf("envsetup: create temporary extra-vars file: %w", err)
	}
	path := f.Name()

	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("envsetup: chmod temporary extra-vars file %s: %w", path, err)
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("envsetup: write temporary extra-vars file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("envsetup: close temporary extra-vars file %s: %w", path, err)
	}
	return path, nil
}
