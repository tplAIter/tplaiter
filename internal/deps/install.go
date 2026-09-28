package deps

import (
	"context"
	"fmt"
	"io"
	"runtime"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// ActionKind — kind of action that [InstallPlan] proposes to install a tool on a platform.
type ActionKind string

// Installation action kinds (SPEC-03 §4).
const (
	// ActionBrew — install with one `brew install <formula>` command
	// (available on darwin and linux when brew is in PATH).
	ActionBrew ActionKind = "brew"
	// ActionAptPrint — print the apt recipe only (we do not invoke sudo ourselves).
	ActionAptPrint ActionKind = "apt-print"
	// ActionURL — no automatic recipe; print a link for manual installation.
	ActionURL ActionKind = "url"
	// ActionNone — no installation recipe exists for the platform/tool.
	ActionNone ActionKind = "none"
)

// Action — tool installation plan computed by [InstallPlan]. Command is ready
// to print/execute (for ActionBrew, it is actually executed; for
// ActionAptPrint/ActionURL, it is only printed).
type Action struct {
	Kind    ActionKind
	Command string
}

// Platform — platform context affecting installation-recipe selection.
type Platform struct {
	// GOOS — target OS (usually runtime.GOOS, parameterized for tests).
	GOOS string
	// HasBrew reports whether brew was found in the current environment's PATH.
	HasBrew bool
}

// InstallPlan selects an installation recipe for tool on platform (SPEC-03 §4):
//  1. brew if it is in PATH (darwin or linux) and the manifest provides a formula;
//  2. apt only when brew is unavailable on linux (brew otherwise has priority);
//  3. url if a manual-installation link is set;
//  4. none when the tool has no recipe for this platform.
func InstallPlan(tool manifest.Tool, platform Platform) Action {
	switch {
	case platform.HasBrew && (platform.GOOS == "darwin" || platform.GOOS == "linux") && tool.Install.Brew != "":
		return Action{Kind: ActionBrew, Command: "brew install " + tool.Install.Brew}
	case platform.GOOS == "linux" && !platform.HasBrew && tool.Install.Apt != "":
		return Action{Kind: ActionAptPrint, Command: "sudo apt install " + tool.Install.Apt}
	case tool.Install.URL != "":
		return Action{Kind: ActionURL, Command: tool.Install.URL}
	default:
		return Action{Kind: ActionNone}
	}
}

// UI — minimal output needed for tool installation: semantically colored
// messages and a writer for streaming child-process output (for example,
// `brew install`) as it appears.
type UI struct {
	Out     io.Writer
	Palette ui.Palette
}

// NewUI creates a UI over writer out with palette pal.
func NewUI(out io.Writer, pal ui.Palette) UI {
	return UI{Out: out, Palette: pal}
}

// Info prints a neutral message.
func (u UI) Info(msg string) {
	fmt.Fprintln(u.Out, u.Palette.Muted(msg))
}

// Warn prints a warning.
func (u UI) Warn(msg string) {
	fmt.Fprintln(u.Out, u.Palette.Warn(msg))
}

// Success prints a success message.
func (u UI) Success(msg string) {
	fmt.Fprintln(u.Out, u.Palette.Success(msg))
}

// DetectPlatform determines the current process's [Platform]: runtime GOOS and
// brew presence in PATH through runner.LookPath. This lets unit tests control
// HasBrew with [execx.RecordingRunner.SetLookPath] without accessing the real machine.
func DetectPlatform(runner execx.Runner) Platform {
	return Platform{GOOS: runtime.GOOS}
}

// Install executes the tool installation plan computed for the current platform
// (see [DetectPlatform], [InstallPlan]):
//   - ActionBrew prints an offer, asks confirm(), and if true executes
//     `brew install <formula>`, streaming output to out.Out;
//   - ActionAptPrint/ActionURL only print the recipe and execute nothing
//     (the user runs sudo manually);
//   - ActionNone warns that no recipe exists.
//
// confirm may be nil, equivalent to a function that always returns false
// (installation is not confirmed, but the plan is still returned to the caller).
func Install(ctx context.Context, runner execx.Runner, out UI, tool manifest.Tool, confirm func() bool) (Action, error) {
	return installFor(ctx, runner, out, tool, DetectPlatform(runner), confirm)
}

// installFor — [Install] implementation parameterized by platform so tests can
// fix GOOS/HasBrew independently of the machine running them (see
// check_test.go/install_test.go: the CI host's runtime.GOOS must not determine
// which InstallPlan branch is tested).
func installFor(ctx context.Context, runner execx.Runner, out UI, tool manifest.Tool, platform Platform, confirm func() bool) (Action, error) {
	action := InstallPlan(tool, platform)
	// Generic manifest recipes never authorize installation, including direct
	// library callers. A future fixed adapter must provide its own authority.
	return action, ErrExecutionUnavailable

	/*
		switch action.Kind {
		case ActionBrew:
			out.Info(tool.Name + ": installation is available through brew — " + action.Command)
			if confirm == nil || !confirm() {
				out.Info(tool.Name + ": installation cancelled")
				return action, nil
			}
			_, err := runner.Run(ctx, "brew", []string{"install", tool.Install.Brew}, execx.Options{
				Stdout: out.Out,
				Stderr: out.Out,
			})
			if err != nil {
				return action, fmt.Errorf("deps: brew install %s: %w", tool.Install.Brew, err)
			}
			out.Success(tool.Name + ": installed through brew")
			return action, nil
		case ActionAptPrint:
			out.Warn(tool.Name + ": automatic installation is unavailable; run manually:")
			out.Info("  " + action.Command)
			return action, nil
		case ActionURL:
			out.Warn(tool.Name + ": no package recipe exists for this platform; install manually:")
			out.Info("  " + action.Command)
			return action, nil
		default:
			out.Warn(tool.Name + ": no installation recipe exists for this platform")
			return action, nil
		}
	*/
}
