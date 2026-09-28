package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/selfupdate"
	"github.com/tplAIter/tplaiter/internal/state"
)

// withRunner replaces package runner with recorder for the test and restores it
// afterward.
func withRunner(t *testing.T, r execx.Runner) {
	t.Helper()
	old := runner
	runner = r
	t.Cleanup(func() { runner = old })
}

// withUpgradeFlag replaces package-level upgradeFlag for the test.
func withUpgradeFlag(t *testing.T, v bool) {
	t.Helper()
	old := upgradeFlag
	upgradeFlag = v
	t.Cleanup(func() { upgradeFlag = old })
}

// withInstallChannel replaces detectInstallChannel with a fixed channel. The
// real selfupdate.DetectChannel() examines os.Executable()/BuildInfo of the
// current process; for a `go test` binary this is consistently
// selfupdate.ChannelUnknown, preventing coverage of the go-install branch.
func withInstallChannel(t *testing.T, ch selfupdate.Channel) {
	t.Helper()
	old := detectInstallChannel
	detectInstallChannel = func() selfupdate.Channel { return ch }
	t.Cleanup(func() { detectInstallChannel = old })
}

func scriptLsRemote(r *execx.RecordingRunner, output string) {
	r.On("git", []string{"ls-remote", "--tags", selfupdate.RepoURL()}, execx.Response{Result: execx.Result{Stdout: output}})
}

func TestSuggestUpdatePreRun_SkipsForSkipList(t *testing.T) {
	for _, topName := range []string{"help", "version", "completion", "init-shell", "self-upgrade"} {
		t.Run(topName, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv(state.HomeEnv, home)

			rec := execx.NewRecordingRunner()
			withRunner(t, rec)

			// top is a direct child of root, as in the real rootCmd tree (see
			// topLevelCommand in firstrun.go: it identifies topName as the nearest
			// root child rather than a deeper subcommand).
			root := &cobra.Command{Use: "tplaiter"}
			top := &cobra.Command{Use: topName}
			root.AddCommand(top)
			top.SetContext(context.Background())

			var stderr bytes.Buffer
			top.SetErr(&stderr)

			suggestUpdatePreRun(top, nil)

			if len(rec.Calls) != 0 {
				t.Errorf("suggestUpdatePreRun() made %d network calls for skipped top-level %q, want 0", len(rec.Calls), topName)
			}
			if stderr.Len() != 0 {
				t.Errorf("suggestUpdatePreRun() printed %q for skipped top-level %q", stderr.String(), topName)
			}
		})
	}
}

func TestSuggestUpdatePreRun_PrintsWhenOutdated(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)

	rec := execx.NewRecordingRunner()
	scriptLsRemote(rec, "aaa\trefs/tags/v99.0.0\n")
	withRunner(t, rec)

	oldVersion := version
	version = "v1.0.0"
	t.Cleanup(func() { version = oldVersion })

	repoCmd := &cobra.Command{Use: "repo"}
	leaf := &cobra.Command{Use: "list"}
	repoCmd.AddCommand(leaf)
	leaf.SetContext(context.Background())

	var stderr bytes.Buffer
	leaf.SetErr(&stderr)

	suggestUpdatePreRun(leaf, nil)

	if !strings.Contains(stderr.String(), "v99.0.0") {
		t.Errorf("suggestUpdatePreRun() stderr = %q, want mention of v99.0.0", stderr.String())
	}
}

func TestSuggestUpdatePreRun_NilContextDoesNotPanic(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)

	rec := execx.NewRecordingRunner()
	scriptLsRemote(rec, "")
	withRunner(t, rec)

	// Neither SetContext nor Execute() was called, so cmd.Context() returns nil.
	// suggestUpdatePreRun must supply context.Background() rather than call
	// context.WithTimeout(nil, ...).
	leaf := &cobra.Command{Use: "list"}

	suggestUpdatePreRun(leaf, nil)
}

func TestRunSelfUpgrade_AlreadyLatest(t *testing.T) {
	oldVersion := version
	version = "v1.0.0"
	t.Cleanup(func() { version = oldVersion })

	rec := execx.NewRecordingRunner()
	scriptLsRemote(rec, "aaa\trefs/tags/v1.0.0\n")
	withRunner(t, rec)

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())

	if err := runSelfUpgrade(cmd, nil); err != nil {
		t.Fatalf("runSelfUpgrade() error = %v", err)
	}
	if !strings.Contains(out.String(), "уже установлена последняя версия") {
		t.Errorf("runSelfUpgrade() output = %q, want up-to-date message", out.String())
	}
	// No "go install" should have run.
	for _, c := range rec.Calls {
		if c.Name == "go" {
			t.Errorf("runSelfUpgrade() ran %q %v when already up to date", c.Name, c.Args)
		}
	}
}

func TestRunSelfUpgrade_OutdatedRunsGoInstall(t *testing.T) {
	oldVersion := version
	version = "v1.0.0"
	t.Cleanup(func() { version = oldVersion })

	rec := execx.NewRecordingRunner()
	scriptLsRemote(rec, "aaa\trefs/tags/v2.0.0\n")
	rec.OnCommand("go", execx.Response{Result: execx.Result{}})
	withRunner(t, rec)
	withInstallChannel(t, selfupdate.ChannelGoInstall)

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())

	if err := runSelfUpgrade(cmd, nil); err != nil {
		t.Fatalf("runSelfUpgrade() error = %v", err)
	}
	if !strings.Contains(out.String(), "v1.0.0 -> v2.0.0") {
		t.Errorf("runSelfUpgrade() output = %q, want mention of the version bump", out.String())
	}

	found := false
	for _, c := range rec.Calls {
		if c.Name == "go" && len(c.Args) > 0 && c.Args[0] == "install" {
			found = true
		}
	}
	if !found {
		t.Errorf("runSelfUpgrade() did not run `go install ...`, calls = %+v", rec.Calls)
	}
}

func TestRunSelfUpgrade_NetworkErrorStillAttemptsUpgrade(t *testing.T) {
	oldVersion := version
	version = "v1.0.0"
	t.Cleanup(func() { version = oldVersion })

	rec := execx.NewRecordingRunner()
	rec.On("git", []string{"ls-remote", "--tags", selfupdate.RepoURL()}, execx.Response{Err: errors.New("unreachable")})
	rec.OnCommand("go", execx.Response{Result: execx.Result{}})
	withRunner(t, rec)
	withInstallChannel(t, selfupdate.ChannelGoInstall)

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())

	if err := runSelfUpgrade(cmd, nil); err != nil {
		t.Fatalf("runSelfUpgrade() error = %v, want nil (upgrade attempted despite failed version check)", err)
	}

	found := false
	for _, c := range rec.Calls {
		if c.Name == "go" {
			found = true
		}
	}
	if !found {
		t.Error("runSelfUpgrade() did not attempt go install after a failed version check")
	}
}

func TestRootRunE_UpgradeFlag(t *testing.T) {
	rec := execx.NewRecordingRunner()
	scriptLsRemote(rec, "aaa\trefs/tags/v1.0.0\n")
	withRunner(t, rec)

	oldVersion := version
	version = "v1.0.0"
	t.Cleanup(func() { version = oldVersion })

	withUpgradeFlag(t, true)

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())

	if err := rootCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("rootCmd.RunE() error = %v", err)
	}
	if !strings.Contains(out.String(), "уже установлена последняя версия") {
		t.Errorf("rootCmd.RunE() with --upgrade output = %q, want it to have dispatched to runSelfUpgrade", out.String())
	}
}

func TestRootRunE_NoUpgradeFlagPrintsHelp(t *testing.T) {
	withUpgradeFlag(t, false)

	rec := execx.NewRecordingRunner()
	withRunner(t, rec)

	// Short must be non-empty; otherwise cobra defaultHelpFunc prints nothing for
	// a command without Long/Short, RunE, or subcommands (as this synthetic cmd
	// is, unlike real rootCmd). We only need to verify cmd.Help(), not
	// runSelfUpgrade, is called.
	cmd := &cobra.Command{Use: "tplaiter", Short: "sentinel help text"}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())

	if err := rootCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("rootCmd.RunE() error = %v", err)
	}
	if len(rec.Calls) != 0 {
		t.Errorf("rootCmd.RunE() without --upgrade made %d runner calls, want 0 (should just print help)", len(rec.Calls))
	}
	if !strings.Contains(out.String(), "sentinel help text") {
		t.Errorf("rootCmd.RunE() without --upgrade output = %q, want it to have printed cmd.Help()", out.String())
	}
}

func TestRootPreRun_BareInvocationSkipsFirstRunAndSuggest(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)
	withUpgradeFlag(t, false)

	rec := execx.NewRecordingRunner()
	withRunner(t, rec)

	// !cmd.HasParent() is the only way to simulate "bare root" without going
	// through rootCmd.Execute(), which shares package flag/AddCommand state across
	// tests.
	bareRoot := &cobra.Command{Use: "tplaiter"}
	bareRoot.SetContext(context.Background())
	var stderr bytes.Buffer
	bareRoot.SetErr(&stderr)

	if err := rootPreRun(bareRoot, nil); err != nil {
		t.Fatalf("rootPreRun() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "repos")); err == nil {
		t.Errorf("rootPreRun() created %s/repos for bare invocation without --upgrade, want no side effects", home)
	}
	if len(rec.Calls) != 0 {
		t.Errorf("rootPreRun() made %d runner calls for bare invocation, want 0", len(rec.Calls))
	}
}

func TestRootPreRun_BareInvocationWithUpgradeFlagRunsFirstRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)
	withUpgradeFlag(t, true)

	rec := execx.NewRecordingRunner()
	scriptLsRemote(rec, "")
	withRunner(t, rec)

	bareRoot := &cobra.Command{Use: "tplaiter"}
	bareRoot.SetContext(context.Background())
	var stderr bytes.Buffer
	bareRoot.SetErr(&stderr)

	if err := rootPreRun(bareRoot, nil); err != nil {
		t.Fatalf("rootPreRun() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "repos")); err != nil {
		t.Errorf("rootPreRun() with --upgrade did not run first-run: %v", err)
	}
}

func TestSuggestUpdatePreRun_RunnerContextHasDeadline(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)

	capture := &ctxCapturingRunner{Runner: execx.NewRecordingRunner()}
	capture.Runner.(*execx.RecordingRunner).On("git", []string{"ls-remote", "--tags", selfupdate.RepoURL()}, execx.Response{Result: execx.Result{}})
	withRunner(t, capture)

	leaf := &cobra.Command{Use: "list"}
	leaf.SetContext(context.Background())

	suggestUpdatePreRun(leaf, nil)

	if capture.gotCtx == nil {
		t.Fatal("suggestUpdatePreRun() never invoked the runner")
	}
	deadline, ok := capture.gotCtx.Deadline()
	if !ok {
		t.Fatal("context passed to runner has no deadline, want ~2s timeout")
	}
	if d := time.Until(deadline); d <= 0 || d > suggestCheckTimeout {
		t.Errorf("context deadline %v from now, want within (0, %v]", d, suggestCheckTimeout)
	}
}

// ctxCapturingRunner — test Runner that records the context from its last Run,
// verifying the 2s timeout set by suggestUpdatePreRun.
type ctxCapturingRunner struct {
	execx.Runner
	gotCtx context.Context
}

func (r *ctxCapturingRunner) Run(ctx context.Context, name string, args []string, opts execx.Options) (execx.Result, error) {
	r.gotCtx = ctx
	return r.Runner.Run(ctx, name, args, opts)
}

func TestNewInitShellCmd_GeneratesCompletionPerShell(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			cmd := newInitShellCmd()
			root := &cobra.Command{Use: "tplaiter"}
			root.AddCommand(cmd)

			var out bytes.Buffer
			root.SetOut(&out)
			root.SetArgs([]string{"init-shell", shell})

			if err := root.Execute(); err != nil {
				t.Fatalf("init-shell %s: Execute() error = %v", shell, err)
			}
			if out.Len() == 0 {
				t.Errorf("init-shell %s: printed nothing, want a completion script", shell)
			}
		})
	}
}

func TestNewInitShellCmd_HelpUsesTplaiterIdentity(t *testing.T) {
	cmd := newInitShellCmd()
	help := cmd.Short + "\n" + cmd.Long
	if !strings.Contains(help, "tplaiter") {
		t.Fatalf("init-shell help does not identify tplaiter: %q", help)
	}
	if strings.Contains(help, "tplater") {
		t.Fatalf("init-shell help contains legacy executable identity: %q", help)
	}
}

func TestNewInitShellCmd_RejectsUnknownShell(t *testing.T) {
	cmd := newInitShellCmd()
	root := &cobra.Command{Use: "tplaiter"}
	root.AddCommand(cmd)
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"init-shell", "powershell"})

	if err := root.Execute(); err == nil {
		t.Error("init-shell powershell: Execute() error = nil, want error (not in ValidArgs)")
	}
}
