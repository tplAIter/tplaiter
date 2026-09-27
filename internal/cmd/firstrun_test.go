package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/state"
)

func TestFirstRunPreRun_CreatesHomeAndPrintsWelcomeOnce(t *testing.T) {
	home := filepath.Join(t.TempDir(), "tplater-home")
	t.Setenv(state.HomeEnv, home)

	leaf := &cobra.Command{Use: "add"}
	repoCmd := &cobra.Command{Use: "repo"}
	repoCmd.AddCommand(leaf)
	root := &cobra.Command{Use: "tplaiter"}
	root.AddCommand(repoCmd)

	var stderr bytes.Buffer
	leaf.SetErr(&stderr)

	if err := firstRunPreRun(leaf, nil); err != nil {
		t.Fatalf("firstRunPreRun() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "repos")); err != nil {
		t.Errorf("firstRunPreRun() did not create %s/repos: %v", home, err)
	}
	if stderr.Len() == 0 {
		t.Error("firstRunPreRun() first call printed nothing, want welcome message")
	}
	if strings.Contains(stderr.String(), "tplater") {
		t.Errorf("firstRunPreRun() printed legacy executable identity: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "tplaiter repo add") {
		t.Errorf("firstRunPreRun() missing tplaiter bootstrap command: %q", stderr.String())
	}

	stderr.Reset()
	if err := firstRunPreRun(leaf, nil); err != nil {
		t.Fatalf("firstRunPreRun() second call error = %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("firstRunPreRun() second call printed %q, want silence (home already existed)", stderr.String())
	}
}

func TestFirstRunPreRun_SkipsForVersionAndHelpAndCompletion(t *testing.T) {
	for _, topName := range []string{"version", "help", "completion"} {
		t.Run(topName, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "tplater-home")
			t.Setenv(state.HomeEnv, home)

			top := &cobra.Command{Use: topName}
			leaf := &cobra.Command{Use: "bash"}
			top.AddCommand(leaf)
			root := &cobra.Command{Use: "tplaiter"}
			root.AddCommand(top)

			var stderr bytes.Buffer
			leaf.SetErr(&stderr)

			if err := firstRunPreRun(leaf, nil); err != nil {
				t.Fatalf("firstRunPreRun() error = %v", err)
			}
			if _, err := os.Stat(home); err == nil {
				t.Errorf("firstRunPreRun() created %s for skipped top-level command %q", home, topName)
			}
			if stderr.Len() != 0 {
				t.Errorf("firstRunPreRun() printed %q for skipped command %q", stderr.String(), topName)
			}
		})
	}
}

func TestTopLevelCommand(t *testing.T) {
	root := &cobra.Command{Use: "tplaiter"}
	completion := &cobra.Command{Use: "completion"}
	bash := &cobra.Command{Use: "bash"}
	completion.AddCommand(bash)
	root.AddCommand(completion)

	if got := topLevelCommand(bash); got.Name() != "completion" {
		t.Errorf("topLevelCommand(bash) = %q, want completion", got.Name())
	}
	if got := topLevelCommand(completion); got.Name() != "completion" {
		t.Errorf("topLevelCommand(completion) = %q, want completion", got.Name())
	}
	if got := topLevelCommand(root); got.Name() != "tplaiter" {
		t.Errorf("topLevelCommand(root) = %q, want tplater", got.Name())
	}
}
