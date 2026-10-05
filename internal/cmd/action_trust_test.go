package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// TestComposedRootDeniesLegacyActionsBeforeHooks exercises the installed
// composition seam, rather than calling an action helper in isolation.
func TestComposedRootDeniesLegacyActionsBeforeHooks(t *testing.T) {
	project := t.TempDir()
	home := filepath.Join(t.TempDir(), "hostile-home-CANARY")
	if err := os.WriteFile(filepath.Join(project, "project-CANARY"), []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	t.Setenv(state.HomeEnv, home)
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "CANARY-shell")

	for _, tc := range []struct {
		name string
		args []string
		want func(error) bool
	}{
		{name: "run", args: []string{"run", "CANARY-command"}, want: func(err error) bool {
			return errors.Is(err, ErrActionUnavailable)
		}},
		{name: "gen", args: []string{"gen", "thing", "CANARY", "--no-build"}, want: func(err error) bool {
			return errors.Is(err, trustload.ErrAnchorMissing)
		}},
		{name: "gen batch empty", args: []string{"gen", "batch", "--operations", "[]", "--no-build"}, want: func(err error) bool {
			var usage *usageError
			return errors.As(err, &usage) && err.Error() == "gen batch: operation list is empty"
		}},
		{name: "gen batch trust guard", args: []string{"gen", "batch", "--operations", `[{"kind":"thing","name":"CANARY"}]`, "--no-build"}, want: func(err error) bool {
			return errors.Is(err, trustload.ErrAnchorMissing)
		}},
		{name: "env setup", args: []string{"env", "setup", "--yes"}, want: func(err error) bool {
			return errors.Is(err, ErrActionUnavailable)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newTrustRootCommand(invocation{})
			var out, stderr bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&stderr)
			root.SetArgs(tc.args)
			err := root.Execute()
			if !tc.want(err) {
				t.Fatalf("Execute(%q) = %v, unexpected error class", tc.args, err)
			}
			if strings.Contains(err.Error(), "CANARY") || strings.Contains(out.String()+stderr.String(), "CANARY") {
				t.Fatalf("denial leaked untrusted input: err=%q output=%q", err, out.String()+stderr.String())
			}
			if _, statErr := os.Stat(home); !os.IsNotExist(statErr) {
				t.Fatalf("action created process home before denial: %v", statErr)
			}
			data, readErr := os.ReadFile(filepath.Join(project, "project-CANARY"))
			if readErr != nil || string(data) != "unchanged" {
				t.Fatalf("action changed project before denial: %q, %v", data, readErr)
			}
		})
	}
}

func TestComposedRootDescriptiveRoutesSkipRootHooks(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv(state.HomeEnv, home)
	t.Setenv("HOME", home)
	for _, args := range [][]string{{"doctor"}, {"--version"}} {
		t.Run(strings.Join(args, "/"), func(t *testing.T) {
			root := newTrustRootCommand(invocation{})
			root.SetArgs(args)
			if err := root.Execute(); err != nil {
				t.Fatalf("descriptive %q: %v", args, err)
			}
			if _, err := os.Stat(home); !os.IsNotExist(err) {
				t.Fatalf("descriptive route initialized home: %v", err)
			}
		})
	}
}
