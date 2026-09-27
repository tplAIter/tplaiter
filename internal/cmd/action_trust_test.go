package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/state"
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

	for _, args := range [][]string{
		{"run", "CANARY-command"},
		{"gen", "thing", "CANARY", "--no-build"},
		{"gen", "batch", "--operations", "[]", "--no-build"},
		{"env", "setup", "--yes"},
	} {
		t.Run(strings.Join(args, "/"), func(t *testing.T) {
			root := newTrustRootCommand(invocation{})
			var out, stderr bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&stderr)
			root.SetArgs(args)
			err := root.Execute()
			if !errors.Is(err, ErrActionUnavailable) {
				t.Fatalf("Execute(%q) = %v, want typed denial", args, err)
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
