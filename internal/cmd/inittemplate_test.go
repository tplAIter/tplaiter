package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runInitLint runs `init-template` in dir and then `lint-template` on it through
// real cobra commands, returning combined output and the error.
// lint.
func runInitLint(t *testing.T, extraInit ...string) (string, error) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "repo")

	initCmd := newInitTemplateCmd()
	var initOut bytes.Buffer
	initCmd.SetOut(&initOut)
	initCmd.SetErr(&initOut)
	args := append([]string{"--dir", dir, "--no-git"}, extraInit...)
	initCmd.SetArgs(append(args, "demo-svc"))
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init-template: %v\n%s", err, initOut.String())
	}

	lintCmd := newLintTemplateCmd()
	var lintOut bytes.Buffer
	lintCmd.SetOut(&lintOut)
	lintCmd.SetErr(&lintOut)
	lintCmd.SetArgs([]string{"--path", dir})
	err := lintCmd.Execute()
	return lintOut.String(), err
}

func TestInitTemplateCmd_GeneratesAndLintsGreen(t *testing.T) {
	out, err := runInitLint(t)
	if err != nil {
		t.Fatalf("lint-template must pass, got: %v\n%s", err, out)
	}
	if !strings.Contains(out, "all combinations are green") {
		t.Errorf("expected green lint output, got:\n%s", out)
	}
}

func TestInitTemplateCmd_BootstrapUsesTplaiter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	cmd := newInitTemplateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--dir", dir, "--no-git", "demo-svc"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init-template: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "tplaiter lint-template") || !strings.Contains(out.String(), "tplaiter repo add") {
		t.Errorf("init-template did not print current bootstrap commands:\n%s", out.String())
	}
	if strings.Contains(out.String(), "tplater ") {
		t.Errorf("init-template printed stale bootstrap command:\n%s", out.String())
	}
}

func TestInitTemplateCmd_MultiGeneratesAndLintsGreen(t *testing.T) {
	out, err := runInitLint(t, "--multi")
	if err != nil {
		t.Fatalf("multi lint-template must pass: %v\n%s", err, out)
	}
	if !strings.Contains(out, "all combinations are green") {
		t.Errorf("expected green lint output (multi):\n%s", out)
	}
}

func TestLintTemplateCmd_BrokenExitsNonZero(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	initCmd := newInitTemplateCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetArgs([]string{"--dir", dir, "--no-git", "demo-svc"})
	if err := initCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	// Corrupt the condition: a conditional segment referring to a nonexistent group.
	brokenDir := filepath.Join(dir, "files", "__if_ghost__")
	if err := os.MkdirAll(brokenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(brokenDir, "x.txt"), []byte("boom"), 0o644); err != nil {
		t.Fatal(err)
	}

	lintCmd := newLintTemplateCmd()
	lintCmd.SetOut(&bytes.Buffer{})
	lintCmd.SetErr(&bytes.Buffer{})
	lintCmd.SetArgs([]string{"--path", dir})
	err := lintCmd.Execute()
	if err == nil {
		t.Fatal("a broken template must fail (exit != 0)")
	}
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Errorf("expected ExitError{Code:1}, got %T: %v", err, err)
	}
}
