package repo

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
)

// newAuthTestManager builds a manager with a real store (temporary home), a
// supplied RecordingRunner, and test-controlled UI (In/Interactive).
func newAuthTestManager(t *testing.T, runner execx.Runner, in string, interactive bool) (*Manager, *auth.Store, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	st, err := auth.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var errBuf bytes.Buffer
	u := UI{
		In:          strings.NewReader(in),
		Out:         &bytes.Buffer{},
		Err:         &errBuf,
		Interactive: interactive,
	}
	return New(home, runner, st, u), st, &errBuf
}

const gitlabURL = "https://gitlab.com/group/repo.git"

func TestResolveGitAuth_SSHSkips(t *testing.T) {
	m, _, _ := newAuthTestManager(t, execx.NewRecordingRunner(), "", false)
	env, err := m.resolveGitAuth(context.Background(), "git@gitlab.com:group/repo.git", state.RepoKindGitLab, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if env != nil {
		t.Errorf("ssh needs no helper env, got %v", env)
	}
}

func TestResolveGitAuth_ExistingToken(t *testing.T) {
	m, st, _ := newAuthTestManager(t, execx.NewRecordingRunner(), "", false)
	if _, err := st.Put(auth.Credential{Host: "gitlab.com", Tool: "gitlab", Token: "glpat-xxx"}); err != nil {
		t.Fatal(err)
	}
	env, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(env) == 0 {
		t.Error("expected helper env for an existing token")
	}
}

func TestResolveGitAuth_TokenStdin(t *testing.T) {
	m, st, _ := newAuthTestManager(t, execx.NewRecordingRunner(), "glpat-frompipe\n", false)
	env, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, true)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(env) == 0 {
		t.Error("expected helper env after token-stdin")
	}
	got, found, _ := st.Get("gitlab.com", "group/repo", "gitlab")
	if !found || got.Token != "glpat-frompipe" {
		t.Errorf("token was not saved from stdin: found=%v cred=%+v", found, got)
	}
}

func TestResolveGitAuth_NonInteractiveSkips(t *testing.T) {
	m, _, errBuf := newAuthTestManager(t, execx.NewRecordingRunner(), "", false)
	env, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if env != nil {
		t.Errorf("non-interactive mode without a token must not set helper env, got %v", env)
	}
	if !strings.Contains(errBuf.String(), "without authentication") {
		t.Errorf("expected warning, got %q", errBuf.String())
	}
}

func TestResolveGitAuth_InteractiveEnterToken(t *testing.T) {
	// Select "t", then enter the token as a line.
	m, st, _ := newAuthTestManager(t, execx.NewRecordingRunner(), "t\nglpat-typed\n", true)
	env, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(env) == 0 {
		t.Error("expected helper env after token input")
	}
	got, found, _ := st.Get("gitlab.com", "", "gitlab")
	if !found || got.Token != "glpat-typed" {
		t.Errorf("entered token was not saved: found=%v cred=%+v", found, got)
	}
}

func TestResolveGitAuth_InteractiveGlabImportOK(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("glab", "/usr/bin/glab")
	runner.On("glab", []string{"auth", "token", "--hostname", "gitlab.com"},
		execx.Response{Result: execx.Result{Stdout: "glpat-imported\n"}})

	m, st, _ := newAuthTestManager(t, runner, "g\n", true)
	env, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(env) == 0 {
		t.Error("expected helper env after import from the GitLab CLI")
	}
	got, found, _ := st.Get("gitlab.com", "", "gitlab")
	if !found || got.Token != "glpat-imported" {
		t.Errorf("imported token was not saved: found=%v cred=%+v", found, got)
	}
}

func TestResolveGitAuth_InteractiveGlabMissing(t *testing.T) {
	// glab is not in PATH (LookPath is unset), so the error includes instructions.
	m, _, _ := newAuthTestManager(t, execx.NewRecordingRunner(), "g\n", true)
	_, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err == nil {
		t.Fatal("expected an error for missing GitLab CLI")
	}
	if !strings.Contains(err.Error(), "not found in PATH") {
		t.Errorf("error without installation recipe: %v", err)
	}
}

func TestResolveGitAuth_InteractiveGlabNotAuthorized(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("glab", "/usr/bin/glab")
	// glab is installed but unauthenticated, so it returns a nonzero status.
	runner.On("glab", []string{"auth", "token", "--hostname", "gitlab.com"},
		execx.Response{Err: errors.New("not logged in")})

	m, _, _ := newAuthTestManager(t, runner, "g\n", true)
	_, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err == nil {
		t.Fatal("expected an error for unauthenticated GitLab CLI")
	}
}

func TestResolveGitAuth_GitHubUsesGh(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("gh", "/usr/bin/gh")
	runner.On("gh", []string{"auth", "token", "--hostname", "github.com"},
		execx.Response{Result: execx.Result{Stdout: "ghp-imported\n"}})

	m, st, _ := newAuthTestManager(t, runner, "g\n", true)
	_, err := m.resolveGitAuth(context.Background(), "https://github.com/org/repo.git", state.RepoKindGitHub, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	got, found, _ := st.Get("github.com", "", "github")
	if !found || got.Token != "ghp-imported" {
		t.Errorf("gh token was not saved: found=%v cred=%+v", found, got)
	}
}
