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

// newAuthTestManager строит менеджер с реальным стором (временный home),
// заданным RecordingRunner и UI, управляемым тестом (In/Interactive).
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
		t.Errorf("для ssh helper-env не нужен, got %v", env)
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
		t.Error("ожидался helper-env для существующего токена")
	}
}

func TestResolveGitAuth_TokenStdin(t *testing.T) {
	m, st, _ := newAuthTestManager(t, execx.NewRecordingRunner(), "glpat-frompipe\n", false)
	env, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, true)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(env) == 0 {
		t.Error("ожидался helper-env после token-stdin")
	}
	got, found, _ := st.Get("gitlab.com", "group/repo", "gitlab")
	if !found || got.Token != "glpat-frompipe" {
		t.Errorf("токен не сохранён из stdin: found=%v cred=%+v", found, got)
	}
}

func TestResolveGitAuth_NonInteractiveSkips(t *testing.T) {
	m, _, errBuf := newAuthTestManager(t, execx.NewRecordingRunner(), "", false)
	env, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if env != nil {
		t.Errorf("в неинтерактивном режиме без токена — без helper-env, got %v", env)
	}
	if !strings.Contains(errBuf.String(), "без аутентификации") {
		t.Errorf("ожидалось предупреждение, got %q", errBuf.String())
	}
}

func TestResolveGitAuth_InteractiveEnterToken(t *testing.T) {
	// Выбор "t", затем токен строкой.
	m, st, _ := newAuthTestManager(t, execx.NewRecordingRunner(), "t\nglpat-typed\n", true)
	env, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(env) == 0 {
		t.Error("ожидался helper-env после ввода токена")
	}
	got, found, _ := st.Get("gitlab.com", "", "gitlab")
	if !found || got.Token != "glpat-typed" {
		t.Errorf("введённый токен не сохранён: found=%v cred=%+v", found, got)
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
		t.Error("ожидался helper-env после импорта из glab")
	}
	got, found, _ := st.Get("gitlab.com", "", "gitlab")
	if !found || got.Token != "glpat-imported" {
		t.Errorf("импортированный токен не сохранён: found=%v cred=%+v", found, got)
	}
}

func TestResolveGitAuth_InteractiveGlabMissing(t *testing.T) {
	// glab не в PATH (LookPath не задан) → ошибка с рецептом.
	m, _, _ := newAuthTestManager(t, execx.NewRecordingRunner(), "g\n", true)
	_, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err == nil {
		t.Fatal("ожидалась ошибка отсутствия glab")
	}
	if !strings.Contains(err.Error(), "не найден в PATH") {
		t.Errorf("ошибка без рецепта установки: %v", err)
	}
}

func TestResolveGitAuth_InteractiveGlabNotAuthorized(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("glab", "/usr/bin/glab")
	// glab установлен, но не авторизован → ненулевой код возврата.
	runner.On("glab", []string{"auth", "token", "--hostname", "gitlab.com"},
		execx.Response{Err: errors.New("not logged in")})

	m, _, _ := newAuthTestManager(t, runner, "g\n", true)
	_, err := m.resolveGitAuth(context.Background(), gitlabURL, state.RepoKindGitLab, false)
	if err == nil {
		t.Fatal("ожидалась ошибка неавторизованного glab")
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
		t.Errorf("токен gh не сохранён: found=%v cred=%+v", found, got)
	}
}
