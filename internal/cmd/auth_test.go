package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
)

// runAuth выполняет свежесобранное дерево команд auth с заданными аргументами и
// stdin, возвращая stdout+stderr. Дерево строится заново на каждый вызов, чтобы
// не зависеть от глобального rootCmd и его state между тестами.
func runAuth(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	c := newAuthCmd()
	var out, errb bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&errb)
	c.SetIn(strings.NewReader(stdin))
	c.SetArgs(args)
	err := c.Execute()
	return out.String(), err
}

func setTestHome(t *testing.T) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "tplater-home")
	t.Setenv(state.HomeEnv, home)
}

func TestAuthAdd_TokenStdin_ThenList(t *testing.T) {
	setTestHome(t)

	out, err := runAuth(t, "glpat-supersecret9999",
		"add", "git.example.test", "--tool", "gitlab", "--username", "svc",
		"--repo", "team/app", "--token-stdin")
	if err != nil {
		t.Fatalf("auth add error = %v", err)
	}
	if !strings.Contains(out, "id=") {
		t.Errorf("add output = %q, want id=", out)
	}
	if strings.Contains(out, "supersecret") {
		t.Errorf("add output leaked token: %q", out)
	}

	out, err = runAuth(t, "", "list")
	if err != nil {
		t.Fatalf("auth list error = %v", err)
	}
	if !strings.Contains(out, "git.example.test") || !strings.Contains(out, "team/app") {
		t.Errorf("list output = %q, want host+repo", out)
	}
	if strings.Contains(out, "supersecret") {
		t.Errorf("list leaked full token: %q", out)
	}
	if !strings.Contains(out, "gl...99") {
		t.Errorf("list output = %q, want masked token gl...99", out)
	}
}

func TestAuthRemove(t *testing.T) {
	setTestHome(t)

	// Добавляем напрямую через стор, чтобы узнать id.
	st, err := auth.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.Put(auth.Credential{Host: "h", Tool: "git", Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	out, err := runAuth(t, "", "remove", strconv.FormatInt(id, 10))
	if err != nil {
		t.Fatalf("auth remove error = %v", err)
	}
	if !strings.Contains(out, "удалён") {
		t.Errorf("remove output = %q", out)
	}

	st, _ = auth.Open(context.Background())
	defer func() { _ = st.Close() }()
	if all, _ := st.List(); len(all) != 0 {
		t.Errorf("after remove List() len = %d, want 0", len(all))
	}
}

func TestAuthImportGlab_Mock(t *testing.T) {
	setTestHome(t)

	rec := execx.NewRecordingRunner()
	rec.SetLookPath("glab", "/usr/local/bin/glab")
	rec.On("glab", []string{"auth", "token", "--hostname", "git.example.test"},
		execx.Response{Result: execx.Result{Stdout: "glpat-imported-token\n"}})

	prev := authRunner
	authRunner = rec
	t.Cleanup(func() { authRunner = prev })

	out, err := runAuth(t, "", "import-glab", "--hostname", "git.example.test")
	if err != nil {
		t.Fatalf("import-glab error = %v", err)
	}
	if !strings.Contains(out, "gitlab") || !strings.Contains(out, "git.example.test") {
		t.Errorf("import output = %q", out)
	}

	st, err := auth.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	got, ok, err := st.Get("git.example.test", "", "gitlab")
	if err != nil || !ok {
		t.Fatalf("Get() ok=%v err=%v, want imported cred", ok, err)
	}
	if got.Token != "glpat-imported-token" {
		t.Errorf("imported token = %q, want glpat-imported-token", got.Token)
	}
}

func TestAuthImportGlab_MissingBinary(t *testing.T) {
	setTestHome(t)

	rec := execx.NewRecordingRunner() // LookPath("glab") -> not found
	prev := authRunner
	authRunner = rec
	t.Cleanup(func() { authRunner = prev })

	if _, err := runAuth(t, "", "import-glab"); err == nil {
		t.Error("expected error when glab is not in PATH")
	}
}

func TestAuthGitCredential_Get(t *testing.T) {
	setTestHome(t)

	st, err := auth.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(auth.Credential{Host: "git.example.test", Tool: "gitlab", Token: "glpat-cred", Username: "svc"}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	out, err := runAuth(t, "protocol=https\nhost=git.example.test\n\n", "git-credential", "get")
	if err != nil {
		t.Fatalf("git-credential get error = %v", err)
	}
	if !strings.Contains(out, "password=glpat-cred\n") {
		t.Errorf("git-credential output = %q, want password", out)
	}
}
