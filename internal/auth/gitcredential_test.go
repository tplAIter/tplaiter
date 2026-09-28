package auth

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func seed(t *testing.T, st *Store, c Credential) int64 {
	t.Helper()
	id, err := st.Put(c)
	if err != nil {
		t.Fatalf("seed Put() error = %v", err)
	}
	return id
}

func TestRunGitCredential_GetFound(t *testing.T) {
	st := openTestStore(t)
	seed(t, st, Credential{Host: "git.example.test", Tool: "gitlab", Token: "glpat-xyz", Username: "svc"})

	in := strings.NewReader("protocol=https\nhost=git.example.test\n\n")
	var out, logw bytes.Buffer
	if err := RunGitCredential(st, "get", in, &out, &logw, time.Now()); err != nil {
		t.Fatalf("RunGitCredential(get) error = %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "username=svc\n") {
		t.Errorf("output = %q, want username=svc", got)
	}
	if !strings.Contains(got, "password=glpat-xyz\n") {
		t.Errorf("output = %q, want password token", got)
	}
}

func TestRunGitCredential_GetRepoPriorityViaPath(t *testing.T) {
	st := openTestStore(t)
	seed(t, st, Credential{Host: "git.example.test", Tool: "gitlab", Token: "HOST"})
	seed(t, st, Credential{Host: "git.example.test", Repo: "team/app", Tool: "gitlab", Token: "REPO"})

	// path with a .git suffix — it should normalize and return the repo-level token.
	in := strings.NewReader("protocol=https\nhost=git.example.test\npath=team/app.git\n\n")
	var out, logw bytes.Buffer
	if err := RunGitCredential(st, "get", in, &out, &logw, time.Now()); err != nil {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(out.String(), "password=REPO\n") {
		t.Errorf("output = %q, want repo-level REPO token", out.String())
	}
}

func TestRunGitCredential_GetNotFoundSilent(t *testing.T) {
	st := openTestStore(t)

	in := strings.NewReader("protocol=https\nhost=unknown.example\n\n")
	var out, logw bytes.Buffer
	if err := RunGitCredential(st, "get", in, &out, &logw, time.Now()); err != nil {
		t.Fatalf("RunGitCredential(get) not-found error = %v, want nil (silent exit 0)", err)
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want empty (git falls back)", out.String())
	}
}

func TestRunGitCredential_GetDefaultUsername(t *testing.T) {
	st := openTestStore(t)
	seed(t, st, Credential{Host: "github.com", Tool: "github", Token: "ghp"})

	in := strings.NewReader("host=github.com\n\n")
	var out, logw bytes.Buffer
	if err := RunGitCredential(st, "get", in, &out, &logw, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "username=x-access-token\n") {
		t.Errorf("output = %q, want default github username", out.String())
	}
}

func TestRunGitCredential_StoreTouchesExisting(t *testing.T) {
	st := openTestStore(t)
	id := seed(t, st, Credential{Host: "git.example.test", Tool: "gitlab", Token: "t"})

	when := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	in := strings.NewReader("host=git.example.test\nusername=svc\npassword=t\n\n")
	var out, logw bytes.Buffer
	if err := RunGitCredential(st, "store", in, &out, &logw, when); err != nil {
		t.Fatalf("store error = %v", err)
	}

	got, _, _ := st.Get("git.example.test", "", "gitlab")
	if !got.LastUsedAt.Equal(when) {
		t.Errorf("LastUsedAt = %v, want %v (store should touch)", got.LastUsedAt, when)
	}
	_ = id
}

func TestRunGitCredential_StoreDoesNotCreate(t *testing.T) {
	st := openTestStore(t)

	in := strings.NewReader("host=new.example\nusername=u\npassword=secret\n\n")
	var out, logw bytes.Buffer
	if err := RunGitCredential(st, "store", in, &out, &logw, time.Now()); err != nil {
		t.Fatalf("store error = %v", err)
	}
	all, _ := st.List()
	if len(all) != 0 {
		t.Errorf("List() len = %d, want 0 (store must not auto-create)", len(all))
	}
	if logw.Len() == 0 {
		t.Error("expected diagnostic log for unstored host")
	}
}

func TestRunGitCredential_EraseNoOp(t *testing.T) {
	st := openTestStore(t)
	seed(t, st, Credential{Host: "git.example.test", Tool: "gitlab", Token: "t"})

	in := strings.NewReader("host=git.example.test\n\n")
	var out, logw bytes.Buffer
	if err := RunGitCredential(st, "erase", in, &out, &logw, time.Now()); err != nil {
		t.Fatalf("erase error = %v", err)
	}
	if all, _ := st.List(); len(all) != 1 {
		t.Errorf("erase deleted a row: List() len = %d, want 1 (no-op)", len(all))
	}
}

func TestRunGitCredential_UnknownOp(t *testing.T) {
	st := openTestStore(t)
	in := strings.NewReader("host=h\n\n")
	var out, logw bytes.Buffer
	if err := RunGitCredential(st, "frobnicate", in, &out, &logw, time.Now()); err == nil {
		t.Error("expected error for unknown op")
	}
}

func TestHelperEnv(t *testing.T) {
	env := HelperEnv("https://git.example.test/team/app.git")
	joined := strings.Join(env, "\n")

	if !strings.Contains(joined, "GIT_CONFIG_COUNT=3") {
		t.Errorf("env = %v, want COUNT=3 for https", env)
	}
	if !strings.Contains(joined, "credential.helper") {
		t.Errorf("env = %v, want credential.helper key", env)
	}
	if !strings.Contains(joined, "auth git-credential") {
		t.Errorf("env = %v, want helper invoking `auth git-credential`", env)
	}
	if !strings.Contains(joined, "credential.useHttpPath") {
		t.Errorf("env = %v, want useHttpPath for https", env)
	}

	// ssh: without useHttpPath.
	sshEnv := strings.Join(HelperEnv("git@git.example.test:team/app.git"), "\n")
	if strings.Contains(sshEnv, "useHttpPath") {
		t.Errorf("ssh env = %v, should not set useHttpPath", sshEnv)
	}
	if !strings.Contains(sshEnv, "GIT_CONFIG_COUNT=2") {
		t.Errorf("ssh env = %v, want COUNT=2", sshEnv)
	}
}

func TestNormalizeRepoPath(t *testing.T) {
	cases := map[string]string{
		"":                  "",
		"/team/app.git":     "team/app",
		"team/app":          "team/app",
		"/team/app/":        "team/app",
		"idp/x/tplater.git": "idp/x/tplater",
	}
	for in, want := range cases {
		if got := normalizeRepoPath(in); got != want {
			t.Errorf("normalizeRepoPath(%q) = %q, want %q", in, got, want)
		}
	}
}
