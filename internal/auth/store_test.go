package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/state"
)

// openTestStore открывает стор в изолированном временном домашнем каталоге.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	home := filepath.Join(t.TempDir(), "tplater-home")
	t.Setenv(state.HomeEnv, home)

	st, err := Open(context.Background())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestStore_PutGetUpdateDelete(t *testing.T) {
	st := openTestStore(t)

	id, err := st.Put(Credential{
		Host:     "git.example.test",
		Repo:     "templates/cli",
		Tool:     "gitlab",
		Token:    "glpat-secretvalue123",
		Username: "svc",
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if id == 0 {
		t.Fatal("Put() returned id 0")
	}

	got, ok, err := st.Get("git.example.test", "templates/cli", "gitlab")
	if err != nil || !ok {
		t.Fatalf("Get() ok=%v err=%v, want found", ok, err)
	}
	if got.Token != "glpat-secretvalue123" || got.Username != "svc" {
		t.Errorf("Get() = %+v, want token/username set", got)
	}
	if got.CreatedAt.IsZero() {
		t.Error("Get() CreatedAt is zero, want set")
	}

	// Upsert: тот же host/repo/tool -> обновление, id не меняется.
	id2, err := st.Put(Credential{
		Host:  "git.example.test",
		Repo:  "templates/cli",
		Tool:  "gitlab",
		Token: "glpat-rotated456",
	})
	if err != nil {
		t.Fatalf("Put() update error = %v", err)
	}
	if id2 != id {
		t.Errorf("Put() upsert id = %d, want %d (same row)", id2, id)
	}
	got, _, _ = st.Get("git.example.test", "templates/cli", "gitlab")
	if got.Token != "glpat-rotated456" {
		t.Errorf("Get() after upsert token = %q, want rotated", got.Token)
	}

	if err := st.Delete(id); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, ok, _ := st.Get("git.example.test", "templates/cli", "gitlab"); ok {
		t.Error("Get() after Delete found row, want not found")
	}
}

func TestStore_HostLevelUpsert(t *testing.T) {
	st := openTestStore(t)

	id, err := st.Put(Credential{Host: "git.example.test", Tool: "gitlab", Token: "host-token-1"})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	// Повторный host-level Put (repo NULL) должен обновить ту же запись, а не
	// создать дубль (проверяем ручной upsert поверх NULL в UNIQUE).
	id2, err := st.Put(Credential{Host: "git.example.test", Tool: "gitlab", Token: "host-token-2"})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if id2 != id {
		t.Errorf("host-level upsert id = %d, want %d", id2, id)
	}
	all, _ := st.List()
	if len(all) != 1 {
		t.Fatalf("List() len = %d, want 1 (no NULL-repo duplicate)", len(all))
	}
	if all[0].Repo != "" {
		t.Errorf("host-level Repo = %q, want empty", all[0].Repo)
	}
}

func TestStore_GetPriorityRepoOverHost(t *testing.T) {
	st := openTestStore(t)

	if _, err := st.Put(Credential{Host: "git.example.test", Tool: "gitlab", Token: "HOST"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(Credential{Host: "git.example.test", Repo: "team/app", Tool: "gitlab", Token: "REPO"}); err != nil {
		t.Fatal(err)
	}

	got, ok, _ := st.Get("git.example.test", "team/app", "gitlab")
	if !ok || got.Token != "REPO" {
		t.Errorf("Get(repo) = %q ok=%v, want REPO", got.Token, ok)
	}

	// Нет точного repo-match -> откат к host-level.
	got, ok, _ = st.Get("git.example.test", "other/app", "gitlab")
	if !ok || got.Token != "HOST" {
		t.Errorf("Get(unknown repo) = %q ok=%v, want HOST fallback", got.Token, ok)
	}

	got, ok, _ = st.Get("git.example.test", "", "gitlab")
	if !ok || got.Token != "HOST" {
		t.Errorf("Get(host-level) = %q ok=%v, want HOST", got.Token, ok)
	}
}

func TestStore_MaskedListHidesToken(t *testing.T) {
	st := openTestStore(t)
	if _, err := st.Put(Credential{Host: "h", Tool: "git", Token: "abcdef1234567890xyz"}); err != nil {
		t.Fatal(err)
	}

	masked, err := st.MaskedList()
	if err != nil {
		t.Fatalf("MaskedList() error = %v", err)
	}
	if len(masked) != 1 {
		t.Fatalf("MaskedList() len = %d, want 1", len(masked))
	}
	if masked[0].Token != "ab...yz" {
		t.Errorf("MaskedList() token = %q, want %q", masked[0].Token, "ab...yz")
	}
	// Полный токен не должен просачиваться.
	full, _ := st.List()
	if full[0].Token != "abcdef1234567890xyz" {
		t.Errorf("List() token = %q, want full value", full[0].Token)
	}
}

func TestMaskToken(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"short":               "****",
		"1234567":             "****",
		"12345678":            "12...78",
		"abcdef1234567890xyz": "ab...yz",
	}
	for in, want := range cases {
		if got := MaskToken(in); got != want {
			t.Errorf("MaskToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStore_TouchLastUsed(t *testing.T) {
	st := openTestStore(t)
	id, err := st.Put(Credential{Host: "h", Tool: "git", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}

	when := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	if err := st.TouchLastUsed(id, when); err != nil {
		t.Fatalf("TouchLastUsed() error = %v", err)
	}
	got, _, _ := st.Get("h", "", "git")
	if !got.LastUsedAt.Equal(when) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, when)
	}
}

func TestStore_ExpiredSoon(t *testing.T) {
	st := openTestStore(t)
	if _, err := st.Put(Credential{
		Host: "h", Repo: "expiring", Tool: "git", Token: "t",
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(Credential{
		Host: "h", Repo: "future", Tool: "git", Token: "t",
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(Credential{Host: "h", Repo: "noexpiry", Tool: "git", Token: "t"}); err != nil {
		t.Fatal(err)
	}

	soon, err := st.ExpiredSoon(0)
	if err != nil {
		t.Fatalf("ExpiredSoon() error = %v", err)
	}
	if len(soon) != 1 || soon[0].Repo != "expiring" {
		t.Errorf("ExpiredSoon(0) = %+v, want only 'expiring'", soon)
	}
}

func TestStore_FilePermissions(t *testing.T) {
	home := filepath.Join(t.TempDir(), "tplater-home")
	t.Setenv(state.HomeEnv, home)

	st, err := Open(context.Background())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = st.Close() }()

	dbInfo, err := os.Stat(st.Path())
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if perm := dbInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("db file perm = %o, want 0600", perm)
	}

	homeInfo, err := os.Stat(home)
	if err != nil {
		t.Fatalf("stat home: %v", err)
	}
	if perm := homeInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("home dir perm = %o, want 0700", perm)
	}
}
