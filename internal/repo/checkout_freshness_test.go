package repo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// TestCheckoutLatestSeesFetchedCommits — регресс: fetch в не-bare клоне двигает
// только origin/<ветка>, поэтому checkout @latest обязан использовать
// origin-реф и видеть новые коммиты после repo update (находка верификации ).
func TestCheckoutLatestSeesFetchedCommits(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	writeFile(t, filepath.Join(origin, templateManifestName), singleManifest)
	writeFile(t, filepath.Join(origin, "hello.txt"), "v1\n")
	commitAll(t, origin, "init")

	m := newIntegrationManager(t)
	if err := m.Add(ctx, AddOptions{Alias: "fr", URL: fileURL(origin)}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Новый коммит в origin ПОСЛЕ add.
	writeFile(t, filepath.Join(origin, "fresh.txt"), "новый\n")
	commitAll(t, origin, "fresh commit")

	if err := m.Update(ctx, "fr"); err != nil {
		t.Fatalf("Update: %v", err)
	}

	res, err := m.ResolveRef("fr/go-service@latest")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	fsys, cleanup, err := m.Checkout(ctx, res.RepoAlias, res.GitRef, res.Entry.Path)
	if err != nil {
		t.Fatalf("Checkout: %v", err)
	}
	defer func() { _ = cleanup() }()

	if _, err := fsys.Open("fresh.txt"); err != nil {
		t.Fatalf("checkout @latest не видит свежий коммит после update: %v", err)
	}
}

// TestUpdate_WorkingTreeAdvancesAfterFetch — регресс: `repo update` делал
// только `git fetch`, не подтягивая рабочее дерево кеш-клона к новому
// origin/<branch>; кеш на диске (и, как следствие, содержимое
// template.manifest.yaml, которым пользуется scanRepo при переиндексации)
// оставался на старом коммите, хотя команда рапортовала успех. Проверяем и
// HEAD клона, и содержимое файла на диске напрямую (без Checkout, который
// уже использует origin-реф и это маскирует баг).
func TestUpdate_WorkingTreeAdvancesAfterFetch(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	writeFile(t, filepath.Join(origin, templateManifestName), singleManifest)
	writeFile(t, filepath.Join(origin, "hello.txt"), "v1\n")
	commitAll(t, origin, "init")

	m := newIntegrationManager(t)
	if err := m.Add(ctx, AddOptions{Alias: "fr", URL: fileURL(origin)}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	beforeHEAD := runGitOutput(t, origin, "rev-parse", "HEAD")

	// Новый коммит в origin ПОСЛЕ add — меняет и HEAD, и содержимое hello.txt.
	writeFile(t, filepath.Join(origin, "hello.txt"), "v2\n")
	commitAll(t, origin, "fresh commit")
	afterHEAD := runGitOutput(t, origin, "rev-parse", "HEAD")
	if beforeHEAD == afterHEAD {
		t.Fatalf("origin HEAD не изменился между коммитами")
	}

	if err := m.Update(ctx, "fr"); err != nil {
		t.Fatalf("Update: %v", err)
	}

	clone := m.cloneDir("fr")
	cloneHEAD := runGitOutput(t, clone, "rev-parse", "HEAD")
	if cloneHEAD != afterHEAD {
		t.Fatalf("HEAD кеш-клона не сдвинулся после update: клон=%s, origin=%s", cloneHEAD, afterHEAD)
	}

	got, err := os.ReadFile(filepath.Join(clone, "hello.txt"))
	if err != nil {
		t.Fatalf("чтение hello.txt из кеш-клона: %v", err)
	}
	if string(got) != "v2\n" {
		t.Fatalf("hello.txt в кеш-клоне после update = %q, ожидалось %q (рабочее дерево не обновилось)", got, "v2\n")
	}
}

// runGitOutput — как runGit, но возвращает обрезанный stdout (для rev-parse и
// подобных однострочных команд).
func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	res, err := gitExec.Run(context.Background(), "git", args, execx.Options{Dir: dir, Env: gitEnv()})
	if err != nil {
		t.Fatalf("git %v: %v\n%s%s", args, err, res.Stdout, res.Stderr)
	}
	return strings.TrimSpace(res.Stdout)
}
