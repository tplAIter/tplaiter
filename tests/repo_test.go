package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRepoLifecycle прогоняет управление репозиториями шаблонов (сценарий 2,
// требование реализацию): add невалидного пути -> ошибка; повторный alias -> ошибка;
// update; remove.
func TestRepoLifecycle(t *testing.T) {
	requireGit(t)
	t.Parallel()

	home := newHome(t)
	origin := buildSingleOrigin(t, filepath.Join(fixturesDir(t), "single-basic"), "v1.0.0")

	// add невалидного пути (локальный file:// на несуществующий каталог) —
	// git clone обязан провалиться, репозиторий не регистрируется.
	badPath := filepath.Join(t.TempDir(), "does-not-exist")
	bad := run(t, home, "", "repo", "add", "bad", "file://"+badPath)
	if bad.ExitCode == 0 {
		t.Fatalf("repo add с несуществующим путём: ожидался ненулевой exit, получен 0\nstdout:\n%s", bad.Stdout)
	}
	listAfterBad := mustRun(t, home, "", "repo", "list")
	if strings.Contains(listAfterBad.Stdout, "bad") {
		t.Errorf("repo add с несуществующим путём НЕ должен регистрировать алиас: %s", listAfterBad.Stdout)
	}

	// добавляем валидный репозиторий под алиасом "dup".
	mustRun(t, home, "", "repo", "add", "dup", "file://"+origin)

	// повторное использование того же алиаса с ЛЮБЫМ URL — ошибка.
	dupAgain := run(t, home, "", "repo", "add", "dup", "file://"+origin)
	if dupAgain.ExitCode == 0 {
		t.Fatalf("repo add с занятым алиасом: ожидался ненулевой exit, получен 0")
	}
	mustContain(t, dupAgain.Stderr+dupAgain.Stdout, "dup", "repo add с занятым алиасом")

	// update: git fetch + переиндексация — на file://-репозитории без новых
	// коммитов должен просто пройти чисто.
	mustRun(t, home, "", "repo", "update", "dup")

	// remove: алиас исчезает из списка репозиториев.
	mustRun(t, home, "", "repo", "remove", "dup")
	afterRemove := mustRun(t, home, "", "repo", "list")
	if strings.Contains(afterRemove.Stdout, "dup") {
		t.Errorf("repo remove: алиас %q всё ещё в списке:\n%s", "dup", afterRemove.Stdout)
	}
	if exists(filepath.Join(home, "repos", "dup")) {
		t.Error("repo remove: каталог клона repos/dup должен быть удалён")
	}
}
