package e2e

import (
	"path/filepath"
	"testing"
)

// TestMultiRepoAmbiguous прогоняет пайплайн мульти-шаблонного репозитория и
// неоднозначность коротких имён (сценарий 4, требование реализацию): repo add
// testdata/fixtures/multi (alpha+beta) под одним алиасом, затем ВТОРОЙ
// репозиторий, содержащий шаблон с ТЕМ ЖЕ именем "alpha" — короткая ссылка
// без repo/-префикса обязана дать ошибку неоднозначности со списком
// кандидатов (internal/repo/resolve.go:findTemplate).
func TestMultiRepoAmbiguous(t *testing.T) {
	requireGit(t)
	t.Parallel()

	home := newHome(t)
	fixtures := fixturesDir(t)

	// multi1: репозиторий-фикстура testdata/fixtures/multi (repo.manifest.yaml,
	// шаблоны alpha/beta) — теги namespaced по  (<name>/vX.Y.Z).
	multiOrigin := filepath.Join(t.TempDir(), "multi-origin")
	copyTree(t, filepath.Join(fixtures, "multi"), multiOrigin)
	initGitOrigin(t, multiOrigin, "alpha/v1.0.0", "beta/v1.0.0")
	mustRun(t, home, "", "repo", "add", "multi1", "file://"+multiOrigin)

	// multi2: одиночный репозиторий, чей ЕДИНСТВЕННЫЙ шаблон тоже называется
	// "alpha" (копия testdata/fixtures/multi/alpha как корня репозитория) —
	// создаёт неоднозначность короткого имени "alpha" между multi1 и multi2.
	alphaOnlyOrigin := buildSingleOrigin(t, filepath.Join(fixtures, "multi", "alpha"), "v1.0.0")
	mustRun(t, home, "", "repo", "add", "multi2", "file://"+alphaOnlyOrigin)

	// Список каталога видит оба шаблона alpha (по одному в каждом репо) плюс beta.
	list := mustRun(t, home, "", "template", "list")
	mustContain(t, list.Stdout, "alpha", "template list (multi)")
	mustContain(t, list.Stdout, "beta", "template list (multi)")

	// Короткое имя "alpha" неоднозначно — ошибка со списком кандидатов
	// "<alias>/alpha" для каждого совпадения.
	ambiguous := run(t, home, "", "template", "show", "alpha")
	if ambiguous.ExitCode == 0 {
		t.Fatalf("template show alpha: ожидалась ошибка неоднозначности, получен exit 0\n%s", ambiguous.Stdout)
	}
	combined := ambiguous.Stderr + ambiguous.Stdout
	mustContain(t, combined, "multi1/alpha", "неоднозначное имя alpha")
	mustContain(t, combined, "multi2/alpha", "неоднозначное имя alpha")

	// Уточнение через repo/ снимает неоднозначность.
	mustRun(t, home, "", "template", "show", "multi1/alpha")
	mustRun(t, home, "", "template", "show", "multi2/alpha")

	// Пайплайн multi целиком: `new` из шаблона beta (уникальное имя, без
	// неоднозначности) успешно создаёт проект.
	projDir := filepath.Join(t.TempDir(), "beta-proj")
	mustRun(t, home, "", "new", "multi1/beta", "Beta Project", "--dir", projDir, "--defaults")
	if !exists(filepath.Join(projDir, ".tplaiter", "project.yaml")) {
		t.Error("new multi1/beta: отсутствует проектный маркер")
	}
}
