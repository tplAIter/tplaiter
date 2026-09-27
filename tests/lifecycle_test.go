package e2e

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestLifecycle прогоняет полный жизненный цикл проекта чёрным ящиком
// (сценарий 1, требование реализацию): init-template (git init/commit включены по
// умолчанию) -> repo add file:// -> template list/show -> new (--set +
// --defaults) -> run test -> settings set -> update --check -> stats --json
// -> projects list.
//
// Источник шаблона — `tplater init-template` (internal/inittemplate), а не
// testdata/fixtures: его скелет несёт settings (feature_x toggle, variant
// select), files-правило, команды, hook, generators, ai-config и environment
// playbook — единственная фикстура репозитория, покрывающая ВСЕ подкоманды
// этого сценария за один проход.
func TestLifecycle(t *testing.T) {
	requireGit(t)
	t.Parallel()

	home := newHome(t)
	base := t.TempDir()
	repoDir := filepath.Join(base, "demo-svc-repo")
	projDir := filepath.Join(base, "proj")

	// 1. init-template: генерирует репозиторий шаблона + git init/commit.
	mustRun(t, home, "", "init-template", "demo-svc", "--dir", repoDir)
	if !exists(filepath.Join(repoDir, ".git")) {
		t.Fatalf("init-template: ожидался git-репозиторий в %s", repoDir)
	}
	if !exists(filepath.Join(repoDir, "template.manifest.yaml")) {
		t.Fatalf("init-template: ожидался template.manifest.yaml в %s", repoDir)
	}

	// 2. repo add file://<repoDir>.
	mustRun(t, home, "", "repo", "add", "example", "file://"+repoDir)

	// 3. template list / list с фильтром по лейблу / show.
	list := mustRun(t, home, "", "template", "list")
	mustContain(t, list.Stdout, "demo-svc", "template list")

	filtered := mustRun(t, home, "", "template", "list", "-l", "lang=example")
	mustContain(t, filtered.Stdout, "demo-svc", "template list -l lang=example")

	show := mustRun(t, home, "", "template", "show", "example/demo-svc")
	mustContain(t, show.Stdout, "demo-svc", "template show")

	// 4. new: --set перекрывает feature_x/variant, --defaults берёт остальное
	// (вложенный toggle verbose под variant=advanced) из дефолтов манифеста.
	mustRun(
		t, home, "", "new", "example/demo-svc", "My Service",
		"--dir", projDir,
		"--module", "example.com/my-service",
		"--set", "feature_x=true",
		"--set", "variant=advanced",
		"--defaults",
	)

	readme := mustReadFile(t, filepath.Join(projDir, "README.md"))
	mustContain(t, readme, "My Service", "README.md рендер имени проекта")
	if !exists(filepath.Join(projDir, "extra.txt")) {
		t.Error("new: feature_x=true должен дать extra.txt (__if_feature_x__/)")
	}
	if !exists(filepath.Join(projDir, "advanced", "notes.md")) {
		t.Error("new: variant=advanced должен дать advanced/notes.md (files-правило)")
	}
	if !exists(filepath.Join(projDir, ".tplaiter", "project.yaml")) {
		t.Fatal("new: отсутствует проектный маркер .tplaiter/project.yaml")
	}

	// 5. run test — команда манифеста (echo-заглушка скелета).
	mustRun(t, home, projDir, "run", "test")

	// 6. settings set: гасим feature_x — 3-way должен убрать extra.txt.
	mustRun(t, home, projDir, "settings", "set", "feature_x=false", "--yes")
	if exists(filepath.Join(projDir, "extra.txt")) {
		t.Error("settings set feature_x=false: extra.txt должен быть удалён 3-way-слиянием")
	}

	// 7. update --check — сканирует дерево на маркеры конфликта; их не
	// должно быть после чистого settings set.
	mustRun(t, home, projDir, "update", "--check")

	// 8. stats --json — валидный JSON со стабильной схемой (internal/stats:
	// FileStat.Score json:"score"), но без проверки конкретного значения.
	statsRes := mustRun(t, home, projDir, "stats", "--json")
	var parsed map[string]any
	if err := json.Unmarshal([]byte(statsRes.Stdout), &parsed); err != nil {
		t.Fatalf("stats --json: невалидный JSON: %v\nstdout:\n%s", err, statsRes.Stdout)
	}
	if _, ok := parsed["score"]; !ok {
		t.Errorf("stats --json: ожидалось поле %q, получено: %v", "score", parsed)
	}

	// 9. projects list — проект зарегистрирован в реестре ~/.tplaiter.
	projList := mustRun(t, home, "", "projects", "list")
	mustContain(t, projList.Stdout, projDir, "projects list")
}
