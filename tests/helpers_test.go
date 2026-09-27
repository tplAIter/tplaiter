package e2e

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runResult — результат одного запуска бинарника tplater.
type runResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// gitIdentityEnv — переменные окружения git для ДЕТЕРМИНИРОВАННЫХ коммитов
// без зависимости от глобального ~/.gitconfig машины (по образцу
// internal/newcmd/newcmd_test.go:gitEnv). Передаются И нашим служебным git-
// командам (сборка origin-фикстур), И самому тестируемому бинарнику tplater
// (repo add клонирует, init-template делает git init+commit) — иначе
// `tplater init-template` внутри процесса без user.name/user.email просто
// понижает сбой коммита до предупреждения (см. inittemplate.go:initGit) и
// сценарий 1 не увидел бы .git с реальным коммитом на CI-раннере без
// настроенной git-идентичности.
func gitIdentityEnv() []string {
	return []string{
		"GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@example.com",
		"GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	}
}

// newHome создаёт изолированный TPLAITER_HOME для одного теста и
// предзаполняет config.yaml с updates.check=false — иначе ЛЮБАЯ команда
// (кроме help/version/completion/self-upgrade, см.
// internal/cmd/selfupgrade.go:suggestSkip) на первом же запуске в свежем
// TPLAITER_HOME запускает фоновую `git ls-remote --tags
// <канонический-репозиторий-tplater>` (internal/selfupdate.MaybeSuggest) —
// сетевой поход с таймаутом до 2с на КАЖДЫЙ тест, лишний и потенциально
// нестабильный на раннере без доступа к сети. Формат — ровно то, что пишет
// state.SaveConfig (internal/state/config.go), проверено юнит-тестами того
// пакета; здесь не импортируем internal-пакеты (черный ящик), поэтому пишем
// тот же YAML текстом.
func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	cfg := "version: 1\nrepos: []\ndefaults: {}\nupdates:\n  check: false\n"
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("newHome: запись config.yaml: %v", err)
	}
	return home
}

// run запускает бинарник tplater с TPLAITER_HOME=home и рабочим каталогом dir
// (пустая строка — временный пустой каталог, т.е. заведомо НЕ внутри
// какого-либо проекта/шаблона). Никогда не вызывает t.Fatal на ненулевой
// код возврата — само по себе это не ошибка теста, лишь на сбой запуска
// процесса (бинарник не найден и т.п.).
func run(t *testing.T, home, dir string, args ...string) runResult {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}

	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	cmd.Env = append(append(
		os.Environ(),
		"TPLAITER_HOME="+home,
		"NO_COLOR=1",
		// $SHELL — используется `tplater run`/hooks (execRunCommand); нормализуем
		// на POSIX shell, независимо от shell окружения раннера/разработчика.
		"SHELL=/bin/sh",
	), gitIdentityEnv()...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run tplater %v: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
		}
	}
	return runResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}
}

// mustRun — вариант run, который проваливает тест немедленно, если
// exit-код ненулевой (для шагов сценария, обязанных пройти чисто).
func mustRun(t *testing.T, home, dir string, args ...string) runResult {
	t.Helper()
	res := run(t, home, dir, args...)
	if res.ExitCode != 0 {
		t.Fatalf("tplater %v: exit=%d\nstdout:\n%s\nstderr:\n%s", args, res.ExitCode, res.Stdout, res.Stderr)
	}
	return res
}

// requireGit скипает тест, если git не найден в PATH — тот же контракт, что
// у internal/newcmd/newcmd_test.go и internal/inittemplate/e2e_test.go (git
// нужен и харнессу для сборки origin-фикстур, и самому tplater для repo
// add/init-template).
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git не найден в PATH — e2e пропущен")
	}
}

// runGit исполняет git-команду с детерминированной идентичностью
// (gitIdentityEnv) — используется ТОЛЬКО харнессом для подготовки
// origin-репозиториев фикстур, не для самого tplater (тот запускает git
// сам через свой Runner).
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), gitIdentityEnv()...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (dir=%s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

// copyTree копирует дерево файлов src в dst (создавая dst), сохраняя
// относительную структуру — используется для материализации origin-
// репозиториев из testdata/fixtures (мы не коммитим git-объекты в
// testdata — фикстуры остаются обычными файлами для остальных пакетов,
// каждый e2e-тест строит свой временный git-репозиторий из их копии).
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if merr := os.MkdirAll(filepath.Dir(target), 0o755); merr != nil {
			return merr
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copyTree(%s -> %s): %v", src, dst, err)
	}
}

// initGitOrigin инициализирует git-репозиторий в dir (уже наполненном
// файлами: copyTree/os.WriteFile до вызова) — init + commit + опциональные
// теги. Возвращает dir как есть, для удобства цепочки вызовов.
func initGitOrigin(t *testing.T, dir string, tags ...string) string {
	t.Helper()
	runGit(t, dir, "init", "-b", "main")
	runGit(t, dir, "config", "uploadpack.allowFilter", "true")
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-m", "init")
	for _, tag := range tags {
		runGit(t, dir, "tag", tag)
	}
	return dir
}

// fixturesDir — корень testdata/fixtures основного репозитория (единственная
// зависимость e2e-харнесса от файловой системы главного модуля — сами
// фикстуры, не Go-код: single-basic/multi, см. testdata/fixtures/README.md).
func fixturesDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "testdata", "fixtures"))
	if err != nil {
		t.Fatalf("fixturesDir: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("fixturesDir: %s: %v (запущен ли тест из tests/?)", abs, err)
	}
	return abs
}

// buildSingleOrigin материализует одиночный шаблон-репозиторий (одно дерево
// с template.manifest.yaml в корне) из каталога src, тегирует его
// stable-тегами tags (формат "vX.Y.Z" — internal/repo/version.go:stableTagsFor
// для single ждёт тег БЕЗ префикса) и возвращает путь к origin-каталогу.
func buildSingleOrigin(t *testing.T, src string, tags ...string) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	copyTree(t, src, origin)
	return initGitOrigin(t, origin, tags...)
}

// gateFixtureManifest — минимальный манифест шаблона с версия-гейтом
// requires.tplaiter, недостижимым ни одной реальной версией tplater
// (">=99.0.0") — единственный способ детерминированно упражнять
// checkTplaterVersion (internal/newcmd/slug.go) в чёрном ящике: тестовый
// бинарник собран с фиксированной версией buildVersion (см. main_test.go), а
// ни один существующий фикстурный шаблон такого гейта не объявляет
// (testdata/fixtures/single-basic требует лишь >=0.1.0).
const gateFixtureManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: gatetpl
  version: 0.1.0
  description: "e2e-фикстура версия-гейта (requires.tplaiter недостижим)."
engine:
  type: gotemplate
  root: files
requires:
  tplater: ">=99.0.0"
`

// buildVersionGateOrigin строит одиночный шаблон-репозиторий, чей манифест
// требует tplater >=99.0.0 — `tplater new` из него обязан провалиться на
// checkTplaterVersion ДО любого создания файлов (сценарий 3, документацию проекта/требование
// реализацию: "version-гейт").
func buildVersionGateOrigin(t *testing.T) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	if err := os.MkdirAll(filepath.Join(origin, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "template.manifest.yaml"), []byte(gateFixtureManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "files", "hello.txt.tmpl"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return initGitOrigin(t, origin, "v1.0.0")
}

// mustContain проваливает тест, если s не содержит sub. Используется только
// для СТАБИЛЬНЫХ подстрок (имена шаблонов/алиасов/групп настроек — данные из
// фикстур этой же реализации), НЕ для декоративного текста cmd/internal/ui,
// который полирует параллельная реализация реализацию (см. пакетный комментарий
// main_test.go).
func mustContain(t *testing.T, s, sub, what string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("%s: ожидалась подстрока %q, не найдена в:\n%s", what, sub, s)
	}
}

// mustReadFile читает файл path целиком как строку, проваливая тест при
// ошибке — используется для ассертов на содержимое, отрендеренное движком из
// НАШИХ фикстур (не декоративный вывод cmd/internal/ui).
func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение %s: %v", path, err)
	}
	return string(data)
}

// exists — короткая проверка наличия файла/каталога по пути (для ассертов
// «файл создан/удалён» — контракт реализации реализацию: ассерты на существование
// файлов, не на точные строки вывода).
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
