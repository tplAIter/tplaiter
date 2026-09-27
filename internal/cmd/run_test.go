package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/state"
)

// runFixtureManifest — минимальный снимок манифеста для тестов run:
// `echoargs` печатает переданные args в marker.txt (проверка проброса
// аргументов после `--`), `failcmd` завершается кодом 3 (проверка
// проброса exit-кода), `avail`/`unavail` — команды с when, одно условие
// совпадает с settings фикстурного проекта (database=postgres), другое нет.
//
// echoargs НЕ содержит своего "$@" — execRunCommand сам дописывает
// ` "$@"` в конец run (см. run.go); "> marker.txt" — это редирекция
// самого printf, а не отдельная команда, поэтому дописанные позиционные
// параметры становятся дополнительными операндами printf независимо от
// того, где в строке команды стоит редирекция.
const runFixtureManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: fixture
  version: "1.0.0"
engine:
  type: gotemplate
  root: files/
commands:
  echoargs: { run: "printf '%s\n' > marker.txt", description: "пишет args в marker.txt" }
  failcmd: { run: "exit 3", description: "падает с кодом 3" }
  avail: { run: "true", description: "доступна", when: "database=postgres" }
  unavail: { run: "true", description: "недоступна", when: "database=mysql" }
`

const runFixtureProject = `apiVersion: tplater.dev/v1alpha1
kind: Project
id: test-id
template:
  repo: example
  name: fixture
  version: "1.0.0"
project:
  name: Fixture
  slug: fixture
settings:
  database: postgres
`

// newRunFixture создаёт каталог проекта (.tplaiter/project.yaml +
// .tplaiter/manifest.snapshot.yaml) и делает его текущим рабочим каталогом
// процесса на время теста (restore через t.Cleanup). Возвращает путь к
// корню проекта.
func newRunFixture(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	tplDir := filepath.Join(root, ".tplaiter")
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", tplDir, err)
	}
	if err := os.WriteFile(filepath.Join(tplDir, "project.yaml"), []byte(runFixtureProject), 0o644); err != nil {
		t.Fatalf("write project.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tplDir, "manifest.snapshot.yaml"), []byte(runFixtureManifest), 0o644); err != nil {
		t.Fatalf("write manifest.snapshot.yaml: %v", err)
	}

	t.Setenv(state.HomeEnv, filepath.Join(t.TempDir(), "tplater-home"))

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("Chdir(%s): %v", root, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(prevWD)
	})

	// Санитарная проверка фикстуры: манифест должен парситься тем же путём,
	// каким его читает project.LoadManifestForProject, чтобы опечатка в YAML
	// фикстуры не всплыла как непонятная ошибка глубоко внутри теста.
	if _, err := manifest.LoadSnapshot(filepath.Join(tplDir, "manifest.snapshot.yaml")); err != nil {
		t.Fatalf("фикстура манифеста невалидна: %v", err)
	}

	return root
}

// runRunCmd исполняет свежесобранную команду `run` с заданными args, возвращая
// stdout+stderr.
func runRunCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	c := newRunCmd()
	var out, errBuf bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&errBuf)
	c.SetArgs(args)
	err := c.Execute()
	return out.String() + errBuf.String(), err
}

func TestRun_List_WhenFiltering(t *testing.T) {
	newRunFixture(t)

	out, err := runRunCmd(t)
	if err != nil {
		t.Fatalf("run list error = %v", err)
	}

	lines := strings.Split(out, "\n")
	var availLine, unavailLine string
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "avail":
			availLine = l
		case "unavail":
			unavailLine = l
		}
	}
	if availLine == "" {
		t.Fatalf("не нашли строку avail в выводе:\n%s", out)
	}
	if unavailLine == "" {
		t.Fatalf("не нашли строку unavail в выводе:\n%s", out)
	}
	if strings.Contains(availLine, "недоступно") {
		t.Errorf("avail (when выполнен) помечена как недоступная: %q", availLine)
	}
	if !strings.Contains(unavailLine, "недоступно") {
		t.Errorf("unavail (when не выполнен) не помечена как недоступная: %q", unavailLine)
	}
	if !strings.Contains(out, "echoargs") || !strings.Contains(out, "failcmd") {
		t.Errorf("в списке нет всех команд манифеста:\n%s", out)
	}
}

func TestRun_Exec_ArgsAfterDoubleDash(t *testing.T) {
	root := newRunFixture(t)

	if _, err := runRunCmd(t, "echoargs", "--", "foo", "bar --baz"); err != nil {
		t.Fatalf("run echoargs error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "marker.txt"))
	if err != nil {
		t.Fatalf("marker.txt не создан: %v", err)
	}
	got := strings.TrimRight(string(data), "\n")
	want := "foo\nbar --baz"
	if got != want {
		t.Errorf("marker.txt = %q, want %q", got, want)
	}
}

func TestRun_Exec_NoArgs(t *testing.T) {
	root := newRunFixture(t)

	if _, err := runRunCmd(t, "echoargs"); err != nil {
		t.Fatalf("run echoargs error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "marker.txt"))
	if err != nil {
		t.Fatalf("marker.txt не создан: %v", err)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("marker.txt = %q, want пусто (нет args)", string(data))
	}
}

func TestRun_Exec_ExitCodePropagates(t *testing.T) {
	newRunFixture(t)

	_, err := runRunCmd(t, "failcmd")
	if err == nil {
		t.Fatal("run failcmd: ожидалась ошибка")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("err = %v (%T), want *ExitError", err, err)
	}
	if exitErr.Code != 3 {
		t.Errorf("ExitError.Code = %d, want 3", exitErr.Code)
	}
}

func TestRun_Exec_WhenMismatch(t *testing.T) {
	newRunFixture(t)

	_, err := runRunCmd(t, "unavail")
	if err == nil {
		t.Fatal("run unavail: ожидалась ошибка when-гейта")
	}
	if !strings.Contains(err.Error(), "недоступна при текущих настройках") {
		t.Errorf("err = %v, want упоминание недоступности при текущих настройках", err)
	}
	if !strings.Contains(err.Error(), "database=mysql") {
		t.Errorf("err = %v, want упоминание условия database=mysql", err)
	}
}

func TestRun_Exec_UnknownCommand(t *testing.T) {
	newRunFixture(t)

	_, err := runRunCmd(t, "does-not-exist")
	if err == nil {
		t.Fatal("run does-not-exist: ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "неизвестная команда") {
		t.Errorf("err = %v, want упоминание неизвестной команды", err)
	}
}

func TestRun_OutsideProject(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "not-a-project")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv(state.HomeEnv, filepath.Join(t.TempDir(), "tplater-home"))

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })

	_, err = runRunCmd(t)
	if err == nil {
		t.Fatal("run вне проекта: ожидалась ошибка")
	}
}
