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

// runFixtureManifest — minimal manifest snapshot for run tests: `echoargs`
// prints passed args to marker.txt (testing arguments after `--`), `failcmd`
// exits with code 3 (testing exit-code forwarding), and `avail`/`unavail` are
// commands with when conditions, one matching fixture settings
// (database=postgres) and one not.
//
// echoargs does NOT contain its own "$@" — execRunCommand appends ` "$@"` to
// the run command (see run.go). `> marker.txt` redirects printf itself rather
// than being a separate command, so appended positional parameters become
// additional printf operands regardless of where the redirect appears.
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

// newRunFixture creates a project directory (.tplaiter/project.yaml plus
// .tplaiter/manifest.snapshot.yaml) and makes it the process working directory
// for the test (restored through t.Cleanup). It returns the project root.
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

	// Fixture sanity check: the manifest must parse through the same path used by
	// project.LoadManifestForProject, so a YAML typo fails here rather than as an
	// obscure error deep inside the test.
	if _, err := manifest.LoadSnapshot(filepath.Join(tplDir, "manifest.snapshot.yaml")); err != nil {
		t.Fatalf("фикстура манифеста невалидна: %v", err)
	}

	return root
}

// runRunCmd executes a freshly built `run` command with the given args, returning
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
	spy := new(doctorSpyRunner)
	old := runRunner
	runRunner = spy
	t.Cleanup(func() { runRunner = old })

	_, err := runRunCmd(t, "echoargs", "--", "foo", "bar --baz")
	if !errors.Is(err, ErrActionUnavailable) {
		t.Fatalf("run echoargs error = %v, want typed denial", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "marker.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("run action wrote marker after denial: %v", statErr)
	}
	if spy.calls != 0 {
		t.Fatalf("run action touched runner before denial: %d calls", spy.calls)
	}
}

func TestRunDirectCobraActionDeniedBeforeContextDiscovery(t *testing.T) {
	project := t.TempDir()
	home := filepath.Join(t.TempDir(), "hostile-home-CANARY")
	canary := filepath.Join(project, "project-CANARY")
	if err := os.WriteFile(canary, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	t.Setenv(state.HomeEnv, home)
	t.Setenv("HOME", home)
	spy := new(doctorSpyRunner)
	old := runRunner
	runRunner = spy
	t.Cleanup(func() { runRunner = old })

	c := newRunCmd()
	var out, stderr bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&stderr)
	c.SetArgs([]string{"CANARY-command"})
	err := c.Execute()
	if !errors.Is(err, ErrActionUnavailable) {
		t.Fatalf("direct run = %v, want typed denial", err)
	}
	if strings.Contains(err.Error(), "CANARY") || strings.Contains(out.String()+stderr.String(), "CANARY") {
		t.Fatalf("denial leaked hostile input: err=%q output=%q", err, out.String()+stderr.String())
	}
	if _, statErr := os.Stat(home); !os.IsNotExist(statErr) {
		t.Fatalf("direct run initialized home: %v", statErr)
	}
	data, readErr := os.ReadFile(canary)
	if readErr != nil || string(data) != "unchanged" {
		t.Fatalf("direct run changed project: %q, %v", data, readErr)
	}
	if spy.calls != 0 {
		t.Fatalf("direct run touched runner: %d calls", spy.calls)
	}
}

func TestRun_Exec_NoArgs(t *testing.T) {
	root := newRunFixture(t)

	if _, err := runRunCmd(t, "echoargs"); !errors.Is(err, ErrActionUnavailable) {
		t.Fatalf("run echoargs error = %v, want typed denial", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "marker.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("run action wrote marker after denial: %v", statErr)
	}
}

func TestRun_Exec_ExitCodePropagates(t *testing.T) {
	newRunFixture(t)

	_, err := runRunCmd(t, "failcmd")
	if err == nil {
		t.Fatal("run failcmd: ожидалась ошибка")
	}
	if !errors.Is(err, ErrActionUnavailable) {
		t.Fatalf("err = %v, want typed denial", err)
	}
}

func TestRun_Exec_WhenMismatch(t *testing.T) {
	newRunFixture(t)

	_, err := runRunCmd(t, "unavail")
	if err == nil {
		t.Fatal("run unavail: ожидалась ошибка when-гейта")
	}
	if !errors.Is(err, ErrActionUnavailable) {
		t.Fatalf("err = %v, want typed denial", err)
	}
}

func TestRun_Exec_UnknownCommand(t *testing.T) {
	newRunFixture(t)

	_, err := runRunCmd(t, "does-not-exist")
	if err == nil {
		t.Fatal("run does-not-exist: ожидалась ошибка")
	}
	if !errors.Is(err, ErrActionUnavailable) {
		t.Fatalf("err = %v, want typed denial", err)
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
