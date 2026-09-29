package engine

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// fixturesRoot returns the absolute testdata/fixtures path relative to this
// test file (internal/engine/), independent of the `go test` working directory.
func fixturesRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "fixtures")
}

// loadFixtureTemplate loads and validates a fixture template manifest.
func loadFixtureTemplate(t *testing.T, dir string) *manifest.Template {
	t.Helper()
	tpl, err := manifest.LoadTemplate(filepath.Join(dir, "template.manifest.yaml"))
	if err != nil {
		t.Fatalf("LoadTemplate(%s): %v", dir, err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatalf("fixture %s is invalid: %v", dir, err)
	}
	return tpl
}

// resolveFixture wraps settings.Resolve and calls t.Fatal on error.
func resolveFixture(t *testing.T, tpl *manifest.Template, explicit settings.Values) settings.Resolved {
	t.Helper()
	resolved, err := settings.Resolve(tpl, explicit)
	if err != nil {
		t.Fatalf("settings.Resolve: %v", err)
	}
	return resolved
}

func demoProject() manifest.ProjectInfo {
	return manifest.ProjectInfo{
		Name:   "Demo Svc",
		Slug:   "demo_svc",
		Module: "git.example.test/demo_svc",
		System: "platform",
		Domain: "orders",
	}
}

// renderSingleBasic renders the single-basic fixture with the given settings
// into target, loading its partials (files/../partials).
func renderSingleBasic(t *testing.T, target string, explicit settings.Values) *Result {
	t.Helper()
	dir := filepath.Join(fixturesRoot(t), "single-basic")
	tpl := loadFixtureTemplate(t, dir)
	resolved := resolveFixture(t, tpl, explicit)

	partials, err := fs.Sub(os.DirFS(dir), "partials")
	if err != nil {
		t.Fatalf("fs.Sub(partials): %v", err)
	}

	res, err := Render(Options{
		Source:   os.DirFS(dir),
		Target:   target,
		Template: tpl,
		Resolved: resolved,
		Project:  demoProject(),
		Runtime:  manifest.ProjectRuntime{Port: 8080},
		Repo:     "https://github.com/tplAIter/tplaiter-fixtures.git",
		Partials: []fs.FS{partials},
	})
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	return res
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected %s to be absent, stat err = %v", path, err)
	}
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected %s to exist: %v", path, err)
	}
}

func TestRenderSingleBasicDefaults(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	renderSingleBasic(t, dir, settings.Values{})

	// database=none, brokers=[]: all conditional branches are disabled.
	mustNotExist(t, filepath.Join(dir, "db", "schema.sql"))
	mustNotExist(t, filepath.Join(dir, "brokers-enabled.txt"))
	mustNotExist(t, filepath.Join(dir, "extra", "postgres-only.txt"))
	// Neither kafka nor rabbitmq: composite removal (when with &&) applied.
	mustNotExist(t, filepath.Join(dir, "integrations", "common.txt"))
	// database=none and brokers=[]: the legacy note was not removed (anyOf/OR is false).
	mustExist(t, filepath.Join(dir, "legacy", "notice.txt"))

	readme := readFileString(t, filepath.Join(dir, "README.md"))
	if !strings.Contains(readme, "Database: none") {
		t.Errorf("README.md missing 'Database: none':\n%s", readme)
	}
	if !strings.Contains(readme, "Kafka: disabled") || !strings.Contains(readme, "RabbitMQ: disabled") {
		t.Errorf("README.md missing disabled brokers:\n%s", readme)
	}

	main := readFileString(t, filepath.Join(dir, "main.txt"))
	if !strings.Contains(main, "project=demo_svc") || !strings.Contains(main, "module=git.example.test/demo_svc") {
		t.Errorf("main.txt missing project identity:\n%s", main)
	}
	if !strings.Contains(main, "port=8080") {
		t.Errorf("main.txt missing runtime port:\n%s", main)
	}
	if !strings.Contains(main, "template=single-basic@0.1.0") {
		t.Errorf("main.txt missing template coordinates:\n%s", main)
	}
	if !strings.Contains(main, "hello, DemoSvc!") {
		t.Errorf("main.txt missing partial-rendered greeting:\n%s", main)
	}

	// The __slug__ placeholder in a file name.
	envFile := readFileString(t, filepath.Join(dir, "config", "demo_svc.env"))
	if envFile != "SLUG=demo_svc\n" {
		t.Errorf("config/demo_svc.env = %q, want SLUG=demo_svc\\n", envFile)
	}

	// copyWithoutRender + postReplace.
	dashboard := readFileString(t, filepath.Join(dir, "dashboards", "board.json"))
	if !strings.Contains(dashboard, "{{ __rate_interval }}") {
		t.Errorf("dashboard should preserve literal {{ __rate_interval }}:\n%s", dashboard)
	}
	if strings.Contains(dashboard, "__PROJECT_SLUG__") {
		t.Errorf("__PROJECT_SLUG__ was not substituted:\n%s", dashboard)
	}
	if !strings.Contains(dashboard, "demo_svc overview") {
		t.Errorf("expected slug demo_svc in dashboard title:\n%s", dashboard)
	}
}

func TestRenderSingleBasicPostgresKafka(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	res := renderSingleBasic(t, dir, settings.Values{
		"database":   "postgres",
		"migrations": true,
		"brokers":    []string{"kafka"},
	})

	schema := readFileString(t, filepath.Join(dir, "db", "schema.sql"))
	if !strings.Contains(schema, "CREATE TABLE demo_svc_demo") {
		t.Errorf("schema.sql missing table:\n%s", schema)
	}
	if !strings.Contains(schema, "migrations enabled") {
		t.Errorf("schema.sql should report migrations enabled:\n%s", schema)
	}

	mustExist(t, filepath.Join(dir, "brokers-enabled.txt"))
	mustExist(t, filepath.Join(dir, "extra", "postgres-only.txt"))
	// brokers=[kafka]: composite removal (when with &&) did not apply.
	mustExist(t, filepath.Join(dir, "integrations", "common.txt"))
	// database=postgres: anyOf/OR is true (the first atom), so legacy was removed.
	mustNotExist(t, filepath.Join(dir, "legacy", "notice.txt"))

	readme := readFileString(t, filepath.Join(dir, "README.md"))
	if !strings.Contains(readme, "Database: PostgreSQL") || !strings.Contains(readme, "Kafka: enabled") {
		t.Errorf("README.md missing postgres/kafka markers:\n%s", readme)
	}

	// __if_database=postgres__ and __if_brokers__ were removed from paths.
	mustNotExist(t, filepath.Join(dir, "__if_database=postgres__"))
	mustNotExist(t, filepath.Join(dir, "__if_brokers__"))

	// baseline: the file exists but is not included in Result.Files.
	mustExist(t, filepath.Join(dir, filepath.FromSlash(BaselineRelPath)))
	for _, f := range res.Files {
		if f == BaselineRelPath {
			t.Errorf("Result.Files must not include the baseline itself: %v", res.Files)
		}
	}
	// Fixture NOTES.tmpl/README.md files outside Engine.Root are not output.
	mustNotExist(t, filepath.Join(dir, "NOTES.tmpl"))
	mustNotExist(t, filepath.Join(dir, "template.manifest.yaml"))

	if res.Baseline.TemplateVersion != "0.1.0" {
		t.Errorf("Baseline.TemplateVersion = %q, want 0.1.0", res.Baseline.TemplateVersion)
	}
	if res.Context == nil || res.Context.Project.Slug != "demo_svc" {
		t.Errorf("Result.Context is not populated as expected: %+v", res.Context)
	}
}

func TestRenderDeterministic(t *testing.T) {
	values := settings.Values{"database": "postgres", "migrations": true, "brokers": []string{"kafka", "rabbitmq"}}
	res1 := renderSingleBasic(t, filepath.Join(t.TempDir(), "a"), values)
	res2 := renderSingleBasic(t, filepath.Join(t.TempDir(), "b"), values)

	if !reflect.DeepEqual(res1.Baseline, res2.Baseline) {
		t.Errorf("baseline is not stable:\n first=%+v\n second=%+v", res1.Baseline, res2.Baseline)
	}
	if !reflect.DeepEqual(res1.Files, res2.Files) {
		t.Errorf("file list is not stable:\n first=%v\n second=%v", res1.Files, res2.Files)
	}
	if len(res1.Files) == 0 {
		t.Fatal("expected non-empty Result.Files")
	}
	sorted := append([]string(nil), res1.Files...)
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1] > sorted[i] {
			t.Errorf("Result.Files is not sorted: %v", sorted)
			break
		}
	}
}

func TestRenderNonEmptyTargetFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	fixDir := filepath.Join(fixturesRoot(t), "single-basic")
	tpl := loadFixtureTemplate(t, fixDir)
	resolved := resolveFixture(t, tpl, settings.Values{})

	_, err := Render(Options{
		Source:   os.DirFS(fixDir),
		Target:   dir,
		Template: tpl,
		Resolved: resolved,
		Project:  demoProject(),
	})
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("expected non-empty target error, got %v", err)
	}
}

func TestRenderRequiresTemplateAndSource(t *testing.T) {
	if _, err := Render(Options{Source: os.DirFS(t.TempDir()), Target: t.TempDir()}); err == nil {
		t.Error("expected error for nil Template")
	}
	if _, err := Render(Options{Template: &manifest.Template{}, Target: t.TempDir()}); err == nil {
		t.Error("expected error for nil Source")
	}
}

// TestRenderNamePlaceholders checks __slug__/__module__ in file and directory
// names using an isolated in-memory template (not a fixture; this scenario is
// specific to substitution mechanics rather than content rendering).
func TestRenderNamePlaceholders(t *testing.T) {
	src := fstest.MapFS{
		"files/__slug__/config/__slug__.txt.tmpl": {Data: []byte("id={{ .Project.Slug }}")},
		"files/__module__/mod.txt":                {Data: []byte("static")},
	}
	tpl := &manifest.Template{
		Metadata: manifest.TemplateMeta{Name: "t", Version: "1.0.0"},
		Engine:   manifest.Engine{Root: "files"},
	}
	dir := filepath.Join(t.TempDir(), "out")
	res, err := Render(Options{
		Source:   src,
		Target:   dir,
		Template: tpl,
		Resolved: settings.Resolved{ActiveValues: settings.Values{}},
		Project:  manifest.ProjectInfo{Name: "Demo", Slug: "demo_svc", Module: "acmemod"},
	})
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	wantFiles := []string{"demo_svc/config/demo_svc.txt", "acmemod/mod.txt"}
	got := append([]string(nil), res.Files...)
	for _, w := range wantFiles {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Files = %v, missing %s", got, w)
		}
	}
	data := readFileString(t, filepath.Join(dir, "demo_svc", "config", "demo_svc.txt"))
	if data != "id=demo_svc" {
		t.Errorf("content = %q, want id=demo_svc", data)
	}
}

// TestRenderMultiFixture checks that both mini-templates in the multi-repository
// fixture (the / implementation) render correctly, guarding against fixture breakage.
func TestRenderMultiFixture(t *testing.T) {
	for _, tc := range []struct {
		name     string
		explicit settings.Values
		want     string
	}{
		{"alpha", settings.Values{}, "alpha says hi to Demo Svc\n(greeting on)"},
		{"beta", settings.Values{"label": "custom"}, "beta label=custom for demo_svc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(fixturesRoot(t), "multi", tc.name)
			tpl := loadFixtureTemplate(t, dir)
			resolved := resolveFixture(t, tpl, tc.explicit)

			target := filepath.Join(t.TempDir(), "out")
			if _, err := Render(Options{
				Source:   os.DirFS(dir),
				Target:   target,
				Template: tpl,
				Resolved: resolved,
				Project:  demoProject(),
			}); err != nil {
				t.Fatalf("Render(%s) = %v", tc.name, err)
			}
			got := strings.TrimSpace(readFileString(t, filepath.Join(target, "hello.txt")))
			if got != tc.want {
				t.Errorf("%s hello.txt = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}
