package inittemplate

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInit_GeneratedRepoPassesLint — key test: a generated init-template
// repository must pass its own lint-template.
func TestInit_GeneratedRepoPassesLint(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "demo-svc")
	if _, err := Init(context.Background(), InitOptions{
		Name: "demo-svc", Dir: repo, NoGit: true, Out: io.Discard,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// The skeleton contains a conditional directory and dotfile; verify embed emitted them.
	for _, rel := range []string{
		"template.manifest.yaml",
		"README.md",
		".github/workflows/template.yml",
		"files/README.md.tmpl",
		"files/__if_feature_x__/extra.txt",
		"files/advanced/notes.md.tmpl",
		"generators/example.go.tmpl",
		"ai-config/config.json",
		"ai-config/rules/00-base.md",
		"ai-config/docs/00-base.md",
		"ai-config/targets/agents_md.tmpl",
		"environment/setup.yml",
		"NOTES.tmpl",
	} {
		if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(rel))); err != nil {
			t.Errorf("ожидался файл %s: %v", rel, err)
		}
	}

	res, err := Lint(LintOptions{Path: repo, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if res.Failed {
		t.Fatalf("сгенерированный репозиторий НЕ прошёл lint-template:\n%s", failDetails(res))
	}
	if len(res.Rows) == 0 {
		t.Fatal("lint не дал ни одной строки результата")
	}
}

// TestInit_GeneratedBootstrapUsesCurrentCLI guards the human-facing material
// that init-template emits. Legacy manifest namespaces and directive markers
// are intentionally excluded: they are parsed wire compatibility, not CLI
// advice for a newly generated repository.
func TestInit_GeneratedBootstrapUsesCurrentCLI(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "demo-svc")
	if _, err := Init(context.Background(), InitOptions{
		Name: "demo-svc", Dir: repo, NoGit: true, Out: io.Discard,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	for _, rel := range []string{
		"README.md",
		".github/workflows/template.yml",
	} {
		body, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read generated %s: %v", rel, err)
		}
		if !strings.Contains(string(body), "github.com/tplAIter/tplaiter") {
			t.Errorf("generated %s omits the current CLI bootstrap location:\n%s", rel, body)
		}
	}
}

func TestInit_Multi_PassesLint(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "demo-repo")
	if _, err := Init(context.Background(), InitOptions{
		Name: "demo-svc", Dir: repo, Multi: true, NoGit: true, Out: io.Discard,
	}); err != nil {
		t.Fatalf("Init --multi: %v", err)
	}
	// In multi mode repo.manifest.yaml is at root and the template is in a subdirectory.
	if _, err := os.Stat(filepath.Join(repo, "repo.manifest.yaml")); err != nil {
		t.Fatalf("ожидался repo.manifest.yaml: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "demo-svc", "template.manifest.yaml")); err != nil {
		t.Fatalf("ожидался demo-svc/template.manifest.yaml: %v", err)
	}

	res, err := Lint(LintOptions{Path: repo, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if res.Failed {
		t.Fatalf("multi-репозиторий НЕ прошёл lint:\n%s", failDetails(res))
	}
}

func TestInit_NonEmptyDirErrors(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "occupied")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "existing.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(context.Background(), InitOptions{
		Name: "demo-svc", Dir: repo, NoGit: true, Out: io.Discard,
	}); err == nil {
		t.Fatal("ожидалась ошибка при init в непустой каталог")
	}
}

func TestInit_InvalidName(t *testing.T) {
	for _, name := range []string{"", "Demo_Svc", "demo svc", "demo/svc"} {
		if _, err := Init(context.Background(), InitOptions{
			Name: name, Dir: filepath.Join(t.TempDir(), "r"), NoGit: true, Out: io.Discard,
		}); err == nil {
			t.Errorf("имя %q должно быть отклонено", name)
		}
	}
}

func failDetails(res *LintResult) string {
	var b []byte
	for _, r := range res.Rows {
		if !r.OK {
			b = append(b, []byte(r.Template+" / "+r.Combo+": "+r.Detail+"\n")...)
		}
	}
	return string(b)
}
