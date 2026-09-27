package aiconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// fixtureTemplate — манифест шаблона с деревом settings (database/brokers),
// достаточным для валидации module.when и гейтинга Filter/Render в тестах
// этого пакета — перенос go-template'овских reg.HasFlag-фикстур на манифест.
func fixtureTemplate() *manifest.Template {
	return &manifest.Template{
		Metadata: manifest.TemplateMeta{Name: "ai-fixture", Version: "0.1.0"},
		Settings: []manifest.SettingGroup{
			{
				Group: "database", Type: manifest.TypeSelect, Default: "none",
				Options: []manifest.Option{{ID: "none"}, {ID: "postgres"}},
			},
			{
				Group: "brokers", Type: manifest.TypeMultiselect, Default: []any{},
				Options: []manifest.Option{{ID: "kafka"}, {ID: "rabbitmq"}},
			},
		},
	}
}

// writeSyntheticSource создаёт минимальный валидный источник ai-config в
// temp dir: config.json + два модуля (00-base безусловный, 06-kafka с
// when=brokers=kafka) + targets/*.tmpl, достаточные для Render.
func writeSyntheticSource(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "config.json"),
		`{"language":"ru","code_language":"en","targets":["cursor","claude","agents_md","gemini"],"line_length":120}`)

	mustWrite(t, filepath.Join(dir, "modules", "00-base.json"),
		`{"id":"00-base","title":"Base","activation":"always","globs":[],"description":"","when":"","rule_file":"rules/00-base.md","doc_file":"docs/base.md"}`)
	mustWrite(t, filepath.Join(dir, "rules", "00-base.md"), "# Base\n\nrule body\n")
	mustWrite(t, filepath.Join(dir, "docs", "base.md"), "# Base doc\n\nbody text\n")

	mustWrite(t, filepath.Join(dir, "modules", "02-models.json"),
		`{"id":"02-models","title":"Models","activation":"globs","globs":["internal/infra/db/models/**"],"when":"database=postgres","rule_file":"rules/02-models.md","doc_file":"docs/models.md"}`)
	mustWrite(t, filepath.Join(dir, "rules", "02-models.md"), "# Models\n")
	mustWrite(t, filepath.Join(dir, "docs", "models.md"), "# Models doc\n")

	mustWrite(t, filepath.Join(dir, "modules", "06-kafka.json"),
		`{"id":"06-kafka","title":"Kafka","activation":"semantic","description":"kafka consumers/producers","when":"brokers=kafka","rule_file":"rules/06-kafka.md","doc_file":"docs/kafka.md"}`)
	mustWrite(t, filepath.Join(dir, "rules", "06-kafka.md"), "# Kafka\n")
	mustWrite(t, filepath.Join(dir, "docs", "kafka.md"), "# Kafka doc\n")

	mustWrite(t, filepath.Join(dir, "targets", "cursorrules.tmpl"),
		`{{ define "cursorrules.tmpl" }}project: {{ .Project.Slug }}{{ end }}`)
	mustWrite(t, filepath.Join(dir, "targets", "cursor_mdc.tmpl"), cursorMDCTmpl)
	mustWrite(t, filepath.Join(dir, "targets", "claude.tmpl"),
		`{{ define "claude.tmpl" }}# CLAUDE.md for {{ .Project.Name }}{{ range .Modules }}
- {{ .ID }}{{ end }}{{ end }}`)
	mustWrite(t, filepath.Join(dir, "targets", "agents.tmpl"),
		`{{ define "agents.tmpl" }}# AGENTS.md{{ end }}`)
	mustWrite(t, filepath.Join(dir, "targets", "gemini.tmpl"),
		`{{ define "gemini.tmpl" }}# GEMINI.md{{ end }}`)

	return dir
}

// cursorMDCTmpl — per-module .mdc с frontmatter, ветвящимся по activation
// (перенос go-template без изменений — формат не относится к when/feature).
const cursorMDCTmpl = `{{ define "cursor_mdc.tmpl" }}---
{{- if eq .Module.Activation "always" }}
alwaysApply: true
{{- else if eq .Module.Activation "globs" }}
globs: {{ joinComma .Module.Globs }}
{{- else if eq .Module.Activation "semantic" }}
description: "{{ .Module.Description }}"
{{- end }}
---
{{ .Module.Rule }}
{{ end }}`

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSyntheticSource(t *testing.T) {
	dir := writeSyntheticSource(t)
	src, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(src.Modules) != 3 {
		t.Fatalf("expected 3 modules, got %d", len(src.Modules))
	}
	if src.Modules[0].ID != "00-base" {
		t.Errorf("first module = %q, want 00-base (sorted)", src.Modules[0].ID)
	}
	if err := src.Validate(fixtureTemplate()); err != nil {
		t.Fatalf("synthetic source must validate: %v", err)
	}
}

func TestFilterByWhen(t *testing.T) {
	src, err := Load(writeSyntheticSource(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	without, err := src.Filter(settings.Values{"database": "none", "brokers": []string{}})
	if err != nil {
		t.Fatalf("Filter: %v", err)
	}
	if containsModule(without, "06-kafka") {
		t.Error("06-kafka must be excluded when brokers does not contain kafka")
	}
	if containsModule(without, "02-models") {
		t.Error("02-models must be excluded when database != postgres")
	}
	if !containsModule(without, "00-base") {
		t.Error("00-base (when=\"\") must always be included")
	}

	with, err := src.Filter(settings.Values{"database": "postgres", "brokers": []string{"kafka"}})
	if err != nil {
		t.Fatalf("Filter: %v", err)
	}
	if !containsModule(with, "06-kafka") {
		t.Error("06-kafka must be included when brokers contains kafka")
	}
	if !containsModule(with, "02-models") {
		t.Error("02-models must be included when database=postgres")
	}
}

func TestFilterUnknownGroupErrors(t *testing.T) {
	src, err := Load(writeSyntheticSource(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Портим when одного модуля на ссылку на несуществующую группу.
	for i := range src.Modules {
		if src.Modules[i].ID == "06-kafka" {
			src.Modules[i].When = "nope=1"
		}
	}
	if _, err := src.Filter(settings.Values{"database": "none", "brokers": []string{}}); err == nil {
		t.Error("expected error for module.when referencing unknown group")
	}
}

func containsModule(mods []LoadedModule, id string) bool {
	for _, m := range mods {
		if m.ID == id {
			return true
		}
	}
	return false
}

func TestRenderCursorFrontmatter(t *testing.T) {
	src, err := Load(writeSyntheticSource(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	root := t.TempDir()
	_, err = src.Render(RenderOptions{
		TargetRoot: root,
		Values:     settings.Values{"database": "postgres", "brokers": []string{}},
		Targets:    []string{TargetCursor},
		Project:    manifest.ProjectInfo{Name: "demo", Slug: "demo"},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	assertFrontmatter(t, root, "00-base", "alwaysApply: true")
	assertFrontmatter(t, root, "02-models", "globs: internal/infra/db/models/**")

	if _, err := os.Stat(filepath.Join(root, ".cursorrules")); err != nil {
		t.Errorf(".cursorrules not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".cursor", "docs", "base.md")); err != nil {
		t.Errorf("base.md doc not written: %v", err)
	}
	// kafka off -> 06-kafka.mdc не должен существовать.
	if _, err := os.Stat(filepath.Join(root, ".cursor", "rules", "06-kafka.mdc")); err == nil {
		t.Error("06-kafka.mdc must not exist when brokers does not contain kafka")
	}
}

func assertFrontmatter(t *testing.T, root, ruleName, want string) {
	t.Helper()
	path := filepath.Join(root, ".cursor", "rules", ruleName+".mdc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	content := string(data)
	if !strings.HasPrefix(content, "---\n") {
		t.Fatalf("%s: no frontmatter start; got:\n%s", ruleName, content[:min(80, len(content))])
	}
	end := strings.Index(content[4:], "---")
	fm := content[4 : 4+end]
	if !strings.Contains(fm, want) {
		t.Errorf("%s frontmatter = %q, want to contain %q", ruleName, fm, want)
	}
}

func TestRenderIdempotent(t *testing.T) {
	src, err := Load(writeSyntheticSource(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	values := settings.Values{"database": "postgres", "brokers": []string{"kafka"}}

	first := t.TempDir()
	second := t.TempDir()
	opts := func(root string) RenderOptions {
		return RenderOptions{TargetRoot: root, Values: values, Project: manifest.ProjectInfo{Name: "demo", Slug: "demo"}}
	}
	r1, err := src.Render(opts(first))
	if err != nil {
		t.Fatalf("first render: %v", err)
	}
	r2, err := src.Render(opts(second))
	if err != nil {
		t.Fatalf("second render: %v", err)
	}
	if len(r1.Written) != len(r2.Written) {
		t.Fatalf("written count differs: %d vs %d", len(r1.Written), len(r2.Written))
	}
	for _, rel := range r1.Written {
		a, err := os.ReadFile(filepath.Join(first, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		b, err := os.ReadFile(filepath.Join(second, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if string(a) != string(b) {
			t.Errorf("non-idempotent output for %s", rel)
		}
	}
}

func TestRenderProtects99(t *testing.T) {
	src, err := Load(writeSyntheticSource(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	root := t.TempDir()
	rulesDir := filepath.Join(root, ".cursor", "rules")
	if err := os.MkdirAll(rulesDir, 0o750); err != nil {
		t.Fatal(err)
	}
	projectRule := filepath.Join(rulesDir, "99-project.mdc")
	const custom = "custom project rule — must survive"
	if err := os.WriteFile(projectRule, []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := src.Render(RenderOptions{
		TargetRoot: root,
		Values:     settings.Values{"database": "postgres", "brokers": []string{}},
		Targets:    []string{TargetCursor},
	}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	got, err := os.ReadFile(projectRule)
	if err != nil {
		t.Fatalf("read 99-project.mdc: %v", err)
	}
	if string(got) != custom {
		t.Errorf("99-project.mdc was overwritten: %q", string(got))
	}
}

func TestValidateBrokenJSON(t *testing.T) {
	dir := writeSyntheticSource(t)
	broken := filepath.Join(dir, "modules", "00-base.json")
	if err := os.WriteFile(broken, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("expected Load error on malformed module json")
	}
}

func TestValidateDuplicateID(t *testing.T) {
	dir := writeSyntheticSource(t)
	dup := filepath.Join(dir, "modules", "00-base-copy.json")
	if err := os.WriteFile(dup, []byte(`{"id":"00-base","title":"Dup","activation":"always","when":"","rule_file":"rules/00-base.md","doc_file":"docs/base.md"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := src.Validate(fixtureTemplate()); err == nil || !strings.Contains(err.Error(), "дублирующийся id") {
		t.Fatalf("expected duplicate id error, got: %v", err)
	}
}

func TestValidateUnknownWhenGroup(t *testing.T) {
	dir := writeSyntheticSource(t)
	bad := filepath.Join(dir, "modules", "50-bad.json")
	if err := os.WriteFile(bad, []byte(`{"id":"50-bad","title":"Bad","activation":"globs","globs":["x/**"],"when":"nonexistent_group=1","rule_file":"rules/00-base.md","doc_file":"docs/base.md"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := src.Validate(fixtureTemplate()); err == nil || !strings.Contains(err.Error(), "несуществующую группу") {
		t.Fatalf("expected unknown-group error, got: %v", err)
	}
}

func TestValidateBrokenWhenSyntax(t *testing.T) {
	dir := writeSyntheticSource(t)
	bad := filepath.Join(dir, "modules", "50-bad.json")
	if err := os.WriteFile(bad, []byte(`{"id":"50-bad","title":"Bad","activation":"always","when":"database","rule_file":"rules/00-base.md","doc_file":"docs/base.md"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := src.Validate(fixtureTemplate()); err == nil {
		t.Fatal("expected error for malformed when syntax (missing operator)")
	}
}
