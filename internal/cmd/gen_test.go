package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/state"
)

// runGenArgs вызывает runGen напрямую с заданными аргументами (без проекта) —
// проверяет разбор позиционных <kind> <name> ДО резолва run-контекста.
func runGenArgs(t *testing.T, args ...string) error {
	t.Helper()
	cmd := &cobra.Command{Use: "gen"}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return runGen(cmd, args)
}

func TestValidateGenBatchParams(t *testing.T) {
	declared := []manifest.Param{{Name: "fields"}, {Name: "aggregate"}}
	if err := validateGenBatchParams(declared, map[string]string{"fields": "id:uuid"}); err != nil {
		t.Fatalf("known param: %v", err)
	}
	err := validateGenBatchParams(declared, map[string]string{"unknown": "x"})
	if err == nil || !strings.Contains(err.Error(), "неизвестный параметр --unknown") {
		t.Fatalf("unknown param: got %v", err)
	}
}

func TestRunGen_ArgValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no_args", nil, "требует аргументы"},
		{"one_arg", []string{"crud"}, "требует аргументы"},
		{"kind_is_flag", []string{"--fields", "x"}, "ожидается <kind>"},
		{"name_is_flag", []string{"crud", "--fields"}, "ожидается <name>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runGenArgs(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("args %v: expected error %q, got %v", tc.args, tc.want, err)
			}
		})
	}
}

// TestRunGen_HelpArg: -h как первый аргумент печатает справку и не требует
// проекта.
func TestRunGen_HelpArg(t *testing.T) {
	cmd := &cobra.Command{Use: "gen"}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := runGen(cmd, []string{"-h"}); err != nil {
		t.Fatalf("gen -h: %v", err)
	}
}

func TestGenBatch_ValidatesOperationsBeforeProjectLookup(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing", nil, "обязателен --operations"},
		{"invalid_json", []string{"--operations", "["}, "разбор --operations JSON"},
		{"empty", []string{"--operations", "[]"}, "список операций пуст"},
		{"missing_kind", []string{"--operations", `[{"name":"Ride"}]`}, "требует kind и name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newGenBatchCmd()
			c.SetOut(&bytes.Buffer{})
			c.SetErr(&bytes.Buffer{})
			c.SetArgs(tc.args)
			err := c.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("args %v: expected %q, got %v", tc.args, tc.want, err)
			}
		})
	}
}

func setupPatternGenProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".tplaiter", "generators"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".tplaiter", "project.yaml"), []byte(`apiVersion: tplater.dev/v1alpha1
kind: Project
id: pattern-test
template: { repo: local, name: local, version: 1.0.0 }
project: { name: pattern-test, slug: pattern-test, module: example/pattern-test }
settings: {}
runtime: { port: 8080 }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".tplaiter", "generators", "migration.sql.tmpl"), []byte("CREATE TABLE {{ index .Params \"table\" }} ();\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tpl := &manifest.Template{
		APIVersion: manifest.APIVersion,
		Kind:       manifest.KindTemplate,
		Metadata:   manifest.TemplateMeta{Name: "local", Version: "1.0.0"},
		Generators: []manifest.Generator{{
			Kind: "migration", Snippet: "migration.sql.tmpl", Target: "migrations/{{ .Name.Snake }}.sql",
			Params: []manifest.Param{{Name: "table", Type: manifest.ParamTypeString, Required: true, Pattern: `^[a-z_][a-z0-9_]*$`}},
		}},
	}
	if err := manifest.SaveSnapshot(filepath.Join(dir, manifest.SnapshotRelPath), tpl); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunGen_PatternFailureDoesNotWriteFile(t *testing.T) {
	dir := setupPatternGenProject(t)
	t.Chdir(dir)
	t.Setenv(state.HomeEnv, filepath.Join(t.TempDir(), "tplater-home"))
	cmd := &cobra.Command{Use: "gen"}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runGen(cmd, []string{"migration", "create_rides", "--table", "rides; DROP TABLE rides", "--no-build"})
	if err == nil || !strings.Contains(err.Error(), "не соответствует pattern") {
		t.Fatalf("expected pattern rejection, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "migrations", "create_rides.sql")); !os.IsNotExist(statErr) {
		t.Errorf("single gen wrote a file after pattern rejection: %v", statErr)
	}
}

func TestGenBatch_PatternFailureDoesNotWriteFiles(t *testing.T) {
	dir := setupPatternGenProject(t)
	t.Chdir(dir)
	t.Setenv(state.HomeEnv, filepath.Join(t.TempDir(), "tplater-home"))
	c := newGenBatchCmd()
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	c.SetArgs([]string{"--operations", `[{"kind":"migration","name":"create_rides","params":{"table":"rides -- comment"}}]`, "--no-build"})
	err := c.Execute()
	if err == nil || !strings.Contains(err.Error(), "не соответствует pattern") {
		t.Fatalf("expected pattern rejection, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "migrations", "create_rides.sql")); !os.IsNotExist(statErr) {
		t.Errorf("batch gen wrote a file after pattern rejection: %v", statErr)
	}
}
