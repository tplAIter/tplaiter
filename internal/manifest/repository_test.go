package manifest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestRepositoryValidate(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		code  string // empty: valid
	}{
		{name: "valid", paths: []string{"alpha", "templates/service/", "./beta", "."}},
		{name: "none", paths: nil},
		{name: "empty", paths: []string{" "}, code: CodeRepoPathInvalid},
		{name: "backslash", paths: []string{`a\b`}, code: CodeRepoPathInvalid},
		{name: "absolute", paths: []string{"/abs"}, code: CodeRepoPathEscape},
		{name: "drive", paths: []string{"C:/abs"}, code: CodeRepoPathEscape},
		{name: "parent", paths: []string{"../x"}, code: CodeRepoPathEscape},
		{name: "inner parent", paths: []string{"a/../a"}, code: CodeRepoPathEscape},
		{name: "duplicate", paths: []string{"a", "a/"}, code: CodeRepoDupPath},
		{name: "duplicate dot", paths: []string{"a/b", "./a//b"}, code: CodeRepoDupPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Repository{}
			for _, p := range tc.paths {
				r.Templates = append(r.Templates, TemplateRef{Path: p})
			}
			err := r.Validate()
			if tc.code == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			var typed *RepositoryError
			if !errors.As(err, &typed) || typed.Code != tc.code {
				t.Fatalf("Validate() = %v, want %s", err, tc.code)
			}
		})
	}
}

func TestCleanTemplatePath(t *testing.T) {
	for in, want := range map[string]string{
		".":                  ".",
		"./":                 ".",
		"templates/service/": "templates/service",
		"a//b/":              "a/b",
	} {
		got, err := CleanTemplatePath(in)
		if err != nil || got != want {
			t.Errorf("CleanTemplatePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestLoadRepositoryRejectsEscapingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.manifest.yaml")
	data := "apiVersion: tplater.dev/v1alpha1\nkind: Repository\nmetadata: {name: r}\ntemplates: [{path: ../outside}]\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRepository(path)
	var typed *RepositoryError
	if !errors.As(err, &typed) || typed.Code != CodeRepoPathEscape || typed.Path != "../outside" {
		t.Fatalf("LoadRepository() = %v, want %s for ../outside", err, CodeRepoPathEscape)
	}
}

func TestRepositoryErrorMessage(t *testing.T) {
	err := NewRepositoryError(CodeRepoDupName, "templates/service", "detail")
	if got, want := err.Error(), `TPL-E-REPO-DUP-NAME: "templates/service": detail`; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	var nilErr *RepositoryError
	if nilErr.Error() != "" {
		t.Fatal("nil RepositoryError must render empty")
	}
}

const repositorySchemaPath = "../../schema/repository.manifest.schema.json"

// TestRepositorySchema_MatchesValidation keeps the IDE schema for
// repo.manifest.yaml in sync with the Go types and with CleanTemplatePath:
// every rejected-path pattern in the schema must agree with Validate.
func TestRepositorySchema_MatchesValidation(t *testing.T) {
	data, err := os.ReadFile(repositorySchemaPath)
	if err != nil {
		t.Fatalf("reading schema: %v", err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	for _, key := range []string{"apiVersion", "kind", "metadata", "templates"} {
		if _, ok := schema.Properties[key]; !ok {
			t.Errorf("schema does not cover %q", key)
		}
	}
	var templates struct {
		Items struct {
			Properties struct {
				Path struct {
					Not struct {
						AnyOf []struct {
							Pattern string `json:"pattern"`
						} `json:"anyOf"`
					} `json:"not"`
				} `json:"path"`
			} `json:"properties"`
		} `json:"items"`
	}
	if err := json.Unmarshal(schema.Properties["templates"], &templates); err != nil {
		t.Fatalf("templates schema: %v", err)
	}
	var patterns []*regexp.Regexp
	for _, p := range templates.Items.Properties.Path.Not.AnyOf {
		patterns = append(patterns, regexp.MustCompile(p.Pattern))
	}
	if len(patterns) == 0 {
		t.Fatal("schema declares no rejected-path patterns")
	}
	for _, p := range []string{"a", "a/b", "./a", ".", "a/b/", "/abs", "C:/x", "../x", "a/../b", "a/..", "..", `a\b`, "a..b", "..a/b"} {
		schemaRejects := false
		for _, re := range patterns {
			if re.MatchString(p) {
				schemaRejects = true
			}
		}
		_, err := CleanTemplatePath(p)
		if schemaRejects != (err != nil) {
			t.Errorf("path %q: schema rejects=%v, CleanTemplatePath error=%v", p, schemaRejects, err)
		}
	}
}
