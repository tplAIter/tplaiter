package inittemplate

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

const nestedProviderFixture = "../../testdata/fixtures/nested-provider"

const discoveryManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: {name: NAME, version: 1.0.0}
engine: {type: gotemplate, root: files}
`

func writeDiscoveryTemplate(t *testing.T, dir, rel, name string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel), templateManifestFileName)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(discoveryManifest, "NAME", name, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLint_RootProviderAndNestedTemplates: lint-template validates the root
// provider template and every nested template, not only the root manifest.
func TestLint_RootProviderAndNestedTemplates(t *testing.T) {
	res, err := Lint(LintOptions{Path: nestedProviderFixture, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if res.Failed {
		t.Fatalf("nested-provider must be green:\n%s", failDetails(res))
	}
	linted := map[string]bool{}
	for _, r := range res.Rows {
		linted[r.Template] = true
	}
	for _, want := range []string{"nested-provider", "bootstrap/template-repository/templates/service", "templates/worker"} {
		if !linted[want] {
			t.Errorf("template %q was not linted; rows: %v", want, linted)
		}
	}
}

func TestLint_DuplicateTemplateNameFails(t *testing.T) {
	dir := t.TempDir()
	writeDiscoveryTemplate(t, dir, ".", "service")
	writeDiscoveryTemplate(t, dir, "templates/service", "service")

	res, err := Lint(LintOptions{Path: dir, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if !res.Failed || !strings.Contains(failDetails(res), manifest.CodeRepoDupName) {
		t.Fatalf("lint must fail with %s:\n%s", manifest.CodeRepoDupName, failDetails(res))
	}
}

func TestLint_RejectsEscapingRepositoryPath(t *testing.T) {
	dir := t.TempDir()
	data := "apiVersion: tplater.dev/v1alpha1\nkind: Repository\nmetadata: {name: r}\ntemplates: [{path: ../outside}]\n"
	if err := os.WriteFile(filepath.Join(dir, repoManifestFileName), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Lint(LintOptions{Path: dir, Out: io.Discard})
	var typed *manifest.RepositoryError
	if !errors.As(err, &typed) || typed.Code != manifest.CodeRepoPathEscape {
		t.Fatalf("Lint error = %v, want %s", err, manifest.CodeRepoPathEscape)
	}
}

func TestLint_RejectsSymlinkedManifestEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires extra privileges on Windows")
	}
	dir := t.TempDir()
	external := t.TempDir()
	writeDiscoveryTemplate(t, dir, ".", "root")
	writeDiscoveryTemplate(t, external, ".", "escaped")
	link := filepath.Join(dir, "templates", "evil", templateManifestFileName)
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(external, templateManifestFileName), link); err != nil {
		t.Fatal(err)
	}
	_, err := Lint(LintOptions{Path: dir, Out: io.Discard})
	var typed *manifest.RepositoryError
	if !errors.As(err, &typed) || typed.Code != manifest.CodeRepoPathEscape {
		t.Fatalf("Lint error = %v, want %s", err, manifest.CodeRepoPathEscape)
	}
}

// TestInit_NestedInsideProvider: init-template may create a nested template
// inside a provider repository, and the provider then discovers it.
func TestInit_NestedInsideProvider(t *testing.T) {
	provider := copyTree(t, nestedProviderFixture)
	target := filepath.Join(provider, "templates", "api")
	if _, err := Init(context.Background(), InitOptions{Name: "api", Dir: target, NoGit: true, Out: io.Discard}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	res, err := Lint(LintOptions{Path: provider, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	found := false
	for _, r := range res.Rows {
		if r.Template == "templates/api" {
			found = true
		}
	}
	if !found {
		t.Fatal("the provider does not discover the nested template created by init-template")
	}
}

// TestInit_RejectsDuplicateNameInsideProvider: creating a nested template
// whose name the enclosing provider already declares fails before writing.
func TestInit_RejectsDuplicateNameInsideProvider(t *testing.T) {
	provider := copyTree(t, nestedProviderFixture)
	target := filepath.Join(provider, "templates", "service-copy")
	_, err := Init(context.Background(), InitOptions{Name: "service", Dir: target, NoGit: true, Out: io.Discard})
	var typed *manifest.RepositoryError
	if !errors.As(err, &typed) || typed.Code != manifest.CodeRepoDupName {
		t.Fatalf("Init error = %v, want %s", err, manifest.CodeRepoDupName)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("Init must not write %s on a duplicate name (stat err %v)", target, statErr)
	}
}

func TestVerifyGenerated(t *testing.T) {
	dir := t.TempDir()
	writeDiscoveryTemplate(t, dir, ".", "one")
	if err := verifyGenerated(InitOptions{Name: "one"}, dir); err != nil {
		t.Fatalf("single: %v", err)
	}
	if err := verifyGenerated(InitOptions{Name: "one", Multi: true}, dir); err == nil {
		t.Fatal("multi layout must discover <name>/, not the root")
	}
	writeDiscoveryTemplate(t, dir, "extra", "extra")
	if err := verifyGenerated(InitOptions{Name: "one"}, dir); err == nil {
		t.Fatal("an extra discovered template must fail verification")
	}
}
