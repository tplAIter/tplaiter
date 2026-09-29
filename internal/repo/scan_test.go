package repo

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/state"
)

const scanTemplateManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: {name: NAME, version: 1.0.0}
engine: {type: gotemplate, root: files}
`

func scanManifest(name string) string {
	return strings.Replace(scanTemplateManifest, "NAME", name, 1)
}

func repoManifest(paths ...string) string {
	var b strings.Builder
	b.WriteString("apiVersion: tplater.dev/v1alpha1\nkind: Repository\nmetadata: {name: provider}\n")
	if len(paths) == 0 {
		return b.String()
	}
	b.WriteString("templates:\n")
	for _, p := range paths {
		b.WriteString("  - path: '" + p + "'\n")
	}
	return b.String()
}

// scanManager returns a manager whose git runner answers `git tag -l` with tags.
func scanManager(t *testing.T, errOut *bytes.Buffer, tags ...string) *Manager {
	t.Helper()
	runner := execx.NewRecordingRunner().SetDefault(execx.Response{
		Result: execx.Result{Stdout: strings.Join(tags, "\n")},
	})
	u := UI{}
	if errOut != nil {
		u.Err = errOut
	}
	return New(t.TempDir(), runner, nil, u)
}

func writeScanFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeTemplate(t *testing.T, dir, rel, name string) {
	t.Helper()
	writeScanFile(t, filepath.Join(dir, filepath.FromSlash(rel), templateManifestName), scanManifest(name))
}

func requireSymlinks(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires extra privileges on Windows")
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// requireRepoError asserts that err wraps a *manifest.RepositoryError with code.
func requireRepoError(t *testing.T, err error, code string) {
	t.Helper()
	_ = asRepoError(t, err, code)
}

// asRepoError is requireRepoError that also returns the typed error.
func asRepoError(t *testing.T, err error, code string) *manifest.RepositoryError {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	var typed *manifest.RepositoryError
	if !errors.As(err, &typed) {
		t.Fatalf("error %v is not a *manifest.RepositoryError (want %s)", err, code)
	}
	if typed.Code != code {
		t.Fatalf("error code = %s (%v), want %s", typed.Code, err, code)
	}
	if !strings.Contains(err.Error(), code) {
		t.Fatalf("error text %q does not carry the code %s", err.Error(), code)
	}
	return typed
}

func entrySummary(entries []state.TemplateEntry) map[string]string {
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		out[e.Name] = e.Path
	}
	return out
}

// copyFixture copies testdata/fixtures/<name> into a fresh directory.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("..", "..", "testdata", "fixtures", name)
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy fixture %s: %v", name, err)
	}
	return dst
}

func TestScanRepoIndexesRootAndNestedTemplates(t *testing.T) {
	dir := copyFixture(t, "nested-provider")

	paths, err := DiscoverTemplatePaths(dir)
	if err != nil {
		t.Fatalf("DiscoverTemplatePaths: %v", err)
	}
	wantPaths := []string{".", "bootstrap/template-repository/templates/service", "templates/worker"}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("paths = %v, want %v", paths, wantPaths)
	}

	m := scanManager(t, nil, "v0.1.0", "service/v0.1.0", "worker/v0.2.0")
	entries, err := m.scanRepo(context.Background(), dir, "main", true)
	if err != nil {
		t.Fatalf("scanRepo: %v", err)
	}
	got := entrySummary(entries)
	want := map[string]string{
		"provider-base": ".",
		"service":       "bootstrap/template-repository/templates/service",
		"worker":        "templates/worker",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	// Index order is deterministic: by name.
	if entries[0].Name != "provider-base" || entries[1].Name != "service" || entries[2].Name != "worker" {
		t.Fatalf("entry order = %+v", entries)
	}
	// The implicit root keeps legacy single tags; nested templates are namespaced.
	tags := map[string][]string{}
	for _, e := range entries {
		tags[e.Name] = e.Tags
	}
	if !reflect.DeepEqual(tags["provider-base"], []string{"v0.1.0"}) ||
		!reflect.DeepEqual(tags["service"], []string{"service/v0.1.0"}) ||
		!reflect.DeepEqual(tags["worker"], []string{"worker/v0.2.0"}) {
		t.Fatalf("tags = %v", tags)
	}
}

func TestScanRepoLegacyLoneRoot(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, ".", "lone")
	writeScanFile(t, filepath.Join(dir, "files", "README.md"), "no manifest here\n")

	entries, err := scanManager(t, nil, "v1.0.0", "other/v2.0.0").scanRepo(context.Background(), dir, "main", true)
	if err != nil {
		t.Fatalf("scanRepo: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "lone" || entries[0].Path != "." {
		t.Fatalf("entries = %+v, want the lone root", entries)
	}
	if !reflect.DeepEqual(entries[0].Tags, []string{"v1.0.0"}) {
		t.Fatalf("tags = %v, want un-namespaced single tags", entries[0].Tags)
	}
}

func TestScanRepoExplicitRootsRecurseAndLimitDiscovery(t *testing.T) {
	dir := t.TempDir()
	writeScanFile(t, filepath.Join(dir, repoManifestName), repoManifest("templates/", "single"))
	writeTemplate(t, dir, ".", "root-not-declared")
	writeTemplate(t, dir, "templates/service", "service")
	writeTemplate(t, dir, "templates/group/worker", "worker")
	writeTemplate(t, dir, "single", "single")
	writeTemplate(t, dir, "undeclared/other", "other")

	paths, err := DiscoverTemplatePaths(dir)
	if err != nil {
		t.Fatalf("DiscoverTemplatePaths: %v", err)
	}
	want := []string{"single", "templates/group/worker", "templates/service"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %v, want %v (only declared roots, recursively)", paths, want)
	}

	entries, err := scanManager(t, nil, "v1.0.0", "single/v1.0.0").scanRepo(context.Background(), dir, "", true)
	if err != nil {
		t.Fatalf("scanRepo: %v", err)
	}
	for _, e := range entries {
		if e.Name == "single" && !reflect.DeepEqual(e.Tags, []string{"single/v1.0.0"}) {
			t.Fatalf("declared templates use namespaced tags, got %v", e.Tags)
		}
		if e.Ref != "HEAD" {
			t.Fatalf("empty branch must index ref HEAD, got %q", e.Ref)
		}
	}
}

func TestScanRepoEmptyTemplatesListScansRoot(t *testing.T) {
	dir := t.TempDir()
	writeScanFile(t, filepath.Join(dir, repoManifestName), repoManifest())
	writeTemplate(t, dir, "a", "a")
	writeTemplate(t, dir, "deep/b", "b")

	paths, err := DiscoverTemplatePaths(dir)
	if err != nil {
		t.Fatalf("DiscoverTemplatePaths: %v", err)
	}
	if !reflect.DeepEqual(paths, []string{"a", "deep/b"}) {
		t.Fatalf("paths = %v", paths)
	}
}

func TestScanRepoRejectsDuplicateName(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, ".", "service")
	writeTemplate(t, dir, "templates/service", "service")

	for _, strict := range []bool{true, false} {
		_, err := scanManager(t, nil).scanRepo(context.Background(), dir, "main", strict)
		typed := asRepoError(t, err, manifest.CodeRepoDupName)
		if typed.Path != "templates/service" || !strings.Contains(typed.Detail, `"."`) {
			t.Fatalf("strict=%v: duplicate detail = %+v", strict, typed)
		}
	}
}

func TestScanRepoRejectsDuplicatePath(t *testing.T) {
	cases := map[string][]string{
		"literal":           {"alpha", "alpha"},
		"trailing slash":    {"alpha/", "alpha"},
		"dot segment":       {"alpha", "./alpha"},
		"redundant slashes": {"a//b", "a/b"},
	}
	for name, paths := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeScanFile(t, filepath.Join(dir, repoManifestName), repoManifest(paths...))
			writeTemplate(t, dir, "alpha", "alpha")
			writeTemplate(t, dir, "a/b", "b")
			_, err := DiscoverTemplatePaths(dir)
			requireRepoError(t, err, manifest.CodeRepoDupPath)
		})
	}
}

func TestScanRepoRejectsDuplicatePathThroughSymlink(t *testing.T) {
	requireSymlinks(t)
	dir := t.TempDir()
	writeScanFile(t, filepath.Join(dir, repoManifestName), repoManifest("real", "alias"))
	writeTemplate(t, dir, "real", "real")
	symlink(t, "real", filepath.Join(dir, "alias"))

	_, err := DiscoverTemplatePaths(dir)
	requireRepoError(t, err, manifest.CodeRepoDupPath)
}

func TestScanRepoRejectsEscapingDeclaredPaths(t *testing.T) {
	cases := map[string]string{
		"parent":           "../outside",
		"inner dotdot":     "templates/../templates",
		"absolute":         "/etc",
		"drive letter":     "C:/templates",
		"trailing dotdot":  "templates/..",
		"only dotdot":      "..",
		"dotdot and slash": "../",
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeScanFile(t, filepath.Join(dir, repoManifestName), repoManifest(p))
			writeTemplate(t, dir, "templates", "templates")
			_, err := scanManager(t, nil).scanRepo(context.Background(), dir, "main", true)
			requireRepoError(t, err, manifest.CodeRepoPathEscape)
		})
	}
}

func TestScanRepoRejectsInvalidDeclaredPaths(t *testing.T) {
	cases := map[string]string{
		"empty":            "  ",
		"backslash":        `templates\service`,
		"missing":          "missing",
		"hidden":           ".hidden/tpl",
		"vendor":           "vendor/tpl",
		"node_modules":     "node_modules/tpl",
		"no manifest":      "empty",
		"file not dir":     "file.txt",
		"git metadata dir": ".git",
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeScanFile(t, filepath.Join(dir, repoManifestName), repoManifest(p))
			for _, rel := range []string{".hidden/tpl", "vendor/tpl", "node_modules/tpl"} {
				writeTemplate(t, dir, rel, "x")
			}
			if err := os.MkdirAll(filepath.Join(dir, "empty"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeScanFile(t, filepath.Join(dir, "file.txt"), "x")
			_, err := DiscoverTemplatePaths(dir)
			requireRepoError(t, err, manifest.CodeRepoPathInvalid)
		})
	}
}

func TestScanRepoRejectsSymlinkEscape(t *testing.T) {
	requireSymlinks(t)
	t.Run("declared root", func(t *testing.T) {
		dir := t.TempDir()
		external := t.TempDir()
		writeTemplate(t, external, ".", "escaped")
		writeScanFile(t, filepath.Join(dir, repoManifestName), repoManifest("templates"))
		symlink(t, external, filepath.Join(dir, "templates"))
		_, err := scanManager(t, nil).scanRepo(context.Background(), dir, "main", true)
		requireRepoError(t, err, manifest.CodeRepoPathEscape)
	})
	t.Run("intermediate component", func(t *testing.T) {
		dir := t.TempDir()
		external := t.TempDir()
		writeTemplate(t, external, "service", "escaped")
		writeScanFile(t, filepath.Join(dir, repoManifestName), repoManifest("link/service"))
		symlink(t, external, filepath.Join(dir, "link"))
		_, err := DiscoverTemplatePaths(dir)
		requireRepoError(t, err, manifest.CodeRepoPathEscape)
	})
	t.Run("manifest file", func(t *testing.T) {
		dir := t.TempDir()
		external := t.TempDir()
		writeTemplate(t, external, ".", "escaped")
		writeTemplate(t, dir, ".", "root")
		symlink(t, filepath.Join(external, templateManifestName), filepath.Join(dir, "templates", "evil", templateManifestName))
		_, err := DiscoverTemplatePaths(dir)
		typed := asRepoError(t, err, manifest.CodeRepoPathEscape)
		if typed.Path != "templates/evil/"+templateManifestName {
			t.Fatalf("escape path = %q", typed.Path)
		}
	})
	t.Run("repository manifest", func(t *testing.T) {
		dir := t.TempDir()
		external := t.TempDir()
		writeScanFile(t, filepath.Join(external, repoManifestName), repoManifest("."))
		writeTemplate(t, dir, ".", "root")
		symlink(t, filepath.Join(external, repoManifestName), filepath.Join(dir, repoManifestName))
		_, err := DiscoverTemplatePaths(dir)
		requireRepoError(t, err, manifest.CodeRepoPathEscape)
	})
	t.Run("directory symlink is not followed", func(t *testing.T) {
		dir := t.TempDir()
		external := t.TempDir()
		writeTemplate(t, external, "service", "escaped")
		writeTemplate(t, dir, ".", "root")
		symlink(t, external, filepath.Join(dir, "templates"))
		paths, err := DiscoverTemplatePaths(dir)
		if err != nil {
			t.Fatalf("DiscoverTemplatePaths: %v", err)
		}
		if !reflect.DeepEqual(paths, []string{"."}) {
			t.Fatalf("paths = %v, want only the root (directory symlinks are not walked)", paths)
		}
	})
}

func TestScanRepoAllowsSymlinkInsideRoot(t *testing.T) {
	requireSymlinks(t)
	t.Run("declared root", func(t *testing.T) {
		dir := t.TempDir()
		writeScanFile(t, filepath.Join(dir, repoManifestName), repoManifest("current"))
		writeTemplate(t, dir, "releases/v2/service", "service")
		symlink(t, filepath.Join("releases", "v2"), filepath.Join(dir, "current"))
		paths, err := DiscoverTemplatePaths(dir)
		if err != nil {
			t.Fatalf("DiscoverTemplatePaths: %v", err)
		}
		// The index stores the resolved path, never the symlink.
		if !reflect.DeepEqual(paths, []string{"releases/v2/service"}) {
			t.Fatalf("paths = %v", paths)
		}
	})
	t.Run("manifest file", func(t *testing.T) {
		dir := t.TempDir()
		writeTemplate(t, dir, ".", "root")
		writeScanFile(t, filepath.Join(dir, "shared", "service.yaml"), scanManifest("service"))
		symlink(t, filepath.Join("..", "..", "shared", "service.yaml"), filepath.Join(dir, "templates", "service", templateManifestName))
		entries, err := scanManager(t, nil).scanRepo(context.Background(), dir, "main", true)
		if err != nil {
			t.Fatalf("scanRepo: %v", err)
		}
		if got := entrySummary(entries); !reflect.DeepEqual(got, map[string]string{"root": ".", "service": "templates/service"}) {
			t.Fatalf("entries = %v", got)
		}
	})
	t.Run("repository reached through a symlink", func(t *testing.T) {
		realDir := t.TempDir()
		writeTemplate(t, realDir, ".", "root")
		writeTemplate(t, realDir, "templates/service", "service")
		link := filepath.Join(t.TempDir(), "clone")
		symlink(t, realDir, link)
		paths, err := DiscoverTemplatePaths(link)
		if err != nil {
			t.Fatalf("DiscoverTemplatePaths: %v", err)
		}
		if !reflect.DeepEqual(paths, []string{".", "templates/service"}) {
			t.Fatalf("paths = %v", paths)
		}
	})
}

func TestScanRepoSkipsExcludedDirectories(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, ".", "root")
	for _, rel := range []string{".git/objects", ".cache/x", "vendor/dep", "node_modules/pkg", "cache/c", "target/build", "templates/svc/vendor/dep"} {
		writeTemplate(t, dir, rel, "must-not-index")
	}
	writeTemplate(t, dir, "templates/svc", "svc")

	paths, err := DiscoverTemplatePaths(dir)
	if err != nil {
		t.Fatalf("DiscoverTemplatePaths: %v", err)
	}
	if !reflect.DeepEqual(paths, []string{".", "templates/svc"}) {
		t.Fatalf("paths = %v", paths)
	}
}

func TestScanRepoDepthLimit(t *testing.T) {
	dir := t.TempDir()
	atLimit := strings.TrimSuffix(strings.Repeat("d/", MaxDiscoveryDepth), "/")
	beyond := atLimit + "/e"
	writeTemplate(t, dir, atLimit, "at-limit")
	writeTemplate(t, dir, beyond, "beyond")

	paths, err := DiscoverTemplatePaths(dir)
	if err != nil {
		t.Fatalf("DiscoverTemplatePaths: %v", err)
	}
	if !reflect.DeepEqual(paths, []string{atLimit}) {
		t.Fatalf("paths = %v, want only %q (depth %d)", paths, atLimit, MaxDiscoveryDepth)
	}
}

func TestScanRepoNoTemplates(t *testing.T) {
	dir := t.TempDir()
	writeScanFile(t, filepath.Join(dir, "README.md"), "nothing\n")
	_, err := scanManager(t, nil).scanRepo(context.Background(), dir, "main", true)
	if err == nil || !strings.Contains(err.Error(), templateManifestName) {
		t.Fatalf("scanRepo error = %v, want no-templates error", err)
	}
}

func TestScanRepoNonStrictSkipsBrokenNestedTemplate(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, ".", "root")
	writeScanFile(t, filepath.Join(dir, "templates", "broken", templateManifestName), "apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata: {}\n")

	if _, err := scanManager(t, nil).scanRepo(context.Background(), dir, "main", true); err == nil {
		t.Fatal("strict scan must fail on a broken nested manifest")
	}
	var warn bytes.Buffer
	entries, err := scanManager(t, &warn).scanRepo(context.Background(), dir, "main", false)
	if err != nil {
		t.Fatalf("non-strict scanRepo: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "root" {
		t.Fatalf("entries = %+v, want only root", entries)
	}
	if !strings.Contains(warn.String(), "templates/broken") {
		t.Fatalf("warning = %q, want the broken template path", warn.String())
	}
}

func TestDiscoverTemplatePathsIsDeterministic(t *testing.T) {
	dir := copyFixture(t, "nested-provider")
	first, err := DiscoverTemplatePaths(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := DiscoverTemplatePaths(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d: %v != %v", i, again, first)
		}
	}
}
