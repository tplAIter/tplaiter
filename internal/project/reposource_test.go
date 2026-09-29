package project

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/state"
)

var repoGitExec = execx.Exec{}

func requireGitBin(t *testing.T) {
	t.Helper()
	if _, err := repoGitExec.LookPath("git"); err != nil {
		t.Skip("git not found in PATH — integration test skipped")
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	env := []string{
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	}
	res, err := repoGitExec.Run(context.Background(), "git", args, execx.Options{Dir: dir, Env: env})
	if err != nil {
		t.Fatalf("git %s: %v\n%s%s", strings.Join(args, " "), err, res.Stdout, res.Stderr)
	}
}

// TestRepoSource_LoadsFromCacheWithoutSnapshot verifies the preferred source:
// with a live repository cache, the manifest loads from it even without a
// snapshot (§4: repo → snapshot order).
func TestRepoSource_LoadsFromCacheWithoutSnapshot(t *testing.T) {
	requireGitBin(t)

	home := filepath.Join(t.TempDir(), "home")
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}

	// Origin with one single svc template, tagged v0.1.0.
	origin := filepath.Join(t.TempDir(), "origin")
	manifestSrc := `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc
  version: 0.1.0
engine:
  root: files
requires:
  tplater: ">=0.1.0"
`
	if err := os.MkdirAll(filepath.Join(origin, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "template.manifest.yaml"), []byte(manifestSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "files", "main.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, origin, "init", "-b", "main")
	gitRun(t, origin, "config", "uploadpack.allowFilter", "true")
	gitRun(t, origin, "add", "-A")
	gitRun(t, origin, "commit", "-m", "v1")
	gitRun(t, origin, "tag", "v0.1.0")

	st, err := auth.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mgr := repo.New(home, repoGitExec, st, repo.UI{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}})
	if err := mgr.Add(context.Background(), repo.AddOptions{Alias: "example", URL: "file://" + origin}); err != nil {
		t.Fatalf("repo add: %v", err)
	}

	// Project without a snapshot: only a marker with a pinned version.
	root := t.TempDir() // Do NOT create a snapshot.
	proj := &manifest.Project{
		Template: manifest.ProjectTemplate{Repo: "example", Name: "svc", Version: "v0.1.0"},
	}

	tpl, source, err := LoadManifestForProject(root, proj, home)
	if err != nil {
		t.Fatalf("LoadManifestForProject: %v", err)
	}
	if source != "repo" {
		t.Errorf("source = %q, expected repo (cache takes precedence over snapshot)", source)
	}
	if tpl.Metadata.Name != "svc" {
		t.Errorf("tpl.Metadata.Name = %q, expected svc", tpl.Metadata.Name)
	}
}
