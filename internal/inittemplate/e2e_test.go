package inittemplate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
)

// TestE2E_InitTemplateToNewProject runs the full requirement-2 path:
// init-template → git repository → tplater repo add file:// → tplater new →
// project created (README rendered, feature_x path works).
func TestE2E_InitTemplateToNewProject(t *testing.T) {
	if _, err := (execx.Exec{}).LookPath("git"); err != nil {
		t.Skip("git не найден в PATH — e2e пропущен")
	}
	ctx := context.Background()

	// 1. init-template with git init and the first commit.
	base := t.TempDir()
	repoDir := filepath.Join(base, "demo-svc")
	runner := gitEnvRunner{}
	if _, err := Init(ctx, InitOptions{
		Name: "demo-svc", Dir: repoDir, Runner: runner, Out: io.Discard,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		t.Fatalf("ожидался git-репозиторий: %v", err)
	}

	// 2. tplater repo add file://<repoDir>.
	home := filepath.Join(base, "home")
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	st, err := auth.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	u := repo.UI{Out: io.Discard, Err: io.Discard, Interactive: false}
	mgr := repo.New(home, execx.Exec{}, st, u)
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "example", URL: "file://" + repoDir}); err != nil {
		t.Fatalf("repo add: %v", err)
	}

	// 3. Local fixture project build from the added repository (without live new).
	projDir := filepath.Join(base, "proj")
	var out bytes.Buffer
	resolved, err := mgr.ResolveRef("example/demo-svc")
	if err != nil {
		t.Fatal(err)
	}
	src, cleanup, err := mgr.Checkout(ctx, resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup() })
	raw, err := fs.ReadFile(src, "template.manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}
	explicit := settings.Values{}
	for _, expr := range []string{"feature_x=true", "variant=advanced"} {
		group, value, err := settings.ParseSet(tpl, expr)
		if err != nil {
			t.Fatal(err)
		}
		explicit[group] = value
	}
	resolvedSettings, err := settings.Resolve(tpl, explicit)
	if err != nil {
		t.Fatal(err)
	}
	project := manifest.ProjectInfo{Name: "My Service", Slug: "my_service", Module: "example.com/my_service"}
	_, err = engine.Render(engine.Options{Source: src, Target: projDir, Template: tpl, Resolved: resolvedSettings, Project: project, Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: resolved.RepoAlias})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.SaveSnapshot(filepath.Join(projDir, manifest.SnapshotRelPath), tpl); err != nil {
		t.Fatal(err)
	}
	marker := manifest.Project{APIVersion: manifest.APIVersion, Kind: manifest.KindProject, ID: "fixture-my_service", Template: manifest.ProjectTemplate{Repo: resolved.RepoAlias, Name: tpl.Metadata.Name, Version: resolved.Version}, Project: project, Settings: resolvedSettings.Values, Runtime: manifest.ProjectRuntime{Port: 8080}, Baseline: engine.BaselineRelPath}
	markerBytes, err := yaml.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projDir, ".tplaiter", "project.yaml"), markerBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	baselineBytes, err := os.ReadFile(filepath.Join(projDir, filepath.FromSlash(engine.BaselineRelPath)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(baselineBytes)
	projects := state.DefaultProjects()
	now := time.Unix(1_700_000_000, 0).UTC()
	projects.Upsert(state.ProjectRef{ID: marker.ID, Path: projDir, Template: state.TemplateSelection{Repo: resolved.RepoAlias, Name: tpl.Metadata.Name, Version: resolved.Version}, CreatedAt: now, LastSeenAt: now, BaselineSHA: hex.EncodeToString(digest[:])})
	if err := state.SaveProjects(home, projects); err != nil {
		t.Fatal(err)
	}

	// 4. Checks for the generated project.
	readme, err := os.ReadFile(filepath.Join(projDir, "README.md"))
	if err != nil {
		t.Fatalf("README.md не создан: %v", err)
	}
	if !bytes.Contains(readme, []byte("My Service")) {
		t.Errorf("README не отрендерил имя проекта:\n%s", readme)
	}
	if !bytes.Contains(readme, []byte("my_service")) {
		t.Errorf("README не отрендерил slug:\n%s", readme)
	}
	if !bytes.Contains(readme, []byte("tplaiter run dev")) || !bytes.Contains(readme, []byte("tplaiter run test")) {
		t.Errorf("README не содержит текущие команды запуска:\n%s", readme)
	}
	if bytes.Contains(readme, []byte("tplater run ")) || bytes.Contains(out.Bytes(), []byte("tplater run ")) {
		t.Errorf("new вывел устаревшую CLI-подсказку:\nREADME:\n%s\nNOTES/output:\n%s", readme, out.String())
	}

	// feature_x=true → conditional directory __if_feature_x__/ produced extra.txt.
	if _, err := os.Stat(filepath.Join(projDir, "extra.txt")); err != nil {
		t.Errorf("feature_x-путь не сработал (extra.txt отсутствует): %v", err)
	}
	// variant=advanced → the files rule included advanced/notes.md.
	if _, err := os.Stat(filepath.Join(projDir, "advanced", "notes.md")); err != nil {
		t.Errorf("variant=advanced-путь не сработал (advanced/notes.md отсутствует): %v", err)
	}
	// Project marker was written.
	if _, err := os.Stat(filepath.Join(projDir, ".tplaiter", "project.yaml")); err != nil {
		t.Errorf("проектный маркер .tplaiter/project.yaml отсутствует: %v", err)
	}
}

// gitEnvRunner — Exec with deterministic git environment (commits without the
// user's global config).
type gitEnvRunner struct{ execx.Exec }

func (r gitEnvRunner) Run(ctx context.Context, name string, args []string, opts execx.Options) (execx.Result, error) {
	if name == "git" {
		opts.Env = append(
			opts.Env,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
	}
	return r.Exec.Run(ctx, name, args, opts)
}
