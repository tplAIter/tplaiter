package settingscmd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/settingscmd"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
	"github.com/tplAIter/tplaiter/internal/update"
	"gopkg.in/yaml.v3"
)

// --- git infrastructure (real git, file:// repository, as in internal/update) ---

var gitExec = execx.Exec{}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := gitExec.LookPath("git"); err != nil {
		t.Skip("git не найден в PATH — интеграционный тест пропущен")
	}
}

func gitEnv() []string {
	return []string{
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	res, err := gitExec.Run(context.Background(), "git", args, execx.Options{Dir: dir, Env: gitEnv()})
	if err != nil {
		t.Fatalf("git %s: %v\n%s%s", strings.Join(args, " "), err, res.Stdout, res.Stderr)
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// manifestYAML is an inline svc template with a requires chain (auth=oauth =>
// database=postgres) and two postgres verticals (schema.sql/seed.sql).
const manifestYAML = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc
  version: 0.1.0
engine:
  root: files
requires:
  tplater: ">=0.1.0"
settings:
  - group: database
    title: DB
    type: select
    default: none
    options:
      - id: none
        title: none
      - id: postgres
        title: postgres
        settings:
          - group: migrations
            title: migrations
            type: toggle
            default: false
  - group: auth
    title: Auth
    type: select
    default: none
    options:
      - id: none
        title: none
      - id: oauth
        title: oauth
        requires: ["database=postgres"]
  - group: brokers
    title: Brokers
    type: multiselect
    options:
      - id: kafka
        title: kafka
      - id: rabbitmq
        title: rabbitmq
`

func templateFiles() map[string]string {
	return map[string]string{
		"template.manifest.yaml":                    manifestYAML,
		"files/main.txt.tmpl":                       "app={{ .Project.Slug }}\n",
		"files/config.txt.tmpl":                     "db-mode: {{ if is \"database\" \"postgres\" }}postgres{{ else }}none{{ end }}\n",
		"files/__if_database=postgres__/schema.sql": "create table t;\n",
		"files/__if_database=postgres__/seed.sql":   "insert into t;\n",
		"files/__if_auth=oauth__/oauth.txt":         "oauth config\n",
	}
}

// initOrigin creates a git origin with one commit and the v0.1.0 tag.
func initOrigin(t *testing.T) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	if err := os.MkdirAll(origin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFiles(t, origin, templateFiles())
	runGit(t, origin, "init", "-b", "main")
	runGit(t, origin, "config", "uploadpack.allowFilter", "true")
	runGit(t, origin, "add", "-A")
	runGit(t, origin, "commit", "-m", "v1")
	runGit(t, origin, "tag", "v0.1.0")
	return origin
}

func newManager(t *testing.T, home string) *repo.Manager {
	t.Helper()
	st, err := auth.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	u := repo.UI{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, Interactive: false}
	return repo.New(home, gitExec, st, u)
}

// setup creates home and the example repository with the svc template, then creates
// a v0.1.0 fixture project with the given --set values. edit applies user changes after creation.
func setup(t *testing.T, sets []string, edit func(projDir string)) (mgr *repo.Manager, home, projDir string) {
	t.Helper()
	requireGit(t)
	home = filepath.Join(t.TempDir(), "home")
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	origin := initOrigin(t)
	mgr = newManager(t, home)
	if err := mgr.Add(context.Background(), repo.AddOptions{Alias: "example", URL: "file://" + origin}); err != nil {
		t.Fatalf("repo add: %v", err)
	}

	projDir = filepath.Join(t.TempDir(), "proj")
	resolvedRef, err := mgr.ResolveRef("example/svc@v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	src, cleanup, err := mgr.Checkout(context.Background(), resolvedRef.RepoAlias, resolvedRef.GitRef, resolvedRef.Entry.Path)
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
	for _, pair := range sets {
		group, value, err := settings.ParseSet(tpl, pair)
		if err != nil {
			t.Fatal(err)
		}
		explicit[group] = value
	}
	resolved, err := settings.Resolve(tpl, explicit)
	if err != nil {
		t.Fatal(err)
	}
	projectInfo := manifest.ProjectInfo{Name: "demo_svc", Slug: "demo_svc", Module: "example.test/demo_svc"}
	_, err = engine.Render(engine.Options{Source: src, Target: projDir, Template: tpl, Resolved: resolved, Project: projectInfo, Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: resolvedRef.RepoAlias})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.SaveSnapshot(filepath.Join(projDir, manifest.SnapshotRelPath), tpl); err != nil {
		t.Fatal(err)
	}
	marker := manifest.Project{APIVersion: manifest.APIVersion, Kind: manifest.KindProject, ID: "fixture-demo_svc", Template: manifest.ProjectTemplate{Repo: resolvedRef.RepoAlias, Name: tpl.Metadata.Name, Version: resolvedRef.Version}, Project: projectInfo, Settings: resolved.Values, Runtime: manifest.ProjectRuntime{Port: 8080}, Baseline: engine.BaselineRelPath}
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
	now := time.Unix(1_700_000_000, 0).UTC()
	projects := state.DefaultProjects()
	projects.Upsert(state.ProjectRef{ID: marker.ID, Path: projDir, Template: state.TemplateSelection{Repo: resolvedRef.RepoAlias, Name: tpl.Metadata.Name, Version: resolvedRef.Version}, CreatedAt: now, LastSeenAt: now, BaselineSHA: hex.EncodeToString(digest[:])})
	if err := state.SaveProjects(home, projects); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(projDir)
	}
	return mgr, home, projDir
}

func testDeps(mgr *repo.Manager, home string, out, errOut *bytes.Buffer, prompter survey.Prompter, interactive bool) settingscmd.Deps {
	return settingscmd.Deps{
		Manager:     mgr,
		Home:        home,
		Out:         out,
		Err:         errOut,
		Palette:     ui.NewPalette(false),
		Now:         func() time.Time { return time.Unix(1_700_000_100, 0).UTC() },
		Prompter:    prompter,
		Interactive: interactive,
	}
}

func readStr(t *testing.T, dir, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func absent(t *testing.T, dir, rel string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel)))
	return os.IsNotExist(err)
}

func loadSettings(t *testing.T, projDir string) map[string]any {
	t.Helper()
	proj, err := manifest.LoadProject(filepath.Join(projDir, project.MarkerRelPath))
	if err != nil {
		t.Fatal(err)
	}
	return proj.Settings
}

func fixtureState(t *testing.T, home, projDir string) map[string][]byte {
	t.Helper()
	state := map[string][]byte{}
	for _, root := range []string{home, projDir} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			state[path] = append([]byte(nil), data...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return state
}

func assertLifecycleUnavailable(t *testing.T, err error, before, after map[string][]byte) {
	t.Helper()
	if !errors.Is(err, update.ErrLifecycleUnavailable) {
		t.Fatalf("expected typed lifecycle denial, got %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("lifecycle denial mutated fixture or HOME state")
	}
}

// --- set: vertical appears ---

func TestSettings_Set_DatabaseAppears(t *testing.T) {
	mgr, home, projDir := setup(t, nil, nil)
	// Initial state: database=none and no vertical.
	if !absent(t, projDir, "schema.sql") {
		t.Fatalf("до set schema.sql не должен существовать")
	}

	before := fixtureState(t, home, projDir)
	var out, errOut bytes.Buffer
	err := settingscmd.Set(context.Background(), testDeps(mgr, home, &out, &errOut, nil, false),
		settingscmd.Options{StartDir: projDir, Pairs: []string{"database=postgres"}})
	assertLifecycleUnavailable(t, err, before, fixtureState(t, home, projDir))
}

// --- set: back to none — remove clean vertical, preserve modified one ---

func TestSettings_Set_DatabaseNone_RemovesCleanKeepsModified(t *testing.T) {
	mgr, home, projDir := setup(t, []string{"database=postgres"}, func(p string) {
		// The user edited seed.sql, so it must survive vertical removal.
		writeFiles(t, p, map[string]string{"seed.sql": "insert into t; -- MINE\n"})
	})
	if absent(t, projDir, "schema.sql") {
		t.Fatalf("до set schema.sql должен существовать")
	}
	before := fixtureState(t, home, projDir)
	var out, errOut bytes.Buffer
	err := settingscmd.Set(context.Background(), testDeps(mgr, home, &out, &errOut, nil, false),
		settingscmd.Options{StartDir: projDir, Pairs: []string{"database=none"}})
	assertLifecycleUnavailable(t, err, before, fixtureState(t, home, projDir))
}

// --- set: requires chain (auth=oauth => database=postgres) ---

func TestSettings_Set_RequiresChain(t *testing.T) {
	mgr, home, projDir := setup(t, nil, nil)
	before := fixtureState(t, home, projDir)
	var out, errOut bytes.Buffer
	err := settingscmd.Set(context.Background(), testDeps(mgr, home, &out, &errOut, nil, false),
		settingscmd.Options{StartDir: projDir, Pairs: []string{"auth=oauth"}})
	assertLifecycleUnavailable(t, err, before, fixtureState(t, home, projDir))
}

// --- set --dry-run: nothing is written, but a summary is printed ---

func TestSettings_Set_DryRun(t *testing.T) {
	mgr, home, projDir := setup(t, nil, nil)
	var out, errOut bytes.Buffer
	err := settingscmd.Set(context.Background(), testDeps(mgr, home, &out, &errOut, nil, false),
		settingscmd.Options{StartDir: projDir, Pairs: []string{"database=postgres"}, DryRun: true})
	if err != nil {
		t.Fatalf("Set --dry-run: %v\n%s", err, errOut.String())
	}

	if !absent(t, projDir, "schema.sql") {
		t.Errorf("--dry-run создал schema.sql")
	}
	if got := loadSettings(t, projDir)["database"]; got != "none" {
		t.Errorf("--dry-run изменил project.yaml: database=%v", got)
	}
	s := out.String()
	if !strings.Contains(s, "--dry-run") {
		t.Errorf("нет пометки --dry-run:\n%s", s)
	}
	if !strings.Contains(s, "изменённые группы") {
		t.Errorf("нет сводки групп в dry-run:\n%s", s)
	}
}

// --- edit one group through ScriptedPrompter ---

func TestSettings_Edit_OneGroup(t *testing.T) {
	mgr, home, projDir := setup(t, nil, nil)
	before := fixtureState(t, home, projDir)

	prompter := &survey.ScriptedPrompter{
		Answers:  []settings.Values{{"database": "postgres"}},
		Confirms: []bool{true},
	}
	var out, errOut bytes.Buffer
	err := settingscmd.Edit(context.Background(), testDeps(mgr, home, &out, &errOut, prompter, true),
		settingscmd.Options{StartDir: projDir, Group: "database"})
	assertLifecycleUnavailable(t, err, before, fixtureState(t, home, projDir))
}

// edit without an argument lists groups as a hint and makes no changes.
func TestSettings_Edit_NoArg_ListsGroups(t *testing.T) {
	mgr, home, projDir := setup(t, nil, nil)

	var out, errOut bytes.Buffer
	err := settingscmd.Edit(context.Background(), testDeps(mgr, home, &out, &errOut, nil, false),
		settingscmd.Options{StartDir: projDir})
	if err != nil {
		t.Fatalf("Edit без группы: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "database") || !strings.Contains(s, "settings edit <group>") {
		t.Errorf("нет списка групп/подсказки:\n%s", s)
	}
}

// --- conflict: user edited a file, set changes the same area => markers, exit 2 ---

func TestSettings_Set_Conflict(t *testing.T) {
	mgr, home, projDir := setup(t, nil, func(p string) {
		// config.txt (a template file depending on database) was edited by the user.
		writeFiles(t, p, map[string]string{"config.txt": "db-mode: MINE\n"})
	})
	before := fixtureState(t, home, projDir)

	var out, errOut bytes.Buffer
	err := settingscmd.Set(context.Background(), testDeps(mgr, home, &out, &errOut, nil, false),
		settingscmd.Options{StartDir: projDir, Pairs: []string{"database=postgres"}})

	assertLifecycleUnavailable(t, err, before, fixtureState(t, home, projDir))
}

// --- settings list: nested activity ---

func TestSettings_List_ActiveColumn(t *testing.T) {
	mgr, home, projDir := setup(t, []string{"database=postgres"}, nil)

	var out, errOut bytes.Buffer
	err := settingscmd.List(testDeps(mgr, home, &out, &errOut, nil, false),
		settingscmd.Options{StartDir: projDir})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	s := out.String()
	// migrations is active (database=postgres selected) and appears in the table.
	for _, want := range []string{"database", "migrations", "brokers", "ACTIVE"} {
		if !strings.Contains(s, want) {
			t.Errorf("в таблице нет %q:\n%s", want, s)
		}
	}
}
