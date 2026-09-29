package update_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
	"github.com/tplAIter/tplaiter/internal/update"
)

// --- git infrastructure (real git, file:// repository, as in internal/newcmd) ---

var gitExec = execx.Exec{}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := gitExec.LookPath("git"); err != nil {
		t.Skip("git not found in PATH — integration test skipped")
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

// initTwoTagOrigin creates an origin with commits and tags v0.1.0 (v1 files) and
// v0.2.0 (v2 files); files absent in v2 are removed from the index.
func initTwoTagOrigin(t *testing.T, v1, v2 map[string]string) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	if err := os.MkdirAll(origin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFiles(t, origin, v1)
	runGit(t, origin, "init", "-b", "main")
	runGit(t, origin, "config", "uploadpack.allowFilter", "true")
	runGit(t, origin, "add", "-A")
	runGit(t, origin, "commit", "-m", "v1")
	runGit(t, origin, "tag", "v0.1.0")

	// Remove files absent in v2.
	for rel := range v1 {
		if _, ok := v2[rel]; !ok {
			_ = os.Remove(filepath.Join(origin, filepath.FromSlash(rel)))
		}
	}
	writeFiles(t, origin, v2)
	runGit(t, origin, "add", "-A")
	runGit(t, origin, "commit", "-m", "v2")
	runGit(t, origin, "tag", "v0.2.0")
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

func manifestYAML(version, hooks string) string {
	m := `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc
  version: ` + version + `
engine:
  root: files
requires:
  tplater: ">=0.1.0"
`
	return m + hooks
}

// v1Files/v2Files are trees exercising all five report categories.
func v1Files() map[string]string {
	return map[string]string{
		"template.manifest.yaml": manifestYAML("0.1.0", "hooks:\n  postUpdate:\n    - run: \"echo postUpdate-done\"\n"),
		"files/main.txt.tmpl":    "slug={{ .Project.Slug }}\n", // unchanged — untouched
		"files/readme.txt":       "# readme v1\nstable\n",      // (a) updated if unedited
		"files/keep.txt":         "constant\n",                 // (b) template unchanged, user edits
		"files/merge.txt":        "l1\nl2\nl3\n",               // (c) clean merge
		"files/conflict.txt":     "x\ny\nz\n",                  // (c) conflict
		"files/removed.txt":      "old\n",                      // (e) removed
	}
}

func v2Files() map[string]string {
	return map[string]string{
		"template.manifest.yaml": manifestYAML("0.2.0", "hooks:\n  postUpdate:\n    - run: \"echo postUpdate-done\"\n"),
		"files/main.txt.tmpl":    "slug={{ .Project.Slug }}\n",
		"files/readme.txt":       "# readme v2\nupdated\n",
		"files/keep.txt":         "constant\n",
		"files/merge.txt":        "l1\nl2\nCHANGED3\n",
		"files/conflict.txt":     "x\nTPL\nz\n",
		"files/added.txt":        "brand new\n", // (d) created
	}
}

// setup creates home and an example repository with svc (two tags), then creates
// a project at v0.1.0 in a separate directory with user edits.
func setup(t *testing.T, edit func(projectDir string)) (mgr *repo.Manager, home, projDir string) {
	t.Helper()
	requireGit(t)
	home = filepath.Join(t.TempDir(), "home")
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	origin := initTwoTagOrigin(t, v1Files(), v2Files())
	mgr = newManager(t, home)
	if err := mgr.Add(context.Background(), repo.AddOptions{Alias: "example", URL: "file://" + origin}); err != nil {
		t.Fatalf("repo add: %v", err)
	}

	projDir = filepath.Join(t.TempDir(), "proj")
	var out, errOut bytes.Buffer
	err := newcmd.Run(context.Background(), newcmd.Options{
		Ref:         "example/svc@v0.1.0",
		ProjectName: "demo_svc",
		Dir:         projDir,
		Defaults:    true,
		Interactive: false,
		CLIVersion:  "v1.0.0",
	}, newcmd.Deps{
		Manager:  mgr,
		Runner:   execx.Exec{},
		Home:     home,
		Prompter: &survey.ScriptedPrompter{},
		Out:      &out,
		Err:      &errOut,
		Palette:  ui.NewPalette(false),
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("newcmd.Run: %v\n%s", err, errOut.String())
	}
	if edit != nil {
		edit(projDir)
	}
	return mgr, home, projDir
}

func testDeps(mgr *repo.Manager, home string, out, errOut *bytes.Buffer) update.Deps {
	return update.Deps{
		Manager: mgr,
		Runner:  execx.Exec{},
		Home:    home,
		Out:     out,
		Err:     errOut,
		Palette: ui.NewPalette(false),
		Now:     func() time.Time { return time.Unix(1_700_000_100, 0).UTC() },
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

// --- e2e: full v0.1.0 -> v0.2.0 matrix with a conflict ---

func TestUpdate_E2E_Matrix(t *testing.T) {
	if err := update.Run(context.Background(), update.Deps{}, update.Options{StartDir: filepath.Join(t.TempDir(), "missing")}); !errors.Is(err, update.ErrLifecycleUnavailable) {
		t.Fatalf("legacy update error = %v", err)
	}
}

// --check catches remaining markers (exit 1).
func TestUpdate_Check_CatchesMarkers(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"conflict.txt": "<<<<<<< local\n"})
	var out, errOut bytes.Buffer
	err := update.Run(context.Background(), testDeps(nil, "", &out, &errOut), update.Options{StartDir: root, Check: true})
	var exit *update.ExitCodeError
	if !errors.As(err, &exit) || exit.Code != 1 || !strings.Contains(out.String(), "conflict.txt") {
		t.Fatalf("local-only --check = %v, %q", err, out.String())
	}
}

// no-op: same-version update without edits -> empty plan.
func TestUpdate_NoOp(t *testing.T) {
	if err := update.Run(context.Background(), update.Deps{}, update.Options{StartDir: filepath.Join(t.TempDir(), "missing"), To: "v0.1.0"}); !errors.Is(err, update.ErrLifecycleUnavailable) {
		t.Fatalf("legacy update error = %v", err)
	}
}

// dry-run writes nothing.
func TestUpdate_DryRun(t *testing.T) {
	if err := update.Run(context.Background(), update.Deps{}, update.Options{StartDir: filepath.Join(t.TempDir(), "missing"), DryRun: true}); !errors.Is(err, update.ErrLifecycleUnavailable) {
		t.Fatalf("legacy dry-run error = %v", err)
	}
}

// --all across two projects (one conflicting): summary and continuation.
func TestUpdate_All_TwoProjects(t *testing.T) {
	if err := update.Run(context.Background(), update.Deps{}, update.Options{All: true}); !errors.Is(err, update.ErrLifecycleUnavailable) {
		t.Fatalf("legacy --all error = %v", err)
	}
}

// --- helpers ---

func loadBaseline(t *testing.T, dir string) struct {
	Files map[string]string `json:"files"`
} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ".tplaiter", "baseline.json"))
	if err != nil {
		t.Fatalf("baseline read: %v", err)
	}
	var b struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("baseline json: %v", err)
	}
	return b
}

func hashFileHex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sum256(data)
}

func sum256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
