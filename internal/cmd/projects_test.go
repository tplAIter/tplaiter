package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
)

// writeProjectsFixtureAt creates .tplaiter/project.yaml plus
// .tplaiter/baseline.json in dir, a minimal fixture sufficient for both
// project.FindRoot (internal/project) and projectsync.SyncCurrent (baseline.json
// is needed to compute baselineSHA).
func writeProjectsFixtureAt(t *testing.T, dir, id string) {
	t.Helper()
	tplDir := filepath.Join(dir, ".tplaiter")
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", tplDir, err)
	}
	marker := "apiVersion: tplater.dev/v1alpha1\n" +
		"kind: Project\n" +
		"id: " + id + "\n" +
		"template:\n  repo: example\n  name: go-service\n  version: 1.4.0\n"
	if err := os.WriteFile(filepath.Join(tplDir, "project.yaml"), []byte(marker), 0o644); err != nil {
		t.Fatalf("write project.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tplDir, "baseline.json"), []byte(`{"schema":1}`), 0o644); err != nil {
		t.Fatalf("write baseline.json: %v", err)
	}
}

// seedProjectsRegistry writes projects.yaml with the given entries under home,
// bypassing WithLock (the test does not contend with itself).
func seedProjectsRegistry(t *testing.T, home string, refs ...state.ProjectRef) {
	t.Helper()
	p := state.DefaultProjects()
	for _, ref := range refs {
		p.Upsert(ref)
	}
	if err := state.SaveProjects(home, p); err != nil {
		t.Fatalf("SaveProjects() error = %v", err)
	}
}

func TestProjectsListCmd_OkAndMissingStatuses(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)

	okDir := t.TempDir()
	writeProjectsFixtureAt(t, okDir, "proj-ok")
	missingDir := filepath.Join(t.TempDir(), "gone") // directory never created.

	seedProjectsRegistry(
		t, home,
		state.ProjectRef{
			ID:   "proj-ok",
			Path: okDir,
			Template: state.TemplateSelection{
				Repo: "example", Name: "go-service", Version: "1.4.0",
			},
			LastSeenAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
		state.ProjectRef{
			ID:   "proj-missing",
			Path: missingDir,
			Template: state.TemplateSelection{
				Repo: "example", Name: "go-service", Version: "1.0.0",
			},
			LastSeenAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		},
	)

	cmd := newProjectsListCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("projects list error = %v", err)
	}

	lines := strings.Split(out.String(), "\n")
	var okLine, missingLine string
	for _, l := range lines {
		switch {
		case strings.Contains(l, "proj-ok") || strings.Contains(l, okDir):
			okLine = l
		case strings.Contains(l, missingDir):
			missingLine = l
		}
	}
	if okLine == "" || !strings.Contains(okLine, "ok") {
		t.Errorf("output = %q, want a line for %s with STATUS=ok", out.String(), okDir)
	}
	if missingLine == "" || !strings.Contains(missingLine, "missing") {
		t.Errorf("output = %q, want a line for %s with STATUS=missing", out.String(), missingDir)
	}
}

func TestProjectsPruneCmd_YesRemovesOnlyMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)

	okDir := t.TempDir()
	writeProjectsFixtureAt(t, okDir, "proj-ok")
	missingDir1 := filepath.Join(t.TempDir(), "gone-1")
	missingDir2 := filepath.Join(t.TempDir(), "gone-2")

	seedProjectsRegistry(
		t, home,
		state.ProjectRef{ID: "proj-ok", Path: okDir, Template: state.TemplateSelection{Repo: "example", Name: "go-service"}},
		state.ProjectRef{ID: "proj-missing-1", Path: missingDir1, Template: state.TemplateSelection{Repo: "example", Name: "a"}},
		state.ProjectRef{ID: "proj-missing-2", Path: missingDir2, Template: state.TemplateSelection{Repo: "example", Name: "b"}},
	)

	cmd := newProjectsPruneCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("projects prune --yes error = %v", err)
	}
	if !strings.Contains(out.String(), "removed entries: 2") {
		t.Errorf("output = %q, want mention of 2 removed records", out.String())
	}

	projects, err := state.LoadProjects(home)
	if err != nil {
		t.Fatalf("LoadProjects() error = %v", err)
	}
	if len(projects.Items) != 1 || projects.Items[0].ID != "proj-ok" {
		t.Errorf("LoadProjects().Items = %+v, want only proj-ok left", projects.Items)
	}
}

func TestProjectsPruneCmd_NothingMissing_NoOp(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)

	okDir := t.TempDir()
	writeProjectsFixtureAt(t, okDir, "proj-ok")
	seedProjectsRegistry(t, home, state.ProjectRef{ID: "proj-ok", Path: okDir})

	cmd := newProjectsPruneCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("projects prune --yes error = %v", err)
	}
	if !strings.Contains(out.String(), "no entries with missing status") {
		t.Errorf("output = %q, want no-op message", out.String())
	}

	projects, err := state.LoadProjects(home)
	if err != nil {
		t.Fatalf("LoadProjects() error = %v", err)
	}
	if len(projects.Items) != 1 {
		t.Errorf("LoadProjects().Items = %+v, want unchanged", projects.Items)
	}
}

func TestProjectsPruneCmd_WithoutYesNonInteractive_ErrorsWithoutRemoving(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)

	missingDir := filepath.Join(t.TempDir(), "gone")
	seedProjectsRegistry(t, home, state.ProjectRef{ID: "proj-missing", Path: missingDir})

	cmd := newProjectsPruneCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("projects prune without --yes in non-interactive mode: error = nil, want an error asking for --yes")
	}

	projects, err := state.LoadProjects(home)
	if err != nil {
		t.Fatalf("LoadProjects() error = %v", err)
	}
	if len(projects.Items) != 1 {
		t.Errorf("LoadProjects().Items = %+v, a declined confirmation must not remove entries", projects.Items)
	}
}

func TestProjectSyncPreRun_SkipsForSkipList(t *testing.T) {
	for _, topName := range []string{"help", "version", "completion", "init-shell"} {
		t.Run(topName, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv(state.HomeEnv, home)

			top := &cobra.Command{Use: topName}
			top.SetContext(context.Background())
			var stderr bytes.Buffer
			top.SetErr(&stderr)

			projectSyncPreRun(top, nil)

			if _, err := os.Stat(filepath.Join(home, "projects.yaml")); err == nil {
				t.Errorf("projectSyncPreRun() created projects.yaml for skipped command %q", topName)
			}
		})
	}
}

// withCwd changes the process working directory to dir for the test and restores
// it afterward (see internal/cmd/run_test.go:newRunFixture, the same pattern).
func withCwd(t *testing.T, dir string) {
	t.Helper()
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })
}

// newProjectSyncIntegrationRoot builds a minimal cobra tree (root plus one
// leafName subcommand) composed like rootCmd (PersistentPreRunE = rootPreRun),
// without package rootCmd and its shared init-registered command state (see the
// same technique in TestRootPreRun_BareInvocationSkipsFirstRunAndSuggest).
func newProjectSyncIntegrationRoot(leafName string) *cobra.Command {
	leaf := &cobra.Command{
		Use: leafName,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
	}
	root := &cobra.Command{Use: "tplaiter", PersistentPreRunE: rootPreRun}
	root.AddCommand(leaf)
	return root
}

func TestProjectSyncPreRun_Integration_CommandInProjectUpdatesLastSeen(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)
	withUpgradeFlag(t, false)

	rec := execx.NewRecordingRunner()
	scriptLsRemote(rec, "") // suggestUpdatePreRun is in the chain and must not use real network.
	withRunner(t, rec)

	projectDir := t.TempDir()
	writeProjectsFixtureAt(t, projectDir, "proj-integration")
	withCwd(t, projectDir)

	root := newProjectSyncIntegrationRoot("list")
	root.SetArgs([]string{"list"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	projects, err := state.LoadProjects(home)
	if err != nil {
		t.Fatalf("LoadProjects() error = %v", err)
	}
	ref, ok := projects.FindByID("proj-integration")
	if !ok {
		t.Fatalf("LoadProjects() does not contain the auto-registered project, items=%+v", projects.Items)
	}
	if ref.LastSeenAt.IsZero() || time.Since(ref.LastSeenAt) > time.Minute {
		t.Errorf("LastSeenAt = %v, want a fresh (just set) timestamp", ref.LastSeenAt)
	}
}

func TestProjectSyncPreRun_Integration_HelpDoesNotTrigger(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)
	withUpgradeFlag(t, false)

	rec := execx.NewRecordingRunner()
	withRunner(t, rec) // no calls expected; completion/help do not reach suggest/sync.

	projectDir := t.TempDir()
	writeProjectsFixtureAt(t, projectDir, "proj-help")
	withCwd(t, projectDir)

	root := newProjectSyncIntegrationRoot("help")
	root.SetArgs([]string{"help"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	if len(rec.Calls) != 0 {
		t.Errorf("help made %d network-like calls through runner, want 0", len(rec.Calls))
	}
	if _, err := os.Stat(filepath.Join(home, "projects.yaml")); err == nil {
		t.Error("help created projects.yaml — registry sync must not trigger for help")
	}
}
