package e2e

import (
	"path/filepath"
	"testing"
)

// TestEnvGenAI runs env/gen/ai against generated projects
// (scenario 6, implementation requirement): `env list` on a project WITHOUT
// playbooks (testdata/fixtures/single-basic declares no environment.playbooks);
// `gen list` and `ai validate` on a project from `tplater init-template` (it
// includes generators + ai-config "out of the box" — the only fixture where
// these commands see a non-empty result).
func TestEnvGenAI(t *testing.T) {
	requireGit(t)
	t.Parallel()

	home := newHome(t)

	t.Run("env_list_without_playbooks", func(t *testing.T) {
		origin := buildSingleOrigin(t, filepath.Join(fixturesDir(t), "single-basic"), "v1.0.0")
		mustRun(t, home, "", "repo", "add", "sb", "file://"+origin)

		projDir := filepath.Join(t.TempDir(), "proj")
		mustRun(t, home, "", "new", "sb/single-basic", "SB Project", "--dir", projDir, "--defaults")

		res := mustRun(t, home, projDir, "env", "list")
		_ = res // the manifest declares no playbooks; successful completion is enough.
	})

	t.Run("gen_and_ai_on_init_template_project", func(t *testing.T) {
		repoDir := filepath.Join(t.TempDir(), "svc-repo")
		mustRun(t, home, "", "init-template", "svc-ai", "--dir", repoDir)
		mustRun(t, home, "", "repo", "add", "svcrepo", "file://"+repoDir)

		projDir := filepath.Join(t.TempDir(), "proj")
		mustRun(t, home, "", "new", "svcrepo/svc-ai", "Svc AI", "--dir", projDir, "--defaults")

		genList := mustRun(t, home, projDir, "gen", "list")
		mustContain(t, genList.Stdout, "example", "gen list (init-template generators)")

		envList := mustRun(t, home, projDir, "env", "list")
		mustContain(t, envList.Stdout, "setup", "env list (init-template playbook)")

		mustRun(t, home, projDir, "ai", "validate")
		mustRun(t, home, projDir, "ai", "list")
	})
}
