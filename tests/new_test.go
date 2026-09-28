package e2e

import (
	"path/filepath"
	"testing"
)

// TestNewErrors runs error paths for `tplater new` (scenario 3, implementation
// requirement): unknown template, repeated new into an occupied directory,
// and the requires.tplaiter version gate.
func TestNewErrors(t *testing.T) {
	requireGit(t)
	t.Parallel()

	home := newHome(t)
	origin := buildSingleOrigin(t, filepath.Join(fixturesDir(t), "single-basic"), "v1.0.0")
	mustRun(t, home, "", "repo", "add", "example", "file://"+origin)

	t.Run("unknown_template", func(t *testing.T) {
		res := run(t, home, "", "new", "example/does-not-exist-template", "proj",
			"--dir", filepath.Join(t.TempDir(), "proj"), "--defaults")
		if res.ExitCode == 0 {
			t.Fatal("new с несуществующим шаблоном: ожидался ненулевой exit, получен 0")
		}
		mustContain(t, res.Stderr+res.Stdout, "does-not-exist-template", "new с несуществующим шаблоном")
	})

	t.Run("occupied_directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "proj")
		mustRun(t, home, "", "new", "example/single-basic", "First", "--dir", dir, "--defaults")

		again := run(t, home, "", "new", "example/single-basic", "Second", "--dir", dir, "--defaults")
		if again.ExitCode == 0 {
			t.Fatal("повторный new в занятый каталог: ожидался ненулевой exit, получен 0")
		}
	})

	t.Run("version_gate", func(t *testing.T) {
		gateOrigin := buildVersionGateOrigin(t)
		mustRun(t, home, "", "repo", "add", "gaterepo", "file://"+gateOrigin)

		res := run(t, home, "", "new", "gaterepo/gatetpl", "proj",
			"--dir", filepath.Join(t.TempDir(), "proj"), "--defaults")
		if res.ExitCode == 0 {
			t.Fatal("new с requires.tplaiter >=99.0.0: ожидался ненулевой exit, получен 0")
		}
		combined := res.Stderr + res.Stdout
		mustContain(t, combined, "99.0.0", "new с недостижимым версия-гейтом")
	})
}
