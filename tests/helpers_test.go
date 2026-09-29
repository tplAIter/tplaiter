package e2e

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runResult — result of one tplater binary invocation.
type runResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// gitIdentityEnv — git environment variables for DETERMINISTIC commits
// without relying on the machine's global ~/.gitconfig (following
// internal/newcmd/newcmd_test.go:gitEnv). They are passed BOTH to our helper
// git commands (building origin fixtures) AND to the tplater binary under test
// (repo add clones, init-template runs git init+commit); otherwise
// `tplater init-template` without user.name/user.email merely downgrades a
// commit failure to a warning (see inittemplate.go:initGit), and scenario 1
// would not see a .git directory with a real commit on a CI runner without
// configured git identity.
func gitIdentityEnv() []string {
	return []string{
		"GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@example.com",
		"GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	}
}

// newHome creates an isolated TPLAITER_HOME for one test and pre-populates
// config.yaml with updates.check=false; otherwise EVERY command
// (except help/version/completion/self-upgrade, see
// internal/cmd/selfupgrade.go:suggestSkip) on its first run in a fresh
// TPLAITER_HOME starts a background `git ls-remote --tags
// <canonical-tplater-repository>` (internal/selfupdate.MaybeSuggest) — a
// network request with a timeout of up to 2s for EVERY test, unnecessary and
// potentially unstable on a runner without network access. The format is
// exactly what state.SaveConfig (internal/state/config.go) writes, verified by
// that package's unit tests; this black-box package does not import internal
// packages, so it writes the same YAML as text.
func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	cfg := "version: 1\nrepos: []\ndefaults: {}\nupdates:\n  check: false\n"
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("newHome: writing config.yaml: %v", err)
	}
	return home
}

// run starts the tplater binary with TPLAITER_HOME=home and working directory
// dir (an empty string means a temporary empty directory, therefore certainly
// NOT inside any project/template). It never calls t.Fatal for a non-zero exit
// code; that alone is not a test error, only a process launch failure (missing
// binary, etc.) is.
func run(t *testing.T, home, dir string, args ...string) runResult {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}

	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	cmd.Env = append(append(
		os.Environ(),
		"TPLAITER_HOME="+home,
		"NO_COLOR=1",
		// $SHELL is used by `tplater run`/hooks (execRunCommand); normalize it to
		// a POSIX shell regardless of the runner/developer shell environment.
		"SHELL=/bin/sh",
	), gitIdentityEnv()...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run tplater %v: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
		}
	}
	return runResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}
}

// mustRun — run variant that fails the test immediately on a non-zero exit
// code (for scenario steps that must succeed cleanly).
func mustRun(t *testing.T, home, dir string, args ...string) runResult {
	t.Helper()
	res := run(t, home, "", args...)
	if res.ExitCode != 0 {
		t.Fatalf("tplater %v: exit=%d\nstdout:\n%s\nstderr:\n%s", args, res.ExitCode, res.Stdout, res.Stderr)
	}
	return res
}

// requireGit skips the test if git is not found in PATH — the same contract as
// internal/newcmd/newcmd_test.go and internal/inittemplate/e2e_test.go (git is
// needed both by the harness to build origin fixtures and by tplater for repo
// add/init-template).
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found in PATH — e2e skipped")
	}
}

// runGit executes a git command with deterministic identity
// (gitIdentityEnv). It is used ONLY by the harness to prepare fixture origin
// repositories, not by tplater itself (tplater runs git through its own
// Runner).
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), gitIdentityEnv()...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (dir=%s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

// copyTree copies the file tree from src to dst (creating dst), preserving
// relative structure. It materializes origin repositories from
// testdata/fixtures (we do not commit git objects into testdata; fixtures
// remain ordinary files for the other packages, and each e2e test builds its
// own temporary git repository from a copy).
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if merr := os.MkdirAll(filepath.Dir(target), 0o755); merr != nil {
			return merr
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copyTree(%s -> %s): %v", src, dst, err)
	}
}

// initGitOrigin initializes a git repository in dir (already populated with
// files by copyTree/os.WriteFile before the call), then runs init + commit +
// optional tags. It returns dir unchanged for convenient call chaining.
func initGitOrigin(t *testing.T, dir string, tags ...string) string {
	t.Helper()
	runGit(t, dir, "init", "-b", "main")
	runGit(t, dir, "config", "uploadpack.allowFilter", "true")
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-m", "init")
	for _, tag := range tags {
		runGit(t, dir, "tag", tag)
	}
	return dir
}

// fixturesDir — root of testdata/fixtures in the main repository (the e2e
// harness's only dependency on the main module's filesystem is the fixtures
// themselves, not Go code: single-basic/multi; see testdata/fixtures/README.md).
func fixturesDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "testdata", "fixtures"))
	if err != nil {
		t.Fatalf("fixturesDir: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("fixturesDir: %s: %v (is the test running from tests/?)", abs, err)
	}
	return abs
}

// buildSingleOrigin materializes a single-template repository (one tree with
// template.manifest.yaml at its root) from src, tags it with stable tags
// (format "vX.Y.Z" — internal/repo/version.go:stableTagsFor expects a tag
// WITHOUT a prefix for single repositories), and returns the origin path.
func buildSingleOrigin(t *testing.T, src string, tags ...string) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	copyTree(t, src, origin)
	return initGitOrigin(t, origin, tags...)
}

// gateFixtureManifest — minimal template manifest with a requires.tplaiter
// version gate unreachable by any real tplater version (">=99.0.0"). This is
// the only deterministic way to exercise checkTplaterVersion
// (internal/newcmd/slug.go) as a black box: the test binary is built with a
// fixed buildVersion (see main_test.go), and no existing fixture template
// declares such a gate (testdata/fixtures/single-basic requires only >=0.1.0).
const gateFixtureManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: gatetpl
  version: 0.1.0
  description: "e2e fixture for the version gate (requires.tplaiter is unreachable)."
engine:
  type: gotemplate
  root: files
requires:
  tplater: ">=99.0.0"
`

// buildVersionGateOrigin builds a single-template repository whose manifest
// requires tplater >=99.0.0. `tplater new` from it must fail at
// checkTplaterVersion BEFORE creating any files (scenario 3, project
// documentation/implementation requirement: "version gate").
func buildVersionGateOrigin(t *testing.T) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	if err := os.MkdirAll(filepath.Join(origin, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "template.manifest.yaml"), []byte(gateFixtureManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "files", "hello.txt.tmpl"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return initGitOrigin(t, origin, "v1.0.0")
}

// mustContain fails the test if s does not contain sub. It is used only for
// STABLE substrings (template/alias/settings-group names from this
// implementation's fixtures), NOT for decorative cmd/internal/ui text, which
// the parallel implementation is polishing (see the package comment in
// main_test.go).
func mustContain(t *testing.T, s, sub, what string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("%s: expected substring %q, not found in:\n%s", what, sub, s)
	}
}

// mustReadFile reads the entire file at path as a string and fails the test on
// error. It is used for assertions on content rendered by the engine from OUR
// fixtures (not decorative cmd/internal/ui output).
func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

// exists — short file/directory existence check (for “file created/removed”
// assertions, an implementation contract: assert file existence rather than
// exact output strings).
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// requireProvisionedTrust skips a trust-dependent test when first-run
// provisioning was unavailable on this platform (see buildInstalledBinary).
// On darwin provisioning is mandatory, so this never skips there.
func requireProvisionedTrust(t *testing.T) {
	t.Helper()
	if provisionErr != "" {
		t.Skip("requires U03 Linux trust store (tp-i9g.4.3.2): " + provisionErr)
	}
}

// liveLifecycleDenial is the typed refusal the published core returns for
// new/update/settings until the live lifecycle is restored.
const liveLifecycleDenial = "TRUST_LIFECYCLE_UNAVAILABLE"

// skipAtLiveLifecycle runs a live-lifecycle step (new, update, settings set)
// and ends the scenario there with a tracked skip marker. It first proves that
// the installed trust launch itself works: the step must fail with exactly the
// lifecycle denial, never with a trust-anchor or provisioning error. Once the
// step succeeds, the test fails so that U07 removes the marker.
func skipAtLiveLifecycle(t *testing.T, home string, args ...string) {
	t.Helper()
	requireProvisionedTrust(t)
	res := run(t, home, "", args...)
	out := res.Stdout + res.Stderr
	if res.ExitCode == 0 {
		t.Fatalf("tplaiter %v now succeeds: remove the U07 skip marker and restore the scenario assertions", args)
	}
	if !strings.Contains(out, liveLifecycleDenial) {
		t.Fatalf("tplaiter %v: expected the %s denial (installed trust must load), got exit=%d\n%s", args, liveLifecycleDenial, res.ExitCode, out)
	}
	t.Skipf("requires U07 live lifecycle: tp-i9g.5.3 (tplaiter %s is %s)", args[0], liveLifecycleDenial)
}
