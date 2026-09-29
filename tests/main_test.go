// Package e2e is the black-box e2e harness for the tplater CLI.
//
// All tests run the REAL tplater binary through os/exec (they call no
// internal package directly; this is a separate module, see go.mod), with
// an isolated TPLAITER_HOME per test and real file:// git repositories
// (without network). Assertions follow harness_test.go: exit codes,
// file/directory existence, valid JSON, and presence of KEY
// substrings (template/group names controlled by THIS implementation through
// testdata/fixtures and the inittemplate skeleton), not full output lines;
// output formatting (internal/ui, cmd/*) is owned elsewhere and may change.
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// binPath is the built tplater binary path, prepared once in TestMain and shared
// by all package tests (building it for every test would be wasteful).
var binPath string

// buildVersion is compiled into the test binary through
// -ldflags (the same mechanism used by Makefile/CI for releases; see
// internal/cmd/version.go: resolveVersion). A fixed parseable semver is
// required for the version-gate test (requires.tplaiter,
// internal/newcmd/slug.go: checkTplaterVersion): a build without ldflags looks
// like a dev build ("dev"/BuildInfo.Main.Version == "(devel)"), so the
// version gate always skips this check and scenario 3 would be untestable.
const buildVersion = "v1.0.0"

// TestMain builds the tplater binary from the repository root (../) into a temporary
// directory before package tests run. The exit code is handled separately by
// [runMain], rather than os.Exit in TestMain itself, because otherwise
// `defer os.RemoveAll(tmp)` would never run (os.Exit does not unwind the defer
// stack).
func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	tmp, err := os.MkdirTemp("", "tplater-e2e-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: mkdir temp:", err)
		return 1
	}
	defer os.RemoveAll(tmp)

	binPath = filepath.Join(tmp, "tplaiter")
	if err := buildBinary(binPath); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: building the tplater binary:", err)
		return 1
	}

	return m.Run()
}

// buildBinary builds the root module (../ relative to tests/) into out.
// ldflags sets the same variable as the release Makefile (LDFLAGS),
// so resolveVersion() returns buildVersion rather than "dev" (see the comment
// above). GOWORK=off makes the build use the module independently; the
// workspace is unnecessary and must not affect the dependency list.
func buildBinary(out string) error {
	pkg := "github.com/tplAIter/tplaiter/internal/cmd"
	ldflags := fmt.Sprintf("-s -w -X %s.version=%s", pkg, buildVersion)

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", out, ".")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	out2, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build: %w\n%s", err, out2)
	}
	return nil
}
