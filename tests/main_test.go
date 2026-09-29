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
	"runtime"
	"strings"
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
	// Offline and machine-independent: no module downloads, and no system git
	// configuration leaks into fixture repositories or the binary under test.
	for key, value := range map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GIT_CONFIG_NOSYSTEM": "1"} {
		if err := os.Setenv(key, value); err != nil {
			fmt.Fprintln(os.Stderr, "e2e: setenv:", err)
			return 1
		}
	}
	tmp, err := os.MkdirTemp("", "tplater-e2e-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: mkdir temp:", err)
		return 1
	}
	defer os.RemoveAll(tmp)

	binPath = filepath.Join(tmp, "tplaiter")
	trustRoot = filepath.Join(tmp, "trust")
	if err := buildInstalledBinary(binPath, trustRoot); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: building the installed tplaiter binary:", err)
		return 1
	}

	return m.Run()
}

// trustRoot is the OSS install root the test binary is linked against.
var trustRoot string

// buildInstalledBinary reproduces `make install` for the test binary: it
// generates the operator-pinned OSS registration under root with the same
// build-time tool (cmd/tplaiter-oss-register), links the binary against the
// registration with the same -X pins as the Makefile, and runs the
// first-run `trust provision`. The harness therefore exercises exactly the
// installed launch path (ADR-005) without importing any internal package.
func buildInstalledBinary(out, root string) error {
	pinsFile := filepath.Join(filepath.Dir(out), "registration.pins")
	gen := exec.Command("go", "run", "./cmd/tplaiter-oss-register", "--root", root, "--output", pinsFile)
	gen.Dir = ".."
	gen.Env = append(os.Environ(), "GOWORK=off")
	if raw, err := gen.CombinedOutput(); err != nil {
		return fmt.Errorf("generate registration: %w\n%s", err, raw)
	}
	raw, err := os.ReadFile(pinsFile)
	if err != nil {
		return err
	}
	pins := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("malformed pin line %q", line)
		}
		pins[key] = value
	}
	if pins["REGISTRATION_PATH"] == "" || pins["REGISTRATION_SHA256"] == "" {
		return fmt.Errorf("registration pins missing in %q", raw)
	}
	registrationSHA256 = pins["REGISTRATION_SHA256"]
	if err := buildBinary(out, pins["REGISTRATION_PATH"], pins["REGISTRATION_SHA256"]); err != nil {
		return err
	}
	provision := exec.Command(out, "trust", "provision")
	provision.Dir = filepath.Dir(out)
	provision.Env = append(os.Environ(), "TPLAITER_HOME="+filepath.Join(filepath.Dir(out), "provision-home"))
	if raw, err := provision.CombinedOutput(); err != nil {
		if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
			return fmt.Errorf("trust provision: %w\n%s", err, raw)
		}
		// The secure trust store exists on darwin and Linux only; Windows is
		// deferred (tp-6v4). Trust-dependent tests skip via
		// requireProvisionedTrust on other platforms.
		provisionErr = fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(raw)))
	}
	return nil
}

// provisionErr records why first-run provisioning was unavailable on this
// platform; it is empty when the trust store was enrolled.
var provisionErr string

// registrationSHA256 is the registration digest linked into the binary.
var registrationSHA256 string

// buildBinary builds the root module (../ relative to tests/) into out.
// ldflags sets the same variables as the Makefile (LDFLAGS): the version, so
// resolveVersion() returns buildVersion rather than "dev" (see the comment
// above), and the installed-registration pins. GOWORK=off makes the build use
// the module independently; the workspace must not affect the dependency list.
func buildBinary(out, registrationPath, registrationDigest string) error {
	pkg := "github.com/tplAIter/tplaiter/internal/cmd"
	ldflags := fmt.Sprintf("-s -w -X %s.version=%s -X %s.installedRegistrationPath=%s -X %s.installedRegistrationSHA256=%s",
		pkg, buildVersion, pkg, registrationPath, pkg, registrationDigest)

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", out, ".")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	out2, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build: %w\n%s", err, out2)
	}
	return nil
}
