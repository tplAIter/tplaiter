package cmd

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/testfixture"
)

// TestMakeInstallRegistration exercises the documented OSS install flow end
// to end (docs/install.md, ADR-005): `make install` into a temporary prefix,
// first-run `trust provision`, `trust inspect --json`, and an MCP initialize
// handshake, all from a synthetic HOME. It also covers reinstall (reuse) and
// rotation. No hand-made linker flags are involved.
func TestMakeInstallRegistration(t *testing.T) {
	testfixture.RequireTrustStore(t)
	makeBin, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make not found in PATH")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prefix, home := filepath.Join(root, "prefix"), filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	moduleRoot := testfixture.ModuleRoot(t)
	install := func(extra ...string) {
		t.Helper()
		args := append([]string{"--no-print-directory", "install", "PREFIX=" + prefix, "BIN=" + filepath.Join(root, "build", "tplaiter")}, extra...)
		cmd := exec.Command(makeBin, args...)
		cmd.Dir = moduleRoot
		cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "MAKEFLAGS=")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("make install %v: %v\n%s", extra, err, out)
		}
	}
	bin := filepath.Join(prefix, "bin", "tplaiter")
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "TPLAITER_HOME=" + filepath.Join(home, ".tplaiter"), "TPLAITER_PROFILE=development", "NO_COLOR=1"}
	run := func(args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir, cmd.Env = root, env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	pins := func() string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, "build", "registration.pins"))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if digest, ok := strings.CutPrefix(line, "REGISTRATION_SHA256="); ok {
				return digest
			}
		}
		t.Fatalf("no registration digest in %q", raw)
		return ""
	}

	install()
	firstDigest := pins()
	if out, err := run("trust", "inspect", "--json"); err == nil || !strings.Contains(out, "TRUST_NOT_PROVISIONED") {
		t.Fatalf("inspect before provisioning: err=%v output=%q", err, out)
	}
	if out, err := run("trust", "provision"); err != nil || out != "trust store provisioned\n" {
		t.Fatalf("trust provision: err=%v output=%q", err, out)
	}
	if out, err := run("trust", "provision"); err != nil || out != "trust store already provisioned\n" {
		t.Fatalf("repeated trust provision: err=%v output=%q", err, out)
	}
	report := inspectInstalled(t, run, firstDigest)
	if got := mcpInitialize(t, bin, root, env); !strings.Contains(got, `"serverInfo"`) {
		t.Fatalf("mcp-server initialize: %s", got)
	}

	// Reinstalling keeps the installation and its enrolled store.
	install()
	if pins() != firstDigest {
		t.Fatal("reinstall replaced a valid installation")
	}
	if again := inspectInstalled(t, run, firstDigest); again.Installation.InstallationID != report.Installation.InstallationID {
		t.Fatalf("reinstall changed the installation: %s -> %s", report.Installation.InstallationID, again.Installation.InstallationID)
	}

	// Rotation creates a new installation that must be provisioned again.
	install("TRUST_ROTATE=1")
	rotated := pins()
	if rotated == firstDigest {
		t.Fatal("rotation kept the old registration")
	}
	if out, err := run("trust", "inspect", "--json"); err == nil || !strings.Contains(out, "TRUST_NOT_PROVISIONED") {
		t.Fatalf("inspect after rotation: err=%v output=%q", err, out)
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision after rotation: %v %s", err, out)
	}
	inspectInstalled(t, run, rotated)
}

type installedInspection struct {
	ID            string `json:"id"`
	EvidenceClass string `json:"evidenceClass"`
	Installation  struct {
		InstallationID     string `json:"installationID"`
		RegistrationSHA256 string `json:"registrationSHA256"`
		Store              string `json:"store"`
	} `json:"installation"`
}

func inspectInstalled(t *testing.T, run func(...string) (string, error), digest string) installedInspection {
	t.Helper()
	out, err := run("trust", "inspect", "--json")
	if err != nil {
		t.Fatalf("trust inspect --json: %v\n%s", err, out)
	}
	var report installedInspection
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("trust inspect --json: %v\n%s", err, out)
	}
	if report.ID != "oss" || strings.Contains(out, `"development"`) || report.EvidenceClass != "production" {
		t.Fatalf("unexpected profile binding: %s", out)
	}
	if report.Installation.RegistrationSHA256 != digest || report.Installation.Store != "provisioned" {
		t.Fatalf("inspect reports %+v, want registration %s", report.Installation, digest)
	}
	return report
}

func mcpInitialize(t *testing.T, bin, dir string, env []string) string {
	t.Helper()
	cmd := exec.Command(bin, "mcp-server")
	cmd.Dir, cmd.Env = dir, env
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		if scanner.Scan() {
			done <- scanner.Text()
		}
		close(done)
	}()
	select {
	case line := <-done:
		_ = cmd.Wait()
		return line
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("mcp-server initialize timed out")
	}
	return ""
}
