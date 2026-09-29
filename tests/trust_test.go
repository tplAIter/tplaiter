package e2e

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// inspectReport is the subset of `trust inspect --json` the harness checks.
type inspectReport struct {
	ID            string `json:"id"`
	Assurance     string `json:"assurance"`
	EvidenceClass string `json:"evidenceClass"`
	Installation  struct {
		InstallationID     string `json:"installationID"`
		RegistrationSHA256 string `json:"registrationSHA256"`
		Store              string `json:"store"`
	} `json:"installation"`
}

// TestInstalledTrust proves the installed launch (ADR-005): the binary built
// like `make install` loads its linker-pinned OSS registration, reports the
// provisioned store, never selects the development profile whatever the
// environment says, and serves MCP over stdio with the same binding.
func TestInstalledTrust(t *testing.T) {
	requireProvisionedTrust(t)
	t.Parallel()

	home := newHome(t)
	inspect := mustRun(t, home, "", "trust", "inspect", "--json")
	var report inspectReport
	if err := json.Unmarshal([]byte(inspect.Stdout), &report); err != nil {
		t.Fatalf("trust inspect --json: invalid JSON: %v\n%s", err, inspect.Stdout)
	}
	if report.ID != "oss" || report.Assurance != "publisher-verified" || report.EvidenceClass != "production" {
		t.Fatalf("trust inspect --json: unexpected binding: %s", inspect.Stdout)
	}
	if report.Installation.RegistrationSHA256 != registrationSHA256 || report.Installation.Store != "provisioned" || !strings.HasPrefix(report.Installation.InstallationID, "oss-") {
		t.Fatalf("trust inspect --json: unexpected installation (want registration %s): %s", registrationSHA256, inspect.Stdout)
	}
	if strings.Contains(inspect.Stdout, "development") {
		t.Fatalf("trust inspect --json mentions the development profile: %s", inspect.Stdout)
	}

	t.Run("environment_never_selects_trust", func(t *testing.T) {
		// A hostile HOME and profile variables must not change the binding:
		// selection is linker-pinned only.
		hostile := t.TempDir()
		for _, dir := range []string{filepath.Join(hostile, ".tplaiter"), filepath.Join(hostile, ".config", "tplaiter")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "registration.json"), []byte(`{"profile":"development"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(binPath, "trust", "inspect", "--json")
		cmd.Dir = t.TempDir()
		cmd.Env = append(os.Environ(), "TPLAITER_HOME="+home, "HOME="+hostile, "XDG_CONFIG_HOME="+filepath.Join(hostile, ".config"),
			"TPLAITER_PROFILE=development", "TPLAITER_REGISTRATION_PATH="+filepath.Join(hostile, ".tplaiter", "registration.json"))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("trust inspect under hostile environment: %v", err)
		}
		if string(out) != inspect.Stdout {
			t.Fatalf("binding changed under hostile environment:\nwant %s\ngot  %s", inspect.Stdout, out)
		}
	})

	t.Run("provision_is_idempotent", func(t *testing.T) {
		res := mustRun(t, home, "", "trust", "provision")
		mustContain(t, res.Stdout, "already provisioned", "repeated trust provision")
	})

	t.Run("mcp_server_stdio", func(t *testing.T) {
		checkMCPTrustInspect(t, home, inspect.Stdout)
	})
}

// checkMCPTrustInspect starts `tplaiter mcp-server`, performs the MCP
// handshake, and requires trust_inspect to return the direct CLI binding.
func checkMCPTrustInspect(t *testing.T, home, direct string) {
	t.Helper()
	cmd := exec.Command(binPath, "mcp-server")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "TPLAITER_HOME="+home, "NO_COLOR=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("mcp-server start: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	lines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	send := func(message map[string]any) {
		t.Helper()
		raw, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stdin.Write(append(raw, '\n')); err != nil {
			t.Fatalf("mcp write: %v (stderr: %s)", err, stderr.String())
		}
	}
	receive := func(id int) map[string]any {
		t.Helper()
		deadline := time.After(60 * time.Second)
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("mcp-server closed stdout (stderr: %s)", stderr.String())
				}
				var message map[string]any
				if err := json.Unmarshal([]byte(line), &message); err != nil {
					t.Fatalf("mcp-server wrote non-JSON %q: %v", line, err)
				}
				if message["id"] == float64(id) {
					if message["error"] != nil {
						t.Fatalf("mcp request %d failed: %v", id, message["error"])
					}
					return message
				}
			case <-deadline:
				t.Fatalf("mcp response %d timed out (stderr: %s)", id, stderr.String())
			}
		}
	}
	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "e2e", "version": "0"}}})
	initialized := receive(1)
	if result, _ := initialized["result"].(map[string]any); result["serverInfo"] == nil {
		t.Fatalf("initialize: no serverInfo: %v", initialized)
	}
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}})
	send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "trust_inspect", "arguments": map[string]any{}}})
	call := receive(2)
	result, _ := call["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("trust_inspect returned an error: %v", call)
	}
	// trust_inspect returns a result/v1 envelope whose data.binding is the
	// binding `trust inspect --json` prints.
	structured, _ := result["structuredContent"].(map[string]any)
	if structured["operation"] != "trust.inspect" || structured["status"] != "ok" {
		t.Fatalf("trust_inspect envelope: %v", call)
	}
	data, _ := structured["data"].(map[string]any)
	binding, ok := data["binding"]
	if !ok {
		t.Fatalf("trust_inspect: no data.binding: %v", call)
	}
	var want any
	if err := json.Unmarshal([]byte(direct), &want); err != nil {
		t.Fatalf("trust inspect --json: %v", err)
	}
	if !reflect.DeepEqual(binding, want) {
		t.Fatalf("trust_inspect over MCP differs from the CLI:\ncli %s\nmcp %v", direct, binding)
	}
}
