package auth_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/testfixture"
)

// leakCanary is a token value that must never appear anywhere except the
// token store itself and the git credential helper's answer to git.
const leakCanary = "tplaiter-leak-canary-3b9f6c1e0d7a"

// gitShim replaces git on PATH. It records its argv and environment, then
// fails like an unreachable remote, so no network is ever used.
const gitShim = `#!/bin/sh
{
  echo "argv: $*"
  /usr/bin/env
  echo "--"
} >> "$GIT_SHIM_LOG"
echo "fatal: git shim: remote unavailable" >&2
exit 128
`

// TestTokenNeverLeaks drives the real installed binary with a canary token
// and proves the credential boundary (tp-i9g.4.3): the token never reaches
// command output, error text, git argv or environment, MCP responses, or any
// state file other than the token store; the only sanctioned outlet is the
// git credential helper protocol answer to git itself.
func TestTokenNeverLeaks(t *testing.T) {
	inst := testfixture.BuildInstalled(t)
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, userHome, shimDir := filepath.Join(work, "tplaiter-home"), filepath.Join(work, "user"), filepath.Join(work, "shim")
	for _, dir := range []string{home, userHome, shimDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("version: 1\nrepos: []\ndefaults: {}\nupdates:\n  check: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shimLog := filepath.Join(work, "git-shim.log")
	if err := os.WriteFile(filepath.Join(shimDir, "git"), []byte(gitShim), 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"PATH=" + shimDir + ":/usr/bin:/bin", "HOME=" + userHome, "TPLAITER_HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(userHome, ".config"), "XDG_CACHE_HOME=" + filepath.Join(userHome, ".cache"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"NO_COLOR=1", "LANG=C", "GIT_SHIM_LOG=" + shimLog,
	}
	var observed bytes.Buffer
	run := func(stdin string, args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(inst.Bin, args...)
		cmd.Dir, cmd.Env = work, env
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.String() + stderr.String(), err
	}
	record := func(out string) { observed.WriteString(out) }

	out, err := run(leakCanary+"\n", "auth", "add", "git.example.test", "--token-stdin", "--username", "e2e")
	if err != nil {
		t.Fatalf("auth add: %v\n%s", err, out)
	}
	record(out)
	out, err = run("", "auth", "list")
	if err != nil {
		t.Fatalf("auth list: %v\n%s", err, out)
	}
	record(out)
	if !strings.Contains(out, "git.example.test") {
		t.Fatalf("auth list does not show the saved host:\n%s", out)
	}
	// A clone through the credential helper: the shim fails like an
	// unreachable remote; tplaiter's error output is recorded too.
	out, _ = run("", "repo", "add", "private", "https://git.example.test/org/templates.git")
	record(out)
	out, _ = run("", "repo", "list")
	record(out)

	// The one sanctioned outlet: git asks the helper and receives the token.
	answer, err := run("protocol=https\nhost=git.example.test\n\n", "auth", "git-credential", "get")
	if err != nil || !strings.Contains(answer, "password="+leakCanary+"\n") {
		t.Fatalf("git credential helper did not answer with the stored token: %v", err)
	}

	if inst.Provisioned {
		record(mcpTranscript(t, inst.Bin, work, env))
	} else {
		t.Log("mcp-server part skipped: trust store unavailable on this platform (requires U03)")
	}

	if strings.Contains(observed.String(), leakCanary) {
		t.Fatalf("token canary leaked into command or MCP output:\n%s", observed.String())
	}

	shim, err := os.ReadFile(shimLog)
	if err != nil {
		t.Fatalf("git shim was never invoked, so the argv/env boundary is unproven: %v", err)
	}
	if bytes.Contains(shim, []byte(leakCanary)) {
		t.Fatal("token canary reached git argv or environment")
	}
	if !bytes.Contains(shim, []byte("auth git-credential")) {
		t.Fatal("git was not configured with the tplaiter credential helper")
	}

	store := filepath.Join(home, "tplater.db")
	info, err := os.Stat(store)
	if err != nil {
		t.Fatalf("token store missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token store mode = %v, want 0600", info.Mode().Perm())
	}
	for _, root := range []string{home, userHome, inst.Root} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() || !d.Type().IsRegular() {
				return walkErr
			}
			if strings.HasPrefix(path, store) { // the store and its journal files hold the token by design
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(raw, []byte(leakCanary)) {
				t.Errorf("token canary leaked into state file %s", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// mcpTranscript runs mcp-server, lists tools and calls the repository tools,
// and returns every raw line the server wrote to stdout and stderr.
func mcpTranscript(t *testing.T, bin, dir string, env []string) string {
	t.Helper()
	cmd := exec.Command(bin, "mcp-server")
	cmd.Dir, cmd.Env = dir, env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	var transcript strings.Builder
	request := func(id int, method string, params map[string]any) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stdin.Write(append(raw, '\n')); err != nil {
			t.Fatalf("mcp write: %v (stderr: %s)", err, stderr.String())
		}
		deadline := time.After(60 * time.Second)
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("mcp-server exited (stderr: %s)", stderr.String())
				}
				transcript.WriteString(line + "\n")
				var message map[string]any
				if json.Unmarshal([]byte(line), &message) == nil && message["id"] == float64(id) {
					return
				}
			case <-deadline:
				t.Fatalf("mcp %s timed out (stderr: %s)", method, stderr.String())
			}
		}
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "leak", "version": "0"}})
	request(2, "tools/list", map[string]any{})
	request(3, "tools/call", map[string]any{"name": "repo_list", "arguments": map[string]any{}})
	request(4, "tools/call", map[string]any{"name": "repo_add", "arguments": map[string]any{"alias": "missing", "url": "file://" + filepath.Join(dir, "missing-origin")}})
	request(5, "tools/call", map[string]any{"name": "trust_inspect", "arguments": map[string]any{}})
	_ = stdin.Close()
	_ = cmd.Wait()
	transcript.WriteString(stderr.String())
	return transcript.String()
}
