package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/diffcmd"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestNativeDiffInstalledCLIAndMCP(t *testing.T) {
	t.Run("blocks", func(t *testing.T) { nativeDiffInstalledProof(t, false) })
	t.Run("configured action", func(t *testing.T) { nativeDiffInstalledProof(t, true) })
}

func nativeDiffInstalledProof(t *testing.T, action bool) {
	testfixture.RequireTrustStore(t)
	extra := []string{}
	if action {
		extra = append(extra, "commands:\n  build:\n    run: echo never-executed\n")
	}
	f := nativeDiffCLIFixture(t, extra...)
	base := filepath.Dir(f.projectRoot)
	home := filepath.Join(base, "process-home")
	if err := os.MkdirAll(filepath.Join(home, "tplaiter"), 0o700); err != nil {
		t.Fatal(err)
	}
	registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
	raw := t5FJSON(t, registration)
	regPath := filepath.Join(base, "registration.json")
	if err := os.WriteFile(regPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=dev -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+regPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+evidencecas.Digest(raw), "-o", bin, ".")
	build.Dir = filepath.Join("..", "..")
	build.Env = testBuildEnv(home)
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, []byte, int) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = base
		cmd.Env = testProcessEnv(home)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		e := cmd.Run()
		code := 0
		if e != nil {
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatalf("child: %v", e)
			}
			code = exit.ExitCode()
		}
		return stdout.Bytes(), stderr.Bytes(), code
	}
	if out, stderr, code := run("trust", "provision"); code != 0 {
		t.Fatalf("provision: %d %s %s", code, out, stderr)
	}
	materializeDiffFixture(t, f, action)
	var install trustload.RuntimeInstall
	raw, e := os.ReadFile(f.selection.RuntimeConfig.Path)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &install); e != nil {
		t.Fatal(e)
	}
	roots := []string{f.projectRoot, home, install.ObjectOrigins[0].RootPath, install.EvidenceRoot, f.store}
	checkCLI := func(want int, args ...string) resultdto.Result {
		t.Helper()
		before := nativeVerifySnapshot(t, roots...)
		out, stderr, code := run(append([]string{"diff", "--json"}, args...)...)
		nativeVerifyUnchanged(t, before, roots...)
		env := decodeOne(t, string(out))
		if code != want || env.Operation != resultdto.OperationProjectDiff {
			t.Fatalf("CLI want %d got %d %s %s", want, code, out, stderr)
		}
		t.Logf("CLI exit=%d %s", code, out)
		return env
	}
	if action {
		blocked := checkCLI(resultdto.ExitUnavailable.Int(), "--exit-code")
		if len(blocked.Changes) != 0 || blocked.Project != nil {
			t.Fatal("unsupported action published a projection")
		}
		return
	}
	// Library cancellation/deadline preserves causes and publishes no partial report.
	r, e := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	if e != nil {
		t.Fatal(e)
	}
	for _, deadline := range []bool{false, true} {
		before := nativeVerifySnapshot(t, roots...)
		var stopped context.Context
		var stop context.CancelFunc
		want := context.Canceled
		if deadline {
			stopped, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			stopped, stop = context.WithCancel(ctx)
			stop()
		}
		report, e := diffcmd.Run(stopped, r, diffcmd.Options{Home: filepath.Join(home, "tplaiter"), RendererVersion: "dev", SecretProvider: readonlyHomeClassifier{}})
		stop()
		if !errors.Is(e, want) || len(report.Changes) != 0 {
			t.Fatalf("cancel: %v %+v", e, report)
		}
		nativeVerifyUnchanged(t, before, roots...)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	clean := checkCLI(0, "--exit-code")
	if clean.Status != resultdto.StatusOK || len(clean.Changes) != 0 {
		t.Fatal(clean)
	}
	moved := strings.Replace(nativeDiffBlocks, "header\n", "header\ngap\n", 1)
	moved = strings.Replace(moved, "id=alpha\ngap\n", "id=alpha\n", 1)
	if e := os.WriteFile(filepath.Join(f.projectRoot, "hello.txt"), []byte(moved), 0o644); e != nil {
		t.Fatal(e)
	}
	assertDiffSkeleton(t, checkCLI(1, "--exit-code"))
	edited := strings.ReplaceAll(strings.ReplaceAll(nativeDiffBlocks, "alpha base", "alpha local"), "beta base", "beta local")
	if e := os.WriteFile(filepath.Join(f.projectRoot, "hello.txt"), []byte(edited), 0o644); e != nil {
		t.Fatal(e)
	}
	changed := checkCLI(1, "--exit-code")
	assertDiffPair(t, changed)
	assertDiffPair(t, checkCLI(0))
	plain := filepath.Join(f.projectRoot, "obsolete.txt")
	if e := os.WriteFile(plain, []byte("ordinary local\n"), 0o644); e != nil {
		t.Fatal(e)
	}
	ordinary := checkCLI(1, "--exit-code")
	if len(ordinary.Changes) != 3 || ordinary.Summary.FilesChanged != 1 || ordinary.Summary.BlocksChanged != 2 {
		t.Fatalf("ordinary: %+v", ordinary)
	}
	if e := os.WriteFile(plain, []byte("old owned\n"), 0o644); e != nil {
		t.Fatal(e)
	}
	checkCLI(resultdto.ExitTrust.Int(), "--dir", base)
	checkCLI(resultdto.ExitUnavailable.Int(), "--project-context", "unknown")
	checkCLI(resultdto.ExitUnavailable.Int(), "--offline=false")
	checkCLI(resultdto.ExitUsage.Int(), "--execute=true")
	if e := os.WriteFile(filepath.Join(f.projectRoot, "hello.txt"), []byte(strings.ReplaceAll(edited, "id=beta", "id=alpha")), 0o644); e != nil {
		t.Fatal(e)
	}
	blocked := checkCLI(resultdto.ExitOperational.Int(), "--exit-code")
	if len(blocked.Changes) != 0 || blocked.Project != nil {
		t.Fatal("error leaked partial projection")
	}
	if e := os.WriteFile(filepath.Join(f.projectRoot, "hello.txt"), []byte(edited), 0o644); e != nil {
		t.Fatal(e)
	}
	// Real server and held installed child, not a RecordingRunner proof.
	server := exec.CommandContext(ctx, bin, "mcp-server")
	server.Dir = base
	server.Env = testProcessEnv(home)
	stdin, e := server.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdout, e := server.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	server.Stderr = &stderr
	if e = server.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = stdin.Close(); _ = server.Wait() }()
	encoder, decoder := json.NewEncoder(stdin), json.NewDecoder(stdout)
	request := func(id int, method string, params any) map[string]any {
		t.Helper()
		if e := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); e != nil {
			t.Fatal(e)
		}
		var response map[string]any
		if e := decoder.Decode(&response); e != nil {
			t.Fatalf("MCP decode: %v %s", e, stderr.String())
		}
		if response["error"] != nil {
			t.Fatalf("MCP error: %+v", response)
		}
		return response
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "native-diff-test", "version": "1"}})
	if e := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); e != nil {
		t.Fatal(e)
	}
	call := func(id int, args map[string]any) resultdto.Result {
		t.Helper()
		before := nativeVerifySnapshot(t, roots...)
		response := request(id, "tools/call", map[string]any{"name": "project_diff", "arguments": args})
		nativeVerifyUnchanged(t, before, roots...)
		result, ok := response["result"].(map[string]any)
		if !ok {
			t.Fatalf("missing MCP result: %+v", response)
		}
		raw, e := json.Marshal(result["structuredContent"])
		if e != nil {
			t.Fatal(e)
		}
		env, e := resultdto.Decode(raw)
		if e != nil {
			t.Fatalf("MCP envelope: %v %s", e, raw)
		}
		if env.Operation != resultdto.OperationProjectDiff {
			t.Fatal(env.Operation)
		}
		t.Logf("MCP %s", raw)
		return env
	}
	assertDiffPair(t, call(2, map[string]any{"dir": f.projectRoot, "exitCode": true}))
	if e := os.WriteFile(filepath.Join(f.projectRoot, "hello.txt"), []byte(moved), 0o644); e != nil {
		t.Fatal(e)
	}
	assertDiffSkeleton(t, call(6, map[string]any{"dir": f.projectRoot, "exitCode": true}))
	foreign := call(3, map[string]any{"dir": base})
	if foreign.Status != resultdto.StatusBlocked || foreign.Project != nil || len(foreign.Changes) != 0 {
		t.Fatalf("MCP foreign: %+v", foreign)
	}
	if e := os.WriteFile(filepath.Join(f.projectRoot, "hello.txt"), []byte(nativeDiffBlocks), 0o644); e != nil {
		t.Fatal(e)
	}
	clean = call(4, map[string]any{"dir": f.projectRoot, "projectContext": "project", "exitCode": true})
	if clean.Status != resultdto.StatusOK || len(clean.Changes) != 0 {
		t.Fatal("MCP clean")
	}
	invalid := call(5, map[string]any{"dir": f.projectRoot, "execute": true})
	if len(invalid.Diagnostics) != 1 || invalid.Diagnostics[0].Code != "MCP_INVALID_ARGUMENT" {
		t.Fatalf("unknown control: %+v", invalid)
	}
	// Invalid stored baseline is an assertion, never alternate authority.
	baselinePath := filepath.Join(f.projectRoot, ".tplaiter", "baseline.json")
	saved, e := os.ReadFile(baselinePath)
	if e != nil {
		t.Fatal(e)
	}
	var baseline map[string]any
	if e = json.Unmarshal(saved, &baseline); e != nil {
		t.Fatal(e)
	}
	baseline["contextHash"] = "caller-forged"
	forged, e := json.Marshal(baseline)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(baselinePath, forged, 0o644); e != nil {
		t.Fatal(e)
	}
	checkCLI(resultdto.ExitOperational.Int())
	if e = os.WriteFile(baselinePath, saved, 0o644); e != nil {
		t.Fatal(e)
	}
	// Fresh immutable object corruption is refused by the installed process.
	object := filepath.Join(install.ObjectOrigins[0].RootPath, f.source.Commit)
	old, e := os.ReadFile(object)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(object, []byte("invalid object"), 0o600); e != nil {
		t.Fatal(e)
	}
	checkCLI(resultdto.ExitTrust.Int())
	if e = os.WriteFile(object, old, 0o600); e != nil {
		t.Fatal(e)
	}
}

func assertDiffPair(t *testing.T, env resultdto.Result) {
	t.Helper()
	if env.Status != resultdto.StatusChanges || len(env.Changes) != 2 || env.Summary.BlocksChanged != 2 || env.Summary.FilesChanged != 0 {
		t.Fatalf("pair: %+v", env)
	}
	for i, id := range []string{"alpha", "beta"} {
		if env.Changes[i].Path != "hello.txt" || env.Changes[i].BlockID != id {
			t.Fatalf("identity: %+v", env.Changes)
		}
	}
}

func assertDiffSkeleton(t *testing.T, env resultdto.Envelope) {
	t.Helper()
	if len(env.Changes) != 1 || env.Changes[0].Action != "skeleton" || env.Summary.FilesChanged != 1 || env.Summary.BlocksChanged != 0 {
		t.Fatalf("ordered boundary drift missing: %+v", env)
	}
}
