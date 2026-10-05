package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/testfixture"
)

// The MCP server launches a held copy of this installed binary. Both transports
// must reach the concrete native command composition and report committed data.
func TestNativeGenInstalledCLIAndMCP(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeGenCLIFixture(t)
	base := filepath.Dir(f.projectRoot)
	registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
	raw, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	registrationPath := filepath.Join(base, "registration.json")
	if err := os.WriteFile(registrationPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "process-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(digest[:]), "-o", bin, ".")
	build.Dir = filepath.Join("..", "..")
	build.Env = testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build installed binary: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, bin, args...)
		c.Env, c.Dir = testProcessEnv(home), base
		return c.CombinedOutput()
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision: %v %s", err, out)
	}
	selection := filepath.Join(base, "selection.json")
	if err := os.WriteFile(selection, t5FSelection(f.source, f.sourceRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run("new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", selection, "--defaults", "--no-hooks", "--json"); err != nil {
		t.Fatalf("new: %v %s", err, out)
	}
	out, err := run("gen", "note", "DirectNote", "--label=direct", "--no-build", "--json")
	if err != nil {
		t.Fatalf("installed gen: %v %s", err, out)
	}
	if env := decodeOne(t, string(out)); env.Operation != resultdto.OperationGenRun || env.Status != resultdto.StatusChanges || env.Project.Root != f.projectRoot {
		t.Fatalf("installed result: %s", out)
	}
	server := exec.CommandContext(ctx, bin, "mcp-server")
	server.Env, server.Dir = testProcessEnv(home), base
	stdin, err := server.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	server.Stderr = &stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = server.Wait() }()
	encoder, decoder := json.NewEncoder(stdin), json.NewDecoder(stdout)
	request := func(id int, method string, params any) map[string]any {
		t.Helper()
		if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response["error"] != nil {
			t.Fatalf("MCP protocol failure: %+v", response)
		}
		return response
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "native-gen-command-test", "version": "1"}})
	if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	call := func(id int, name string, args map[string]any, op resultdto.Operation, want resultdto.Status) {
		t.Helper()
		response := request(id, "tools/call", map[string]any{"name": name, "arguments": args})
		result, ok := response["result"].(map[string]any)
		if !ok {
			t.Fatalf("MCP missing result: %+v", response)
		}
		structured, err := json.Marshal(result["structuredContent"])
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := resultdto.Decode(structured)
		if err != nil || envelope.Operation != op || envelope.Status != want {
			t.Fatalf("MCP %s: %v %s", name, err, structured)
		}
		if want == resultdto.StatusChanges || want == resultdto.StatusOK {
			if envelope.Project == nil || envelope.Project.Root != f.projectRoot {
				t.Fatalf("MCP project: %s", structured)
			}
		}
	}
	call(2, "gen_list", map[string]any{"dir": f.projectRoot}, resultdto.OperationGenList, resultdto.StatusOK)
	call(3, "gen", map[string]any{"dir": f.projectRoot, "kind": "note", "name": "McpNote", "params": map[string]string{"label": "mcp"}, "noBuild": true}, resultdto.OperationGenRun, resultdto.StatusChanges)
	call(4, "gen_batch", map[string]any{"dir": f.projectRoot, "operations": []map[string]any{{"kind": "note", "name": "McpBatchOne", "params": map[string]string{"label": "one"}}, {"kind": "note", "name": "McpBatchTwo", "params": map[string]string{"label": "two"}}}, "noBuild": true}, resultdto.OperationGenBatch, resultdto.StatusChanges)
	before := nativeGenTree(t, f.projectRoot)
	call(5, "gen", map[string]any{"dir": f.projectRoot, "kind": "note", "name": "DefaultBuild", "params": map[string]string{"label": "default"}}, resultdto.OperationGenRun, resultdto.StatusBlocked)
	if !equalStringMap(before, nativeGenTree(t, f.projectRoot)) {
		t.Fatal("MCP default build refusal changed project")
	}
	for _, path := range []string{"direct_note", "mcp_note", "mcp_batch_one", "mcp_batch_two"} {
		if _, err := os.Stat(filepath.Join(f.projectRoot, "notes", path+".txt")); err != nil {
			t.Fatal(err)
		}
	}
}
