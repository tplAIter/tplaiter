package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Installed child processes authenticate actual disk registration and provision
// signed evidence. CLI and MCP each update a separate A project to signed B.
func TestNativeUpdateInstalledCLIAndMCP(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeUpdateCLIFixture(t)
	base := filepath.Dir(f.projectRoot)
	second := filepath.Join(base, "project-mcp")
	var install trustload.RuntimeInstall
	raw, err := os.ReadFile(f.selection.RuntimeConfig.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &install); err != nil {
		t.Fatal(err)
	}
	pc := install.ProjectContexts[0]
	pc.Key, pc.ProjectID, pc.RootPath = "second", "project-second", second
	install.ProjectContexts = append(install.ProjectContexts, pc)
	raw = t5FJSON(t, install)
	if err := os.WriteFile(f.selection.RuntimeConfig.Path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	f.selection.RuntimeConfig.SHA256, err = install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
	raw = t5FJSON(t, registration)
	registrationPath := filepath.Join(base, "registration.json")
	if err := os.WriteFile(registrationPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "process-home")
	secondHome := filepath.Join(base, "mcp-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(digest[:]), "-o", bin, ".")
	build.Dir, build.Env = filepath.Join("..", ".."), testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	activeHome := home
	run := func(args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, bin, args...)
		c.Env, c.Dir = testProcessEnv(activeHome), base
		return c.Output()
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision: %v %s", err, out)
	}
	sourcePath, targetPath := filepath.Join(base, "source.json"), filepath.Join(base, "target.json")
	for path, data := range map[string][]byte{sourcePath: t5FSelection(f.source, f.sourceRefs), targetPath: t5FSelection(f.target, f.targetRefs)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for key, root := range map[string]string{"project": f.projectRoot, "second": second} {
		activeHome = home
		if key == "second" {
			activeHome = secondHome
		}
		if out, err := run("new", f.source.Commit, "project", "--project-context", key, "--dir", root, "--source-input", sourcePath, "--defaults", "--no-hooks", "--json"); err != nil {
			t.Fatalf("new %s: %v %s", key, err, out)
		}
		if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("local one\nbase two\nbase three\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	activeHome = home
	registry := filepath.Join(home, "tplaiter", "projects.yaml")
	// Every refusal/check compares full project+registry+CAS+transaction inventory.
	observed := func(root string) map[string]string {
		m := nativeUpdateObservedTree(t, root)
		selectedHome := home
		if root == second {
			selectedHome = secondHome
		}
		for prefix, dir := range map[string]string{"home/": filepath.Join(selectedHome, "tplaiter"), "objects/": install.ObjectOrigins[0].RootPath, "evidence/": install.EvidenceRoot} {
			for p, v := range nativeUpdateObservedTree(t, dir) {
				m[prefix+p] = v
			}
		}
		return m
	}
	badPath := filepath.Join(base, "wrong-signature.json")
	badSelection := f.targetRefs
	badSelection.SignatureCAS = f.sourceRefs.SignatureCAS
	if err := os.WriteFile(badPath, t5FSelection(f.target, badSelection), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--dir", base}, {"--project-context", "missing"}, {"--to", f.source.Commit}, {"--source-input", badPath},
	} {
		before := observed(f.projectRoot)
		out, err := run(append([]string{"update", "--source-input", targetPath, "--json"}, args...)...)
		if err == nil {
			t.Fatalf("negative accepted: %s", out)
		}
		if !reflect.DeepEqual(before, observed(f.projectRoot)) {
			t.Fatal("negative changed project/registry/CAS/journal")
		}
		t.Logf("CLI refusal %v: %s", args, out)
	}
	for _, flag := range []string{"--dry-run", "--check"} {
		before := observed(f.projectRoot)
		out, err := run("update", flag, "--dir", f.projectRoot, "--source-input", targetPath, "--to", f.target.Commit, "--json")
		if err != nil {
			t.Fatalf("plan %s: %v %s", flag, err, out)
		}
		env := decodeOne(t, string(out))
		if env.PlanSHA256 == "" || env.CurrentRef != f.source.Commit || env.TargetRef != f.target.Commit || len(env.Changes) < 3 || env.TransactionID != nil {
			t.Fatalf("empty plan: %s", out)
		}
		if !reflect.DeepEqual(before, observed(f.projectRoot)) {
			t.Fatal("plan changed project/registry/CAS/journal")
		}
		t.Logf("CLI %s: %s", flag, out)
	}
	if err := os.WriteFile(filepath.Join(f.projectRoot, "added.txt"), []byte("foreign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := observed(f.projectRoot)
	out, err := run("update", "--dir", f.projectRoot, "--source-input", targetPath, "--json")
	if err == nil || decodeOne(t, string(out)).Status != resultdto.StatusConflicted {
		t.Fatalf("foreign accepted: %v %s", err, out)
	}
	if !reflect.DeepEqual(before, observed(f.projectRoot)) {
		t.Fatal("foreign refusal had effects")
	}
	t.Logf("CLI foreign refusal: %s", out)
	if err := os.Remove(filepath.Join(f.projectRoot, "added.txt")); err != nil {
		t.Fatal(err)
	}
	out, err = run("update", "--dir", f.projectRoot, "--source-input", targetPath, "--to", f.target.Commit, "--json")
	if err != nil {
		t.Fatalf("CLI apply: %v %s", err, out)
	}
	env := decodeOne(t, string(out))
	if env.Operation != resultdto.OperationUpdateApply || env.Status != resultdto.StatusChanges || env.TransactionID == nil {
		t.Fatalf("apply result: %s", out)
	}
	t.Logf("CLI signed A->B: %s", out)
	nativeUpdateAssertPublished(t, f, f.projectRoot, "project-t5f", registry)
	// Cold runtime must accept the committed state and a terminal-prior B->B plan.
	out, err = run("update", "--source-input", targetPath, "--json")
	if err != nil || decodeOne(t, string(out)).Status != resultdto.StatusOK {
		t.Fatalf("B->B: %v %s", err, out)
	}
	server := exec.CommandContext(ctx, bin, "mcp-server")
	server.Env, server.Dir = testProcessEnv(secondHome), base
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
			t.Fatalf("MCP decode: %v %s", err, stderr.String())
		}
		if response["error"] != nil {
			t.Fatalf("MCP transport: %+v", response)
		}
		return response
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "native-update-test", "version": "1"}})
	if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	call := func(id int, args map[string]any) resultdto.Result {
		response := request(id, "tools/call", map[string]any{"name": "update", "arguments": args})
		result, ok := response["result"].(map[string]any)
		if !ok {
			t.Fatalf("missing result: %+v", response)
		}
		raw, err := json.Marshal(result["structuredContent"])
		if err != nil {
			t.Fatal(err)
		}
		env, err := resultdto.Decode(raw)
		if err != nil {
			t.Fatalf("MCP result: %v %s", err, raw)
		}
		t.Logf("MCP update: %s", raw)
		return env
	}
	before = observed(second)
	env = call(2, map[string]any{"dir": second, "sourceInput": targetPath})
	if env.Status != resultdto.StatusBlocked {
		t.Fatal("MCP wrong default root accepted")
	}
	if !reflect.DeepEqual(before, observed(second)) {
		t.Fatal("MCP wrong-root refusal had effects")
	}
	env = call(3, map[string]any{"dir": second, "projectContext": "second", "sourceInput": targetPath, "dryRun": true})
	if env.Operation != resultdto.OperationUpdatePlan || env.PlanSHA256 == "" || env.Project.ID != "project-second" {
		t.Fatalf("MCP plan: %+v", env)
	}
	if !reflect.DeepEqual(before, observed(second)) {
		t.Fatal("MCP plan had effects")
	}
	env = call(4, map[string]any{"dir": second, "projectContext": "second", "sourceInput": targetPath, "to": f.target.Commit})
	if env.Operation != resultdto.OperationUpdateApply || env.Status != resultdto.StatusChanges || env.TransactionID == nil {
		t.Fatalf("MCP apply: %+v", env)
	}
	nativeUpdateAssertPublished(t, f, second, "project-second", filepath.Join(secondHome, "tplaiter", "projects.yaml"))
}

func nativeUpdateAssertPublished(t *testing.T, f t5FFixture, root, id, registry string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "hello.txt"))
	if err != nil || string(raw) != "local one\nbase two\nupstream three\n" {
		t.Fatalf("three-way: %q %v", raw, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "obsolete.txt")); !os.IsNotExist(err) {
		t.Fatalf("deletion: %v", err)
	}
	raw, err = os.ReadFile(filepath.Join(root, "added.txt"))
	if err != nil || string(raw) != "new owned\n" {
		t.Fatalf("addition: %q %v", raw, err)
	}
	raw, err = os.ReadFile(registry)
	if err != nil {
		t.Fatal(err)
	}
	projects, err := state.DecodeProjectsRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := projects.FindByID(id)
	if !ok || entry.Path != root || entry.Template.Version != f.target.Commit {
		t.Fatalf("registry: %+v", entry)
	}
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	key := "project"
	if id == "project-second" {
		key = "second"
	}
	r, err := composeRuntimeForProject(withInvocation(context.Background(), in), key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := stateledger.VerifyStable(context.Background(), root, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	raw, err = registeredSourceInput(context.Background(), r)
	if err != nil || !strings.Contains(string(raw), f.target.Commit) {
		t.Fatalf("cold source: %v %s", err, raw)
	}
}

// Identity and mode comparisons supplement bytes: a refusal must preserve
// foreign inodes, project root, registry and sealed source/evidence files.
func nativeUpdateObservedTree(t *testing.T, root string) map[string]string {
	t.Helper()
	m := nativeGenTree(t, root)
	for p, data := range m {
		info, err := os.Lstat(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("native stat identity unavailable")
		}
		m[p] = fmt.Sprintf("%d:%d:%o:%s", stat.Dev, stat.Ino, info.Mode(), data)
	}
	return m
}
