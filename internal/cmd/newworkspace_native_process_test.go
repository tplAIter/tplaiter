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
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/modfile"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/workspace"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

type workspaceChildInput struct {
	preparingChildInput
	Renderer string `json:"renderer"`
}

func TestNativeWorkspaceStagingChild(t *testing.T) {
	name := os.Getenv("TPLAITER_WORKSPACE_CHILD_INPUT")
	if name == "" {
		return
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var input workspaceChildInput
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	wr, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: input.Selection, ProjectKey: "project", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer wr.Close()
	sr, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: input.Selection, ProjectKey: input.Key, Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Close()
	plan, err := workspace.Prepare(ctx, wr, sr, input.Home, input.Renderer, workspace.Input{Name: input.Key, Defaults: true, WorkspaceSource: input.Source, ServiceSource: input.Target})
	if err != nil {
		t.Fatal(err)
	}
	prior := map[string]bool{}
	names, _ := filepath.Glob(filepath.Join(input.Home, "transactions", "project", "tx-*", "state.json"))
	for _, name := range names {
		prior[name] = true
	}
	boundary := &preparingKillContext{Context: ctx, input: input.preparingChildInput, prior: prior}
	tx, err := workspace.Begin(boundary, plan, plan.Fingerprint())
	if tx != nil {
		tx.Release()
	}
	t.Fatalf("staging child returned before kill: %v", err)
}

func TestNativeWorkspaceInstalledCLIAndMCP(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeWorkspaceCLIFixture(t)
	base := filepath.Dir(f.projectRoot)
	var install trustload.RuntimeInstall
	raw, err := os.ReadFile(f.selection.RuntimeConfig.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &install); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cli", "mcp", "recover", "cancel", "orphan"} {
		pc := install.ProjectContexts[0]
		pc.WorkspaceContext = "project"
		pc.Key = key
		pc.ProjectID = "service-" + key
		pc.RootPath = filepath.Join(f.projectRoot, "services", key)
		install.ProjectContexts = append(install.ProjectContexts, pc)
	}
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
	hash := sha256.Sum256(raw)
	bin := filepath.Join(base, "tplaiter")
	home := filepath.Join(base, "process-home")
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(hash[:]), "-o", bin, ".")
	build.Dir = filepath.Join("..", "..")
	build.Env = testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("installed build: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = testProcessEnv(home)
		cmd.Dir = base
		return cmd.CombinedOutput()
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision: %v %s", err, out)
	}
	sourcePath, targetPath := filepath.Join(base, "workspace-source.json"), filepath.Join(base, "service-source.json")
	for name, data := range map[string][]byte{sourcePath: t5FSelection(f.source, f.sourceRefs), targetPath: t5FSelection(f.target, f.targetRefs)} {
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := run("new", f.source.Commit, "Workspace", "--module", "example.test/ws", "--dir", f.projectRoot, "--source-input", sourcePath, "--defaults", "--json"); err != nil {
		t.Fatalf("workspace new: %v %s", err, out)
	}
	ledgerHome := filepath.Join(home, "tplaiter")
	observed := func() map[string]string {
		tree := nativeUpdateObservedTree(t, f.projectRoot)
		for prefix, root := range map[string]string{"home/": ledgerHome, "objects/": install.ObjectOrigins[0].RootPath, "evidence/": install.EvidenceRoot} {
			for p, v := range nativeUpdateObservedTree(t, root) {
				tree[prefix+p] = v
			}
		}
		return tree
	}
	invocationArgs := func(key string) []string {
		return []string{"workspace", "add-service", key, "--project-context", "project", "--service-context", key, "--dir", f.projectRoot, "--source-input", targetPath, "--defaults", "--json"}
	}
	before := observed()
	if out, err := run(append(invocationArgs("cli"), "--dry-run")...); err != nil {
		t.Fatalf("dry-run: %v %s", err, out)
	} else {
		env := decodeOne(t, string(out))
		if env.PlanSHA256 == "" || env.TransactionID != nil || env.Operation != resultdto.OperationWorkspaceAddService {
			t.Fatalf("dry-run envelope %s", out)
		}
		t.Logf("installed dry-run: %s", out)
	}
	if !reflect.DeepEqual(before, observed()) {
		t.Fatal("dry-run changed workspace/registry/source/transactions")
	}
	for _, tail := range [][]string{{"--service-context", "missing"}, {"--service-context", "mcp"}, {"--dir", base}, {"--source-input", sourcePath}} {
		before := observed()
		out, err := run(append(invocationArgs("cli"), tail...)...)
		if err == nil || !reflect.DeepEqual(before, observed()) {
			t.Fatalf("refusal had effects: %v %s", err, out)
		}
		t.Logf("installed refusal: %s", out)
	}
	before = observed()
	bad := invocationArgs("cli")
	bad[2] = "../bad"
	if out, err := run(bad...); err == nil || !reflect.DeepEqual(before, observed()) {
		t.Fatalf("invalid name effect: %v %s", err, out)
	}
	if err := os.Mkdir(filepath.Join(f.projectRoot, "services"), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(f.projectRoot, "services", "cli")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	before = observed()
	if out, err := run(invocationArgs("cli")...); err == nil || !reflect.DeepEqual(before, observed()) {
		t.Fatalf("foreign path effect: %v %s", err, out)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, foreign); err != nil {
		t.Fatal(err)
	}
	// Symlink observations use raw lstat metadata: no traversal of the target.
	linkBefore, err := os.Lstat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	registryBefore, err := os.ReadFile(state.ProjectsPath(ledgerHome))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := run(invocationArgs("cli")...); err == nil {
		t.Fatalf("symlink accepted %s", out)
	}
	linkAfter, err := os.Lstat(foreign)
	registryAfter, _ := os.ReadFile(state.ProjectsPath(ledgerHome))
	if err != nil || !os.SameFile(linkBefore, linkAfter) || !bytes.Equal(registryBefore, registryAfter) {
		t.Fatal("symlink refusal changed foreign inode/registry")
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	out, err := run(invocationArgs("cli")...)
	if err != nil {
		t.Fatalf("CLI add: %v %s", err, out)
	}
	env := decodeOne(t, string(out))
	if env.Status != resultdto.StatusChanges || env.TransactionID == nil {
		t.Fatalf("CLI result: %s", out)
	}
	t.Logf("installed signed CLI: %s", out)
	assertNativeWorkspaceService(t, f, ledgerHome, "cli")
	before = observed()
	if out, err := run(invocationArgs("cli")...); err == nil || !reflect.DeepEqual(before, observed()) {
		t.Fatalf("duplicate creation effect: %v %s", err, out)
	}
	firstService := nativeUpdateObservedTree(t, filepath.Join(f.projectRoot, "services", "cli"))
	server := exec.CommandContext(ctx, bin, "mcp-server")
	server.Env = testProcessEnv(home)
	server.Dir = base
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
			t.Fatalf("MCP: %v %s", err, stderr.String())
		}
		if response["error"] != nil {
			t.Fatalf("MCP transport %+v", response)
		}
		return response
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "workspace-test", "version": "1"}})
	if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		t.Fatal(err)
	}
	call := func(id int, dry bool) resultdto.Result {
		response := request(id, "tools/call", map[string]any{"name": "workspace_add_service", "arguments": map[string]any{"name": "mcp", "dir": f.projectRoot, "projectContext": "project", "serviceContext": "mcp", "sourceInput": targetPath, "dryRun": dry, "defaults": true}})
		result := response["result"].(map[string]any)
		raw, err := json.Marshal(result["structuredContent"])
		if err != nil {
			t.Fatal(err)
		}
		env, err := resultdto.Decode(raw)
		if err != nil {
			t.Fatalf("MCP structured: %v %s", err, raw)
		}
		t.Logf("installed MCP: %s", raw)
		return env
	}
	before = observed()
	env = call(2, true)
	if env.Status != resultdto.StatusChanges || env.PlanSHA256 == "" || env.TransactionID != nil || !reflect.DeepEqual(before, observed()) {
		t.Fatal("MCP dry-run had effects")
	}
	env = call(3, false)
	if env.Status != resultdto.StatusChanges || env.TransactionID == nil {
		t.Fatalf("MCP apply %+v", env)
	}
	assertNativeWorkspaceService(t, f, ledgerHome, "mcp")
	if !reflect.DeepEqual(firstService, nativeUpdateObservedTree(t, filepath.Join(f.projectRoot, "services", "cli"))) {
		t.Fatal("second service changed first service")
	}
	// Cold preparing receipt comes from actual signed staging. Reopen through the
	// installed CLI, not caller-provided journal material or phase substitutions.
	wr, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer wr.Close()
	current, err := registeredSourceInput(ctx, wr)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"recover", "cancel"} {
		sr, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: key, Clock: f.clock})
		if err != nil {
			t.Fatal(err)
		}
		input := workspace.Input{Name: key, Defaults: true, WorkspaceSource: current, ServiceSource: t5FSelection(f.target, f.targetRefs)}
		plan, err := workspace.Prepare(ctx, wr, sr, ledgerHome, env.Meta.TplaiterVersion, input)
		if err != nil {
			t.Fatal(err)
		}
		if key == "recover" {
			// Same path with a replaced root cannot adopt the previously prepared image.
			held := f.projectRoot + "-held"
			if err := os.Rename(f.projectRoot, held); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.projectRoot, 0o755); err != nil {
				t.Fatal(err)
			}
			foreignBefore := nativeUpdateObservedTree(t, f.projectRoot)
			if tx, err := workspace.Begin(ctx, plan, plan.Fingerprint()); err == nil || tx != nil {
				t.Fatalf("root drift admitted: %v", err)
			}
			if !reflect.DeepEqual(foreignBefore, nativeUpdateObservedTree(t, f.projectRoot)) {
				t.Fatal("root drift refusal changed foreign root")
			}
			if err := os.Remove(f.projectRoot); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(held, f.projectRoot); err != nil {
				t.Fatal(err)
			}
			plan, err = workspace.Prepare(ctx, wr, sr, ledgerHome, env.Meta.TplaiterVersion, input)
			if err != nil {
				t.Fatal(err)
			}
		}
		boundary := &nativeUpdateBoundaryCancel{Context: ctx, home: ledgerHome, phase: "preparing", minimum: 1}
		tx, err := workspace.Begin(boundary, plan, plan.Fingerprint())
		if err == nil || tx == nil || !boundary.fired {
			t.Fatalf("real preparing interruption %v", err)
		}
		id := tx.ID()
		if key == "recover" {
			pending, err := workspace.Open(ctx, wr, sr, ledgerHome, id, env.Meta.TplaiterVersion)
			if err != nil {
				t.Fatal(err)
			}
			before := observed()
			out, err := run(invocationArgs("cancel")...)
			pending.Release()
			if err == nil || !reflect.DeepEqual(before, observed()) {
				t.Fatalf("coordinated lease refusal had effects: %v %s", err, out)
			}
			t.Logf("coordinated workspace/service/registry lease refusal: %s", out)
		}
		tx.Release()
		sr.Close()
		verb := "continue"
		if key == "cancel" {
			verb = "abort"
		}
		for repeat := 0; repeat < 2; repeat++ {
			out, err := run("workspace", verb, id, "--project-context", "project", "--service-context", key, "--dir", f.projectRoot, "--json")
			if err != nil {
				t.Fatalf("cold %s: %v %s", verb, err, out)
			}
			t.Logf("cold %s repeat%d: %s", verb, repeat, out)
		}
		if key == "recover" {
			assertNativeWorkspaceService(t, f, ledgerHome, key)
		} else {
			if _, err := os.Lstat(filepath.Join(f.projectRoot, "services", key)); !os.IsNotExist(err) {
				t.Fatal("aborted service exists")
			}
		}
	}
	// Kill a separate process while an actual signed preparing prefix is durable.
	readyPath := filepath.Join(base, "workspace-crash-ready.json")
	inputPath := filepath.Join(base, "workspace-crash-child.json")
	input := workspaceChildInput{preparingChildInput: preparingChildInput{Selection: f.selection, Key: "orphan", Home: ledgerHome, Source: current, Target: t5FSelection(f.target, f.targetRefs), Minimum: 1, Ready: readyPath}, Renderer: env.Meta.TplaiterVersion}
	if err := os.WriteFile(inputPath, t5FJSON(t, input), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, executable, "-test.run=^TestNativeWorkspaceStagingChild$", "-test.v")
	child.Env = append(testProcessEnv(home), "TPLAITER_WORKSPACE_CHILD_INPUT="+inputPath)
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	workBefore, err := os.ReadFile(filepath.Join(f.projectRoot, "go.work"))
	if err != nil {
		t.Fatal(err)
	}
	registryBefore, err = os.ReadFile(state.ProjectsPath(ledgerHome))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	var ready preparingReady
	exited := false
	var waitErr error
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(readyPath); err == nil && json.Unmarshal(raw, &ready) == nil && ready.ID != "" {
			break
		}
		select {
		case waitErr = <-done:
			exited = true
		default:
		}
		if exited {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !exited {
		if err := child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		waitErr = <-done
	}
	if ready.ID == "" || ready.Prefix != 1 || waitErr == nil {
		t.Fatalf("crash boundary: %v %s", waitErr, output.String())
	}
	workAfter, err := os.ReadFile(filepath.Join(f.projectRoot, "go.work"))
	if err != nil {
		t.Fatal(err)
	}
	registryAfter, err = os.ReadFile(state.ProjectsPath(ledgerHome))
	if err != nil || !bytes.Equal(workBefore, workAfter) || !bytes.Equal(registryBefore, registryAfter) {
		t.Fatal("crash published workspace/registry")
	}
	if _, err := os.Lstat(filepath.Join(f.projectRoot, "services", "orphan")); !os.IsNotExist(err) {
		t.Fatal("crash published service")
	}
	t.Logf("killed actual signed workspace staging: prefix=%d id=%s", ready.Prefix, ready.ID)
	if out, err := run("workspace", "continue", ready.ID, "--project-context", "project", "--service-context", "orphan", "--dir", f.projectRoot, "--json"); err != nil {
		t.Fatalf("crash continue: %v %s", err, out)
	} else {
		t.Logf("crash continue: %s", out)
	}
	assertNativeWorkspaceService(t, f, ledgerHome, "orphan")
}

func assertNativeWorkspaceService(t *testing.T, f t5FFixture, home, key string) {
	t.Helper()
	root := filepath.Join(f.projectRoot, "services", key)
	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || string(raw) != "module example.test/ws/services/"+key+"\ngo 1.26\n" {
		t.Fatalf("module: %v %q", err, raw)
	}
	workRaw, err := os.ReadFile(filepath.Join(f.projectRoot, "go.work"))
	if err != nil {
		t.Fatal(err)
	}
	wf, err := modfile.ParseWork("go.work", workRaw, nil)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, u := range wf.Use {
		if filepath.Clean(u.Path) == "services/"+key {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("go.work registration count=%d", count)
	}
	registryRaw, err := os.ReadFile(state.ProjectsPath(home))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := state.DecodeProjectsRaw(registryRaw)
	if err != nil {
		t.Fatal(err)
	}
	count = 0
	for _, p := range registry.Items {
		if p.ID == "service-"+key {
			count++
			if p.Path != root || p.Template.Version != f.target.Commit {
				t.Fatal("service registry mismatch")
			}
		}
	}
	if count != 1 {
		t.Fatal("service not registered exactly once")
	}
	r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: key, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := stateledger.VerifyStable(context.Background(), root, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		t.Fatal("actual service ledger", err)
	}
	raw, err = registeredSourceInput(context.Background(), r)
	if err != nil || !strings.Contains(string(raw), f.target.Commit) {
		t.Fatal("actual service source", err)
	}
}

func TestNativeWorkspaceTerminalOwnedRepeats(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeWorkspaceCLIFixture(t)
	base := filepath.Dir(f.projectRoot)
	var install trustload.RuntimeInstall
	raw, err := os.ReadFile(f.selection.RuntimeConfig.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &install); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cli", "mcp", "recover", "cancel", "orphan"} {
		pc := install.ProjectContexts[0]
		pc.WorkspaceContext = "project"
		pc.Key = key
		pc.ProjectID = "service-" + key
		pc.RootPath = filepath.Join(f.projectRoot, "services", key)
		install.ProjectContexts = append(install.ProjectContexts, pc)
	}
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
	hash := sha256.Sum256(raw)
	bin := filepath.Join(base, "tplaiter")
	home := filepath.Join(base, "process-home")
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(hash[:]), "-o", bin, ".")
	build.Dir = filepath.Join("..", "..")
	build.Env = testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("installed build: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = testProcessEnv(home)
		cmd.Dir = base
		return cmd.CombinedOutput()
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision: %v %s", err, out)
	}
	sourcePath, targetPath := filepath.Join(base, "workspace-source.json"), filepath.Join(base, "service-source.json")
	for name, data := range map[string][]byte{sourcePath: t5FSelection(f.source, f.sourceRefs), targetPath: t5FSelection(f.target, f.targetRefs)} {
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := run("new", f.source.Commit, "Workspace", "--module", "example.test/ws", "--dir", f.projectRoot, "--source-input", sourcePath, "--defaults", "--json"); err != nil {
		t.Fatalf("workspace new: %v %s", err, out)
	}
	ledgerHome := filepath.Join(home, "tplaiter")
	observed := func() map[string]string {
		tree := nativeUpdateObservedTree(t, f.projectRoot)
		for prefix, root := range map[string]string{"home/": ledgerHome, "objects/": install.ObjectOrigins[0].RootPath, "evidence/": install.EvidenceRoot} {
			for p, v := range nativeUpdateObservedTree(t, root) {
				tree[prefix+p] = v
			}
		}
		return tree
	}
	invocationArgs := func(key string) []string {
		return []string{"workspace", "add-service", key, "--project-context", "project", "--service-context", key, "--dir", f.projectRoot, "--source-input", targetPath, "--defaults", "--json"}
	}

	out, err := run(invocationArgs("cli")...)
	if err != nil {
		t.Fatalf("create: %v %s", err, out)
	}
	env := decodeOne(t, string(out))
	if env.TransactionID == nil {
		t.Fatal("missing transaction")
	}
	id := *env.TransactionID
	repeat := func(verb, id, key string) {
		t.Helper()
		before := observed()
		out, err := run("workspace", verb, id, "--project-context", "project", "--service-context", key, "--dir", f.projectRoot, "--json")
		if err != nil {
			t.Fatalf("owned terminal repeat: %v %s", err, out)
		}
		result := decodeOne(t, string(out))
		if result.Status != resultdto.StatusOK || result.TransactionID == nil || *result.TransactionID != id || !reflect.DeepEqual(before, observed()) {
			t.Fatalf("owned repeat failed preservation: %s", out)
		}
		t.Logf("valid current-owned %s: %s", verb, out)
	}
	repeat("continue", id, "cli")
	file := filepath.Join(f.projectRoot, "services", "cli", "go.mod")
	original, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(raw, []byte("// legitimate in-place owner edit\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	edited, err := os.Stat(file)
	if err != nil || !os.SameFile(original, edited) {
		t.Fatal("positive fixture replaced owned inode")
	}
	repeat("continue", id, "cli")
	if out, err := run(invocationArgs("mcp")...); err != nil {
		t.Fatalf("later independent service: %v %s", err, out)
	}
	repeat("continue", id, "cli")
	wr, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer wr.Close()
	sr, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "cancel", Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Close()
	current, err := registeredSourceInput(ctx, wr)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := workspace.Prepare(ctx, wr, sr, ledgerHome, env.Meta.TplaiterVersion, workspace.Input{Name: "cancel", Defaults: true, WorkspaceSource: current, ServiceSource: t5FSelection(f.target, f.targetRefs)})
	if err != nil {
		t.Fatal(err)
	}
	boundary := &nativeUpdateBoundaryCancel{Context: ctx, home: ledgerHome, phase: "preparing", minimum: 1}
	tx, err := workspace.Begin(boundary, plan, plan.Fingerprint())
	if err == nil || tx == nil || !boundary.fired {
		t.Fatalf("preparing cancellation: %v", err)
	}
	abortID := tx.ID()
	tx.Release()
	if out, err := run("workspace", "abort", abortID, "--project-context", "project", "--service-context", "cancel", "--dir", f.projectRoot, "--json"); err != nil {
		t.Fatalf("first abort: %v %s", err, out)
	}
	repeat("abort", abortID, "cancel")
	repeat("abort", abortID, "cancel")
}
