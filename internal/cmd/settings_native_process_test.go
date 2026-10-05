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
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/settingscmd"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Installed child processes authenticate actual disk registration and provision
// signed evidence. CLI and MCP each update a separate A project to signed B.
func TestNativeSettingsInstalledCLIAndMCP(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeSettingsFixture(t)
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
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=v-settings -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(digest[:]), "-o", bin, ".")
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
		if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("local one\nalpha\nbase three\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	activeHome = home
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

	sealedSources := nativeUpdateObservedTree(t, install.ObjectOrigins[0].RootPath)
	sealedEvidence := nativeUpdateObservedTree(t, install.EvidenceRoot)
	rootIdentity, err := os.Stat(f.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	checkNoEffects := func(args ...string) resultdto.Result {
		t.Helper()
		before := observed(f.projectRoot)
		out, _ := run(args...)
		env := decodeOne(t, string(out))
		if !reflect.DeepEqual(before, observed(f.projectRoot)) {
			t.Fatalf("unexpected effects: %v %s", args, out)
		}
		return env
	}
	env := checkNoEffects("settings", "show", "--json")
	if env.Operation != resultdto.OperationSettingsShow || env.Project.ID != "project-t5f" {
		t.Fatalf("show: %+v", env)
	}
	for _, args := range [][]string{
		{"settings", "set", "missing=x", "--json"},
		{"settings", "set", "tls=notbool", "--json"},
		{"settings", "set", "label=one", "label=two", "--json"},
		{"settings", "set", "feature=advanced", "tls=false", "--json"},
		{"settings", "set", "label=x", "--project-context", "foreign", "--json"},
		{"settings", "set", "label=x", "--dir", second, "--json"},
		{"settings", "edit", "label", "--json"},
	} {
		env = checkNoEffects(args...)
		if env.Status != resultdto.StatusBlocked && env.Status != resultdto.StatusFailed {
			t.Fatalf("refusal: %v %+v", args, env)
		}
		t.Logf("refusal %v: %+v", args, env.Diagnostics)
	}
	env = checkNoEffects("settings", "set", "label=beta", "feature=advanced", "--dry-run", "--json")
	if env.PlanSHA256 == "" || env.CurrentRef != f.source.Commit || env.TargetRef != f.source.Commit || env.TransactionID != nil {
		t.Fatalf("preview: %+v", env)
	}
	// Conditional foreign additions and edited deletions refuse before publication.
	advanced := filepath.Join(f.projectRoot, "advanced.txt")
	if err := os.WriteFile(advanced, []byte("foreign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env = checkNoEffects("settings", "set", "feature=advanced", "--json")
	if env.Status != resultdto.StatusConflicted {
		t.Fatalf("foreign addition: %+v", env)
	}
	if err := os.Remove(advanced); err != nil {
		t.Fatal(err)
	}
	basic := filepath.Join(f.projectRoot, "basic.txt")
	if err := os.WriteFile(basic, []byte("local edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env = checkNoEffects("settings", "set", "feature=advanced", "--dry-run", "--json")
	if env.Status != resultdto.StatusChanges {
		t.Fatalf("retained edited deletion preview: %+v", env)
	}
	if err := os.WriteFile(basic, []byte("old clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run("settings", "set", "label=beta", "feature=advanced", "--yes", "--json")
	if err != nil {
		t.Fatalf("apply: %v %s", err, out)
	}
	env = decodeOne(t, string(out))
	if env.TransactionID == nil || env.Project.ID != "project-t5f" {
		t.Fatalf("apply: %s", out)
	}
	t.Logf("CLI actual settings apply: %s", out)
	assertSettings := func(root, key, id, selectedHome, label, feature string) {
		t.Helper()
		if !reflect.DeepEqual(sealedSources, nativeUpdateObservedTree(t, install.ObjectOrigins[0].RootPath)) || !reflect.DeepEqual(sealedEvidence, nativeUpdateObservedTree(t, install.EvidenceRoot)) {
			t.Fatal("settings mutated sealed source/evidence")
		}
		if root == f.projectRoot {
			fresh, err := os.Stat(root)
			if err != nil || !os.SameFile(rootIdentity, fresh) {
				t.Fatal("settings changed bound root identity")
			}
		}
		raw, err := os.ReadFile(filepath.Join(root, "hello.txt"))
		if err != nil || string(raw) != "local one\n"+label+"\nbase three\n" {
			t.Fatalf("threeway: %v %q", err, raw)
		}
		want, absent := "advanced.txt", "basic.txt"
		if feature == "basic" {
			want, absent = absent, want
		}
		if _, err := os.Stat(filepath.Join(root, want)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, absent)); !os.IsNotExist(err) {
			t.Fatalf("conditional delete: %v", err)
		}
		raw, err = os.ReadFile(filepath.Join(selectedHome, "tplaiter", "projects.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		projects, err := state.DecodeProjectsRaw(raw)
		if err != nil {
			t.Fatal(err)
		}
		entry, ok := projects.FindByID(id)
		if !ok || entry.Path != root || entry.Template.Version != f.source.Commit {
			t.Fatalf("registry: %+v", entry)
		}
		in := invocation{Selection: f.selection, ProjectKey: key, Clock: f.clock}
		r, err := composeRuntimeForProject(withInvocation(ctx, in), key)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := stateledger.VerifyStable(ctx, root, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
			t.Fatal(err)
		}
		service, err := settingscmd.NewNative(r, filepath.Join(selectedHome, "tplaiter"), "v-settings")
		if err != nil {
			t.Fatal(err)
		}
		view, err := service.Read(ctx)
		if err != nil || view.Values["label"] != label || view.Values["feature"] != feature {
			t.Fatalf("cold show: %v %+v", err, view)
		}
		if feature == "advanced" && (view.Values["storage"] != "postgres" || view.Values["tls"] != true) {
			t.Fatalf("requires chain: %+v", view.Values)
		}
	}
	assertSettings(f.projectRoot, "project", "project-t5f", home, "beta", "advanced")
	out, err = run("settings", "edit", "label", "--value=gamma", "--yes", "--json")
	if err != nil || decodeOne(t, string(out)).Operation != resultdto.OperationSettingsReanswer {
		t.Fatalf("edit: %v %s", err, out)
	}
	assertSettings(f.projectRoot, "project", "project-t5f", home, "gamma", "advanced")
	out, err = run("settings", "set", "feature=basic", "storage=none", "tls=false", "--yes", "--json")
	if err != nil {
		t.Fatalf("disable: %v %s", err, out)
	}
	assertSettings(f.projectRoot, "project", "project-t5f", home, "gamma", "basic")
	out, err = run("settings", "set", "label=gamma", "--yes", "--json")
	if err != nil {
		t.Fatalf("same-value cold no-op: %v %s", err, out)
	}
	assertSettings(f.projectRoot, "project", "project-t5f", home, "gamma", "basic")
	// Altered authenticated resources cannot become settings authority.
	marker := filepath.Join(f.projectRoot, ".tplaiter", "project.yaml")
	original, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, append(original, []byte("tampered: true\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	env = checkNoEffects("settings", "set", "label=bad", "--json")
	if env.Status != resultdto.StatusBlocked {
		t.Fatalf("tampered metadata: %+v", env)
	}
	if err := os.WriteFile(marker, original, 0o644); err != nil {
		t.Fatal(err)
	}
	wrongID := bytes.Replace(original, []byte("id: project-t5f"), []byte("id: foreign-project"), 1)
	if bytes.Equal(wrongID, original) {
		t.Fatal("identity fixture missing marker ID")
	}
	if err := os.WriteFile(marker, wrongID, 0o644); err != nil {
		t.Fatal(err)
	}
	env = checkNoEffects("settings", "show", "--json")
	if env.Status != resultdto.StatusBlocked || env.Diagnostics[0].Code != "TRUST_NATIVE_SETTINGS_STATE_INVALID" {
		t.Fatalf("foreign marker ID: %+v", env)
	}
	if err := os.WriteFile(marker, original, 0o644); err != nil {
		t.Fatal(err)
	}
	resourcePath := filepath.Join(f.projectRoot, ".tplaiter", "generators", "generators", "entity.tmpl")
	resourceBytes, err := os.ReadFile(resourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resourcePath, []byte("foreign generator\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env = checkNoEffects("settings", "set", "label=bad", "--json")
	if env.Status != resultdto.StatusBlocked {
		t.Fatalf("tampered frozen resource: %+v", env)
	}
	if err := os.WriteFile(resourcePath, resourceBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(f.projectRoot, ".tplaiter", "manifest.snapshot.yaml")
	snapshotBytes, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshotPath, append(snapshotBytes, []byte("# changed local manifest\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	env = checkNoEffects("settings", "show", "--json")
	if env.Status != resultdto.StatusBlocked || env.Diagnostics[0].Code != "TRUST_SOURCE_ADAPTER_UNSUPPORTED" {
		t.Fatalf("unsigned snapshot show: %+v", env)
	}
	if err := os.WriteFile(snapshotPath, snapshotBytes, 0o644); err != nil {
		t.Fatal(err)
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
	call := func(id int, tool string, args map[string]any) resultdto.Result {
		response := request(id, "tools/call", map[string]any{"name": tool, "arguments": args})
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
		t.Logf("MCP settings: %s", raw)
		return env
	}

	before := observed(second)
	env = call(2, "settings_set", map[string]any{"dir": second, "values": map[string]string{"label": "delta"}})
	if env.Status != resultdto.StatusBlocked || !reflect.DeepEqual(before, observed(second)) {
		t.Fatal("MCP exact root missing-context refusal")
	}
	env = call(3, "settings_set", map[string]any{"dir": second, "projectContext": "second", "values": map[string]string{"label": "delta", "feature": "advanced"}, "dryRun": true})
	if env.PlanSHA256 == "" || env.Project.ID != "project-second" || !reflect.DeepEqual(before, observed(second)) {
		t.Fatalf("MCP preview: %+v", env)
	}
	env = call(4, "settings_set", map[string]any{"dir": second, "projectContext": "second", "values": map[string]string{"label": "delta", "feature": "advanced"}})
	if env.TransactionID == nil {
		t.Fatalf("MCP apply: %+v", env)
	}
	assertSettings(second, "second", "project-second", secondHome, "delta", "advanced")
	env = call(5, "settings_edit", map[string]any{"dir": second, "projectContext": "second", "group": "label", "value": "epsilon"})
	if env.TransactionID == nil || env.Operation != resultdto.OperationSettingsReanswer {
		t.Fatalf("MCP edit: %+v", env)
	}
	assertSettings(second, "second", "project-second", secondHome, "epsilon", "advanced")
	before = observed(second)
	env = call(6, "settings_list", map[string]any{"dir": second, "projectContext": "second"})
	if env.Project.ID != "project-second" || env.Operation != resultdto.OperationSettingsShow || !reflect.DeepEqual(before, observed(second)) {
		t.Fatalf("MCP authenticated show: %+v", env)
	}
}
