package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"gopkg.in/yaml.v3"
)

// Installed child processes authenticate actual disk registration and provision
// signed evidence. CLI and MCP each update a separate A project to signed B.
func TestNativeSettingsCorrectiveInstalledCLIAndMCP(t *testing.T) {
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
		if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("base one\nMINE\nbase three\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	activeHome = home

	observed := func(root string) map[string]string {
		m := nativeUpdateObservedTree(t, root)
		h := home
		if root == second {
			h = secondHome
		}
		for prefix, dir := range map[string]string{"home/": filepath.Join(h, "tplaiter"), "objects/": install.ObjectOrigins[0].RootPath, "evidence/": install.EvidenceRoot} {
			for p, v := range nativeUpdateObservedTree(t, dir) {
				m[prefix+p] = v
			}
		}
		return m
	}
	checkNoEffects := func(args ...string) resultdto.Result {
		t.Helper()
		before := observed(f.projectRoot)
		out, _ := run(args...)
		env := decodeOne(t, string(out))
		if !reflect.DeepEqual(before, observed(f.projectRoot)) {
			t.Fatalf("refusal/preview effects: %v %s", args, out)
		}
		if env.TransactionID != nil {
			t.Fatalf("no publication claimed transaction: %+v", env)
		}
		return env
	}
	seed := []byte("insert into t; -- MINE\n")
	for _, root := range []string{f.projectRoot, second} {
		if err := os.WriteFile(filepath.Join(root, "seed.sql"), seed, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sealedObjects := nativeUpdateObservedTree(t, install.ObjectOrigins[0].RootPath)
	sealedEvidence := nativeUpdateObservedTree(t, install.EvidenceRoot)
	identities := map[string]os.FileInfo{}
	for _, root := range []string{f.projectRoot, second} {
		info, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		identities[root] = info
	}
	assertCommitted := func(root, key, h, label string, env resultdto.Result) {
		t.Helper()
		if !reflect.DeepEqual(sealedObjects, nativeUpdateObservedTree(t, install.ObjectOrigins[0].RootPath)) || !reflect.DeepEqual(sealedEvidence, nativeUpdateObservedTree(t, install.EvidenceRoot)) {
			t.Fatal("product correction mutated sealed sources/evidence")
		}
		fresh, err := os.Stat(root)
		if err != nil || !os.SameFile(identities[root], fresh) {
			t.Fatal("product correction changed root identity")
		}
		got, err := os.ReadFile(filepath.Join(root, "seed.sql"))
		if err != nil || !bytes.Equal(got, seed) {
			t.Fatalf("seed not exact: %v %q", err, got)
		}
		if _, err := os.Stat(filepath.Join(root, "schema.sql")); !os.IsNotExist(err) {
			t.Fatalf("clean schema deletion: %v", err)
		}
		if env.TransactionID == nil {
			t.Fatal("missing durable transaction")
		}
		in := invocation{Selection: f.selection, ProjectKey: key, Clock: f.clock}
		r, err := composeRuntimeForProject(withInvocation(ctx, in), key)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		// Fresh cold authentication reconstructs warning/decision/content bytes.
		receipt, err := projecttransaction.OpenUpdate(ctx, r, filepath.Join(h, "tplaiter"), *env.TransactionID, "v-settings")
		if err != nil {
			t.Fatal(err)
		}
		if err := receipt.Commit(ctx); err != nil {
			receipt.Release()
			t.Fatal(err)
		}
		receipt.Release()
		input, err := registeredSourceInput(ctx, r)
		if err != nil || !bytes.Contains(input, []byte(f.source.Commit)) {
			t.Fatalf("immutable source: %v %s", err, input)
		}
		// Read marker via installed CLI below; also require exact conflict payload.
		if label == "beta" {
			raw, err := os.ReadFile(filepath.Join(root, "hello.txt"))
			want := "base one\n<<<<<<< ours\nMINE\n=======\nbeta\n>>>>>>> template\nbase three\n"
			if err != nil || string(raw) != want {
				t.Fatalf("exact conflict bytes: %v %q", err, raw)
			}
			if env.Status != resultdto.StatusConflicted || env.Summary.Conflicts != 1 {
				t.Fatalf("committed conflict outcome: %+v", env)
			}
			written := false
			for _, c := range env.Changes {
				if c.Path == "hello.txt" && c.Action == "write" {
					written = true
				}
			}
			if !written {
				t.Fatal("committed conflict missing actual write")
			}
		}
	}

	// Same-value explicit intent changes only authenticated marker provenance.
	assertAnswerReceipt := func(root, key, h string, env resultdto.Result) {
		t.Helper()
		if env.TransactionID == nil || env.PlanSHA256 == "" || env.Summary.FilesChanged != 1 || env.Summary.BlocksChanged != 0 || env.Summary.Conflicts != 0 || len(env.Changes) != 1 || env.Changes[0].Path != ".tplaiter/project.yaml" || env.Changes[0].Action != "write" {
			t.Fatalf("provenance-only receipt/counter: %+v", env)
		}
		raw, err := os.ReadFile(filepath.Join(root, ".tplaiter/project.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var marker stateledger.ProjectV2
		if err := yaml.Unmarshal(raw, &marker); err != nil {
			t.Fatal(err)
		}
		if marker.Answers["label"].Source != "user" || marker.Answers["label"].Value != "alpha" || marker.Answers["database"].Source != "default" || marker.Answers["tls"].Source != "default" {
			t.Fatalf("explicit/untouched origins: %+v", marker.Answers)
		}
		in := invocation{Selection: f.selection, ProjectKey: key, Clock: f.clock}
		r, err := composeRuntimeForProject(withInvocation(ctx, in), key)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		receipt, err := projecttransaction.OpenUpdate(ctx, r, filepath.Join(h, "tplaiter"), *env.TransactionID, "v-settings")
		if err != nil {
			t.Fatal(err)
		}
		defer receipt.Release()
		if receipt.ID() != *env.TransactionID {
			t.Fatal("cold recovery changed transaction ID")
		}
		if err := receipt.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(filepath.Join(root, ".tplaiter/project.yaml"))
		if err != nil || !bytes.Equal(raw, after) {
			t.Fatalf("cold same-value afterimage changed: %v", err)
		}
		sum := sha256.Sum256(after)
		t.Logf("installed same-value provenance receipt: txn=%s plan=%s markerSHA256=%x result=%+v", receipt.ID(), env.PlanSHA256, sum, env)
	}
	preview := checkNoEffects("settings", "edit", "label", "--value=alpha", "--dry-run", "--json")
	if preview.Summary.FilesChanged != 1 || len(preview.Changes) != 1 || preview.Changes[0].Path != ".tplaiter/project.yaml" {
		t.Fatalf("provenance-only preview hidden: %+v", preview)
	}
	intentOut, intentErr := run("settings", "edit", "label", "--value=alpha", "--yes", "--json")
	if intentErr != nil {
		t.Fatalf("same-value edit: %v %s", intentErr, intentOut)
	}
	assertAnswerReceipt(f.projectRoot, "project", home, decodeOne(t, string(intentOut)))
	repeated, repeatedErr := run("settings", "set", "label=alpha", "--yes", "--json")
	if repeatedErr != nil {
		t.Fatalf("repeat explicit answer: %v %s", repeatedErr, repeated)
	}
	if got := decodeOne(t, string(repeated)); got.Summary.FilesChanged != 0 || len(got.Changes) != 0 {
		t.Fatalf("same user origin was not a no-op: %+v", got)
	}
	env := checkNoEffects("settings", "set", "database=none", "--dry-run", "--json")
	if env.Status != resultdto.StatusChanges {
		t.Fatalf("database preview: %+v", env)
	}
	warning := func(env resultdto.Result) bool {
		for _, d := range env.Diagnostics {
			if d.Severity == "warning" && d.Path == "seed.sql" && strings.Contains(d.Message, "local edits") {
				return true
			}
		}
		return false
	}
	if !warning(env) {
		t.Fatal("retained seed preview warning missing")
	}
	out, err := run("settings", "set", "database=none", "--yes", "--json")
	if err != nil {
		t.Fatalf("database apply: %v %s", err, out)
	}
	env = decodeOne(t, string(out))
	if !warning(env) {
		t.Fatal("retained seed committed warning missing")
	}
	assertCommitted(f.projectRoot, "project", home, "alpha", env)
	t.Logf("CLI DatabaseNone committed: %s", out)
	env = checkNoEffects("settings", "set", "label=beta", "--dry-run", "--json")
	if env.Status != resultdto.StatusConflicted || env.Summary.Conflicts != 1 {
		t.Fatalf("text conflict preview: %+v", env)
	}
	out, err = run("settings", "set", "label=beta", "--yes", "--json")
	var childExit *exec.ExitError
	if !errors.As(err, &childExit) || childExit.ExitCode() != 2 {
		t.Fatalf("real conflict process exit: %v %s", err, out)
	}
	env = decodeOne(t, string(out))
	if err := env.ValidateExit(resultdto.ExitCode(2)); err != nil {
		t.Fatal(err)
	}
	assertCommitted(f.projectRoot, "project", home, "beta", env)
	t.Logf("CLI text conflict committed exit=2: %s", out)
	out, err = run("settings", "show", "--json")
	if err != nil {
		t.Fatalf("show after conflict: %v %s", err, out)
	}
	var shown resultdto.SettingsShowData
	decoded := decodeOne(t, string(out))
	if err := json.Unmarshal(decoded.Data, &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Settings["label"] != "beta" || shown.Settings["database"] != "none" {
		t.Fatalf("committed target settings: %+v", shown)
	}
	// The retained seed is now foreign to the disabled signed selection.
	env = checkNoEffects("settings", "set", "database=postgres", "--yes", "--json")
	if env.Status != resultdto.StatusConflicted {
		t.Fatalf("foreign addition accepted: %+v", env)
	}
	hello := filepath.Join(f.projectRoot, "hello.txt")
	original, err := os.ReadFile(hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hello, []byte("binary\x00local"), 0o644); err != nil {
		t.Fatal(err)
	}
	env = checkNoEffects("settings", "set", "label=gamma", "--yes", "--json")
	if env.Status != resultdto.StatusConflicted {
		t.Fatalf("binary conflict published: %+v", env)
	}
	if err := os.WriteFile(hello, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hello, 0o600); err != nil {
		t.Fatal(err)
	}
	env = checkNoEffects("settings", "set", "label=gamma", "--yes", "--json")
	if env.Status != resultdto.StatusConflicted && env.Status != resultdto.StatusBlocked && env.Status != resultdto.StatusFailed {
		t.Fatalf("unsafe mode published: %+v", env)
	}
	if err := os.Chmod(hello, 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink may never receive published conflict bytes.
	if err := os.Remove(hello); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("seed.sql", hello); err != nil {
		t.Fatal(err)
	}
	env = checkNoEffects("settings", "edit", "label", "--value=gamma", "--yes", "--json")
	if env.Status == resultdto.StatusChanges || env.Status == resultdto.StatusOK {
		t.Fatalf("symlink published: %+v", env)
	}
	if err := os.Remove(hello); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hello, original, 0o644); err != nil {
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
		if env.Status == resultdto.StatusConflicted && env.TransactionID != nil && result["isError"] != true {
			t.Fatal("MCP committed conflict falsely reported success")
		}
		t.Logf("MCP settings: %s", raw)
		return env
	}

	assertAnswerReceipt(second, "second", secondHome, call(20, "settings_edit", map[string]any{"dir": second, "projectContext": "second", "group": "label", "value": "alpha"}))
	before := observed(second)
	env = call(2, "settings_set", map[string]any{"dir": second, "projectContext": "second", "values": map[string]string{"database": "none"}, "dryRun": true})
	if !warning(env) || !reflect.DeepEqual(before, observed(second)) || env.TransactionID != nil {
		t.Fatalf("MCP database preview: %+v", env)
	}
	env = call(3, "settings_set", map[string]any{"dir": second, "projectContext": "second", "values": map[string]string{"database": "none"}})
	if !warning(env) {
		t.Fatal("MCP retained seed warning")
	}
	assertCommitted(second, "second", secondHome, "alpha", env)
	env = call(4, "settings_edit", map[string]any{"dir": second, "projectContext": "second", "group": "label", "value": "beta"})
	if env.Operation != resultdto.OperationSettingsReanswer {
		t.Fatalf("MCP edit operation: %+v", env)
	}
	assertCommitted(second, "second", secondHome, "beta", env)
	before = observed(second)
	env = call(5, "settings_list", map[string]any{"dir": second, "projectContext": "second"})
	if !reflect.DeepEqual(before, observed(second)) {
		t.Fatal("MCP show effects")
	}
	if err := json.Unmarshal(env.Data, &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Settings["database"] != "none" || shown.Settings["label"] != "beta" {
		t.Fatalf("MCP show target settings: %+v", shown)
	}
}
