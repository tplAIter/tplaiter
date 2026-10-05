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

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Actual installed CLI and MCP processes share authenticated two-version source
// fixtures, but have distinct projects and homes. No model, network or execution.
func TestDeprecatedAnswersInstalledCLIAndMCP(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeDeprecatedFixture(t)
	base := filepath.Dir(f.projectRoot)
	second := filepath.Join(base, "project-mcp")
	var install trustload.RuntimeInstall
	raw := mustMigrationFile(t, base, "runtime.json")
	if err := json.Unmarshal(raw, &install); err != nil {
		t.Fatal(err)
	}
	pc := install.ProjectContexts[0]
	pc.Key, pc.ProjectID, pc.RootPath = "second", "project-second", second
	install.ProjectContexts = append(install.ProjectContexts, pc)
	freshRoot := filepath.Join(base, "project-fresh")
	freshPC := pc
	freshPC.Key, freshPC.ProjectID, freshPC.RootPath = "fresh", "project-fresh", freshRoot
	install.ProjectContexts = append(install.ProjectContexts, freshPC)

	raw = t5FJSON(t, install)
	if err := os.WriteFile(f.selection.RuntimeConfig.Path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
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
	home, secondHome := filepath.Join(base, "process-home"), filepath.Join(base, "mcp-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=v-deprecated -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(digest[:]), "-o", bin, ".")
	build.Dir, build.Env = filepath.Join("..", ".."), testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	t.Logf("installed binary SHA256=%x signed versions=1.0.0 -> 3.0.0", sha256.Sum256(mustMigrationFile(t, base, "tplaiter")))
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	activeHome := home
	run := func(args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, bin, args...)
		c.Env, c.Dir = testProcessEnv(activeHome), base
		out, err := c.Output()
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok && len(exit.Stderr) > 0 {
				t.Logf("bounded installed refusal/failure: %s", exit.Stderr)
			}
		}
		return out, err
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision %v %s", err, out)
	}
	sourcePath, targetPath := filepath.Join(base, "source.json"), filepath.Join(base, "target.json")
	for path, data := range map[string][]byte{sourcePath: t5FSelection(f.source, f.sourceRefs), targetPath: t5FSelection(f.target, f.targetRefs)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, project := range []struct{ key, root, home string }{{"project", f.projectRoot, home}, {"second", second, secondHome}} {
		activeHome = project.home
		if out, err := run("new", f.source.Commit, "project", "--project-context", project.key, "--dir", project.root, "--source-input", sourcePath, "--defaults", "--no-hooks", "--json"); err != nil {
			t.Fatalf("new %s %v %s", project.key, err, out)
		}
	}
	activeHome = home
	observed := func(root, h string) map[string]string {
		out := nativeUpdateObservedTree(t, root)
		for prefix, dir := range map[string]string{"home/": filepath.Join(h, "tplaiter"), "objects/": install.ObjectOrigins[0].RootPath, "evidence/": install.EvidenceRoot} {
			for p, v := range nativeUpdateObservedTree(t, dir) {
				out[prefix+p] = v
			}
		}
		return out
	}
	before := observed(f.projectRoot, home)
	out, err := run("update", "--to", f.target.Commit, "--source-input", targetPath, "--dry-run", "--json")
	if err != nil {
		t.Fatalf("preview %v %s", err, out)
	}
	t.Logf("actual CLI Update preview envelope=%s", out)
	preview := decodeOne(t, string(out))
	if preview.TransactionID != nil || preview.PlanSHA256 == "" || !reflect.DeepEqual(before, observed(f.projectRoot, home)) {
		t.Fatal("preview effects or missing fingerprint")
	}
	out, err = run("update", "--to", f.target.Commit, "--source-input", targetPath, "--json")
	if err != nil {
		t.Fatalf("update %v %s", err, out)
	}
	t.Logf("actual CLI Update applied envelope=%s", out)
	applied := decodeOne(t, string(out))
	if applied.TransactionID == nil || applied.PlanSHA256 != preview.PlanSHA256 {
		t.Fatalf("different plan %+v %+v", preview, applied)
	}
	assertDeprecatedState(t, f.projectRoot)
	assertDeprecatedWarnings(t, applied)
	// Reader history is verified, not merely accepted because the JSON is valid.
	ledgerPath := filepath.Join(f.projectRoot, migrations.LedgerRelPath)
	originalLedger := mustMigrationFile(t, f.projectRoot, migrations.LedgerRelPath)
	var forgedLedger migrations.Ledger
	if err := json.Unmarshal(originalLedger, &forgedLedger); err != nil {
		t.Fatal(err)
	}
	forgedLedger.Applied[0].Digest = forgedLedger.Applied[1].Digest
	if err := os.WriteFile(ledgerPath, t5FJSON(t, forgedLedger), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"settings", "list", "--json"}, {"diff", "--offline=true", "--json"}} {
		before := observed(f.projectRoot, home)
		if out, err := run(args...); err == nil {
			t.Fatalf("forged signed history read accepted: %v %s", args, out)
		}
		if !reflect.DeepEqual(before, observed(f.projectRoot, home)) {
			t.Fatal("refused reader effects")
		}
	}
	if err := os.WriteFile(ledgerPath, originalLedger, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"settings", "list", "--json"}, {"diff", "--offline=true", "--json"}, {"settings", "set", "choice=old", "--dry-run", "--json"}} {
		before := observed(f.projectRoot, home)
		out, err := run(args...)
		if err != nil {
			t.Fatalf("post-update reader %v: %v %s", args, err, out)
		}
		if !reflect.DeepEqual(before, observed(f.projectRoot, home)) {
			t.Fatal("post-update reader effects")
		}
	}
	// Cold committed CLI replay keeps the same receipt ID and reconstructs exact
	// source-before and migrated target-after semantics from sealed beforeimages.
	out, err = run("update", "continue", *applied.TransactionID, "--json")
	if err != nil {
		t.Fatalf("continue %v %s", err, out)
	}
	continued := decodeOne(t, string(out))
	if continued.TransactionID == nil || *continued.TransactionID != *applied.TransactionID {
		t.Fatal("cold ID changed")
	}
	assertDeprecatedState(t, f.projectRoot)
	// Also reauthenticate the material through a fresh runtime, not observer labels.
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	r, err := composeRuntimeForProject(withInvocation(ctx, in), "project")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := projecttransaction.OpenUpdate(ctx, r, filepath.Join(home, "tplaiter"), *applied.TransactionID, "v-deprecated")
	if err != nil {
		r.Close()
		t.Fatal(err)
	}
	receipt.Release()
	r.Close()

	out, err = run("settings", "set", "choice=old", "--json")
	if err != nil {
		t.Fatalf("CLI retained same-value %v %s", err, out)
	}
	assertDeprecatedOrigin(t, f.projectRoot, "choice", "user")
	out, err = run("settings", "edit", "choice", "--value", "new", "--json")
	if err != nil {
		t.Fatalf("CLI supported replacement %v %s", err, out)
	}
	before = observed(f.projectRoot, home)
	if out, err = run("settings", "set", "choice=old", "--json"); err == nil {
		t.Fatal("CLI retired reintroduction admitted", string(out))
	}
	if !reflect.DeepEqual(before, observed(f.projectRoot, home)) {
		t.Fatal("refusal effects")
	}
	activeHome = filepath.Join(base, "fresh-home")
	answerPath := filepath.Join(base, "answers.yaml")
	if err := os.WriteFile(answerPath, []byte("choice: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	freshArgs := []string{"new", f.target.Commit, "project", "--project-context", "fresh", "--dir", freshRoot, "--source-input", targetPath, "--defaults", "--no-hooks", "--json"}
	for _, extra := range [][]string{{"--set", "choice=old"}, {"--answers", answerPath}} {
		if out, err := run(append(append([]string{}, freshArgs...), extra...)...); err == nil {
			t.Fatal("fresh retired selection admitted", string(out))
		}
		if _, err := os.Stat(freshRoot); !os.IsNotExist(err) {
			t.Fatal("fresh refusal created project", err)
		}
	}
	if out, err := run(freshArgs...); err != nil {
		t.Fatalf("fresh supported defaults %v %s", err, out)
	}
	freshMarker := readDeprecatedMarker(t, freshRoot)
	for _, key := range []string{"retired", "title", "child"} {
		if _, ok := freshMarker.Answers[key]; ok {
			t.Fatal("fresh retired record synthesized", key)
		}
	}
	if freshMarker.Answers["choice"].Value != "new" {
		t.Fatal("fresh supported default lost")
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
			t.Fatalf("MCP %v %s", err, stderr.String())
		}
		if response["error"] != nil {
			t.Fatalf("MCP %+v", response)
		}
		return response
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "migration-test", "version": "1"}})
	if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	call := func(id int, tool string, args map[string]any) resultdto.Result {
		t.Helper()
		response := request(id, "tools/call", map[string]any{"name": tool, "arguments": args})
		result := response["result"].(map[string]any)
		raw, err := json.Marshal(result["structuredContent"])
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("actual MCP %s structured envelope=%s", tool, raw)
		env, err := resultdto.Decode(raw)
		if err != nil || result["isError"] == true {
			t.Fatalf("MCP %v %s", err, raw)
		}
		return env
	}
	before = observed(second, secondHome)
	mcpPreview := call(2, "update", map[string]any{"dir": second, "projectContext": "second", "to": f.target.Commit, "sourceInput": targetPath, "dryRun": true})
	if mcpPreview.TransactionID != nil || !reflect.DeepEqual(before, observed(second, secondHome)) {
		t.Fatal("MCP preview effects")
	}
	mcpApplied := call(3, "update", map[string]any{"dir": second, "projectContext": "second", "to": f.target.Commit, "sourceInput": targetPath})
	if mcpApplied.TransactionID == nil || mcpApplied.PlanSHA256 != mcpPreview.PlanSHA256 {
		t.Fatal("MCP plan mismatch")
	}
	assertDeprecatedState(t, second)
	read := call(4, "settings_list", map[string]any{"dir": second, "projectContext": "second"})
	assertDeprecatedWarnings(t, read)
	same := call(6, "settings_set", map[string]any{"dir": second, "projectContext": "second", "values": map[string]string{"choice": "old"}})
	if same.TransactionID == nil {
		t.Fatal("MCP same-value intent missing transaction")
	}
	assertDeprecatedOrigin(t, second, "choice", "user")
	call(7, "settings_edit", map[string]any{"dir": second, "projectContext": "second", "group": "choice", "value": "new"})
	before = observed(second, secondHome)
	bad := request(8, "tools/call", map[string]any{"name": "settings_set", "arguments": map[string]any{"dir": second, "projectContext": "second", "values": map[string]string{"choice": "old"}}})
	if bad["result"].(map[string]any)["isError"] != true {
		t.Fatal("MCP retired reintroduction admitted")
	}

	if !reflect.DeepEqual(before, observed(second, secondHome)) {
		t.Fatal("MCP refusal effects")
	}
	call(5, "project_diff", map[string]any{"dir": second, "projectContext": "second"})
	t.Logf("actual installed CLI txn=%s plan=%s; MCP txn=%s plan=%s; previews zero effects, post-history readers and same-ID CLI cold replay passed", *applied.TransactionID, applied.PlanSHA256, *mcpApplied.TransactionID, mcpApplied.PlanSHA256)
}

func readDeprecatedMarker(t *testing.T, root string) stateledger.ProjectV2 {
	t.Helper()
	var m stateledger.ProjectV2
	if err := yaml.Unmarshal(mustMigrationFile(t, root, ".tplaiter/project.yaml"), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func assertDeprecatedOrigin(t *testing.T, root, key, source string) {
	t.Helper()
	if readDeprecatedMarker(t, root).Answers[key].Source != source {
		t.Fatal("origin mismatch", key)
	}
}

func assertDeprecatedWarnings(t *testing.T, env resultdto.Result) {
	t.Helper()
	found := 0
	for _, d := range env.Diagnostics {
		if d.Code == "TPL-W-NATIVE-DEPRECATED-ANSWER" {
			found++
		}
	}
	if found < 5 {
		t.Fatal("retention diagnostics absent", env.Diagnostics)
	}
}

func assertDeprecatedState(t *testing.T, root string) {
	t.Helper()
	m := readDeprecatedMarker(t, root)
	for key, want := range map[string]stateledger.Answer{"choice": {Value: "old", Source: "default"}, "retired": {Value: false, Source: "default"}, "child": {Value: true, Source: "default"}, "title": {Value: "recorded", Source: "migration"}, "label": {Value: "beta", Source: "default"}} {
		if m.Answers[key] != want {
			t.Fatalf("%s answer %+v want %+v", key, m.Answers[key], want)
		}
	}
	if m.Answers["multi"].Source != "default" || !reflect.DeepEqual(m.Answers["multi"].Value, []any{"old"}) {
		t.Fatalf("retired default-origin multi lost: %+v", m.Answers["multi"])
	}
	if _, ok := m.Answers["oldtitle"]; ok {
		t.Fatal("renamed key retained")
	}
	if _, ok := m.Answers["obsolete"]; ok {
		t.Fatal("deleted key retained")
	}
	if got := string(mustMigrationFile(t, root, "hello.txt")); got != "target old false false recorded\n" {
		t.Fatalf("retained/inactive render %q", got)
	}
	var ledger migrations.Ledger
	if err := json.Unmarshal(mustMigrationFile(t, root, migrations.LedgerRelPath), &ledger); err != nil || len(ledger.Applied) != 2 {
		t.Fatal("migration history lost", err)
	}
	t.Logf("retained default/migration/inactive state marker=%x", sha256.Sum256(mustMigrationFile(t, root, ".tplaiter/project.yaml")))
}
