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

const migrationSourceSettings = `settings:
  - group: label
    type: string
    default: alpha
  - group: obsolete
    type: string
    default: gone
  - group: untouched
    type: string
    default: retained
  - group: parent
    type: select
    default: off
    options:
      - id: off
      - id: on
        settings:
          - group: oldchild
            type: toggle
            default: true
`

const migrationTargetSettings = `settings:
  - group: title
    type: string
    default: new-default
  - group: untouched
    type: string
    default: retained
  - group: parent
    type: select
    default: off
    options:
      - id: off
      - id: on
        settings:
          - group: child
            type: toggle
            default: false
`

const migrationDeclarations = `migrations:
  - id: rename-v2
    from: 1.0.0
    to: 2.0.0
    phase: after
    settings:
      rename: {label: title, oldchild: child}
  - id: delete-v3
    from: 2.0.0
    to: 3.0.0
    phase: before
    settings:
      delete: [obsolete]
`

func nativeAnswerMigrationFixture(t *testing.T, executable bool) t5FFixture {
	declarations := migrationDeclarations
	if executable {
		declarations += "    steps:\n      - run: must-never-execute\n"
	}
	return nativeUpdateCLIFixtureVersions(t, false, "1.0.0", "3.0.0",
		"source {{ index .Settings \"label\" }}\n", "target {{ index .Settings \"title\" }} {{ index .Settings \"child\" }}\n",
		[]string{migrationSourceSettings}, migrationTargetSettings, declarations)
}

func assertAnswerMigrationState(t *testing.T, root string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, ".tplaiter/project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(raw, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.Answers["title"] != (stateledger.Answer{Value: "alpha", Source: "migration"}) || marker.Answers["child"] != (stateledger.Answer{Value: true, Source: "migration"}) || marker.Answers["untouched"].Source != "default" {
		t.Fatalf("answers %+v", marker.Answers)
	}
	for _, key := range []string{"label", "oldchild", "obsolete"} {
		if _, ok := marker.Answers[key]; ok {
			t.Fatalf("removed answer %s retained", key)
		}
	}
	raw, err = os.ReadFile(filepath.Join(root, migrations.LedgerRelPath))
	if err != nil {
		t.Fatal(err)
	}
	var ledger migrations.Ledger
	if err := json.Unmarshal(raw, &ledger); err != nil {
		t.Fatal(err)
	}
	if len(ledger.Applied) != 2 || ledger.Applied[0].ID != "rename-v2" || ledger.Applied[1].ID != "delete-v3" || ledger.Applied[0].Order != 0 || ledger.Applied[1].Order != 1 {
		t.Fatalf("ledger %+v", ledger)
	}
	raw, err = os.ReadFile(filepath.Join(root, "hello.txt"))
	if err != nil || string(raw) != "target alpha false\n" {
		t.Fatalf("inactive rendering: %v %q", err, raw)
	}
	t.Logf("migration marker/ledger/render verified: marker=%x ledger=%+v", sha256.Sum256(mustMigrationFile(t, root, ".tplaiter/project.yaml")), ledger)
}

func mustMigrationFile(t *testing.T, root, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Actual installed CLI and MCP processes share authenticated two-version source
// fixtures, but have distinct projects and homes. No model, network or execution.
func TestSignedAnswerMigrationsInstalledCLIAndMCP(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeAnswerMigrationFixture(t, false)
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
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=v-migrations -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(digest[:]), "-o", bin, ".")
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
		return c.Output()
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
	preview := decodeOne(t, string(out))
	if preview.TransactionID != nil || preview.PlanSHA256 == "" || !reflect.DeepEqual(before, observed(f.projectRoot, home)) {
		t.Fatal("preview effects or missing fingerprint")
	}
	out, err = run("update", "--to", f.target.Commit, "--source-input", targetPath, "--json")
	if err != nil {
		t.Fatalf("update %v %s", err, out)
	}
	applied := decodeOne(t, string(out))
	if applied.TransactionID == nil || applied.PlanSHA256 != preview.PlanSHA256 {
		t.Fatalf("different plan %+v %+v", preview, applied)
	}
	assertAnswerMigrationState(t, f.projectRoot)
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
	for _, args := range [][]string{{"settings", "list", "--json"}, {"diff", "--offline=true", "--json"}, {"settings", "set", "title=alpha", "--dry-run", "--json"}} {
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
	assertAnswerMigrationState(t, f.projectRoot)
	// Also reauthenticate the material through a fresh runtime, not observer labels.
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	r, err := composeRuntimeForProject(withInvocation(ctx, in), "project")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := projecttransaction.OpenUpdate(ctx, r, filepath.Join(home, "tplaiter"), *applied.TransactionID, "v-migrations")
	if err != nil {
		r.Close()
		t.Fatal(err)
	}
	receipt.Release()
	r.Close()
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
	assertAnswerMigrationState(t, second)
	call(4, "settings_list", map[string]any{"dir": second, "projectContext": "second"})
	call(5, "project_diff", map[string]any{"dir": second, "projectContext": "second"})
	t.Logf("actual installed CLI txn=%s plan=%s; MCP txn=%s plan=%s; previews zero effects, post-history readers and same-ID CLI cold replay passed", *applied.TransactionID, applied.PlanSHA256, *mcpApplied.TransactionID, mcpApplied.PlanSHA256)
}
