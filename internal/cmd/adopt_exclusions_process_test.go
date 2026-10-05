package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/diffcmd"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/linkcmd"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/adoption"
	linktx "github.com/tplAIter/tplaiter/internal/projecttransaction/link"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/updateplan"
	"gopkg.in/yaml.v3"
)

func TestNativeAdoptionMixedInstalledRuntime(t *testing.T) {
	f, r, home, in := linkAdmissionFixture(t)
	ctx := context.Background()
	in.Action = "adopt"
	in.Choices = map[string]string{"go.mod": "user-owned", "added.txt": "user-owned"}
	user := []byte("module local.test/owner\n// user owned\n")
	rel := filepath.Join(f.projectRoot, "go.mod")
	if e := os.WriteFile(rel, user, 0o644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(rel, 0o640); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(f.projectRoot, "added.txt")); e != nil {
		t.Fatal(e)
	}
	original, e := os.Lstat(rel)
	if e != nil {
		t.Fatal(e)
	}
	assertUser := func() {
		t.Helper()
		i, e := os.Lstat(rel)
		if e != nil || !os.SameFile(original, i) || i.Mode() != original.Mode() {
			t.Fatal("excluded identity/mode changed", e)
		}
		b, e := os.ReadFile(rel)
		if e != nil || !bytes.Equal(b, user) {
			t.Fatal("excluded bytes changed", e)
		}
		if _, e = os.Lstat(filepath.Join(f.projectRoot, "added.txt")); !os.IsNotExist(e) {
			t.Fatal("missing exclusion created", e)
		}
	}
	p, e := linkcmd.Prepare(ctx, r, home, in, "dev")
	if e != nil {
		t.Fatal(e)
	}
	tx, e := linktx.Begin(ctx, p, p.Fingerprint(), "dev")
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		tx.Release()
		t.Fatal(e)
	}
	id := tx.ID()
	tx.Release()
	assertUser()
	raw, e := os.ReadFile(filepath.Join(f.projectRoot, ".tplaiter/project.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	var marker stateledger.ProjectV2
	if e = yaml.Unmarshal(raw, &marker); e != nil {
		t.Fatal(e)
	}
	policy, e := adoptionpolicy.Parse(marker.Ownership)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := adoption.Read(ctx, r, home, policy)
	if e != nil || proof.ReceiptID() != id {
		t.Fatal("installed origin", e)
	}
	t.Logf("installed mixed exclusion fixture root=%s home=%s origin=%s", f.projectRoot, home, id)
	report, e := diffcmd.Run(ctx, r, diffcmd.Options{Home: home, RendererVersion: "dev", SecretProvider: readonlyHomeClassifier{}})
	if e != nil {
		t.Fatal("diff", e)
	}
	if len(report.Excluded) != 2 || len(report.Changes) != 2 {
		t.Fatalf("truthful diff %#v", report)
	}
	b, e := updateplan.New(r, home, "dev")
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []struct{ source, target []byte }{{t5FSelection(f.target, f.targetRefs), t5FSelection(f.source, f.sourceRefs)}, {t5FSelection(f.source, f.sourceRefs), t5FSelection(f.target, f.targetRefs)}} {
		plan, e := b.Prepare(ctx, updateplan.Input{SourceInput: step.source, TargetInput: step.target})
		if e != nil {
			t.Fatal("prepare update", e)
		}
		mt, _, e := plan.TransactionMaterial(ctx, plan.Fingerprint())
		if e != nil {
			t.Fatal("material", e)
		}
		if mt.Version != 2 || mt.Protection == nil {
			t.Fatal("v2 protection absent")
		}
		update, e := projecttransaction.BeginUpdate(ctx, plan, plan.Fingerprint())
		if e != nil {
			t.Fatal("begin update", e)
		}
		if e = update.Commit(ctx); e != nil {
			update.Release()
			t.Fatal("commit update", e)
		}
		update.Release()
		assertUser()
	}
	t.Log("actual installed-runtime remove/reintroduce retained full signed lineage and exact excluded user inode/mode/bytes")
}

func TestNativeAdoptionInstalledCLIAndMCP(t *testing.T) {
	testfixture.RequireTrustStore(t)
	var extra []string
	if os.Getenv("TPLAITER_ADOPTION_GEN_TARGETS") == "1" {
		for _, entry := range []struct{ kind, target string }{{"present", "go.mod"}, {"missing", "added.txt"}} {
			extra = append(extra, "  - kind: "+entry.kind+"\n    description: Excluded target fixture\n    snippet: generators/note.txt.tmpl\n    target: "+entry.target+"\n    params:\n      - name: label\n        type: string\n        required: true\n        pattern: '^[a-z]+$'\n")
		}
	}
	f := nativeLinkCLIFixture(t, true, extra...)
	base := filepath.Dir(f.projectRoot)
	var install trustload.RuntimeInstall
	raw, e := os.ReadFile(f.selection.RuntimeConfig.Path)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &install); e != nil {
		t.Fatal(e)
	}
	roots := map[string]string{}
	for _, key := range []string{"cli", "mcp", "project"} {
		pc := install.ProjectContexts[0]
		pc.Key = key
		pc.ProjectID = "exclusion-" + key
		pc.RootPath = filepath.Join(base, key)
		if key == "project" {
			pc = install.ProjectContexts[0]
		} else {
			install.ProjectContexts = append(install.ProjectContexts, pc)
		}
		roots[key] = pc.RootPath
		for _, dir := range []string{pc.RootPath, filepath.Join(pc.RootPath, "aa"), filepath.Join(pc.RootPath, "bb"), filepath.Join(base, key+"-home", "tplaiter")} {
			if e = os.MkdirAll(dir, 0o751); e != nil {
				t.Fatal(e)
			}
		}
		for name, data := range map[string][]byte{"go.mod": []byte("module owner.test/local\n"), "aa/note.txt": []byte("tracked local edit\n"), "bb/note.txt": []byte("signed directory\n"), "foreign.bin": {0, 1, 2, 3}} {
			if e = os.WriteFile(filepath.Join(pc.RootPath, name), data, 0o640); e != nil {
				t.Fatal(e)
			}
		}
		if e = os.Chmod(filepath.Join(pc.RootPath, "bb/note.txt"), 0o644); e != nil {
			t.Fatal(e)
		}
		if key == "project" {
			if e = os.WriteFile(filepath.Join(pc.RootPath, "aa/note.txt"), []byte("signed directory\n"), 0o640); e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(filepath.Join(pc.RootPath, "aa/note.txt"), 0o644); e != nil {
				t.Fatal(e)
			}
		}
	}
	raw = t5FJSON(t, install)
	if e = os.WriteFile(f.selection.RuntimeConfig.Path, raw, 0o600); e != nil {
		t.Fatal(e)
	}
	f.selection.RuntimeConfig.SHA256, e = install.Digest()
	if e != nil {
		t.Fatal(e)
	}
	registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
	raw = t5FJSON(t, registration)
	reg := filepath.Join(base, "registration.json")
	if e = os.WriteFile(reg, raw, 0o600); e != nil {
		t.Fatal(e)
	}
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=dev -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+reg+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+evidencecas.Digest(raw), "-o", bin, ".")
	if overlay := os.Getenv("TPLAITER_ADOPTION_GEN_OVERLAY"); overlay != "" {
		build.Args = append(build.Args[:2], append([]string{"-overlay", overlay}, build.Args[2:]...)...)
	}
	build.Dir = filepath.Join("..", "..")
	build.Env = testBuildEnv(filepath.Join(base, "build-home"))
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build %v %s", e, out)
	}
	if e = os.WriteFile(filepath.Join(base, "source-input.json"), t5FSelection(f.source, f.sourceRefs), 0o600); e != nil {
		t.Fatal(e)
	}
	selection := filepath.Join(base, "target-input.json")
	if e = os.WriteFile(selection, t5FSelection(f.target, f.targetRefs), 0o600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(base, "launch-selection.json"), t5FJSON(t, f.selection), 0o600); e != nil {
		t.Fatal(e)
	}
	before := map[string]map[string]linkObservedFile{}
	for key, root := range roots {
		before[key] = map[string]linkObservedFile{}
		for _, rel := range []string{".", "aa", "bb", "go.mod", "aa/note.txt", "bb/note.txt", "foreign.bin"} {
			info, e := os.Lstat(filepath.Join(root, rel))
			if e != nil {
				t.Fatal(e)
			}
			var b []byte
			if !info.IsDir() {
				b, e = os.ReadFile(filepath.Join(root, rel))
				if e != nil {
					t.Fatal(e)
				}
			}
			before[key][rel] = linkObservedFile{info, b}
		}
	}
	assertUser := func(key string) {
		t.Helper()
		for rel, old := range before[key] {
			info, e := os.Lstat(filepath.Join(roots[key], rel))
			if e != nil || !os.SameFile(old.info, info) || old.info.Mode() != info.Mode() {
				t.Fatalf("%s user inode/mode %s %v", key, rel, e)
			}
			if !info.IsDir() {
				b, e := os.ReadFile(filepath.Join(roots[key], rel))
				if e != nil || !bytes.Equal(b, old.raw) {
					t.Fatal("user bytes", rel, e)
				}
			}
		}
		if _, e := os.Lstat(filepath.Join(roots[key], "added.txt")); !os.IsNotExist(e) {
			t.Fatal("missing user-owned created", e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	run := func(key string, args ...string) (resultdto.Result, int) {
		t.Helper()
		child := exec.CommandContext(ctx, bin, args...)
		child.Dir = base
		child.Env = testProcessEnv(filepath.Join(base, key+"-home"))
		var out, errout bytes.Buffer
		child.Stdout = &out
		child.Stderr = &errout
		e := child.Run()
		code := 0
		if e != nil {
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatal(e)
			}
			code = exit.ExitCode()
		}
		env, e := resultdto.Decode(out.Bytes())
		if e != nil {
			t.Fatalf("decode %v %s %s", e, &out, &errout)
		}
		t.Logf("installed %s %v exit=%d status=%s", key, args, code, env.Status)
		return env, code
	}
	provision := exec.CommandContext(ctx, bin, "trust", "provision")
	provision.Dir = base
	provision.Env = testProcessEnv(filepath.Join(base, "cli-home"))
	if out, e := provision.CombinedOutput(); e != nil {
		t.Fatalf("provision %v %s", e, out)
	}
	args := []string{"adopt", f.target.Commit, "Adopt", "--project-context=cli", "--source-input=" + selection, "--module=example.test/adopt", "--ownership=go.mod=user-owned", "--ownership=added.txt=user-owned", "--ownership=aa/note.txt=track", "--json"}
	bad := append([]string{}, args...)
	bad = append(bad, "--ownership=foreign.bin=user-owned")
	if env, code := run("cli", bad...); code == 0 || len(env.Changes) != 0 {
		t.Fatal("irrelevant choice had effects")
	}
	assertUser("cli")
	env, code := run("cli", args...)
	if code != 0 || env.Operation != resultdto.OperationProjectAdopt {
		t.Fatal("CLI adoption failed", env)
	}
	assertUser("cli")
	coldArgs := []string{"adopt", f.target.Commit, "Adopt", "--project-context=project", "--source-input=" + selection, "--module=example.test/adopt", "--ownership=go.mod=user-owned", "--ownership=added.txt=user-owned", "--json"}
	if env, code := run("project", coldArgs...); code != 0 || env.Operation != resultdto.OperationProjectAdopt {
		t.Fatal("cold fixture adoption failed", env)
	}
	assertUser("project")
	var data resultdto.ProjectLinkData
	if e = json.Unmarshal(env.Data, &data); e != nil {
		t.Fatal(e)
	}
	if len(data.ExcludedPaths) != 2 || len(data.TrackedConflicts) != 1 || data.TrackedConflicts[0].Path != "aa/note.txt" {
		t.Fatalf("truthful ownership DTO %#v", data)
	}
	if env, code = run("cli", "diff", "--project-context=cli", "--exit-code", "--json"); code != 1 {
		t.Fatal("diff failed to report excluded drift", env)
	}
	assertUser("cli")
	server := exec.CommandContext(ctx, bin, "mcp-server")
	server.Dir = base
	server.Env = testProcessEnv(filepath.Join(base, "mcp-home"))
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
	defer func() { stdin.Close(); server.Wait() }()
	enc, dec := json.NewEncoder(stdin), json.NewDecoder(stdout)
	request := func(id int, method string, params any) map[string]any {
		t.Helper()
		if e = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); e != nil {
			t.Fatal(e)
		}
		var response map[string]any
		if e = dec.Decode(&response); e != nil {
			t.Fatalf("MCP %v %s", e, &stderr)
		}
		if response["error"] != nil {
			t.Fatal(response)
		}
		return response
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "exclusion-proof", "version": "1"}})
	if e = enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); e != nil {
		t.Fatal(e)
	}
	listed := request(9, "tools/list", map[string]any{})["result"].(map[string]any)["tools"].([]any)
	baselineRaw, e := os.ReadFile("../../tests/testdata/mcp/tools.schema.golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var baseline []map[string]any
	if e = json.Unmarshal(baselineRaw, &baseline); e != nil {
		t.Fatal(e)
	}
	objects := map[string]any{}
	for _, v := range listed {
		object := v.(map[string]any)
		objects[object["name"].(string)] = object
	}
	if len(objects) != len(baseline) {
		t.Fatal("MCP names changed")
	}
	for _, v := range baseline {
		if v["name"] != "project_link" && v["name"] != "project_diff" && !reflect.DeepEqual(objects[v["name"].(string)], v) {
			t.Fatalf("unrelated named MCP object changed: %s", v["name"])
		}
	}
	named, e := json.MarshalIndent(listed, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(base, "installed-tools.json"), named, 0o600); e != nil {
		t.Fatal(e)
	}
	t.Log("all 28 unrelated canonical named MCP objects preserved exactly; project_link/project_diff named entries retained for primary integration")
	result := request(2, "tools/call", map[string]any{"name": "project_link", "arguments": map[string]any{"action": "adopt", "dir": roots["mcp"], "projectContext": "mcp", "ref": f.target.Commit, "name": "Adopt", "module": "example.test/adopt", "sourceInput": selection, "ownership": map[string]string{"go.mod": "user-owned", "added.txt": "user-owned", "aa/note.txt": "track"}}})["result"].(map[string]any)
	raw, e = json.Marshal(result["structuredContent"])
	if e != nil {
		t.Fatal(e)
	}
	env, e = resultdto.Decode(raw)
	if e != nil || env.Status != resultdto.StatusChanges || env.Operation != resultdto.OperationProjectAdopt {
		t.Fatalf("MCP adoption %v %s", e, raw)
	}
	assertUser("mcp")
	t.Logf("installed CLI/MCP mixed fixture ready: %s (keys cli/mcp; present go.mod and missing added.txt exclusions; launch-selection.json/registration.json/target-input.json; per-key ledger home KEY-home/tplaiter)", base)
}

func TestNativeAdoptionProtectedDriftBeforeEffects(t *testing.T) {
	cases := []string{"content", "equal-inode", "removed", "missing-created", "setuid", "setgid", "sticky", "directory-sticky", "policy", "origin", "source"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f, r, home, in := linkAdmissionFixture(t)
			ctx := context.Background()
			in.Action = "adopt"
			in.Choices = map[string]string{"go.mod": "user-owned", "added.txt": "user-owned"}
			rel := filepath.Join(f.projectRoot, "go.mod")
			if e := os.WriteFile(rel, []byte("user bytes\n"), 0o644); e != nil {
				t.Fatal(e)
			}
			if e := os.Remove(filepath.Join(f.projectRoot, "added.txt")); e != nil {
				t.Fatal(e)
			}
			p, e := linkcmd.Prepare(ctx, r, home, in, "dev")
			if e != nil {
				t.Fatal(e)
			}
			link, e := linktx.Begin(ctx, p, p.Fingerprint(), "dev")
			if e != nil {
				t.Fatal(e)
			}
			if e = link.Commit(ctx); e != nil {
				link.Release()
				t.Fatal(e)
			}
			origin := link.ID()
			link.Release()
			b, e := updateplan.New(r, home, "dev")
			if e != nil {
				t.Fatal(e)
			}
			plan, e := b.Prepare(ctx, updateplan.Input{SourceInput: t5FSelection(f.target, f.targetRefs), TargetInput: t5FSelection(f.source, f.sourceRefs)})
			if e != nil {
				t.Fatal(e)
			}
			tx, e := projecttransaction.BeginUpdate(ctx, plan, plan.Fingerprint())
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Release()
			receipt := filepath.Join(home, "transactions", "project", "tx-"+tx.ID(), "state.json")
			paths := []string{filepath.Join(f.projectRoot, ".tplaiter/baseline.json"), filepath.Join(f.projectRoot, ".tplaiter/ownership.json"), filepath.Join(home, "projects.yaml"), receipt}
			before := map[string][]byte{}
			for _, p := range paths {
				raw, e := os.ReadFile(p)
				if e != nil {
					t.Fatal(e)
				}
				before[p] = raw
			}
			switch name {
			case "content":
				e = os.WriteFile(rel, []byte("protected drift\n"), 0o644)
			case "equal-inode":
				var raw []byte
				raw, e = os.ReadFile(rel)
				if e == nil {
					e = os.Rename(rel, filepath.Join(filepath.Dir(f.projectRoot), "retained-user-inode"))
				}
				if e == nil {
					e = os.WriteFile(rel, raw, 0o644)
				}
			case "removed":
				e = os.Rename(rel, filepath.Join(filepath.Dir(f.projectRoot), "retained-user-inode"))
			case "missing-created":
				e = os.WriteFile(filepath.Join(f.projectRoot, "added.txt"), []byte("foreign appeared\n"), 0o644)
			case "setuid":
				e = os.Chmod(rel, 0o644|os.ModeSetuid)
			case "setgid":
				e = os.Chmod(rel, 0o644|os.ModeSetgid)
			case "sticky":
				e = os.Chmod(rel, 0o644|os.ModeSticky)
			case "directory-sticky":
				e = os.Chmod(f.projectRoot, 0o700|os.ModeSticky)
			case "policy":
				var raw []byte
				mp := filepath.Join(f.projectRoot, ".tplaiter/project.yaml")
				raw, e = os.ReadFile(mp)
				if e == nil {
					var marker stateledger.ProjectV2
					e = yaml.Unmarshal(raw, &marker)
					if e == nil {
						marker.Ownership = nil
						raw, e = yaml.Marshal(marker)
					}
					if e == nil {
						e = os.WriteFile(mp, raw, 0o644)
					}
				}
			case "origin":
				e = os.WriteFile(filepath.Join(home, "transactions", "project", "tx-"+origin, "plan.json"), []byte("{}\n"), 0o600)
			case "source":
				hex := strings.TrimPrefix(f.targetRefs.StatementCAS, "sha256:")
				e = os.WriteFile(filepath.Join(f.evidenceRoot, "sha256", hex[:2], hex[2:]), []byte("tampered retained source\n"), 0o600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = tx.Commit(ctx); e == nil {
				t.Fatal("protected drift published")
			}
			for p, raw := range before {
				now, e := os.ReadFile(p)
				if e != nil || !bytes.Equal(raw, now) {
					t.Fatalf("refusal advanced %s %v", p, e)
				}
			}
			t.Logf("actual Begin+tamper+Commit %s refused before state/registry/receipt advancement; changed evidence retained at %s", name, filepath.Dir(f.projectRoot))
		})
	}
}

type exclusionRecoveryInput struct {
	Selection        trustload.LaunchSelection
	Key, Home, Ready string
	Source, Target   []byte
	Apply            bool
}

func TestNativeAdoptionRecoveryChild(t *testing.T) {
	locator := os.Getenv("TPLAITER_ADOPTION_RECOVERY_INPUT")
	if locator == "" {
		t.Skip("actual signed recovery child only")
	}
	raw, e := os.ReadFile(locator)
	if e != nil {
		t.Fatal(e)
	}
	var in exclusionRecoveryInput
	if e = json.Unmarshal(raw, &in); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	r, e := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: in.Selection, ProjectKey: in.Key, Clock: bootstrap.ClockFunc(time.Now)})
	if e != nil {
		t.Fatal(e)
	}
	b, e := updateplan.New(r, in.Home, "dev")
	if e != nil {
		t.Fatal(e)
	}
	p, e := b.Prepare(ctx, updateplan.Input{SourceInput: in.Source, TargetInput: in.Target})
	if e != nil {
		t.Fatal(e)
	}
	tx, e := projecttransaction.BeginUpdate(ctx, p, p.Fingerprint())
	if e != nil {
		t.Fatal(e)
	}
	if in.Apply {
		if e = tx.Apply(ctx); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(in.Ready, []byte(tx.ID()), 0o600); e != nil {
		t.Fatal(e)
	}
	// Abrupt exit deliberately leaves retained native leases to process death.
	os.Exit(91)
}
func TestNativeAdoptionInstalledColdRecovery(t *testing.T) {
	base := os.Getenv("TPLAITER_ADOPTION_FIXTURE")
	if base == "" {
		t.Skip("retained installed CLI/MCP fixture locator required")
	}
	raw, e := os.ReadFile(filepath.Join(base, "launch-selection.json"))
	if e != nil {
		t.Fatal(e)
	}
	var selection trustload.LaunchSelection
	if e = json.Unmarshal(raw, &selection); e != nil {
		t.Fatal(e)
	}
	var install trustload.RuntimeInstall
	raw, e = os.ReadFile(selection.RuntimeConfig.Path)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &install); e != nil {
		t.Fatal(e)
	}
	var root string
	for _, pc := range install.ProjectContexts {
		if pc.Key == "project" {
			root = pc.RootPath
		}
	}
	if root == "" {
		t.Fatal("installed cold context missing")
	}
	// Original source locator is derived from the retained receipt's signed input
	// by the fixture publisher: the source selection is written by surface setup.
	source, e := os.ReadFile(filepath.Join(base, "source-input.json"))
	if e != nil {
		t.Fatal(e)
	}
	target, e := os.ReadFile(filepath.Join(base, "target-input.json"))
	if e != nil {
		t.Fatal(e)
	}
	rel := filepath.Join(root, "go.mod")
	before, e := os.Lstat(rel)
	if e != nil {
		t.Fatal(e)
	}
	user, e := os.ReadFile(rel)
	if e != nil {
		t.Fatal(e)
	}
	assertUser := func() {
		t.Helper()
		i, e := os.Lstat(rel)
		if e != nil || !os.SameFile(before, i) || before.Mode() != i.Mode() {
			t.Fatal("cold recovery changed excluded identity/mode", e)
		}
		now, e := os.ReadFile(rel)
		if e != nil || !bytes.Equal(now, user) {
			t.Fatal("cold recovery changed bytes", e)
		}
		if _, e = os.Lstat(filepath.Join(root, "added.txt")); !os.IsNotExist(e) {
			t.Fatal("cold recovery recreated exclusion", e)
		}
	}
	testbin, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	for _, tc := range []struct {
		name, verb     string
		source, target []byte
		apply          bool
	}{{"prepared-continue", "continue", target, source, false}, {"applied-abort", "abort", source, target, true}} {
		ready := filepath.Join(base, "cold-"+tc.name+".id")
		input := exclusionRecoveryInput{Selection: selection, Key: "project", Home: filepath.Join(base, "project-home", "tplaiter"), Ready: ready, Source: tc.source, Target: tc.target, Apply: tc.apply}
		locator := filepath.Join(base, "cold-"+tc.name+".json")
		if e = os.WriteFile(locator, t5FJSON(t, input), 0o600); e != nil {
			t.Fatal(e)
		}
		child := exec.CommandContext(ctx, testbin, "-test.run=^TestNativeAdoptionRecoveryChild$", "-test.v")
		child.Env = append(testProcessEnv(filepath.Join(base, "project-home")), "TPLAITER_ADOPTION_RECOVERY_INPUT="+locator)
		child.Dir = base
		out, e := child.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(e, &exit) || exit.ExitCode() != 91 {
			t.Fatalf("abrupt %s %v %s", tc.name, e, out)
		}
		id, e := os.ReadFile(ready)
		if e != nil {
			t.Fatal(e)
		}
		command := exec.CommandContext(ctx, filepath.Join(base, "tplaiter"), "update", tc.verb, string(id), "--project-context=project", "--dir="+root, "--json")
		command.Env = testProcessEnv(filepath.Join(base, "project-home"))
		command.Dir = base
		out, e = command.CombinedOutput()
		if e != nil {
			t.Fatalf("installed cold %s %v %s", tc.name, e, out)
		}
		env, e := resultdto.Decode(out)
		if e != nil || env.Status == resultdto.StatusFailed {
			t.Fatalf("cold envelope %v %s", e, out)
		}
		assertUser()
		t.Logf("actual abrupt %s -> installed update %s receipt=%s preserved excluded inode/mode/bytes/absence", tc.name, tc.verb, id)
	}
}

func TestNativeAdoptionOriginSurvivesActualNewGC(t *testing.T) {
	f, r, home, in := linkAdmissionFixture(t)
	ctx := context.Background()
	in.Action = "adopt"
	in.Choices = map[string]string{"go.mod": "user-owned"}
	if e := os.WriteFile(filepath.Join(f.projectRoot, "go.mod"), []byte("user origin bytes\n"), 0o644); e != nil {
		t.Fatal(e)
	}
	p, e := linkcmd.Prepare(ctx, r, home, in, "dev")
	if e != nil {
		t.Fatal(e)
	}
	tx, e := linktx.Begin(ctx, p, p.Fingerprint(), "dev")
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		tx.Release()
		t.Fatal(e)
	}
	id := tx.ID()
	tx.Release()
	raw, e := os.ReadFile(filepath.Join(f.projectRoot, ".tplaiter/project.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	var marker stateledger.ProjectV2
	if e = yaml.Unmarshal(raw, &marker); e != nil {
		t.Fatal(e)
	}
	policy, e := adoptionpolicy.Parse(marker.Ownership)
	if e != nil {
		t.Fatal(e)
	}
	before, e := adoption.Read(ctx, r, home, policy)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := newtransaction.PlanGC(home, time.Now().Add(90*24*time.Hour), false)
	if e != nil {
		t.Fatal(e)
	}
	for _, selected := range plan.IDs {
		if selected == id {
			t.Fatal("project origin selected by new GC")
		}
	}
	// Caller-supplied project IDs still cannot widen the production deletion scope.
	plan.IDs = append(plan.IDs, id)
	if e = newtransaction.ExecuteGC(home, plan); e != nil {
		t.Fatal(e)
	}
	after, e := adoption.Read(ctx, r, home, policy)
	if e != nil || after.ReceiptID() != before.ReceiptID() || after.PlanDigest() != before.PlanDigest() || after.ReceiptDigest() != before.ReceiptDigest() {
		t.Fatal("required receipt/CAS retention failed", e)
	}
	t.Log("actual newtransaction.PlanGC/ExecuteGC cannot collect the preserved committed project origin; fresh signed source reconstruction and CAS reads still succeed")
}

func TestNativeAdoptionInstalledGenRefusesPresentAndMissing(t *testing.T) {
	base := os.Getenv("TPLAITER_ADOPTION_FIXTURE")
	if base == "" {
		t.Skip("retained guarded installed fixture locator required")
	}
	raw, e := os.ReadFile(filepath.Join(base, "launch-selection.json"))
	if e != nil {
		t.Fatal(e)
	}
	var selection trustload.LaunchSelection
	if e = json.Unmarshal(raw, &selection); e != nil {
		t.Fatal(e)
	}
	var install trustload.RuntimeInstall
	raw, e = os.ReadFile(selection.RuntimeConfig.Path)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &install); e != nil {
		t.Fatal(e)
	}
	root := install.ProjectContexts[0].RootPath
	home := filepath.Join(base, "project-home", "tplaiter")
	snapshot := func() map[string]linkcmd.File {
		t.Helper()
		out := map[string]linkcmd.File{}
		e := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, name)
			if err != nil {
				return err
			}
			f, err := linkcmd.ObservePath(root, filepath.ToSlash(rel))
			if err != nil {
				return err
			}
			out[rel] = f
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	before := snapshot()
	assertZero := func() {
		t.Helper()
		if !reflect.DeepEqual(before, snapshot()) {
			t.Fatal("generation changed user files, metadata, modes or inodes")
		}
	}
	if _, e = os.Lstat(filepath.Join(root, "go.mod")); e != nil {
		t.Fatal("present exclusion absent", e)
	}
	if _, e = os.Lstat(filepath.Join(root, "added.txt")); !os.IsNotExist(e) {
		t.Fatal("missing exclusion appeared", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r, e := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: selection, ProjectKey: "project", Clock: bootstrap.ClockFunc(time.Now)})
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"present", "missing"} {
		plan, e := gen.PlanNative(ctx, r, home, []gen.NativeOperation{{Kind: kind, Name: "NoPromotion", Provided: map[string]string{"label": "proof"}}})
		if !errors.Is(e, gen.ErrNativeOwnership) || plan != nil {
			r.Close()
			t.Fatalf("common planner %s %v %#v", kind, e, plan)
		}
		assertZero()
		t.Logf("common PlanNative signed %s excluded target -> typed %s changes=0", kind, e)
	}
	r.Close()
	checkEnvelope := func(raw []byte, label string) {
		t.Helper()
		env, e := resultdto.Decode(raw)
		if e != nil {
			t.Fatalf("%s decode %v %s", label, e, raw)
		}
		d, _ := json.Marshal(env.Diagnostics)
		if len(env.Changes) != 0 || env.Summary.FilesChanged != 0 || env.Summary.BlocksChanged != 0 || env.Summary.Conflicts != 0 || (env.Status != resultdto.StatusFailed && env.Status != resultdto.StatusBlocked) || !bytes.Contains(d, []byte(gen.ErrNativeOwnership.Error())) {
			t.Fatalf("%s wrong refusal %s", label, raw)
		}
		assertZero()
		t.Logf("actual installed %s typed ownership refusal changes=0; full user/managed inode/mode/byte snapshot unchanged", label)
	}
	for _, kind := range []string{"present", "missing"} {
		child := exec.CommandContext(ctx, filepath.Join(base, "tplaiter"), "gen", kind, "NoPromotion", "--label=proof", "--no-build", "--project-context=project", "--dir="+root, "--json")
		child.Dir = base
		child.Env = testProcessEnv(filepath.Join(base, "project-home"))
		var stderr bytes.Buffer
		child.Stderr = &stderr
		out, e := child.Output()
		if e == nil {
			t.Fatal("installed CLI promoted exclusion", kind)
		}
		checkEnvelope(out, "CLI/"+kind)
	}
	server := exec.CommandContext(ctx, filepath.Join(base, "tplaiter"), "mcp-server")
	server.Dir = base
	server.Env = testProcessEnv(filepath.Join(base, "project-home"))
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
	defer func() { stdin.Close(); server.Wait() }()
	enc, dec := json.NewEncoder(stdin), json.NewDecoder(stdout)
	request := func(id int, method string, params any) map[string]any {
		t.Helper()
		if e = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); e != nil {
			t.Fatal(e)
		}
		var response map[string]any
		if e = dec.Decode(&response); e != nil {
			t.Fatalf("MCP %v %s", e, &stderr)
		}
		if response["error"] != nil {
			t.Fatal(response)
		}
		return response
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "exclusion-gen-proof", "version": "1"}})
	if e = enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); e != nil {
		t.Fatal(e)
	}
	for i, kind := range []string{"present", "missing"} {
		result := request(i+2, "tools/call", map[string]any{"name": "gen", "arguments": map[string]any{"dir": root, "kind": kind, "name": "NoPromotion", "params": map[string]string{"label": "proof"}, "noBuild": true}})["result"].(map[string]any)
		raw, e = json.Marshal(result["structuredContent"])
		if e != nil {
			t.Fatal(e)
		}
		checkEnvelope(raw, "MCP/"+kind)
	}
}
