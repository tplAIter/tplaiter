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

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/linkcmd"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	linktx "github.com/tplAIter/tplaiter/internal/projecttransaction/link"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestNativeLinkInstalledProcess(t *testing.T) {
	testNativeLinkInstalledProcess(t, []string{"journal", "stage-created", "prepared", "state-renamed", "registry-renamed", "committed"})
}

// Canonical integration proof for the repaired live guards and new sealed plan
// identity: cold early preparation and registry publication, without a full replay.
func TestNativeLinkInstalledAdmissionAndSurface(t *testing.T) {
	testNativeLinkInstalledProcess(t, []string{"journal", "registry-renamed"})
}
func testNativeLinkInstalledProcess(t *testing.T, boundaries []string) {
	testfixture.RequireTrustStore(t)
	f := nativeLinkCLIFixture(t, false)
	base := filepath.Dir(f.projectRoot)
	home := filepath.Join(base, "process-home")
	ledgerHome := filepath.Join(home, "tplaiter")
	if err := os.MkdirAll(ledgerHome, 0o700); err != nil {
		t.Fatal(err)
	}
	// Multiple finite installed roots exercise independent link/adopt/recovery contexts.
	raw, e := os.ReadFile(f.selection.RuntimeConfig.Path)
	if e != nil {
		t.Fatal(e)
	}
	var install trustload.RuntimeInstall
	if e = json.Unmarshal(raw, &install); e != nil {
		t.Fatal(e)
	}
	roots := map[string]string{}
	keys := []string{"clean", "modified", "mcp", "missing", "stale"}
	for _, boundary := range boundaries {
		keys = append(keys, "continue-"+boundary)
		if boundary != "committed" {
			keys = append(keys, "abort-"+boundary)
		}
	}
	for _, key := range keys {
		pc := install.ProjectContexts[0]
		pc.Key = key
		pc.ProjectID = "link-" + key
		pc.RootPath = filepath.Join(base, key)
		if e = os.Mkdir(pc.RootPath, 0o751); e != nil {
			t.Fatal(e)
		}
		install.ProjectContexts = append(install.ProjectContexts, pc)
		roots[key] = pc.RootPath
		if e = os.MkdirAll(filepath.Join(base, "home-"+key, "tplaiter"), 0o700); e != nil {
			t.Fatal(e)
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
	build.Dir = filepath.Join("..", "..")
	build.Env = testBuildEnv(home)
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, []byte, int) {
		t.Helper()
		child := exec.CommandContext(ctx, bin, args...)
		childHome := home
		for _, arg := range args {
			if strings.HasPrefix(arg, "--project-context=") {
				key := strings.TrimPrefix(arg, "--project-context=")
				if roots[key] != "" {
					childHome = filepath.Join(base, "home-"+key)
				}
			}
		}
		child.Env = testProcessEnv(childHome)
		child.Dir = base
		var out, stderr bytes.Buffer
		child.Stdout = &out
		child.Stderr = &stderr
		e := child.Run()
		code := 0
		if e != nil {
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatal(e)
			}
			code = exit.ExitCode()
		}
		t.Logf("installed %v exit=%d stdout=%s stderr=%s", args, code, out.Bytes(), stderr.Bytes())
		return out.Bytes(), stderr.Bytes(), code
	}
	if out, err, code := run("trust", "provision"); code != 0 {
		t.Fatalf("provision %s %s", out, err)
	}
	selection := filepath.Join(base, "source-input.json")
	if e = os.WriteFile(selection, t5FSelection(f.target, f.targetRefs), 0o600); e != nil {
		t.Fatal(e)
	}
	for _, root := range roots {
		for name, b := range map[string][]byte{"go.mod": []byte("module example.test/adopt\ngo 1.26\n"), "added.txt": []byte("new owned\n"), "extra.sh": []byte("#!/bin/sh\nprintf user\n")} {
			mode := os.FileMode(0o644)
			if name == "extra.sh" {
				mode = 0o751
			}
			if e = os.WriteFile(filepath.Join(root, name), b, mode); e != nil {
				t.Fatal(e)
			}
		}
	}
	userBefore := func(root string) map[string]linkObservedFile {
		t.Helper()
		out := map[string]linkObservedFile{}
		for _, name := range []string{".", "go.mod", "added.txt", "extra.sh"} {
			info, e := os.Lstat(filepath.Join(root, name))
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				t.Fatal(e)
			}
			var raw []byte
			if !info.IsDir() {
				raw, e = os.ReadFile(filepath.Join(root, name))
				if e != nil {
					t.Fatal(e)
				}
			}
			out[name] = linkObservedFile{info, raw}
		}
		return out
	}
	assertUsers := func(root string, before map[string]linkObservedFile) {
		t.Helper()
		after := userBefore(root)
		if len(before) != len(after) {
			t.Fatal("user namespace changed")
		}
		for name, b := range before {
			a, ok := after[name]
			if !ok || !os.SameFile(b.info, a.info) || b.info.Mode() != a.info.Mode() || !bytes.Equal(a.raw, b.raw) {
				t.Fatalf("user path mutated: %s", name)
			}
		}
	}
	invoke := func(action, key string, extra ...string) resultdto.Result {
		t.Helper()
		before := userBefore(roots[key])
		args := []string{action, f.target.Commit, "Adopt", "--project-context=" + key, "--dir=" + roots[key], "--source-input=" + selection, "--module=example.test/adopt", "--json"}
		args = append(args, extra...)
		out, stderr, code := run(args...)
		assertUsers(roots[key], before)
		env, e := resultdto.Decode(out)
		if e != nil {
			t.Fatalf("envelope %v %s %s", e, out, stderr)
		}
		if code != 0 {
			t.Fatalf("operation failed exit=%d %s %s", code, out, stderr)
		}
		return env
	}
	dry := invoke("link", "clean", "--dry-run")
	if dry.TransactionID != nil {
		t.Fatal("dry-run transaction")
	}
	if _, e = os.Lstat(filepath.Join(roots["clean"], ".tplaiter")); !os.IsNotExist(e) {
		t.Fatal("dry-run managed writes")
	}
	linked := invoke("link", "clean")
	if linked.TransactionID == nil || linked.Operation != resultdto.OperationProjectLink {
		t.Fatal(linked)
	}
	if out, stderr, code := run("verify", "--project-context=clean", "--dir="+roots["clean"], "--json"); code != 0 {
		t.Fatalf("verify %s %s", out, stderr)
	}
	if out, stderr, code := run("diff", "--project-context=clean", "--dir="+roots["clean"], "--exit-code", "--json"); code != 0 {
		t.Fatalf("signed clean diff %s %s", out, stderr)
	}
	if e = os.WriteFile(filepath.Join(roots["modified"], "go.mod"), []byte("module local.test/modified\ngo 1.26\n"), 0o644); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Join(roots["modified"], "go.mod"), 0o751); e != nil {
		t.Fatal(e)
	}
	before := userBefore(roots["modified"])
	invalidArgs := []string{"adopt", f.target.Commit, "Adopt", "--project-context=modified", "--source-input=" + selection, "--module=example.test/adopt", "--json"}
	if out, _, code := run(invalidArgs...); code == 0 {
		t.Fatalf("implicit ownership accepted %s", out)
	}
	assertUsers(roots["modified"], before)
	if out, _, code := run(append(invalidArgs, "--ownership=go.mod=user-owned")...); code != resultdto.ExitUnavailable.Int() {
		t.Fatalf("consumer-incompatible exclusion: %d %s", code, out)
	}
	adopted := invoke("adopt", "modified", "--ownership=go.mod=track")
	if adopted.Operation != resultdto.OperationProjectAdopt {
		t.Fatal(adopted)
	}
	if out, stderr, code := run("diff", "--project-context=modified", "--dir="+roots["modified"], "--exit-code", "--json"); code != 1 {
		t.Fatalf("signed modified diff %d %s %s", code, out, stderr)
	}
	if e = os.Remove(filepath.Join(roots["missing"], "added.txt")); e != nil {
		t.Fatal(e)
	}
	invoke("adopt", "missing", "--ownership=added.txt=track")
	if _, e = os.Lstat(filepath.Join(roots["missing"], "added.txt")); !os.IsNotExist(e) {
		t.Fatal("missing user file recreated")
	}
	if out, stderr, code := run("diff", "--project-context=missing", "--exit-code", "--json"); code != 1 {
		t.Fatalf("missing lineage diff %d %s %s", code, out, stderr)
	}
	// Fresh-process terminal retry and foreign root refusal.
	if out, stderr, code := run("link", "continue", *linked.TransactionID, "--project-context=clean", "--json"); code != 0 {
		t.Fatalf("cold retry %s %s", out, stderr)
	}
	if out, _, code := run("adopt", "continue", *linked.TransactionID, "--project-context=clean", "--json"); code == 0 {
		t.Fatalf("wrong operation accepted %s", out)
	}
	if out, _, code := run("link", "continue", *linked.TransactionID, "--project-context=modified", "--json"); code == 0 {
		t.Fatalf("foreign context accepted %s", out)
	}
	// A changed signed object is refused before publication, not trusted from caller JSON.
	object := filepath.Join(install.ObjectOrigins[0].RootPath, f.target.Commit)
	savedObject, e := os.ReadFile(object)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(object, []byte("tampered object"), 0o600); e != nil {
		t.Fatal(e)
	}
	if out, _, code := run("link", f.target.Commit, "Adopt", "--project-context=stale", "--source-input="+selection, "--module=example.test/adopt", "--json"); code == 0 {
		t.Fatalf("tampered source accepted %s", out)
	}
	if _, e = os.Lstat(filepath.Join(roots["stale"], ".tplaiter")); !os.IsNotExist(e) {
		t.Fatal("tamper published state")
	}
	if e = os.WriteFile(object, savedObject, 0o600); e != nil {
		t.Fatal(e)
	}

	// Abrupt exit in a real signed-runtime process, then recover via a fresh
	// installed CLI process. No mock runtime or trusted caller plan is involved.
	testBin, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, boundary := range boundaries {
		for _, verb := range []string{"continue", "abort"} {
			if boundary == "committed" && verb == "abort" {
				continue
			}
			key := verb + "-" + boundary
			root := roots[key]
			childHome := filepath.Join(base, "home-"+key)
			lh := filepath.Join(childHome, "tplaiter")
			before := userBefore(root)
			// Exchange publication must preserve an existing registry, including its
			// original inode on rollback, rather than treating every Home as empty.
			registryPath := filepath.Join(lh, "projects.yaml")
			var registryBefore []byte
			var registryInfo os.FileInfo
			if boundary == "registry-renamed" {
				registryBefore, e = state.MarshalProjects(state.Projects{Version: state.ProjectsVersion, Items: []state.ProjectRef{{ID: "unrelated", Path: filepath.Join(base, "unrelated-project")}}})
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(registryPath, registryBefore, 0o640); e != nil {
					t.Fatal(e)
				}
				registryInfo, e = os.Lstat(registryPath)
				if e != nil {
					t.Fatal(e)
				}
			}
			input := linkCrashInput{Selection: f.selection, Key: key, Home: lh, Root: root, Boundary: boundary, Input: linkcmd.Input{Action: "link", Ref: f.target.Commit, Name: "Adopt", Module: "example.test/adopt", Source: t5FSelection(f.target, f.targetRefs), Choices: map[string]string{}}}
			config := filepath.Join(base, "crash-"+key+".json")
			if e = os.WriteFile(config, t5FJSON(t, input), 0o600); e != nil {
				t.Fatal(e)
			}
			child := exec.CommandContext(ctx, testBin, "-test.run=^TestNativeLinkCrashChild$", "-test.v")
			child.Dir = base
			child.Env = append(testProcessEnv(childHome), "TPLAITER_LINK_CRASH_INPUT="+config)
			out, e := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 91 {
				t.Fatalf("boundary %s did not die: %v %s", key, e, out)
			}
			receipts, e := filepath.Glob(filepath.Join(lh, "transactions", "project", "tx-*", "state.json"))
			if e != nil || len(receipts) != 1 {
				t.Fatalf("receipt %s %+v %v", key, receipts, e)
			}
			id := strings.TrimPrefix(filepath.Base(filepath.Dir(receipts[0])), "tx-")
			assertUsers(root, before)
			if boundary == "prepared" && verb == "continue" {
				// Same bytes at a foreign inode do not become adoption ownership.
				stage := filepath.Join(base, "."+key+"-tplaiter-link-"+id)
				path := filepath.Join(stage, "baseline.json")
				saved, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				held := filepath.Join(base, "foreign-held-"+id)
				if e = os.Rename(path, held); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(path, saved, 0o644); e != nil {
					t.Fatal(e)
				}
				if out, _, code := run("link", verb, id, "--project-context="+key, "--json"); code == 0 {
					t.Fatalf("foreign matching inode accepted %s", out)
				}
				if got, e := os.ReadFile(path); e != nil || !bytes.Equal(got, saved) {
					t.Fatal("foreign bytes changed")
				}
				if e = os.Remove(path); e != nil {
					t.Fatal(e)
				}
				if e = os.Rename(held, path); e != nil {
					t.Fatal(e)
				}
				// Cold recovery reauthenticates source; retained journal bytes cannot authorize it.
				if e = os.WriteFile(object, []byte("changed source"), 0o600); e != nil {
					t.Fatal(e)
				}
				if out, _, code := run("link", verb, id, "--project-context="+key, "--json"); code == 0 {
					t.Fatalf("stale source recovery accepted %s", out)
				}
				if e = os.WriteFile(object, savedObject, 0o600); e != nil {
					t.Fatal(e)
				}
			}
			if boundary == "state-renamed" && verb == "continue" {
				receipt := receipts[0]
				saved, e := os.ReadFile(receipt)
				if e != nil {
					t.Fatal(e)
				}
				tampered := bytes.Replace(saved, []byte("publishing"), []byte("committed"), 1)
				if e = os.WriteFile(receipt, tampered, 0o600); e != nil {
					t.Fatal(e)
				}
				if out, _, code := run("link", verb, id, "--project-context="+key, "--json"); code == 0 {
					t.Fatalf("tampered receipt accepted %s", out)
				}
				if e = os.WriteFile(receipt, saved, 0o600); e != nil {
					t.Fatal(e)
				}
			}
			if out, stderr, code := run("link", verb, id, "--project-context="+key, "--json"); code != 0 {
				t.Fatalf("cold %s %d %s %s", key, code, out, stderr)
			}
			assertUsers(root, before)
			if verb == "abort" {
				if _, e = os.Lstat(filepath.Join(root, ".tplaiter")); !os.IsNotExist(e) {
					t.Fatal("aborted managed state remains")
				}
				if registryInfo == nil {
					if _, e = os.Lstat(registryPath); !os.IsNotExist(e) {
						t.Fatal("aborted registry beforeimage changed")
					}
				} else {
					raw, err := os.ReadFile(registryPath)
					info, statErr := os.Lstat(registryPath)
					if err != nil || statErr != nil || !bytes.Equal(raw, registryBefore) || !os.SameFile(info, registryInfo) || info.Mode() != registryInfo.Mode() {
						t.Fatal("existing registry bytes/mode/inode not restored")
					}
				}
			}
			if verb == "continue" {
				if registryInfo != nil {
					registered, err := state.LoadProjects(lh)
					info, statErr := os.Lstat(registryPath)
					if err != nil || statErr != nil || len(registered.Items) != 2 || registered.Items[0].ID != "unrelated" || info.Mode() != registryInfo.Mode() {
						t.Fatal("existing registry entry/mode not preserved")
					}
				}
				if out, stderr, code := run("verify", "--project-context="+key, "--json"); code != 0 {
					t.Fatalf("cold verify %s %s", out, stderr)
				}
			}
			t.Logf("signed abrupt boundary %s -> installed %s verified", boundary, verb)
		}
	}
	// Actual MCP server + installed CLI child. Existing 29 named descriptor objects stay identical.
	server := exec.CommandContext(ctx, bin, "mcp-server")
	server.Dir = base
	server.Env = testProcessEnv(filepath.Join(base, "home-mcp"))
	stdin, e := server.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdout, e := server.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var serr bytes.Buffer
	server.Stderr = &serr
	if e = server.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { stdin.Close(); server.Wait() }()
	enc, dec := json.NewEncoder(stdin), json.NewDecoder(stdout)
	request := func(id int, method string, params any) map[string]any {
		t.Helper()
		if e := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); e != nil {
			t.Fatal(e)
		}
		var response map[string]any
		if e := dec.Decode(&response); e != nil {
			t.Fatalf("MCP %v %s", e, serr.String())
		}
		if response["error"] != nil {
			t.Fatal(response)
		}
		return response
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "link-proof", "version": "1"}})
	if e = enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); e != nil {
		t.Fatal(e)
	}
	listed := request(2, "tools/list", map[string]any{})["result"].(map[string]any)["tools"].([]any)
	oldRaw, e := os.ReadFile("../../tests/testdata/mcp/tools.schema.golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var old []map[string]any
	if e = json.Unmarshal(oldRaw, &old); e != nil {
		t.Fatal(e)
	}
	actual := map[string]any{}
	for _, v := range listed {
		m := v.(map[string]any)
		actual[m["name"].(string)] = m
	}
	inherited := 0
	for _, entry := range old {
		if entry["name"] != "project_link" {
			inherited++
		}
	}
	if len(actual) != 35 || actual["project_link"] == nil || inherited != 34 {
		t.Fatalf("tool names %d canonical inherited %d", len(actual), inherited)
	}
	for _, v := range old {
		if !reflect.DeepEqual(actual[v["name"].(string)], v) {
			t.Fatalf("descriptor changed: %s", v["name"])
		}
	}
	t.Log("all 29 canonical MCP descriptor objects preserved, including run/gen/gen_batch; project_link is the only addition")
	mcpBefore := userBefore(roots["mcp"])
	result := request(3, "tools/call", map[string]any{"name": "project_link", "arguments": map[string]any{"action": "link", "dir": roots["mcp"], "projectContext": "mcp", "ref": f.target.Commit, "name": "Adopt", "module": "example.test/adopt", "sourceInput": selection}})["result"].(map[string]any)
	out, e := json.Marshal(result["structuredContent"])
	if e != nil {
		t.Fatal(e)
	}
	env, e := resultdto.Decode(out)
	if e != nil || env.Status != resultdto.StatusChanges || env.Operation != resultdto.OperationProjectLink {
		t.Fatalf("MCP %v %s", e, out)
	}
	assertUsers(roots["mcp"], mcpBefore)
	rejected := request(4, "tools/call", map[string]any{"name": "project_link", "arguments": map[string]any{"action": "continue", "dir": roots["mcp"], "execute": true}})["result"].(map[string]any)
	out, _ = json.Marshal(rejected["structuredContent"])
	env, e = resultdto.Decode(out)
	if e != nil || len(env.Diagnostics) != 1 || env.Diagnostics[0].Code != "MCP_INVALID_ARGUMENT" {
		t.Fatalf("closed MCP %s", out)
	}
	t.Logf("actual installed CLI/MCP state-only proof complete: %s", base)
}

type linkObservedFile struct {
	info os.FileInfo
	raw  []byte
}

// linkCrashInput carries public synthetic locators and intent only.
type linkCrashInput struct {
	Selection                 trustload.LaunchSelection
	Key, Home, Root, Boundary string
	Input                     linkcmd.Input
}
type linkKillContext struct {
	context.Context
	input linkCrashInput
}

func (c *linkKillContext) Err() error {
	receipts, _ := filepath.Glob(filepath.Join(c.input.Home, "transactions", "project", "tx-*", "state.json"))
	for _, path := range receipts {
		raw, e := os.ReadFile(path)
		if e != nil {
			continue
		}
		var outer struct {
			Payload json.RawMessage `json:"payload"`
		}
		if json.Unmarshal(raw, &outer) != nil {
			continue
		}
		var state struct {
			Phase string `json:"phase"`
		}
		if json.Unmarshal(outer.Payload, &state) != nil {
			continue
		}
		hit := false
		switch c.input.Boundary {
		case "journal":
			hit = state.Phase == "initializing"
		case "stage-created":
			hit = state.Phase == "preparing"
		case "prepared":
			hit = state.Phase == "prepared"
		case "state-renamed":
			_, e := os.Lstat(filepath.Join(c.input.Root, ".tplaiter"))
			hit = state.Phase == "publishing" && e == nil
		case "registry-renamed":
			raw, e := os.ReadFile(filepath.Join(c.input.Home, "projects.yaml"))
			hit = state.Phase == "state-published" && e == nil && bytes.Contains(raw, []byte("link-"+c.input.Key))
		case "committed":
			hit = state.Phase == "committed"
		}
		if hit {
			os.Exit(91)
		}
	}
	return c.Context.Err()
}
func TestNativeLinkCrashChild(t *testing.T) {
	path := os.Getenv("TPLAITER_LINK_CRASH_INPUT")
	if path == "" {
		t.Skip("signed crash subprocess only")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var in linkCrashInput
	if e = json.Unmarshal(raw, &in); e != nil {
		t.Fatal(e)
	}
	base := context.Background()
	r, e := trustload.OpenRuntime(base, trustload.RuntimeOptions{Selection: in.Selection, ProjectKey: in.Key, Clock: bootstrap.ClockFunc(time.Now)})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	p, e := linkcmd.Prepare(base, r, in.Home, in.Input, "dev")
	if e != nil {
		t.Fatal(e)
	}
	stopped := &linkKillContext{Context: base, input: in}
	tx, e := linktx.Begin(stopped, p, p.Fingerprint(), "dev")
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Release()
	if e = tx.Commit(stopped); e != nil {
		t.Fatal(e)
	}
	t.Fatal("crash boundary not observed")
}
