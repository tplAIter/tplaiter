//go:build darwin || linux

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type stockReadonlyFixture struct {
	binary, trust, home, stateHome, cwd, selection string
	targets                                        []string
	env                                            []string
	run                                            func(string, string, ...string) ([]byte, error)
}

// Uses the official make install and local operator enrollment from the
// accepted db3bf7d stock public-source fixture. Setup runs before observation.
func prepareStockReadonly(t *testing.T, create bool) *stockReadonlyFixture {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("Git is required")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if keep := os.Getenv("TPLAITER_STOCK_GO_ARTIFACTS"); keep != "" {
		if !filepath.IsAbs(keep) {
			t.Fatal("artifact root must be absolute")
		}
		if err := os.Mkdir(keep, 0o700); err != nil {
			t.Fatal(err)
		}
		base = keep
	}
	t.Logf("STOCK_GO artifacts=%s commit=%s", base, stockGoCommit)
	repo, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	build := filepath.Join(base, "build")
	stockCopySource(t, repo, build)
	home := filepath.Join(base, "home")
	stateHome := filepath.Join(home, "tplaiter")
	cwd := filepath.Join(base, "unrelated", "child")
	for _, dir := range []string{stateHome, cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stockWrite(t, filepath.Join(stateHome, "config.yaml"), []byte("version: 1\nrepos: []\ndefaults: {}\nupdates:\n  check: false\n"))
	// Only public tool/cache locators are inherited; HOME/XDG/state are isolated.
	cache := exec.Command("go", "env", "GOMODCACHE", "GOCACHE")
	cache.Dir = repo
	cacheOut, err := cache.Output()
	if err != nil {
		t.Fatal(err)
	}
	caches := strings.Fields(string(cacheOut))
	if len(caches) != 2 {
		t.Fatal("Go cache locators missing")
	}
	env := make([]string, 0, 22)
	env = append(env, "PATH="+os.Getenv("PATH"), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "config"), "XDG_DATA_HOME="+filepath.Join(home, "data"), "XDG_CACHE_HOME="+filepath.Join(home, "cache"), "XDG_STATE_HOME="+filepath.Join(home, "state"), "TPLAITER_HOME="+stateHome, "GOMODCACHE="+caches[0], "GOCACHE="+caches[1], "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=-buildvcs=false", "NO_COLOR=1", "SHELL=/bin/sh", "CGO_ENABLED=0", "GIT_CONFIG_NOSYSTEM=1")
	env = append(env, gitIdentityEnv()...)
	run := func(dir, name string, args ...string) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = dir
		cmd.Env = env
		raw, err := cmd.CombinedOutput()
		t.Logf("STOCK_GO %s %v exit=%v\n%s", filepath.Base(name), args, err, raw)
		return raw, err
	}
	must := func(dir, name string, args ...string) []byte {
		t.Helper()
		raw, err := run(dir, name, args...)
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, raw)
		}
		return raw
	}
	source := filepath.Join(base, "removable-source")
	stockPublicObjects(t, repo, source)
	if local := os.Getenv("TPLAITER_STOCK_GO_SOURCE"); local != "" {
		// Copy the public input, never mutate or remove its owner's tree.
		if err := os.RemoveAll(source); err != nil {
			t.Fatal(err)
		}
		copyTree(t, local, source)
	}
	targets := []string{filepath.Join(base, "custom-a"), filepath.Join(base, "custom-b")}
	contexts := make([]map[string]string, 0, 2)
	for i, key := range []string{"a", "b"} {
		contexts = append(contexts, map[string]string{"key": key, "projectID": "stock-go-" + key, "submitterPrincipalID": "principal:operator", "minimumProfile": "oss", "rootPath": targets[i]})
	}
	localInput := filepath.Join(base, "local-sources.json")
	contextInput := filepath.Join(base, "contexts.json")
	stockJSON(t, localInput, []map[string]string{{"repositoryPath": source, "origin": stockGoOrigin, "templatePath": ".", "commit": stockGoCommit}})
	stockJSON(t, contextInput, contexts)
	prefix := filepath.Join(base, "prefix")
	trust := filepath.Join(base, "trust")
	install := must(build, "make", "install", "PREFIX="+prefix, "TRUST_ROOT="+trust, "TRUST_LOCAL_SOURCES="+localInput, "TRUST_PROJECT_CONTEXTS="+contextInput, "VERSION=v1.0.0")
	stockWrite(t, filepath.Join(base, "install.log"), install)
	for _, target := range targets {
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("install materialized target before create: %s (%v)", target, err)
		}
	}
	binary := filepath.Join(prefix, "bin", "tplaiter")
	must(cwd, binary, "trust", "provision")
	must(cwd, binary, "trust", "provision")
	stockWrite(t, filepath.Join(base, "inspect.json"), must(cwd, binary, "trust", "inspect", "--json"))
	selections := stockRead(t, filepath.Join(trust, "config", "source-selections.json"))
	var selected []json.RawMessage
	if err := json.Unmarshal(selections, &selected); err != nil || len(selected) != 1 {
		t.Fatalf("selection: %v", err)
	}
	selection := filepath.Join(base, "selection.json")
	stockWrite(t, selection, selected[0])
	publication := stockRead(t, filepath.Join(trust, "config", "local-publisher.json"))
	if bytes.Contains(publication, []byte(source)) || !bytes.Contains(publication, []byte("local-operator-")) || !bytes.Contains(publication, []byte(stockGoCommit)) {
		t.Fatal("operator attestation provenance")
	}
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatal("input source survived removal")
	}
	if create {
		for i, key := range []string{"a", "b"} {
			raw := must(cwd, binary, "new", stockGoCommit, "Readonly "+key, "--dir", targets[i], "--project-context", key, "--source-input", selection, "--defaults", "--no-hooks", "--no-deps-check", "--no-env-setup", "--json")
			stockResult(t, raw, "stock-go-"+key, targets[i], "Readonly "+key)
		}
	}
	// After setup, any accidental CLI Git/probe/hook launch leaves an
	// observable sentinel in the caller-owned cwd; no shell is used by verify.
	probes := filepath.Join(base, "forbidden-probes")
	if err := os.Mkdir(probes, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"git", "curl", "go", "sh", "bash", "ansible"} {
		path := filepath.Join(probes, name)
		stockWrite(t, path, []byte("#!/bin/sh\nprintf invoked > '"+filepath.Join(cwd, "forbidden-exec")+"'\nexit 91\n"))
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for i, item := range env {
		if strings.HasPrefix(item, "PATH=") {
			env[i] = "PATH=" + probes
		}
	}
	return &stockReadonlyFixture{binary: binary, trust: trust, home: home, stateHome: stateHome, cwd: cwd, targets: targets, selection: selection, env: env, run: run}
}

func (f *stockReadonlyFixture) snapshots(t *testing.T) map[string]map[string]string {
	t.Helper()
	components := map[string][]string{"trust": {f.trust}, "home": {f.home}, "xdg": {filepath.Join(f.home, "config"), filepath.Join(f.home, "data"), filepath.Join(f.home, "cache"), filepath.Join(f.home, "state")}, "project": f.targets, "cwd": {f.cwd}}
	out := map[string]map[string]string{}
	for name, roots := range components {
		values := map[string]string{}
		for _, root := range roots {
			if _, err := os.Lstat(root); os.IsNotExist(err) {
				values[root] = "absent"
				continue
			}
			for path, value := range stockSnapshot(t, root) {
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				values[path] = value + ":" + info.ModTime().UTC().Format(time.RFC3339Nano)
			}
		}
		out[name] = values
	}
	return out
}

func (f *stockReadonlyFixture) unchanged(t *testing.T, before map[string]map[string]string) {
	t.Helper()
	after := f.snapshots(t)
	for name, want := range before {
		if !reflect.DeepEqual(want, after[name]) {
			t.Fatalf("readonly operation changed %s", name)
		}
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("READONLY_UNCHANGED component=%s before=after sha256=%x", name, sha256.Sum256(raw))
	}
}

func readonlyStockEnvelope(t *testing.T, raw []byte, op, status, code, id, root string) map[string]any {
	t.Helper()
	raw = bytes.SplitN(bytes.TrimSpace(raw), []byte("\n"), 2)[0]
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode: %v %s", err, raw)
	}
	for _, key := range envelopeRequiredKeys {
		if _, ok := env[key]; !ok {
			t.Fatalf("missing %s", key)
		}
	}
	kinds := map[string]string{"project.verify": "ProjectVerify", "project.check": "ProjectCheck", "deps.verify": "DepsVerify"}
	if env["apiVersion"] != "tplaiter.dev/result/v1" || env["kind"] != kinds[op] || env["operation"] != op || env["status"] != status || env["transactionId"] != nil {
		t.Fatalf("typed result mismatch: %s", raw)
	}
	for _, key := range []string{"changes", "artifacts"} {
		items, ok := env[key].([]any)
		if !ok || len(items) != 0 {
			t.Fatalf("invalid %s", key)
		}
	}
	diagnostics, ok := env["diagnostics"].([]any)
	if !ok {
		t.Fatal("null diagnostics")
	}
	if code != "" {
		codes := make([]string, 0, len(diagnostics))
		for _, entry := range diagnostics {
			d, ok := entry.(map[string]any)
			if !ok {
				t.Fatal("invalid diagnostic")
			}
			value, ok := d["code"].(string)
			if !ok {
				t.Fatal("missing diagnostic code")
			}
			codes = append(codes, value)
		}
		sort.Strings(codes)
		if strings.Join(codes, ",") != code || env["project"] != nil || env["data"] != nil {
			t.Fatalf("exact refusal mismatch: %s", raw)
		}
	} else {
		p, ok := env["project"].(map[string]any)
		if !ok || p["id"] != id || p["root"] != root || len(diagnostics) != 0 {
			t.Fatalf("scope mismatch: %s", raw)
		}
		data, ok := env["data"].(map[string]any)
		if !ok || data["offline"] != true {
			t.Fatalf("missing offline data: %s", raw)
		}
	}
	return env
}

// Routing and missing-root refusals do not credit backend positive acceptance.
func TestStockReadonlyInstalledRoutingRefusals(t *testing.T) {
	f := prepareStockReadonly(t, false)
	c := startMCP(t, f.env, f.binary, "mcp-server")
	c.initialize()
	for _, tc := range []struct {
		tool, op string
		argv     []string
	}{
		{"project_verify", "project.verify", []string{"verify"}},
		{"project_check", "project.check", []string{"check"}},
		{"deps_verify", "deps.verify", []string{"deps", "verify"}},
	} {
		for _, negative := range []struct {
			key, target, flag, code string
			exit                    int
		}{
			{"unknown", "", "", "TRUST_PROVENANCE_UNAVAILABLE", 8},
			{"a", f.targets[1], "", "TRUST_PROJECT_CONTEXT_MISMATCH", 5},
			{"a", "", "--offline=false", "TPL-E-ONLINE-UNSUPPORTED-001", 8},
			{"a", "", "", "TPL-E-ROOT-MISSING", 8},
		} {
			before := f.snapshots(t)
			args := append(append([]string(nil), tc.argv...), "--project-context", negative.key, "--json")
			if negative.target != "" {
				args = append(args, "--dir", negative.target)
			}
			if negative.flag != "" {
				args = append(args, negative.flag)
			}
			raw, err := f.run(f.cwd, f.binary, args...)
			var e *exec.ExitError
			if !errors.As(err, &e) || e.ExitCode() != negative.exit {
				t.Fatalf("%s: %v want exit %d: %s", tc.op, err, negative.exit, raw)
			}
			readonlyStockEnvelope(t, raw, tc.op, "blocked", negative.code, "", "")
			f.unchanged(t, before)
			a := map[string]any{"dir": f.cwd, "projectContext": negative.key}
			if negative.target != "" {
				a["targetDir"] = negative.target
			}
			if negative.flag != "" {
				a["offline"] = false
			}
			before = f.snapshots(t)
			res := c.callTool(tc.tool, a)
			if !res.IsError {
				t.Fatal("MCP accepted refusal")
			}
			requireEnvelope(t, tc.tool, res)
			raw, err = json.Marshal(res.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			readonlyStockEnvelope(t, raw, tc.op, "blocked", negative.code, "", "")
			f.unchanged(t, before)
		}
	}
	// A missing authenticated CAS root is refused during runtime composition.
	evidence := filepath.Join(f.trust, "evidence")
	parked := filepath.Join(f.trust, "evidence-unavailable")
	if err := os.Rename(evidence, parked); err != nil {
		t.Fatal(err)
	}
	before := f.snapshots(t)
	for _, argv := range [][]string{{"verify"}, {"check"}, {"deps", "verify"}} {
		args := append(append([]string(nil), argv...), "--project-context", "a", "--offline", "--json")
		raw, err := f.run(f.cwd, f.binary, args...)
		var e *exec.ExitError
		if !errors.As(err, &e) || e.ExitCode() != 8 {
			t.Fatalf("missing CAS: %v %s", err, raw)
		}
		op := "project." + argv[0]
		if len(argv) == 2 {
			op = "deps.verify"
		}
		readonlyStockEnvelope(t, raw, op, "blocked", "TRUST_PROVENANCE_UNAVAILABLE", "", "")
		f.unchanged(t, before)
	}
	if err := os.Rename(parked, evidence); err != nil {
		t.Fatal(err)
	}
}

// Execute only after primary accepts and binds the backend owner freeze. No
// skip switch or fake authority can turn an unavailable backend into success.
func TestStockReadonlyInstalledAcceptedBackend(t *testing.T) {
	f := prepareStockReadonly(t, true)
	c := startMCP(t, f.env, f.binary, "mcp-server")
	c.initialize()
	for _, tc := range []struct {
		tool, op string
		argv     []string
	}{
		{"project_verify", "project.verify", []string{"verify"}},
		{"project_check", "project.check", []string{"check"}},
		{"deps_verify", "deps.verify", []string{"deps", "verify"}},
	} {
		for i, key := range []string{"a", "b"} {
			before := f.snapshots(t)
			args := append(append([]string(nil), tc.argv...), "--project-context", key, "--offline", "--json")
			raw, err := f.run(f.cwd, f.binary, args...)
			if err != nil {
				t.Fatalf("%s: %v %s", tc.op, err, raw)
			}
			env := readonlyStockEnvelope(t, raw, tc.op, "ok", "", "stock-go-"+key, f.targets[i])
			f.unchanged(t, before)
			if tc.op == "project.verify" {
				data := env["data"].(map[string]any)
				if data["dependencyCount"] != float64(0) || data["dependencyState"] != "not-applicable" {
					t.Fatal("explicit empty dependencies unverified")
				}
			}
			before = f.snapshots(t)
			res := c.callTool(tc.tool, map[string]any{"dir": f.cwd, "targetDir": f.targets[i], "projectContext": key, "offline": true})
			if res.IsError {
				t.Fatalf("%s: %+v", tc.tool, res)
			}
			raw, err = json.Marshal(res.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			readonlyStockEnvelope(t, raw, tc.op, "ok", "", "stock-go-"+key, f.targets[i])
			t.Logf("READONLY_RECEIPT transport=MCP operation=%s context=%s envelope=%s", tc.op, key, raw)
			f.unchanged(t, before)
		}
	}
	// Managed output drift is a finding (exit 1), not success or a trust
	// failure; state ledgers remain sealed while an ordinary generated file moves.
	managed := filepath.Join(f.targets[0], "go.mod")
	originalManaged := stockRead(t, managed)
	info, err := os.Stat(managed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, append(append([]byte(nil), originalManaged...), []byte("\n// local managed drift\n")...), info.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	driftBefore := f.snapshots(t)
	driftRaw, driftErr := f.run(f.cwd, f.binary, "check", "--project-context", "a", "--offline", "--json")
	var driftExit *exec.ExitError
	if !errors.As(driftErr, &driftExit) || driftExit.ExitCode() != 1 {
		t.Fatalf("check drift: %v %s", driftErr, driftRaw)
	}
	driftEnv := readonlyStockEnvelope(t, driftRaw, "project.check", "changes", "", "stock-go-a", f.targets[0])
	if driftEnv["data"].(map[string]any)["managed"].(map[string]any)["state"] != "drift" {
		t.Fatal("managed drift projection missing")
	}
	f.unchanged(t, driftBefore)
	driftTool := c.callTool("project_check", map[string]any{"dir": f.cwd, "projectContext": "a", "offline": true})
	if !driftTool.IsError {
		t.Fatal("MCP check lost finding exit")
	}
	driftRaw, err = json.Marshal(driftTool.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	readonlyStockEnvelope(t, driftRaw, "project.check", "changes", "", "stock-go-a", f.targets[0])
	f.unchanged(t, driftBefore)
	if err := os.WriteFile(managed, originalManaged, info.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	stockReadonlyInstalledCancel(t, f, c)
	marker := filepath.Join(f.targets[0], ".tplaiter", "project.yaml")
	original := stockRead(t, marker)
	if err := os.WriteFile(marker, stockRead(t, filepath.Join(f.targets[1], ".tplaiter", "project.yaml")), 0o600); err != nil {
		t.Fatal(err)
	}
	before := f.snapshots(t)
	raw, err := f.run(f.cwd, f.binary, "verify", "--project-context", "a", "--offline", "--json")
	var e *exec.ExitError
	if !errors.As(err, &e) || e.ExitCode() != 5 {
		t.Fatalf("replay: %v %s", err, raw)
	}
	readonlyStockEnvelope(t, raw, "project.verify", "blocked", "TPL-E-TRUST-001,TRUST_RUNTIME_INVALID", "", "")
	f.unchanged(t, before)
	replay := c.callTool("project_verify", map[string]any{"dir": f.cwd, "projectContext": "a", "offline": true})
	if !replay.IsError {
		t.Fatal("MCP accepted replayed marker")
	}
	replayRaw, err := json.Marshal(replay.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	readonlyStockEnvelope(t, replayRaw, "project.verify", "blocked", "TPL-E-TRUST-001,TRUST_RUNTIME_INVALID", "", "")
	t.Logf("READONLY_RECEIPT transport=MCP replay envelope=%s", replayRaw)
	f.unchanged(t, before)
	if err := os.WriteFile(marker, original, 0o600); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(f.targets[0], ".tplaiter", "root-template.lock.json")
	original = stockRead(t, lock)
	tampered := bytes.Replace(original, []byte(stockGoCommit), []byte(strings.Repeat("f", 40)), 1)
	if bytes.Equal(tampered, original) {
		t.Fatal("tamper probe inactive")
	}
	if err := os.WriteFile(lock, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	before = f.snapshots(t)
	raw, err = f.run(f.cwd, f.binary, "deps", "verify", "--project-context", "a", "--offline", "--json")
	if !errors.As(err, &e) || e.ExitCode() != 7 {
		t.Fatalf("tamper: %v %s", err, raw)
	}
	readonlyStockEnvelope(t, raw, "deps.verify", "blocked", "TPL-E-DIGEST-001", "", "")
	f.unchanged(t, before)
	tamper := c.callTool("deps_verify", map[string]any{"dir": f.cwd, "projectContext": "a", "offline": true})
	if !tamper.IsError {
		t.Fatal("MCP accepted tampered dependency evidence")
	}
	tamperRaw, err := json.Marshal(tamper.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	readonlyStockEnvelope(t, tamperRaw, "deps.verify", "blocked", "TPL-E-DIGEST-001", "", "")
	t.Logf("READONLY_RECEIPT transport=MCP tamper envelope=%s", tamperRaw)
	f.unchanged(t, before)
	if err := os.WriteFile(lock, original, 0o600); err != nil {
		t.Fatal(err)
	}
	stockReadonlyLifecycleCASFailures(t, f, c, original)
}

// Cancel a real installed verification child while it inventories rebuildable
// graph-cache files. These public bytes carry no authority or success shortcut.
func stockReadonlyInstalledCancel(t *testing.T, f *stockReadonlyFixture, c *mcpClient) {
	t.Helper()
	graph := filepath.Join(f.targets[0], ".tplaiter", "graph-cache", "cancellation-probe")
	if err := os.MkdirAll(graph, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4096; i++ {
		stockWrite(t, filepath.Join(graph, strconv.Itoa(i)), []byte(strings.Repeat("public graph observation\n", 64)))
	}
	before := f.snapshots(t)
	id, ch := c.start("tools/call", map[string]any{"name": "project_verify", "arguments": map[string]any{"dir": f.cwd, "projectContext": "a", "offline": true}})
	deadline := time.Now().Add(10 * time.Second)
	children := []int{}
	for len(children) == 0 && time.Now().Before(deadline) {
		select {
		case <-ch:
			t.Fatal("verification completed before cancellation probe observed a child")
		default:
		}
		children = stockReadonlyChildren(t, c.cmd.Process.Pid)
		if len(children) == 0 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	if len(children) == 0 {
		t.Fatal("installed verification child was not observed")
	}
	c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id, "reason": "installed readonly cancellation proof"}})
	select {
	case msg := <-ch:
		if msg.Error != nil {
			t.Fatalf("cancellation protocol error: %+v", msg.Error)
		}
		var res toolResult
		if err := json.Unmarshal(msg.Result, &res); err != nil {
			t.Fatal(err)
		}
		op, status, codes := requireEnvelope(t, "project_verify", res)
		if !res.IsError || op != "project.verify" || status != "failed" || len(codes) != 1 || codes[0] != "MCP_CANCELLED" {
			t.Fatalf("cancellation: %+v", res)
		}
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("READONLY_RECEIPT transport=MCP cancellation envelope=%s", raw)
	case <-time.After(15 * time.Second):
		t.Fatal("installed MCP cancelled request did not return typed receipt")
	}
	for _, pid := range children {
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("cancelled verification child %d remains: %v", pid, err)
		}
	}
	if remaining := stockReadonlyChildren(t, c.cmd.Process.Pid); len(remaining) != 0 {
		t.Fatalf("cancelled child group remains: %v", remaining)
	}
	f.unchanged(t, before)
	// The same installed transport must continue serving actual verification.
	res := c.callTool("deps_verify", map[string]any{"dir": f.cwd, "projectContext": "a", "offline": true})
	if res.IsError {
		t.Fatal("installed server did not recover after cancellation")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	readonlyStockEnvelope(t, raw, "deps.verify", "ok", "", "stock-go-a", f.targets[0])
	f.unchanged(t, before)
	if err := os.RemoveAll(graph); err != nil {
		t.Fatal(err)
	}
}

func stockReadonlyChildren(t *testing.T, parent int) []int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "/bin/ps", "-A", "-o", "pid=,ppid=").Output()
	if err != nil {
		t.Fatalf("observe test child PIDs: %v", err)
	}
	children := []int{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil || ppid != parent {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatal(err)
		}
		children = append(children, pid)
	}
	return children
}

// Lifecycle objects belong to the authenticated fixed CAS, independent of
// bootstrap trust-store rows. Missing bytes cannot trigger refresh or fallback.
func stockReadonlyLifecycleCASFailures(t *testing.T, f *stockReadonlyFixture, c *mcpClient, lock []byte) {
	t.Helper()
	var root struct {
		Root struct {
			StatementCAS string `json:"statementCAS"`
		} `json:"root"`
	}
	if err := json.Unmarshal(lock, &root); err != nil {
		t.Fatal(err)
	}
	digest := strings.TrimPrefix(root.Root.StatementCAS, "sha256:")
	if len(digest) != 64 {
		t.Fatal("invalid source evidence locator in signed fixture")
	}
	path := filepath.Join(f.trust, "evidence", "sha256", digest[:2], digest[2:])
	original := stockRead(t, path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, code string
		exit       int
	}{
		{"missing", "TPL-E-OFFLINE-MISS-001", 8},
		{"corrupt", "TPL-E-TRUST-001", 5},
	} {
		if tc.name == "missing" {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.WriteFile(path, []byte("corrupted public lifecycle evidence"), info.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
		}
		before := f.snapshots(t)
		for _, op := range []struct {
			tool, operation string
			argv            []string
		}{
			{"project_verify", "project.verify", []string{"verify"}},
			{"project_check", "project.check", []string{"check"}},
			{"deps_verify", "deps.verify", []string{"deps", "verify"}},
		} {
			args := append(append([]string(nil), op.argv...), "--project-context", "a", "--offline", "--json")
			raw, err := f.run(f.cwd, f.binary, args...)
			var e *exec.ExitError
			if !errors.As(err, &e) || e.ExitCode() != tc.exit {
				t.Fatalf("%s lifecycle CAS %s: %v %s", op.operation, tc.name, err, raw)
			}
			readonlyStockEnvelope(t, raw, op.operation, "blocked", tc.code, "", "")
			f.unchanged(t, before)
			res := c.callTool(op.tool, map[string]any{"dir": f.cwd, "projectContext": "a", "offline": true})
			if !res.IsError {
				t.Fatalf("MCP accepted %s lifecycle CAS", tc.name)
			}
			raw, err = json.Marshal(res.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			readonlyStockEnvelope(t, raw, op.operation, "blocked", tc.code, "", "")
			t.Logf("READONLY_RECEIPT transport=MCP lifecycleCAS=%s operation=%s envelope=%s", tc.name, op.operation, raw)
			f.unchanged(t, before)
		}
		if err := os.WriteFile(path, original, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
}
