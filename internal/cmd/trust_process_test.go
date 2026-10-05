package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// TestInstalledRegistrationRealCLIAndMCP uses the signed disk fixture through
// a freshly built main binary. No command authority is injected in-process.
func TestInstalledRegistrationRealCLIAndMCP(t *testing.T) {
	testfixture.RequireTrustStore(t)
	_, anchor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, publisher, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := t5FTrustFixtureWith(t, t5FFixtureOptions{Anchor: anchor, Publisher: publisher, Now: time.Now().UTC()})
	root, err := os.MkdirTemp(testfixture.PrivateTempBase(), "tplaiter-t7-process-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	registrationPath := filepath.Join(root, "registration.json")
	registration := ossinstall.Registration{
		APIVersion: "tplaiter.dev/installed-launch-registration/v1",
		Profile:    f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig,
		OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID,
		ProjectKey: "project",
	}
	raw, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registrationPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "synthetic-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	shadow := filepath.Join(root, "shadow-bin")
	if err := os.Mkdir(shadow, 0o700); err != nil {
		t.Fatal(err)
	}
	spy := filepath.Join(root, "unexpected-spawn")
	for _, name := range []string{"tplaiter", "git", "curl", "ssh"} {
		canary := []byte("#!/bin/sh\n/usr/bin/touch " + spy + "\nexit 99\n")
		if err := os.WriteFile(filepath.Join(shadow, name), canary, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{filepath.Join(home, ".tplaiter"), filepath.Join(home, "xdg-config", "tplaiter")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "trust-profile.json"), []byte(`{"profile":"development","authority":"hostile-home"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := sha256.Sum256(raw)
	if got, err := readFixedTrustDocument(context.Background(), registrationPath); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("registration read: %v bytes=%v", err, bytes.Equal(got, raw))
	}
	bin := filepath.Join(root, "tplaiter")
	ldflags := "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath=" + registrationPath +
		" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:" + hex.EncodeToString(h[:])
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", ldflags, "-o", bin, ".")
	build.Dir = filepath.Join("..", "..")
	build.Env = testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	binaryRaw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	binaryDigest := sha256.Sum256(binaryRaw)
	t.Logf("T7_PROOF registration_sha256=%x runtime_digest=%s binary_sha256=%x", h, f.selection.RuntimeConfig.SHA256, binaryDigest)
	unpinned := filepath.Join(root, "tplaiter-unpinned")
	unpinnedBuild := exec.Command(testfixture.GoBinary(t), "build", "-o", unpinned, ".")
	unpinnedBuild.Dir, unpinnedBuild.Env = filepath.Join("..", ".."), testBuildEnv(home)
	if out, err := unpinnedBuild.CombinedOutput(); err != nil {
		t.Fatalf("build stock binary: %v\n%s", err, out)
	}
	unpinnedRaw, err := os.ReadFile(unpinned)
	if err != nil {
		t.Fatal(err)
	}
	unpinnedDigest := sha256.Sum256(unpinnedRaw)
	t.Logf("T7_PROOF unpinned_binary_sha256=%x", unpinnedDigest)

	env := append(
		testProcessEnv(home),
		"PATH="+shadow+":/usr/bin:/bin", "TPLAITER_PROFILE=development",
		"TPLAITER_REGISTRATION_PATH="+filepath.Join(home, ".tplaiter", "trust-profile.json"),
	)
	unpinnedBaseline := snapshotOwned(t, filepath.Dir(f.projectRoot), root)
	unpinnedInspect := exec.Command(unpinned, "trust", "inspect", "--json")
	unpinnedInspect.Env, unpinnedInspect.Dir = env, root
	if out, err := unpinnedInspect.CombinedOutput(); err == nil || string(out) != "error: trustload: TRUST_ANCHOR_MISSING\n" {
		t.Fatalf("unpinned stock main accepted trust command: exit=%v output=%q", err, out)
	}
	if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(unpinnedBaseline, after) {
		t.Fatalf("unpinned stock main changed fixture: %v", changedSnapshotKeys(unpinnedBaseline, after))
	}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(context.Background(), bin, args...)
		cmd.Env, cmd.Dir = env, filepath.Dir(bin)
		return cmd.CombinedOutput()
	}
	// A linked registration does not authorize an unprovisioned runtime,
	// even when the caller supplies genuine signed source evidence.
	creationInput := filepath.Join(root, "creation-source-selection.json")
	sourceRaw := t5FSelection(f.source, f.sourceRefs)
	if err := os.WriteFile(creationInput, sourceRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	unprovisionedBaseline := snapshotOwned(t, filepath.Dir(f.projectRoot), root)
	if out, err := run("new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", creationInput, "--defaults", "--no-hooks"); err == nil || !bytes.Contains(out, []byte("TRUST_ANCHOR_MISSING")) || bytes.Contains(out, []byte(f.projectRoot)) {
		t.Fatalf("unprovisioned live new accepted or unsafe: exit=%v output=%q", err, out)
	}
	if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(unprovisionedBaseline, after) {
		t.Fatalf("unprovisioned live new changed fixture: %v", changedSnapshotKeys(unprovisionedBaseline, after))
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision: %v\n%s", err, out)
	}
	out, err := run("trust", "inspect", "--json")
	if err != nil {
		t.Fatalf("inspect: %v\n%s", err, out)
	}
	var binding map[string]any
	if json.Unmarshal(out, &binding) != nil || binding["id"] != "oss" || binding["evidenceClass"] != "simulated" {
		t.Fatalf("unexpected binding: %s", out)
	}
	directInspectDigest := sha256.Sum256(out)
	t.Logf("T7_PROOF direct_inspect_sha256=%x", directInspectDigest)
	// Materialize the bounded action-free fixture through the installed CLI,
	// rather than fabricating project lock files for the later previews.
	created, err := run("new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", creationInput, "--defaults", "--no-hooks", "--json")
	if err != nil {
		t.Fatalf("signed live new: %v %s", err, created)
	}
	var creationResult struct {
		Status  string                    `json:"status"`
		Project struct{ ID, Root string } `json:"project"`
		Data    struct {
			DryRun bool `json:"dryRun"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created, &creationResult); err != nil || creationResult.Status != "ok" || creationResult.Data.DryRun || creationResult.Project.ID != "project-t5f" || creationResult.Project.Root != f.projectRoot {
		t.Fatalf("signed live new result: %v %s", err, created)
	}
	materialized, err := os.ReadFile(filepath.Join(f.projectRoot, "hello.txt"))
	if err != nil || string(materialized) != "hello source\n" {
		t.Fatalf("signed live new output: %q %v", materialized, err)
	}
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	if err != nil {
		t.Fatalf("fixture runtime: %v", err)
	}
	_, verifyErr := stateledger.VerifyStable(context.Background(), f.projectRoot, runtime.TrustRuntime(), stateledger.StableVerifyOptions{})
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if verifyErr != nil {
		t.Fatalf("signed live new ledger: %v", verifyErr)
	}
	projects, err := state.LoadProjects(filepath.Join(home, "tplaiter"))
	if err != nil || len(projects.Items) != 1 || projects.Items[0].ID != creationResult.Project.ID || projects.Items[0].Path != f.projectRoot {
		t.Fatalf("signed live new registry: %+v %v", projects, err)
	}
	rootLock, err := os.ReadFile(filepath.Join(f.projectRoot, ".tplaiter", "root-template.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	depsLock, err := os.ReadFile(filepath.Join(f.projectRoot, ".tplaiter", "template.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	creationDigest := sha256.Sum256(created)
	t.Logf("T7_PROOF signed_live_new_sha256=%x", creationDigest)

	sourceInput := filepath.Join(f.projectRoot, "source-selection.json")
	targetInput := filepath.Join(f.projectRoot, "target-selection.json")
	if err := os.WriteFile(sourceInput, sourceRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetInput, t5FSelection(f.target, f.targetRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceInputDigest := sha256.Sum256(sourceRaw)
	targetInputRaw := t5FSelection(f.target, f.targetRefs)
	targetInputDigest := sha256.Sum256(targetInputRaw)
	rootLockDigest := sha256.Sum256(rootLock)
	depsLockDigest := sha256.Sum256(depsLock)
	bundleDigest := sha256.Sum256(f.bundleRaw)
	evidenceSnapshot, err := json.Marshal(snapshotTree(t, f.evidenceRoot))
	if err != nil {
		t.Fatal(err)
	}
	evidenceDigest := sha256.Sum256(evidenceSnapshot)
	t.Logf("T7_PROOF fixture_source_sha256=%x fixture_target_sha256=%x fixture_root_lock_sha256=%x fixture_dependency_lock_sha256=%x fixture_bundle_sha256=%x fixture_evidence_tree_sha256=%x", sourceInputDigest, targetInputDigest, rootLockDigest, depsLockDigest, bundleDigest, evidenceDigest)
	baseline := snapshotOwned(t, filepath.Dir(f.projectRoot), root)
	baselineRaw, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	baselineDigest := sha256.Sum256(baselineRaw)
	t.Logf("T7_PROOF owned_baseline_sha256=%x", baselineDigest)
	for index, args := range [][]string{{"new", f.source.Commit, "project", "--dry-run", "--source-input", sourceInput}, {"update", "--dry-run", "--source-input", targetInput, "--to", f.target.Commit}} {
		got, e := run(args...)
		validPreview := e == nil && string(got) == "dry-run prepared\n"
		if index == 1 {
			validPreview = e == nil && bytes.Contains(got, []byte("TPL-I-NATIVE-UPDATE-REGISTRY project registry transition")) && bytes.Contains(got, []byte(" (update.plan)\n"))
		}
		if !validPreview {
			t.Fatalf("direct %v: %v %q", args, e, got)
		}
		previewDigest := sha256.Sum256(got)
		t.Logf("T7_PROOF direct_preview_%d_sha256=%x", index, previewDigest)
	}
	if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(baseline, after) {
		t.Fatalf("direct preview changed fixture: %v", changedSnapshotKeys(baseline, after))
	}
	// Exercise the actual stdio transport and its independently reloading child.
	mcp := exec.CommandContext(context.Background(), bin, "mcp-server")
	mcp.Env, mcp.Dir = env, filepath.Dir(bin)
	in, err := mcp.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := mcp.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	mcp.Stderr = &stderr
	if err := mcp.Start(); err != nil {
		t.Fatalf("mcp start: %v", err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = mcp.Wait() })
	write := func(message any) {
		encoded, e := json.Marshal(message)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = in.Write(append(encoded, '\n')); e != nil {
			t.Fatalf("mcp write: %v", e)
		}
	}
	lines := make(chan []byte, 8)
	readErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 2<<20)
		for scanner.Scan() {
			lines <- append([]byte(nil), scanner.Bytes()...)
		}
		readErr <- scanner.Err()
	}()
	next := func() map[string]any {
		select {
		case line := <-lines:
			var response map[string]any
			if e := json.Unmarshal(line, &response); e != nil {
				t.Fatalf("mcp response %q: %v", line, e)
			}
			return response
		case e := <-readErr:
			t.Fatalf("mcp closed early: %v stderr=%s", e, stderr.String())
		case <-time.After(30 * time.Second):
			t.Fatalf("mcp response timeout stderr=%s", stderr.String())
		}
		return nil
	}
	write(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t7", "version": "1"}}})
	if response := next(); response["id"] != float64(1) || response["error"] != nil {
		t.Fatalf("initialize response: %#v", response)
	}
	write(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}})
	write(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}})
	list := next()
	if list["id"] != float64(2) || list["error"] != nil {
		t.Fatalf("tools/list response: %#v", list)
	}
	tools, _ := list["result"].(map[string]any)
	listed, _ := tools["tools"].([]any)
	found := false
	for _, item := range listed {
		if tool, ok := item.(map[string]any); ok && tool["name"] == "trust_inspect" {
			found = true
		}
	}
	if !found {
		t.Fatalf("trust_inspect absent: %#v", list)
	}
	call := func(id int, name string, arguments map[string]any) map[string]any {
		write(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": arguments}})
		return next()
	}
	result := call(3, "trust_inspect", map[string]any{})
	if result["id"] != float64(3) || result["error"] != nil {
		t.Fatalf("trust inspect response: %#v", result)
	}
	mcpBinding, envelope := mcpTrustBinding(result)
	if !equalJSONBinding(binding, mcpBinding) {
		t.Fatalf("direct=%s mcp=%#v", out, result)
	}
	mcpInspectDigest := sha256.Sum256(envelope)
	t.Logf("T7_PROOF mcp_inspect_sha256=%x", mcpInspectDigest)
	for id, callSpec := range []struct {
		name string
		args map[string]any
	}{{"project_new", map[string]any{"ref": f.source.Commit, "name": "project", "dir": filepath.Dir(f.projectRoot), "dryRun": true, "sourceInput": sourceInput}}, {"update", map[string]any{"dir": f.projectRoot, "to": f.target.Commit, "dryRun": true, "sourceInput": targetInput}}} {
		response := call(10+id, callSpec.name, callSpec.args)
		result, _ := response["result"].(map[string]any)
		if response["error"] != nil || result["isError"] == true {
			t.Fatalf("mcp %s: %#v", callSpec.name, response)
		}
		structured, _ := result["structuredContent"].(map[string]any)
		data, _ := structured["data"].(map[string]any)
		wantStatus := "ok"
		if callSpec.name == "update" {
			wantStatus = "changes"
		}
		if structured["status"] != wantStatus || data["dryRun"] != true {
			t.Fatalf("mcp %s result: %#v", callSpec.name, response)
		}
		preview, _ := json.Marshal(structured)
		previewDigest := sha256.Sum256(preview)
		t.Logf("T7_PROOF mcp_preview_%d_sha256=%x", id, previewDigest)
	}
	expectFailure := func(response map[string]any, want string) {
		t.Helper()
		result, _ := response["result"].(map[string]any)
		if response["error"] != nil || result["isError"] != true {
			t.Fatalf("negative request accepted: %#v", response)
		}
		structured, _ := result["structuredContent"].(map[string]any)
		diagnostics, _ := structured["diagnostics"].([]any)
		for _, d := range diagnostics {
			diagnostic, _ := d.(map[string]any)
			code, _ := diagnostic["code"].(string)
			if code == want || (strings.HasSuffix(want, "*") && strings.HasPrefix(code, strings.TrimSuffix(want, "*"))) {
				return
			}
		}
		t.Fatalf("negative diagnostics = %#v, want %q", diagnostics, want)
	}
	// Unknown MCP fields are inert data, never a registration/profile selector.
	unknown := call(4, "trust_inspect", map[string]any{"authority": "development", "profile": "organization"})
	unknownBinding, _ := mcpTrustBinding(unknown)
	if unknown["error"] != nil || !equalJSONBinding(binding, unknownBinding) {
		t.Fatalf("unknown authority fields affected binding: %#v", unknown)
	}
	liveBaseline := snapshotOwned(t, filepath.Dir(f.projectRoot), root)
	for _, tc := range []struct {
		name string
		args map[string]any
		cli  []string
		code string
	}{
		// A registered runtime and public-looking ref do not supply source authority.
		{"project_new", map[string]any{"ref": f.source.Commit, "name": "project", "dir": filepath.Dir(f.projectRoot)}, []string{"new", f.source.Commit, "project"}, "TRUST_SOURCE_ADAPTER_UNSUPPORTED"},
		{"run", map[string]any{"dir": f.projectRoot, "command": "test"}, []string{"run", "test"}, "TRUST_ACTION_UNAVAILABLE"},
		{"gen", map[string]any{"dir": f.projectRoot, "kind": "fixture", "name": "thing"}, []string{"gen", "fixture", "thing"}, "TRUST_GENERATION_EXECUTION_UNAVAILABLE"},
		{"env_setup", map[string]any{"dir": f.projectRoot, "yes": true}, []string{"env", "setup"}, "TRUST_ACTION_UNAVAILABLE"},
	} {
		expectFailure(call(40, tc.name, tc.args), tc.code)
		out, err := run(tc.cli...)
		if err == nil || !strings.Contains(string(out), tc.code) || bytes.Contains(out, []byte(f.projectRoot)) {
			t.Fatalf("direct live %s was available or unsafe: exit=%v output=%q", tc.name, err, out)
		}
		if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(liveBaseline, after) {
			t.Fatalf("live %s changed fixture: %v", tc.name, changedSnapshotKeys(liveBaseline, after))
		}
	}
	// Genuine evidence is not permission to overwrite a populated project.
	// MCP forwards the CLI's ordinary occupancy refusal as a failed operation.
	expectFailure(call(41, "project_new", map[string]any{"ref": f.source.Commit, "name": "project", "dir": filepath.Dir(f.projectRoot), "sourceInput": sourceInput, "defaults": true, "noHooks": true}), "CLI_OPERATION_FAILED")
	if out, err := run("new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", sourceInput, "--defaults", "--no-hooks"); err == nil || !bytes.Contains(out, []byte("target is not empty")) || bytes.Contains(out, []byte(f.projectRoot)) {
		t.Fatalf("repeated signed live new accepted or unsafe: exit=%v output=%q", err, out)
	}
	if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(liveBaseline, after) {
		t.Fatalf("repeated signed live new changed fixture: %v", changedSnapshotKeys(liveBaseline, after))
	}
	for _, candidate := range []struct {
		name, path string
		mutate     func([]byte) []byte
	}{
		{"semantic runtime config", f.selection.RuntimeConfig.Path, func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"installationID":"t5f-install"`), []byte(`"installationID":"t5f-install-drift"`), 1)
		}},
		{"raw policy pin", filepath.Join(filepath.Dir(f.projectRoot), "policy.json"), func(raw []byte) []byte {
			return append(append([]byte(nil), raw...), '\n')
		}},
	} {
		original, err := os.ReadFile(candidate.path)
		if err != nil {
			t.Fatal(err)
		}
		changed := candidate.mutate(original)
		if bytes.Equal(changed, original) {
			t.Fatalf("%s fixture did not change", candidate.name)
		}
		if err := os.WriteFile(candidate.path, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		driftBaseline := snapshotOwned(t, filepath.Dir(f.projectRoot), root)
		expectFailure(call(30, "trust_inspect", map[string]any{}), "TRUST_PIN_MISMATCH")
		if out, err := run("trust", "inspect", "--json"); err == nil || string(out) != "error: trustload: TRUST_PIN_MISMATCH\n" {
			t.Fatalf("direct %s drift: exit=%v output=%q", candidate.name, err, out)
		}
		if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(driftBaseline, after) {
			t.Fatalf("rejected %s drift changed fixture: %v", candidate.name, changedSnapshotKeys(driftBaseline, after))
		}
		if err := os.WriteFile(candidate.path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		recovered := call(31, "trust_inspect", map[string]any{})
		recoveredResult, _ := recovered["result"].(map[string]any)
		if recovered["error"] != nil || recoveredResult["isError"] == true {
			t.Fatalf("restored %s did not recover child: %#v", candidate.name, recovered)
		}
		if recoveredBinding, _ := mcpTrustBinding(recovered); !equalJSONBinding(binding, recoveredBinding) {
			t.Fatalf("restored %s changed binding: %#v", candidate.name, recovered)
		}
	}
	// Each negative begins from its own snapshot. The command may inspect an
	// untrusted candidate but must not repair, rewrite, or otherwise mutate it.
	if err := os.WriteFile(sourceInput, []byte(`{"authority":"development"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	negativeBaseline := snapshotOwned(t, filepath.Dir(f.projectRoot), root)
	expectFailure(call(5, "project_new", map[string]any{"ref": f.source.Commit, "name": "project", "dir": filepath.Dir(f.projectRoot), "dryRun": true, "sourceInput": sourceInput}), "TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(negativeBaseline, after) {
		t.Fatalf("rejected source candidate mutated fixture\nbefore=%v\nafter=%v", negativeBaseline, after)
	}
	if err := os.WriteFile(sourceInput, sourceRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.projectRoot, ".tplaiter", "root-template.lock.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	negativeBaseline = snapshotOwned(t, filepath.Dir(f.projectRoot), root)
	expectFailure(call(6, "update", map[string]any{"dir": f.projectRoot, "to": f.target.Commit, "dryRun": true, "sourceInput": targetInput}), "TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	if out, err := run("update", "--dry-run", "--source-input", targetInput, "--to", f.target.Commit); err == nil || bytes.Contains(out, []byte(f.projectRoot)) {
		t.Fatalf("direct drifted lock: exit=%v output=%q", err, out)
	}
	if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(negativeBaseline, after) {
		t.Fatalf("rejected lock drift mutated fixture\nbefore=%v\nafter=%v", negativeBaseline, after)
	}
	if err := os.WriteFile(filepath.Join(f.projectRoot, ".tplaiter", "root-template.lock.json"), rootLock, 0o644); err != nil {
		t.Fatal(err)
	}
	// Authenticated CAS evidence and the raw source object are consumed by
	// each child. Changing either one must fail the same preview in both
	// transports without changing any other owned file. Over MCP the child's
	// result/v1 envelope carries the typed trust refusal (never the path).
	casHex := strings.TrimPrefix(f.sourceRefs.StatementCAS, "sha256:")
	casPath := filepath.Join(f.evidenceRoot, "sha256", casHex[:2], casHex[2:])
	objectPath := filepath.Join(filepath.Dir(f.projectRoot), "objects", f.source.Commit)
	for _, candidate := range []struct {
		name, path string
	}{{"publisher CAS", casPath}, {"source object", objectPath}} {
		original, err := os.ReadFile(candidate.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(candidate.path, append(append([]byte(nil), original...), 'x'), 0o600); err != nil {
			t.Fatal(err)
		}
		driftBaseline := snapshotOwned(t, filepath.Dir(f.projectRoot), root)
		expectFailure(call(20, "project_new", map[string]any{"ref": f.source.Commit, "name": "project", "dir": filepath.Dir(f.projectRoot), "dryRun": true, "sourceInput": sourceInput}), "TRUST_*")
		if out, err := run("new", f.source.Commit, "project", "--dry-run", "--source-input", sourceInput); err == nil || bytes.Contains(out, []byte(candidate.path)) {
			t.Fatalf("direct %s drift: exit=%v output=%q", candidate.name, err, out)
		}
		if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(driftBaseline, after) {
			t.Fatalf("rejected %s drift changed fixture: %v", candidate.name, changedSnapshotKeys(driftBaseline, after))
		}
		if err := os.WriteFile(candidate.path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A direct signed refresh is an explicit maintenance mutation. The next MCP
	// child must independently reopen the current store rather than retaining a
	// startup runtime lease.
	expiresAt := time.Now().UTC().Add(25 * time.Second).Truncate(time.Second)
	rotatedValidity := bootstrap.Validity{
		NotBefore: f.now.Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter:  expiresAt.Format(time.RFC3339),
	}
	nextBundle, nextEvidence := t5FRefreshBundleWithValidity(t, f, &rotatedValidity)
	for digest, value := range nextEvidence {
		t5FWriteCAS(t, f.evidenceRoot, digest, value)
	}
	refreshInput := filepath.Join(f.projectRoot, "refresh-bundle.json")
	if err := os.WriteFile(refreshInput, nextBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run("trust", "refresh", "--bundle-input", refreshInput); err != nil {
		t.Fatalf("refresh: %v %s", err, out)
	}
	rotated := call(7, "trust_inspect", map[string]any{})
	if rotated["error"] != nil {
		t.Fatalf("mcp child after refresh: %#v", rotated)
	}
	rotatedBinding, rotatedEnvelope := mcpTrustBinding(rotated)
	if rotatedBinding == nil ||
		rotatedBinding["authoritySHA256"] == binding["authoritySHA256"] ||
		rotatedBinding["configSHA256"] != binding["configSHA256"] ||
		rotatedBinding["policySHA256"] == binding["policySHA256"] {
		t.Fatalf("rotation did not update signed policy and authority binding: %s", rotatedEnvelope)
	}
	rotatedDirect, err := run("trust", "inspect", "--json")
	var rotatedDirectBinding map[string]any
	if err != nil || json.Unmarshal(rotatedDirect, &rotatedDirectBinding) != nil || !equalJSONBinding(rotatedBinding, rotatedDirectBinding) {
		t.Fatalf("rotated direct/MCP binding mismatch: direct=%q MCP=%s err=%v", rotatedDirect, rotatedEnvelope, err)
	}
	rotatedInspectDigest := sha256.Sum256(rotatedDirect)
	t.Logf("T7_PROOF rotated_inspect_sha256=%x", rotatedInspectDigest)
	if err := os.WriteFile(registrationPath, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	expectFailure(call(8, "trust_inspect", map[string]any{}), "TRUST_PIN_MISMATCH")
	if err := os.WriteFile(registrationPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	recovered := call(9, "trust_inspect", map[string]any{})
	recoveredResult, _ := recovered["result"].(map[string]any)
	if recovered["error"] != nil || recoveredResult["isError"] == true {
		t.Fatalf("restored registration did not recover child: %#v", recovered)
	}
	if recoveredBinding, _ := mcpTrustBinding(recovered); !equalJSONBinding(rotatedBinding, recoveredBinding) {
		t.Fatalf("restored registration changed binding: %#v", recovered)
	}
	// The rotated envelope is signed with a short finite validity. A later
	// child must use wall time and reject it after expiry, without a clock flag.
	preExpiry := snapshotOwned(t, filepath.Dir(f.projectRoot), root)
	if remaining := time.Until(expiresAt.Add(150 * time.Millisecond)); remaining > 0 {
		time.Sleep(remaining)
	}
	expectFailure(call(10, "trust_inspect", map[string]any{}), "TRUST_RUNTIME_INVALID")
	if out, err := run("trust", "inspect", "--json"); err == nil || string(out) != "error: TRUST_RUNTIME_INVALID\n" {
		t.Fatalf("expired signed direct authority: exit=%v output=%q", err, out)
	}
	if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(preExpiry, after) {
		t.Fatalf("expired signed authority changed fixture: %v", changedSnapshotKeys(preExpiry, after))
	}
	// The server's held executable is a temporary lease. Require it to
	// disappear after EOF and child reaping.
	baseline = snapshotWithoutHeldStage(snapshotOwned(t, filepath.Dir(f.projectRoot), root))
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if err := mcp.Wait(); err != nil {
		t.Fatalf("mcp shutdown: %v stderr=%s", err, stderr.String())
	}
	if after := snapshotOwned(t, filepath.Dir(f.projectRoot), root); !equalStringMap(baseline, after) {
		t.Fatalf("verification mutated fixture: %v", changedSnapshotKeys(baseline, after))
	}
	if _, err := os.Stat(spy); !os.IsNotExist(err) {
		t.Fatalf("hostile PATH executable was spawned: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(f.projectRoot), "scratch"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("MCP scratch remains after clean EOF: %v entries=%v", err, entries)
	}
}

func snapshotWithoutHeldStage(snapshot map[string]string) map[string]string {
	for path := range snapshot {
		if strings.HasPrefix(path, "fixture/scratch/tplaiter-held-stage-") {
			delete(snapshot, path)
		}
	}
	return snapshot
}

func snapshotOwned(t *testing.T, fixtureRoot, processRoot string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for prefix, root := range map[string]string{"fixture": fixtureRoot, "process": processRoot} {
		for relative, value := range snapshotTree(t, root) {
			out[prefix+"/"+relative] = value
		}
	}
	return out
}

func changedSnapshotKeys(before, after map[string]string) []string {
	keys := map[string]bool{}
	for key, value := range before {
		if after[key] != value {
			keys[key] = true
		}
	}
	for key, value := range after {
		if before[key] != value {
			keys[key] = true
		}
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func equalJSONBinding(a, b map[string]any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(root, path)
		info, e := d.Info()
		if e != nil {
			return e
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, e := os.Readlink(path)
			if e != nil {
				return e
			}
			out[rel] = fmt.Sprintf("link:%o:%s", info.Mode(), target)
			return nil
		}
		if d.IsDir() {
			out[rel] = fmt.Sprintf("dir:%o", info.Mode())
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(raw)
		out[rel] = fmt.Sprintf("file:%o:%x", info.Mode(), sum)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}

// mcpTrustBinding extracts data.binding of a trust_inspect result/v1
// envelope from a tools/call response, with the canonical envelope bytes.
func mcpTrustBinding(response map[string]any) (map[string]any, []byte) {
	result, _ := response["result"].(map[string]any)
	structured, _ := result["structuredContent"].(map[string]any)
	if structured["operation"] != "trust.inspect" {
		return nil, nil
	}
	data, _ := structured["data"].(map[string]any)
	binding, _ := data["binding"].(map[string]any)
	raw, _ := json.Marshal(structured)
	return binding, raw
}

func testProcessEnv(home string) []string {
	return []string{
		"PATH=/opt/homebrew/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TERM=dumb", "NO_COLOR=1", "TZ=UTC",
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "xdg-config"),
		"XDG_CACHE_HOME=" + filepath.Join(home, "xdg-cache"),
		"XDG_DATA_HOME=" + filepath.Join(home, "xdg-data"),
		"XDG_STATE_HOME=" + filepath.Join(home, "xdg-state"),
		"TPLAITER_HOME=" + filepath.Join(home, "tplaiter"), "TPLATER_HOME=",
	}
}

func testBuildEnv(home string) []string {
	cacheRoot := os.Getenv("GOCACHE")
	if cacheRoot == "" {
		// Mirror the go command defaults: os.UserCacheDir is ~/Library/Caches on
		// Darwin and $XDG_CACHE_HOME or ~/.cache on Linux.
		if userCache, err := os.UserCacheDir(); err == nil {
			cacheRoot = filepath.Join(userCache, "go-build")
		}
	}
	moduleRoot := os.Getenv("GOMODCACHE")
	if moduleRoot == "" {
		gopath := filepath.Join(os.Getenv("HOME"), "go")
		if list := filepath.SplitList(os.Getenv("GOPATH")); len(list) > 0 && list[0] != "" {
			gopath = list[0]
		}
		moduleRoot = filepath.Join(gopath, "pkg", "mod")
	}
	return append(
		testProcessEnv(home),
		"GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off",
		"GOMODCACHE="+moduleRoot, "GOCACHE="+cacheRoot,
	)
}
