package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// This uses the accepted external enrollment producer and stock linked main,
// with random ephemeral test keys, rather than an injected runtime.
func TestStableProjectIdentityStockCLIAndMCP(t *testing.T) {
	testfixture.RequireTrustStore(t)
	root, err := os.MkdirTemp(testfixture.PrivateTempBase(), "tplaiter-finite-selection-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cwd := filepath.Join(root, "unrelated")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	publisher, pkg := selectionSignedPackage(t, "https://example.test/finite", nil)
	contexts := []trustload.ProjectContext{
		{Key: "a", ProjectID: "installed-a", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(root, "target-a")},
		{Key: "b", ProjectID: "installed-b", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(root, "target-b")},
	}
	contexts = append(contexts, trustload.ProjectContext{Key: "cli", ProjectID: "installed-cli", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(root, "cli-target")})
	result, err := ossinstall.Generate(ossinstall.Options{Root: filepath.Join(root, "install"), Publishers: []ossinstall.Publisher{publisher}, SourcePackages: []ossinstall.SourcePackage{pkg}, ProjectContexts: contexts})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(result.RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := ossinstall.DecodeRegistration(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(result.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var selections []operationtrust.SourceSelection
	if err := json.Unmarshal(raw, &selections); err != nil || len(selections) != 1 {
		t.Fatalf("selections: %v", err)
	}
	source := selections[0]
	input := filepath.Join(root, "source.json")
	raw, err = json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "tplaiter")
	flags := "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath=" + result.RegistrationPath + " -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=" + result.RegistrationSHA256
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", flags, "-o", binary, ".")
	build.Dir = "../.."
	build.Env = testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := testProcessEnv(home)
	run := func(args ...string) ([]byte, error) {
		c := exec.Command(binary, args...)
		c.Dir, c.Env = cwd, env
		return c.CombinedOutput()
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision: %v %s", err, out)
	}
	if out, err := run("trust", "contexts"); err != nil {
		t.Fatalf("contexts: %v %s", err, out)
	} else {
		var listed []trustload.ProjectContext
		if err := json.Unmarshal(out, &listed); err != nil || len(listed) != len(contexts) {
			t.Fatalf("contexts: %v %s", err, out)
		}
		for i, p := range contexts {
			if listed[i] != p {
				t.Fatalf("contexts changed: %+v", listed)
			}
		}
	}
	tampered := source
	tampered.Subject.Commit = strings.Repeat("f", 40)
	tamperedRaw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(root, "tampered-source.json")
	if err := os.WriteFile(tamperedPath, tamperedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Negative operations must leave both absent roots and the registry untouched.
	baseline := snapshotTree(t, root)
	for _, args := range [][]string{
		{"new", source.Subject.Commit, "Different Display", "--project-context", "a", "--dir", contexts[0].RootPath, "--source-input", tamperedPath, "--defaults"},
		{"new", source.Subject.Commit, "Different Display", "--project-context", "unknown", "--dir", contexts[0].RootPath, "--source-input", input, "--defaults"},
		{"new", source.Subject.Commit, "Different Display", "--project-context", "a", "--dir", contexts[1].RootPath, "--source-input", input, "--defaults"},
		{"new", source.Subject.Commit, "Different Display", "--project-context", "a", "--source-input", input, "--defaults"},
	} {
		if out, err := run(args...); err == nil {
			t.Fatalf("denied CLI succeeded: %s", out)
		}
		if after := snapshotTree(t, root); !equalStringMap(baseline, after) {
			t.Fatalf("denied CLI wrote: %v", changedSnapshotKeys(baseline, after))
		}
	}
	// A direct stock CLI creates A with an explicit target and unrelated name.
	if out, err := run("new", source.Subject.Commit, "CLI Display", "--project-context", "cli", "--dir", contexts[2].RootPath, "--source-input", input, "--defaults", "--no-hooks", "--json"); err != nil {
		t.Fatalf("CLI A: %v %s", err, out)
	}
	verify := func(p trustload.ProjectContext) {
		t.Helper()
		runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: registration.Selection(), ProjectKey: p.Key, Clock: bootstrap.ClockFunc(time.Now)})
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.Close()
		if _, err := stateledger.VerifyStable(context.Background(), p.RootPath, runtime.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
			t.Fatalf("%s locks: %v", p.Key, err)
		}
		raw, err := os.ReadFile(filepath.Join(p.RootPath, "hello.txt"))
		if err != nil || string(raw) != "hello\n" {
			t.Fatalf("%s bytes %q %v", p.Key, raw, err)
		}
		raw, err = os.ReadFile(filepath.Join(p.RootPath, ".tplaiter", "project.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var marker struct{ ID string }
		if err := yaml.Unmarshal(raw, &marker); err != nil || marker.ID != p.ProjectID {
			t.Fatalf("marker: %s %v", raw, err)
		}
	}
	verify(contexts[2])
	m := exec.Command(binary, "mcp-server")
	m.Dir, m.Env = cwd, env
	in, err := m.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	m.Stderr = &stderr
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = m.Wait() })
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	send := func(v any) map[string]any {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := in.Write(append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
		if !scanner.Scan() {
			t.Fatalf("MCP EOF: %v %s", scanner.Err(), stderr.String())
		}
		var r map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "finite", "version": "1"}}})
	if _, err := in.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	call := func(id int, args map[string]any) map[string]any {
		return send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "project_new", "arguments": args}})
	}
	for i, args := range []map[string]any{
		{"ref": source.Subject.Commit, "name": "MCP Display", "dir": cwd, "projectContext": "unknown", "targetDir": contexts[0].RootPath, "sourceInput": input, "defaults": true},
		{"ref": source.Subject.Commit, "name": "MCP Display", "dir": cwd, "projectContext": "a", "targetDir": contexts[1].RootPath, "sourceInput": input, "defaults": true},
		{"ref": source.Subject.Commit, "name": "MCP Display", "dir": cwd, "projectContext": "a", "sourceInput": input, "defaults": true},
	} {
		before := snapshotTree(t, root)
		r := call(10+i, args)
		res, _ := r["result"].(map[string]any)
		if r["error"] == nil && res["isError"] != true {
			t.Fatalf("MCP denied succeeded: %#v", r)
		}
		if after := snapshotTree(t, root); !equalStringMap(before, after) {
			t.Fatalf("MCP denial wrote: %v", changedSnapshotKeys(before, after))
		}
	}
	for i, p := range contexts[:2] {
		r := call(20+i, map[string]any{"ref": source.Subject.Commit, "name": "Display " + p.Key, "dir": cwd, "targetDir": p.RootPath, "projectContext": p.Key, "sourceInput": input, "defaults": true, "noHooks": true})
		res, _ := r["result"].(map[string]any)
		if r["error"] != nil || res["isError"] == true {
			t.Fatalf("MCP %s: %#v", p.Key, r)
		}
		verify(p)
	}
	// Verified resolutions and prepared operation inputs are bound to the
	// selected project/runtime even when source and profile are identical.
	runtimeA, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: registration.Selection(), ProjectKey: "a", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeA.Close()
	runtimeB, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: registration.Selection(), ProjectKey: "b", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeB.Close()
	resolution, err := runtimeA.TrustRuntime().VerifySubject(context.Background(), source.TrustSubject(), source.EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	if resolution.ValidFor(runtimeB.TrustRuntime(), runtimeB.TrustRuntime().Binding()) {
		t.Fatal("A resolution valid in B")
	}
	if _, err := operationtrust.SnapshotFS(runtimeB.TrustRuntime(), resolution); err == nil {
		t.Fatal("A resolution replay accepted by B snapshot consumer")
	}
	raw, err = os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	preparedA, err := operationtrust.PrepareNew(context.Background(), runtimeA, operationtrust.PrepareNewInput{SourceInput: raw, Render: renderref.Input{}, RendererVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !preparedA.ValidFor(runtimeA.TrustRuntime()) || preparedA.ValidFor(runtimeB.TrustRuntime()) {
		t.Fatal("prepared A plan replay accepted in B")
	}
	preparedB, err := operationtrust.PrepareNew(context.Background(), runtimeB, operationtrust.PrepareNewInput{SourceInput: raw, Render: renderref.Input{}, RendererVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if preparedA.OperationInputsSHA256() == preparedB.OperationInputsSHA256() {
		t.Fatal("selected project missing from operation input digest")
	}
	projects, err := state.LoadProjects(filepath.Join(home, "tplaiter"))
	if err != nil || len(projects.Items) != 3 {
		t.Fatalf("registry: %+v %v", projects, err)
	}
	for _, p := range contexts {
		found := false
		for _, item := range projects.Items {
			if item.ID == p.ProjectID && item.Path == p.RootPath {
				found = true
			}
		}
		if !found {
			t.Fatalf("registry missing %s", p.Key)
		}
	}
	// Reproduction: only the marker ID is replayed; B source locks stay intact.
	markerPath := filepath.Join(contexts[1].RootPath, ".tplaiter", "project.yaml")
	original, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	replayed := bytes.Replace(original, []byte("id: installed-b"), []byte("id: installed-a"), 1)
	if bytes.Equal(original, replayed) {
		t.Fatal("marker ID fixture replacement missed")
	}
	if err := os.WriteFile(markerPath, replayed, 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, root)
	if _, err := stateledger.VerifyStable(context.Background(), contexts[1].RootPath, runtimeB.TrustRuntime(), stateledger.StableVerifyOptions{}); !errors.Is(err, stateledger.ErrProjectIdentity) {
		t.Fatalf("marker A replay accepted in B or wrong failure: %v", err)
	}
	if after := snapshotTree(t, root); !equalStringMap(before, after) {
		t.Fatal("replay verification wrote state")
	}
	if err := os.WriteFile(markerPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	// Copy the entire actual A marker into B as in the original finding.
	markerA, err := os.ReadFile(filepath.Join(contexts[0].RootPath, ".tplaiter", "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, markerA, 0o600); err != nil {
		t.Fatal(err)
	}
	before = snapshotTree(t, root)
	if _, err := stateledger.VerifyStable(context.Background(), contexts[1].RootPath, runtimeB.TrustRuntime(), stateledger.StableVerifyOptions{}); !errors.Is(err, stateledger.ErrProjectIdentity) {
		t.Fatalf("whole A marker copied into B: %v", err)
	}
	if after := snapshotTree(t, root); !equalStringMap(before, after) {
		t.Fatal("whole-marker verification wrote state")
	}
	if err := os.WriteFile(markerPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	// Deterministic race: B is genuinely checked first, then the writer swaps
	// in A before InventoryContext hashes the marker. Final check must not use B.
	interleaved := &markerInterleavingAuthority{Runtime: runtimeB.TrustRuntime(), afterFirst: func() error { return os.WriteFile(markerPath, markerA, 0o600) }}
	got, err := stateledger.VerifyStable(context.Background(), contexts[1].RootPath, interleaved, stateledger.StableVerifyOptions{})
	if err == nil || got != nil {
		t.Fatal("MARKER_COHERENCE_REPRODUCTION: initial B check plus inventory A marker returned success")
	}
	if interleaved.checks != 1 {
		t.Fatalf("unexpected real check count: %d", interleaved.checks)
	}
	current, err := os.ReadFile(markerPath)
	if err != nil || !bytes.Equal(current, markerA) {
		t.Fatalf("verification changed writer marker: %v", err)
	}
	if err := os.WriteFile(markerPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	// Restore B after the project inventory captured A: current marker alone
	// looks valid again, but the foreign marker digest in snapshot must refuse.
	restoreHome := filepath.Join(root, "marker-observer-home")
	if err := os.Mkdir(restoreHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(restoreHome, "public-sentinel"), []byte("public"), 0o600); err != nil {
		t.Fatal(err)
	}
	restorer := &markerRestoreSecrets{restore: func() error { return os.WriteFile(markerPath, original, 0o600) }}
	interleaved = &markerInterleavingAuthority{Runtime: runtimeB.TrustRuntime(), afterFirst: func() error { return os.WriteFile(markerPath, markerA, 0o600) }}
	got, err = stateledger.VerifyStable(context.Background(), contexts[1].RootPath, interleaved, stateledger.StableVerifyOptions{HomeRoot: restoreHome, SecretProvider: restorer})
	if err == nil || got != nil || !restorer.restored {
		t.Fatalf("captured foreign snapshot survived restoration: %v restored=%v", err, restorer.restored)
	}
	current, err = os.ReadFile(markerPath)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatalf("restore hook did not restore B: %v", err)
	}

	// Mutation after inventory must be caught by actual marker reobservation.
	interleaved = &markerInterleavingAuthority{Runtime: runtimeB.TrustRuntime(), afterFirst: func() error { return nil }, afterBinding: func() error { return os.WriteFile(markerPath, markerA, 0o600) }}
	got, err = stateledger.VerifyStable(context.Background(), contexts[1].RootPath, interleaved, stateledger.StableVerifyOptions{})
	if err == nil || got != nil {
		t.Fatal("post-inventory marker replacement returned success")
	}
	if err := os.WriteFile(markerPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	// Same bytes with a changed mode must not masquerade as the checked marker.
	info, err := os.Stat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	originalMode := info.Mode().Perm()
	interleaved = &markerInterleavingAuthority{Runtime: runtimeB.TrustRuntime(), afterFirst: func() error { return os.Chmod(markerPath, originalMode^0o200) }}
	got, err = stateledger.VerifyStable(context.Background(), contexts[1].RootPath, interleaved, stateledger.StableVerifyOptions{})
	if err == nil || got != nil {
		t.Fatal("marker mode drift returned success")
	}
	if err := os.Chmod(markerPath, originalMode); err != nil {
		t.Fatal(err)
	}
	t.Log("MARKER_COHERENCE_PROOF real B checker then A marker before inventory denied; marker mode drift denied")

	// Using A's authority on untouched B fails before profile/source lock checks.
	assertDenied := func(ctx context.Context, projectRoot string, authority stateledger.BindingAuthority, want error) {
		t.Helper()
		before := snapshotTree(t, root)
		if _, err := stateledger.VerifyStable(ctx, projectRoot, authority, stateledger.StableVerifyOptions{}); !errors.Is(err, want) {
			t.Fatalf("identity boundary: got %v want %v", err, want)
		}
		if after := snapshotTree(t, root); !equalStringMap(before, after) {
			t.Fatal("identity boundary wrote state")
		}
	}
	assertDenied(context.Background(), contexts[1].RootPath, runtimeA.TrustRuntime(), stateledger.ErrProjectIdentity)
	// The wrong root also fails even when its marker ID was changed to match A.
	if err := os.WriteFile(markerPath, replayed, 0o600); err != nil {
		t.Fatal(err)
	}
	assertDenied(context.Background(), contexts[1].RootPath, runtimeA.TrustRuntime(), stateledger.ErrProjectIdentity)
	if err := os.WriteFile(markerPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	assertDenied(cancelled, contexts[1].RootPath, runtimeB.TrustRuntime(), context.Canceled)
	// A live runtime must reauthenticate semantic config and every nested raw pin.
	loaded, err := trustload.Load(context.Background(), registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{registration.RuntimeConfig.Path, loaded.Install.Descriptor.Path, loaded.Install.ExecutionPolicy.Path} {
		pristine, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		mutated := append(append([]byte(nil), pristine...), '\n')
		if path == registration.RuntimeConfig.Path {
			mutated = bytes.Replace(pristine, []byte("installed-b"), []byte("replaced-b"), 1)
		}
		if err := os.WriteFile(path, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		assertDenied(context.Background(), contexts[1].RootPath, runtimeB.TrustRuntime(), stateledger.ErrProjectIdentity)
		if err := os.WriteFile(path, pristine, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	verify(contexts[0])
	verify(contexts[1])
	t.Log("P1_IDENTITY_PROOF marker=A-in-B denied; authority=A-at-B denied; root=B-with-A-ID denied; semantic/raw-pin drift denied; cancellation preserved; no verification writes; custom-display A/B positive")

	binaryRaw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("FINITE_SELECTION_PROOF binary=%s registration=%s runtime=%s CLI=cli MCP=A,B cwd=unrelated targets=absent locks=verified registry=3 replay=denied", evidencecas.Digest(binaryRaw), result.RegistrationSHA256, registration.RuntimeConfig.SHA256)
}

// This is a forwarding checker, not a synthetic identity grant. The hook
// schedules an external writer only after the real runtime's first check.
type markerInterleavingAuthority struct {
	*trustverify.Runtime
	afterFirst   func() error
	afterBinding func() error
	checks       int
}

func (a *markerInterleavingAuthority) CheckProjectIdentity(ctx context.Context, root, observedID string) error {
	if err := a.Runtime.CheckProjectIdentity(ctx, root, observedID); err != nil {
		return err
	}
	a.checks++
	if a.checks == 1 {
		return a.afterFirst()
	}
	return nil
}

// Home inventory runs after project inventory. This schedules a public-fixture
// writer restoring B after A's marker was hashed; it grants no project identity.
type markerRestoreSecrets struct {
	restore  func() error
	restored bool
}

func (s *markerRestoreSecrets) DigestSecret(ctx context.Context, _ stateledger.SecretLocator) (stateledger.SecretDigestResult, error) {
	if err := ctx.Err(); err != nil {
		return stateledger.SecretDigestResult{}, err
	}
	if !s.restored {
		if err := s.restore(); err != nil {
			return stateledger.SecretDigestResult{}, err
		}
		s.restored = true
	}
	return stateledger.SecretDigestResult{}, nil
}

func (a *markerInterleavingAuthority) CheckBinding(binding bootstrap.ProfileBinding) error {
	if err := a.Runtime.CheckBinding(binding); err != nil {
		return err
	}
	if a.afterBinding != nil {
		return a.afterBinding()
	}
	return nil
}
