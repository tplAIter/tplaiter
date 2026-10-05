package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/trustload"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/testfixture"
)

// This is the production installed CLI and held-image stdio MCP server, not
// NewDirect, an in-process handler, a recording runner or a callback authority.
func TestContextInstalledCLIAndStdioSignedZeroWrites(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeGenCLIFixture(t)
	base := filepath.Dir(f.projectRoot)
	registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
	raw, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	registrationPath := filepath.Join(base, "registration.json")
	if err = os.WriteFile(registrationPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "process-home")
	if err = os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-trimpath", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(digest[:]), "-o", bin, ".")
	build.Dir = filepath.Join("..", "..")
	build.Env = testBuildEnv(home)
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("installed build: %v %s", e, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, bin, args...)
		c.Env, c.Dir = testProcessEnv(home), base
		return c.Output()
	}
	if out, e := run("trust", "provision"); e != nil {
		t.Fatalf("fixture provisioning: %v %s", e, out)
	}
	selection := filepath.Join(base, "selection.json")
	if err = os.WriteFile(selection, t5FSelection(f.source, f.sourceRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, e := run("new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", selection, "--defaults", "--no-hooks", "--json"); e != nil {
		t.Fatalf("fixture source creation: %v %s", e, out)
	}
	image := func() map[string]string {
		return contextReadImage(t, f.projectRoot, home, f.store, f.evidenceRoot, filepath.Join(base, "objects"))
	}
	before := image()
	defaultDiscovery, err := run("context", "discover", "--json")
	if err != nil {
		t.Fatalf("default installed byte discovery: %v %s", err, defaultDiscovery)
	}
	defaultEnvelope := decodeOne(t, string(defaultDiscovery))
	var defaultData resultdto.ContextData
	if err = json.Unmarshal(defaultEnvelope.Data, &defaultData); err != nil {
		t.Fatal(err)
	}
	if defaultData.BytePlan == nil || defaultData.Bytes > 32768 || defaultData.Total != 6 || defaultData.WindowState != "unknown" {
		t.Fatal("default byte discovery is not bounded/usable")
	}
	cli, err := run("context", "discover", "--limit=1", "--max-bytes=32768", "--json")
	if err != nil {
		t.Fatalf("installed context discover: %v %s", err, cli)
	}
	env := decodeOne(t, string(cli))
	var first resultdto.ContextData
	if err = json.Unmarshal(env.Data, &first); err != nil {
		t.Fatal(err)
	}
	if env.Project == nil || env.Project.Root != f.projectRoot || first.Total != 6 || len(first.Entries) != 1 || first.NextCursor == "" || first.Bytes != len(env.Data) {
		t.Fatalf("actual discovery: %s", cli)
	}
	if first.BytePlan == nil || first.ByteProfile == nil || first.Spending == nil || first.RetrievalState != "local-byte-delivery-finished" {
		t.Fatal("actual discovery did not reach C04 reservation/delivery/finish")
	}
	if first.BytePlan.EnvelopeBytes != len(first.BytePlan.Envelope) || first.Spending.InputBytes != int64(first.BytePlan.EnvelopeBytes) || first.Spending.OutputBytes <= 0 || first.BytePlan.CountedTokens != 0 || first.BytePlan.OutputReserve != 0 || first.BytePlan.CapacityAccounting != "model-window-unknown" || first.ByteProfile.ModelCapacity != "unknown" || first.Spending.InputTokens != 0 || first.Spending.OutputTokens != 0 {
		t.Fatal("local bytes manufactured model token authority")
	}
	t.Logf("actual C04 byte reservation/delivery/finish: wire=%d bytes, delivered response=%d bytes, capacity=%s, counted tokens=%d", first.BytePlan.EnvelopeBytes, first.Spending.OutputBytes, first.BytePlan.CapacityAccounting, first.BytePlan.CountedTokens)
	entry := first.Entries[0]
	get, err := run("context", "get", "--id="+entry.ID, "--snapshot="+first.Snapshot, "--max-bytes=32768", "--json")
	if err != nil {
		t.Fatalf("installed signed get: %v %s", err, get)
	}
	got := decodeOne(t, string(get))
	var content resultdto.ContextData
	if err = json.Unmarshal(got.Data, &content); err != nil {
		t.Fatal(err)
	}
	if content.Packet == nil || len(content.Packet.Excerpts) != 2 || len(content.Packet.SourceEvidence) != 1 || len(content.Packet.RequiredFloor) != 3 {
		t.Fatalf("get didn't reach C03 signed snapshot: %s", get)
	}
	for _, excerpt := range content.Packet.Excerpts {
		if excerpt.Path != entry.Path || excerpt.Content == "" || excerpt.Digest == "" {
			t.Fatalf("signed excerpt: %+v", excerpt)
		}
	}
	// The real CLI honors an exact compact-data byte limit, including cursor and
	// required-floor overhead. A smaller limit returns a typed whole refusal.
	exact, err := run("context", "get", "--id="+entry.ID, "--snapshot="+first.Snapshot, fmt.Sprintf("--max-bytes=%d", content.Bytes), "--json")
	if err != nil {
		t.Fatalf("exact data bytes: %v %s", err, exact)
	}
	short, err := run("context", "get", "--id="+entry.ID, "--snapshot="+first.Snapshot, fmt.Sprintf("--max-bytes=%d", content.Bytes-1), "--json")
	if err == nil {
		t.Fatal("byte overflow succeeded")
	}
	shortEnv := decodeOne(t, string(short))
	if len(shortEnv.Data) != 0 || len(shortEnv.Diagnostics) != 1 || shortEnv.Diagnostics[0].Code != contextcmd.Budget {
		t.Fatalf("partial byte refusal: %s", short)
	}
	if !reflect.DeepEqual(before, image()) {
		t.Fatal("CLI reads/refusals changed persistent bytes/modes")
	}

	server := exec.CommandContext(ctx, bin, "mcp-server")
	server.Env, server.Dir = testProcessEnv(home), base
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
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = stdin.Close()
			_ = server.Wait()
		}
	}()
	encoder := json.NewEncoder(stdin)
	decoder := json.NewDecoder(stdout)
	var mu sync.Mutex
	replies := map[int]chan map[string]json.RawMessage{}
	go func() {
		for {
			var reply map[string]json.RawMessage
			if decoder.Decode(&reply) != nil {
				return
			}
			var id int
			if json.Unmarshal(reply["id"], &id) != nil {
				continue
			}
			mu.Lock()
			ch := replies[id]
			mu.Unlock()
			if ch != nil {
				ch <- reply
			}
		}
	}()
	next := 0
	start := func(method string, params any) (int, <-chan map[string]json.RawMessage) {
		next++
		id := next
		ch := make(chan map[string]json.RawMessage, 1)
		mu.Lock()
		replies[id] = ch
		mu.Unlock()
		if e := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); e != nil {
			t.Fatal(e)
		}
		return id, ch
	}
	request := func(method string, params any) map[string]json.RawMessage {
		_, ch := start(method, params)
		select {
		case reply := <-ch:
			if len(reply["error"]) > 0 {
				t.Fatalf("stdio protocol error: %s", reply["error"])
			}
			return reply
		case <-ctx.Done():
			t.Fatalf("stdio timeout: %s", stderr.String())
			return nil
		}
	}
	request("initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "c05-installed-context", "version": "1"}})
	if err = encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		t.Fatal(err)
	}
	listed := request("tools/list", map[string]any{})
	var list struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err = json.Unmarshal(listed["result"], &list); err != nil {
		t.Fatal(err)
	}
	// Capture the complete installed tools/list result separately from the new
	// context descriptor, never into either shared runtime golden.
	if capture := os.Getenv("TPLAITER_C05_CATALOG_CAPTURE"); capture != "" {
		if err = os.WriteFile(capture, append(listed["result"], '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(list.Tools) != 30 {
		t.Fatalf("published 30-tool inventory not preserved: %d", len(list.Tools))
	}
	found := false
	for _, rawTool := range list.Tools {
		var tool struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(rawTool, &tool) != nil {
			t.Fatal("descriptor JSON")
		}
		if tool.Name == "context" {
			found = true
			t.Logf("installed tools/list: context descriptor=%d bytes; total tools=%d", len(rawTool), len(list.Tools))
		}
	}
	if !found {
		t.Fatal("context not registered in real server")
	}
	call := func(action string, req map[string]any) resultdto.Result {
		reply := request("tools/call", map[string]any{"name": "context", "arguments": map[string]any{"action": action, "projectContext": "project", "dir": f.projectRoot, "request": req}})
		var result struct {
			Structured json.RawMessage `json:"structuredContent"`
		}
		if e := json.Unmarshal(reply["result"], &result); e != nil {
			t.Fatal(e)
		}
		envelope, e := resultdto.Decode(result.Structured)
		if e != nil {
			t.Fatalf("stdio typed result: %v %s", e, reply["result"])
		}
		if envelope.Operation != resultdto.OperationContextQuery {
			t.Fatal(envelope.Operation)
		}
		return envelope
	}
	mcpBefore := image()
	discovered := call("discover", map[string]any{"limit": 1, "maxBytes": 32768})
	if discovered.Status != resultdto.StatusOK {
		t.Fatalf("stdio positive discover: %+v", discovered.Diagnostics)
	}
	var page resultdto.ContextData
	if err = json.Unmarshal(discovered.Data, &page); err != nil {
		t.Fatal(err)
	}
	second := call("continue", map[string]any{"cursor": page.NextCursor})
	if second.Status != resultdto.StatusOK {
		t.Fatalf("actual continuation: %+v", second.Diagnostics)
	}
	var continued resultdto.ContextData
	if err = json.Unmarshal(second.Data, &continued); err != nil {
		t.Fatal(err)
	}
	if continued.Snapshot != page.Snapshot || len(continued.Entries) != 1 || continued.Entries[0].ID == page.Entries[0].ID {
		t.Fatal("continuation repeated or lost snapshot")
	}
	// Continuations reject caller replacement selectors and stale carried bounds.
	// A cursor is an inert locator, never an authority grant.
	replaced := call("continue", map[string]any{"cursor": page.NextCursor, "limit": 2})
	if replaced.Status == resultdto.StatusOK || len(replaced.Data) != 0 || replaced.Diagnostics[0].Code != contextcmd.Invalid {
		t.Fatal("continuation accepted replacement bounds")
	}
	cursorRaw, err := base64.RawURLEncoding.DecodeString(page.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	var cursorFields map[string]any
	if err = json.Unmarshal(cursorRaw, &cursorFields); err != nil {
		t.Fatal(err)
	}
	cursorFields["request"].(map[string]any)["maxBytes"] = 32767
	cursorRaw, err = json.Marshal(cursorFields)
	if err != nil {
		t.Fatal(err)
	}
	changedBounds := call("continue", map[string]any{"cursor": base64.RawURLEncoding.EncodeToString(cursorRaw)})
	if changedBounds.Status != resultdto.StatusBlocked || len(changedBounds.Data) != 0 || changedBounds.Diagnostics[0].Code != contextcmd.Stale {
		t.Fatal("continuation accepted stale query/bounds binding")
	}
	searched := call("search", map[string]any{"path": entry.Path, "kind": "resource", "limit": 1, "maxBytes": 32768})
	if searched.Status != resultdto.StatusOK {
		t.Fatal(searched.Diagnostics)
	}
	signed := call("get", map[string]any{"id": entry.ID, "snapshot": page.Snapshot, "maxBytes": 32768})
	if signed.Status != resultdto.StatusOK {
		t.Fatal(signed.Diagnostics)
	}
	schema := call("schema", map[string]any{})
	if schema.Status != resultdto.StatusOK {
		t.Fatal(schema.Diagnostics)
	}
	planned := call("plan", map[string]any{"limit": 1, "maxBytes": 32768})
	var bytePlanned resultdto.ContextData
	if err = json.Unmarshal(planned.Data, &bytePlanned); err != nil {
		t.Fatal(err)
	}
	if bytePlanned.BytePlan == nil || bytePlanned.Spending == nil || bytePlanned.BytePlan.CapacityAccounting != "model-window-unknown" || bytePlanned.Spending.InputBytes <= 0 {
		t.Fatal("unknown model prevented actual bounded C04 byte planning")
	}
	if planned.Status != resultdto.StatusBlocked || len(planned.Diagnostics) != 1 || planned.Diagnostics[0].Code != contextcmd.WindowUnknown {
		t.Fatal("plan granted guessed window")
	}
	t.Log("actual C04 model-host reservation returned typed CONTEXT_WINDOW_UNKNOWN; local byte plan remains available")
	missing := call("get", map[string]any{"id": entry.ID, "required": []string{"installed:resource:missing"}, "maxBytes": 32768})
	if missing.Status != resultdto.StatusBlocked || len(missing.Data) != 0 || len(missing.Diagnostics) != 1 || missing.Diagnostics[0].Code != "CONTEXT_INDEX_MISSING" {
		t.Fatalf("missing required wasn't typed zero-packet refusal: %+v", missing)
	}
	drift := call("get", map[string]any{"id": entry.ID, "snapshot": "sha256:" + fmt.Sprintf("%064d", 0), "maxBytes": 32768})
	if drift.Status != resultdto.StatusBlocked || drift.Diagnostics[0].Code != contextcmd.Stale {
		t.Fatal("foreign snapshot accepted")
	}
	// Real snapshot-addressed resource, routed through the same installed get.
	resource := request("resources/read", map[string]any{"uri": entry.ResourceURI})
	var resourceResult struct {
		Contents []struct {
			Text string `json:"text"`
		} `json:"contents"`
	}
	if err = json.Unmarshal(resource["result"], &resourceResult); err != nil {
		t.Fatal(err)
	}
	if len(resourceResult.Contents) != 1 {
		t.Fatal("addressed resource missing")
	}
	var resourceData resultdto.ContextData
	if err = json.Unmarshal([]byte(resourceResult.Contents[0].Text), &resourceData); err != nil || resourceData.Packet == nil || len(resourceData.Packet.SourceEvidence) != 1 {
		t.Fatalf("resource wasn't source authenticated: %v", err)
	}

	// Notify cancellation after the actual installed child has had time to enter
	// its authenticated read. Protocol permits suppressing a cancelled reply.
	id, ch := start("tools/call", map[string]any{"name": "context", "arguments": map[string]any{"action": "get", "request": map[string]any{"id": entry.ID, "maxBytes": 32768}}})
	time.Sleep(10 * time.Millisecond)
	if err = encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id, "reason": "focused public cancellation probe"}}); err != nil {
		t.Fatal(err)
	}
	request("ping", map[string]any{})
	select {
	case reply := <-ch:
		var result struct {
			Structured json.RawMessage `json:"structuredContent"`
		}
		if json.Unmarshal(reply["result"], &result) != nil {
			t.Fatal("cancel response shape")
		}
		cancelled, e := resultdto.Decode(result.Structured)
		if e != nil || len(cancelled.Diagnostics) != 1 || cancelled.Diagnostics[0].Code != "MCP_CANCELLED" {
			t.Fatalf("cancel not typed: %v %s", e, reply["result"])
		}
		t.Log("actual installed stdio cancellation: MCP_CANCELLED; server ping remains responsive")
	case <-time.After(time.Second):
		t.Log("actual installed stdio cancellation reply suppressed per protocol; server ping remains responsive")
	}
	if !reflect.DeepEqual(mcpBefore, image()) {
		t.Fatal("stdio positive/refusal/cancel requests changed persistent bytes/modes")
	}
	scratch, err := os.ReadDir(filepath.Join(base, "scratch"))
	if err != nil {
		t.Fatal(err)
	}
	// The held MCP executable stage is transport-owned; source hooks/tools must
	// never populate any execution path. Close removes the transport stage.
	if len(scratch) != 1 || !scratch[0].IsDir() || !strings.HasPrefix(scratch[0].Name(), "tplaiter-held-stage-") {
		t.Fatalf("source execution populated scratch: %v", scratch)
	}
	stageEntries, err := os.ReadDir(filepath.Join(base, "scratch", scratch[0].Name()))
	if err != nil || len(stageEntries) != 1 || stageEntries[0].Name() != "tplaiter" || stageEntries[0].IsDir() {
		t.Fatalf("scratch contains more than the held executable: %v %v", stageEntries, err)
	}
	t.Logf("transport scratch entries while server is live=%d (held executable stage only)", len(scratch))
	t.Logf("actual C03 discovery snapshot=%s; signed get compact-data bytes=%d; required floor=%d", page.Snapshot, content.Bytes, len(content.Packet.RequiredFloor))
	// Corrupt the actual object behind the signed commit. A cached cursor or
	// unchanged mutable project metadata cannot authorize stale retrieval.
	object := filepath.Join(base, "objects", f.source.Commit)
	corrupt, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	corrupt[len(corrupt)-1] ^= 1
	if err = os.WriteFile(object, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	afterTamper := image()
	stale := call("continue", map[string]any{"cursor": page.NextCursor})
	if stale.Status != resultdto.StatusBlocked || len(stale.Data) != 0 || len(stale.Diagnostics) != 2 || stale.Diagnostics[0].Code != "CONTEXT_AUTHENTICATION_FAILED" || stale.Diagnostics[1].Code != "TRUST_SUBJECT_INVALID" {
		t.Fatalf("actual source tamper accepted: %+v", stale)
	}
	if !reflect.DeepEqual(afterTamper, image()) {
		t.Fatal("stale source refusal wrote persistent state")
	}
	t.Log("actual signed commit-object corruption: typed source authentication refusal, no partial data and no persistent writes")
	if err = stdin.Close(); err != nil {
		t.Fatal(err)
	}
	err = server.Wait()
	waited = true
	if err != nil {
		t.Fatalf("stdio shutdown: %v", err)
	}
	scratch, err = os.ReadDir(filepath.Join(base, "scratch"))
	if err != nil || len(scratch) != 0 {
		t.Fatalf("held transport stage leaked: %v %v", scratch, err)
	}
	t.Log("source execution scratch empty after installed stdio shutdown")
}

func contextReadImage(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	image := map[string]string{}
	for n, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			key := fmt.Sprintf("%d/%s", n, rel)
			value := info.Mode().String()
			if !entry.IsDir() {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				h := sha256.New()
				_, err = io.Copy(h, f)
				closeErr := f.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return closeErr
				}
				value += "/" + hex.EncodeToString(h.Sum(nil))
			}
			image[key] = value
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return image
}

// This preview test uses the actual build-time registration command, its
// writer-produced linker pins, trust provision, and the installed CLI/MCP.
func TestLocalPreviewInstalledCommandAndMCP(t *testing.T)      { testLocalPreviewInstalled(t, 2) }
func TestLocalPreviewLargeCatalogSparseInstalled(t *testing.T) { testLocalPreviewInstalled(t, 12) }
func testLocalPreviewInstalled(t *testing.T, sourceCount int) {
	if runtime.GOOS != "darwin" {
		t.Skip("bounded Darwin local preview")
	}
	fixture := startPreviewSynthetic(t, sourceCount)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	projectRoot := filepath.Join(base, "project")
	if err = os.Mkdir(projectRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	if err = os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	projects := []trustload.ProjectContext{{Key: "preview", ProjectID: "project.preview", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: projectRoot}}
	spec := ossinstall.LocalProviderSpec{RegistrationID: "synthetic", ProjectKeys: []string{"preview"}, Protocol: "local-provider.session/v1", Qualification: trustload.LocalObserved, Limits: trustload.LocalReadLimits{FrameBytes: 32768, TotalBytes: 2097152, Pages: 128, SourceBytes: 8192, DeadlineMs: 2000}}
	spec.Endpoint.Kind = "unix"
	spec.Endpoint.SocketPath = fixture.socket
	spec.Endpoint.OwnerUID = uint32(os.Geteuid())
	projectInput := filepath.Join(base, "projects.json")
	providerInput := filepath.Join(base, "providers.json")
	if err = os.WriteFile(projectInput, previewJSON(t, projects), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(providerInput, previewJSON(t, []ossinstall.LocalProviderSpec{spec}), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := exec.CommandContext(ctx, testfixture.GoBinary(t), "run", "./cmd/tplaiter-oss-register", "--root", filepath.Join(base, "installation"), "--project-contexts", projectInput, "--local-providers", providerInput)
	writer.Dir = filepath.Join("..", "..")
	writer.Env = testBuildEnv(home)
	pins, err := writer.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			t.Fatal("real operator writer", e, string(e.Stderr))
		}
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(pins)), "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			t.Fatal("writer pins")
		}
		values[kv[0]] = kv[1]
	}
	bin := filepath.Join(base, "tplaiter")
	build := exec.CommandContext(ctx, testfixture.GoBinary(t), "build", "-trimpath", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+values["REGISTRATION_PATH"]+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+values["REGISTRATION_SHA256"], "-o", bin, ".")
	build.Dir = filepath.Join("..", "..")
	build.Env = testBuildEnv(home)
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	run := func(args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, bin, args...)
		c.Dir = base
		c.Env = testProcessEnv(home)
		return c.Output()
	}
	if out, e := run("trust", "provision"); e != nil {
		if x, ok := e.(*exec.ExitError); ok {
			t.Fatal("provision", string(out), string(x.Stderr))
		}
		t.Fatal(e)
	}
	before := contextReadImage(t, projectRoot, filepath.Join(base, "installation"), home)
	catalogRequest := contextcmd.LocalPreviewRequest{RegistrationID: "synthetic"}
	if sourceCount > 2 {
		catalogRequest.Limit = 1
	}
	raw, e := run("context", "preview-catalog", "--request", string(previewJSON(t, catalogRequest)), "--json")
	if e != nil {
		if x, ok := e.(*exec.ExitError); ok {
			t.Fatal("preview catalog", string(raw), string(x.Stderr))
		}
		t.Fatal(e)
	}
	schemaRaw, err := os.ReadFile("../../schema/context-local-preview.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err = compiler.AddResource("preview.json", schemaDoc); err != nil {
		t.Fatal(err)
	}
	previewSchema, err := compiler.Compile("preview.json")
	if err != nil {
		t.Fatal(err)
	}
	decode := func(raw []byte) resultdto.ContextData {
		env, e := resultdto.Decode(raw)
		if e != nil {
			t.Fatal(e, string(raw))
		}
		var data resultdto.ContextData
		if e = json.Unmarshal(env.Data, &data); e != nil {
			t.Fatal(e)
		}
		if data.LocalPreview == nil || data.LocalPreview.Qualification != trustload.LocalObserved || data.LocalPreview.SourceAuthentication != "none" || data.Packet != nil || len(data.LocalPreview.Metadata.SourceEvidence) != 0 || data.LocalPreview.Selection.CodeIdentity != "unchecked" {
			t.Fatal("false qualification")
		}
		payload := previewJSON(t, data.LocalPreview)
		value, e := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
		if e != nil {
			t.Fatal(e)
		}
		if e = previewSchema.Validate(value); e != nil {
			t.Fatal("actual preview schema", e)
		}
		return data
	}
	catalog := decode(raw)
	if catalog.LocalPreview.CatalogWire != nil || catalog.LocalPreview.Observation.CatalogSHA256 != previewDigest(fixture.catalog) || catalog.LocalPreview.Observation.CatalogByteLength != len(fixture.catalog) {
		t.Fatal("default must retain receipt pin without delivering whole wire")
	}
	if sourceCount > 2 && (len(fixture.catalog) <= 32768 || len(catalog.LocalPreview.Metadata.Records) != 2 || len(catalog.LocalPreview.Assets) != 1) {
		t.Fatalf("large complete catalog must support sparse selected output: wire=%d records=%d assets=%d", len(fixture.catalog), len(catalog.LocalPreview.Metadata.Records), len(catalog.LocalPreview.Assets))
	}
	if len(raw) > 32768 {
		t.Fatal("complete envelope bound")
	}
	diagnostic := catalogRequest
	diagnostic.IncludeCatalogWire = true
	diagnosticRaw, diagnosticErr := run("context", "preview-catalog", "--request", string(previewJSON(t, diagnostic)), "--json")
	if sourceCount > 2 {
		if diagnosticErr == nil || bytes.Contains(diagnosticRaw, []byte(`"localPreview"`)) {
			t.Fatal("oversized complete diagnostic must refuse")
		}
	} else {
		if diagnosticErr != nil {
			t.Fatal("explicit diagnostic", diagnosticErr)
		}
		d := decode(diagnosticRaw)
		if d.LocalPreview.CatalogWire == nil {
			t.Fatal("missing explicit diagnostic")
		}
		observed, e := base64.StdEncoding.DecodeString(d.LocalPreview.CatalogWire.Data)
		if e != nil || !bytes.Equal(observed, fixture.catalog) {
			t.Fatal("diagnostic wire bytes changed")
		}
	}
	asset := catalog.LocalPreview.Assets[0]
	req := contextcmd.LocalPreviewRequest{RegistrationID: "synthetic", SourceID: asset.SourceID, AssetID: asset.AssetID, ExpectedCatalogSHA256: catalog.Snapshot, MaxBytes: 32768}
	for _, a := range catalog.LocalPreview.Assets {
		req.Required = append(req.Required, a.ItemID)
	}
	if sourceCount > 2 {
		alias := strings.TrimPrefix(asset.SourceID, "example:source:")
		req.Required = []string{"example:resource:" + alias + "-readme", "example:resource:" + alias + "-guide"}
	}
	raw, e = run("context", "preview-resource", "--request", string(previewJSON(t, req)), "--json")
	if e != nil {
		t.Fatal("resource", e, string(raw))
	}
	resource := decode(raw)
	expectedBodies := 4
	if sourceCount > 2 {
		expectedBodies = 2
	}
	if len(resource.LocalPreview.Resources) != expectedBodies {
		t.Fatalf("body floor got %d want %d; selected=%s", len(resource.LocalPreview.Resources), expectedBodies, asset.ItemID)
	}
	for _, observed := range resource.LocalPreview.Resources {
		body, e := base64.StdEncoding.DecodeString(observed.Data)
		if e != nil || string(body) != fixture.bodies[observed.AssetID] || previewDigest(body) != observed.ContentSHA256 {
			t.Fatal("body observation")
		}
	}
	for _, bad := range []string{`{"registrationID":"synthetic","socketPath":"/caller"}`, `{"registrationID":"missing"}`, `{"registrationID":"synthetic","maxBytes":1}`, `{"registrationID":"synthetic","required":["example:resource:absent"]}`, `{"registrationID":"synthetic","required":["example:resource:preview-00-readme","example:resource:preview-00-guide"],"maxRecords":1}`} {
		if _, e = run("context", "preview-catalog", "--request", bad, "--json"); e == nil {
			t.Fatal("invalid local request succeeded")
		}
	}
	for _, fault := range []int32{1, 2} {
		fixture.fault.Store(fault)
		started := time.Now()
		failed, e := run("context", "preview-catalog", "--registration", "synthetic", "--json")
		if e == nil || time.Since(started) > 4*time.Second || bytes.Contains(failed, []byte(`"localPreview"`)) {
			t.Fatal("slow/partial peer must refuse within deadline without partial preview")
		}
	}
	fixture.fault.Store(0)
	server := exec.CommandContext(ctx, bin, "mcp-server")
	server.Dir = base
	server.Env = testProcessEnv(home)
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
	waited := false
	defer func() {
		if !waited {
			_ = stdin.Close()
			_ = server.Wait()
		}
	}()
	encoder := json.NewEncoder(stdin)
	decoder := json.NewDecoder(stdout)
	next := 0
	call := func(method string, params any) map[string]json.RawMessage {
		next++
		id := next
		if e = encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); e != nil {
			t.Fatal(e)
		}
		for {
			var reply map[string]json.RawMessage
			if e = decoder.Decode(&reply); e != nil {
				t.Fatal(e, stderr.String())
			}
			var got int
			_ = json.Unmarshal(reply["id"], &got)
			if got == id {
				if reply["error"] != nil {
					t.Fatal("MCP error", string(reply["error"]))
				}
				return reply
			}
		}
	}
	call("initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "public-local-preview", "version": "1"}})
	if e = encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); e != nil {
		t.Fatal(e)
	}
	listed := call("tools/list", map[string]any{})
	var inventory struct {
		Tools []json.RawMessage `json:"tools"`
	}
	_ = json.Unmarshal(listed["result"], &inventory)
	if len(inventory.Tools) != 30 {
		t.Fatal("native tool inventory changed", len(inventory.Tools))
	}
	reply := call("tools/call", map[string]any{"name": "context", "arguments": map[string]any{"action": "preview-catalog", "preview": catalogRequest}})
	var result struct {
		Structured json.RawMessage `json:"structuredContent"`
		IsError    bool            `json:"isError"`
	}
	result.IsError = false
	if e = json.Unmarshal(reply["result"], &result); e != nil || result.IsError {
		t.Fatal("MCP preview failed", string(reply["result"]))
	}
	mcpData := decode(result.Structured)
	if mcpData.Snapshot != catalog.Snapshot {
		t.Fatal("shared route pins changed")
	}
	reply = call("tools/call", map[string]any{"name": "context", "arguments": map[string]any{"action": "preview-catalog", "preview": diagnostic}})
	result.IsError = false
	if e = json.Unmarshal(reply["result"], &result); e != nil {
		t.Fatal(e)
	}
	if sourceCount > 2 {
		if !result.IsError || bytes.Contains(result.Structured, []byte(`"localPreview"`)) {
			t.Fatal("MCP oversized full diagnostic must refuse")
		}
	} else {
		if result.IsError {
			t.Fatal("MCP explicit diagnostic", string(reply["result"]))
		}
		d := decode(result.Structured)
		if d.LocalPreview.CatalogWire == nil {
			t.Fatal("MCP diagnostic absent")
		}
		observed, e := base64.StdEncoding.DecodeString(d.LocalPreview.CatalogWire.Data)
		if e != nil || !bytes.Equal(observed, fixture.catalog) {
			t.Fatal("MCP exact diagnostic")
		}
	}

	reply = call("resources/read", map[string]any{"uri": asset.ResourceURI})
	var read struct {
		Contents []struct {
			Text string `json:"text"`
		} `json:"contents"`
	}
	if e = json.Unmarshal(reply["result"], &read); e != nil || len(read.Contents) != 1 {
		t.Fatal("resource callback", e)
	}
	var callback resultdto.ContextData
	if e = json.Unmarshal([]byte(read.Contents[0].Text), &callback); e != nil || callback.LocalPreview == nil || len(callback.LocalPreview.Resources) == 0 {
		t.Fatal("resource preview callback", e)
	}
	reply = call("tools/call", map[string]any{"name": "context", "arguments": map[string]any{"action": "preview-resource", "preview": req}})
	result.IsError = false
	if e = json.Unmarshal(reply["result"], &result); e != nil || result.IsError {
		t.Fatal("MCP body", string(reply["result"]))
	}
	decode(result.Structured)
	reply = call("tools/call", map[string]any{"name": "context", "arguments": map[string]any{"action": "preview-catalog", "preview": map[string]any{"registrationID": "synthetic", "maxBytes": 1}}})
	_ = json.Unmarshal(reply["result"], &result)
	if !result.IsError {
		t.Fatal("MCP full envelope budget ignored")
	}
	_ = stdin.Close()
	err = server.Wait()
	waited = true
	if err != nil {
		t.Fatal("MCP shutdown", err, stderr.String())
	}
	if !reflect.DeepEqual(before, contextReadImage(t, projectRoot, filepath.Join(base, "installation"), home)) {
		t.Fatal("preview mutated persistent state")
	}
	t.Log("actual operator-command v2 pins, installed CLI/MCP two-page catalog/body/resource callback/refusals, 30 tools and zero writes PASS")
}
