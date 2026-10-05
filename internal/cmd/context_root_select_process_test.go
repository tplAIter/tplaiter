package cmd

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/mcpsrv"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func rootB2Source(t *testing.T, repo string, variant string) string {
	t.Helper()
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: neutral-context\n  version: 1.0.0\nengine:\n  type: gotemplate\n  root: files\n")
	contract := rootB2JSON(t, operationtrust.NativeContract{APIVersion: operationtrust.NativeContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: []string{}})
	contractDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", evidencecas.Digest(contract)})
	if err != nil {
		t.Fatal(err)
	}
	tool := []byte("Readonly task context, no tool execution.\n")
	files := map[string][]byte{"template.manifest.yaml": manifest, "template.contract.json": contract, "files/hello.txt.tmpl": []byte("hello\n"), contextcmd.DefaultRootBindingsPath: []byte(`{"apiVersion":"tplaiter.dev/context-root-bindings/v1","kind":"ContextRootBindings","source":{"alias":"base","providerID":"neutral","parameters":[],"entriesPath":"catalog/entries.json","payloadDirectory":"catalog/payloads","toolPath":"catalog/tool.md"}}`), "catalog/tool.md": tool}
	entries := []exports.ExportEntry{}
	for _, v := range []struct{ id, domain, name, body string }{{"context", "block", "context", "Retain source pins and prerequisites.\n"}, {"review", "skill", "review", "Review the public project.\n"}, {"careful", "approach", "careful", "Read the project context before changes.\n"}} {
		if variant == "missing-floor" && v.id == "context" {
			continue
		}
		body := []byte(v.body)
		if variant == "large-image" && v.id == "review" {
			body = bytes.Repeat([]byte("complete resource bytes\n"), 300)
		}
		sourcePath := "resources/" + v.id + ".md"
		payload := rootB2JSON(t, exports.ExportPayload{APIVersion: exports.ExportPayloadAPIVersion, ExportID: v.id, Files: []exports.PayloadFile{{SourcePath: sourcePath, TargetPath: "context/" + v.id + ".md", Mode: "100644", ContentSHA256: evidencecas.Digest(body)}}, Slots: []exports.PayloadSlot{}, Blocks: []exports.PayloadBlock{}})
		requires := []exports.ExportRequirement{}
		if v.id != "context" {
			requires = append(requires, exports.ExportRequirement{Selector: "base.block.context", ContractDigest: contractDigest, CompatibleRange: ">=1.0.0 <2.0.0"})
		}
		entries = append(entries, exports.ExportEntry{ID: v.id, Domain: v.domain, Name: v.name, Version: "1.0.0", ContentDigest: evidencecas.Digest(payload), Parameters: []exports.ScalarParameter{}, ToolDigest: evidencecas.Digest(tool), Requires: requires})
		files[sourcePath] = body
		files["catalog/payloads/"+v.id+".json"] = payload
	}
	files["catalog/entries.json"] = rootB2JSON(t, entries)
	switch variant {
	case "missing-binding":
		delete(files, contextcmd.DefaultRootBindingsPath)
	case "tool-mismatch":
		files["catalog/tool.md"] = []byte("changed signed tool declaration\n")
	case "malformed-duplicate":
		files["catalog/entries.json"] = []byte(strings.Replace(string(files["catalog/entries.json"]), `"id":"context"`, `"id":"context","id":"context"`, 1))
	}
	objects := map[string][]byte{}
	add := func(kind string, b []byte) string {
		raw := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(b))), b...)
		h := sha1.Sum(raw)
		id := hex.EncodeToString(h[:])
		objects[id] = raw
		return id
	}
	var tree func(string) string
	tree = func(prefix string) string {
		names := map[string]bool{}
		for p := range files {
			if strings.HasPrefix(p, prefix) {
				names[strings.SplitN(strings.TrimPrefix(p, prefix), "/", 2)[0]] = true
			}
		}
		ordered := []string{}
		for n := range names {
			ordered = append(ordered, n)
		}
		sort.Strings(ordered)
		var raw []byte
		for _, n := range ordered {
			p := prefix + n
			mode := "100644"
			id := ""
			if b, ok := files[p]; ok {
				id = add("blob", b)
			} else {
				mode = "40000"
				id = tree(p + "/")
			}
			oid, _ := hex.DecodeString(id)
			raw = append(raw, []byte(mode+" "+n+"\x00")...)
			raw = append(raw, oid...)
		}
		return add("tree", raw)
	}
	commit := add("commit", []byte("tree "+tree("")+"\n\nPublic synthetic ROOT fixture; no upstream authorship claim.\n"))
	for id, raw := range objects {
		p := filepath.Join(repo, ".git", "objects", id[:2], id[2:])
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		f, e := os.Create(p)
		if e != nil {
			t.Fatal(e)
		}
		z := zlib.NewWriter(f)
		if _, e = z.Write(raw); e != nil {
			t.Fatal(e)
		}
		if e = z.Close(); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
	}
	if err = os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\nrepositoryformatversion=0\nbare=false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return commit
}

// Generate and normal installed new create all source evidence and lock pairs.
// This fixture makes no upstream publisher-authorship claim.
type rootB2Fixture struct {
	bin, base, project, home, install, objects string
	in                                         invocation
	source                                     operationtrust.SourceSelection
}

func normalRootB2Fixture(t *testing.T) *rootB2Fixture { t.Helper(); return normalRootB2Variant(t, "") }
func normalRootB2Variant(t *testing.T, variant string) *rootB2Fixture {
	t.Helper()
	testfixture.RequireTrustStore(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(base, "public-fixture")
	commit := rootB2Source(t, repo, variant)
	home := filepath.Join(base, "home")
	project := filepath.Join(base, "project")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	generated, err := ossinstall.GenerateWithContext(context.Background(), ossinstall.Options{Root: filepath.Join(base, "install"), LocalSources: []sourcepackage.CaptureInput{{RepositoryPath: repo, Origin: "https://example.test/neutral-context", TemplatePath: ".", Commit: commit}}, ProjectContexts: []trustload.ProjectContext{{Key: "root", ProjectID: "project-root-fixture", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: project}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(generated.RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := ossinstall.DecodeRegistration(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(generated.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var selections []operationtrust.SourceSelection
	if err = json.Unmarshal(raw, &selections); err != nil || len(selections) != 1 {
		t.Fatal("normal source enrollment", err)
	}
	selectionPath := filepath.Join(base, "source-selection.json")
	if err = os.WriteFile(selectionPath, rootB2JSON(t, selections[0]), 0600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-trimpath", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+generated.RegistrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+generated.RegistrationSHA256, "-o", bin, ".")
	build.Dir = testfixture.ModuleRoot(t)
	cacheCmd := exec.Command(testfixture.GoBinary(t), "env", "GOMODCACHE")
	cache, err := cacheCmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	build.Env = []string{"PATH=" + filepath.Join(testfixture.GoRoot(t), "bin") + ":/usr/bin:/bin", "HOME=" + home, "GOCACHE=/private/tmp/tplaiter-root-b1-gocache", "GOMODCACHE=" + strings.TrimSpace(string(cache)), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off", "CGO_ENABLED=0"}
	if raw, e := build.CombinedOutput(); e != nil {
		t.Fatalf("normal installed build: %v %s", e, raw)
	}
	f := &rootB2Fixture{bin: bin, base: base, project: project, home: home, install: generated.Root, in: invocation{Selection: registration.Selection(), ProjectKey: "root", Clock: bootstrap.ClockFunc(time.Now)}, source: selections[0]}
	if raw, e := f.run("trust", "provision"); e != nil {
		t.Fatalf("normal provision: %v %s", e, raw)
	}
	if raw, e := f.run("new", commit, "project", "--dir", project, "--source-input", selectionPath, "--defaults", "--no-hooks", "--json"); e != nil {
		t.Fatalf("normal new: %v %s", e, raw)
	}
	loaded, err := trustload.Load(context.Background(), registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	f.objects = loaded.Install.ObjectOrigins[0].RootPath
	image, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("installed image=%s registration=%s source=%s contract=%s", evidencecas.Digest(image), generated.RegistrationSHA256, selections[0].Subject.Commit, selections[0].Subject.ContractSHA256)
	t.Log("Generate -> installed trust provision -> normal new; source authority=local operator, synthetic public data")
	return f
}
func (f *rootB2Fixture) command(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, f.bin, args...)
	c.Dir = f.base
	c.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + f.home, "TPLAITER_HOME=" + f.home}
	return c
}
func (f *rootB2Fixture) run(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return f.command(ctx, args...).CombinedOutput()
}
func rootB2Image(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			value := info.Mode().String()
			if !d.IsDir() {
				b, e := os.ReadFile(p)
				if e != nil {
					return e
				}
				value += evidencecas.Digest(b)
			}
			out[p] = value
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return out
}
func rootB2AssertLease(t *testing.T, project string, held bool) {
	t.Helper()
	path := filepath.Join(project, ".tplaiter", "update.lock")
	// Use the actual native writer coordination inode, not an invented lock.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if os.IsNotExist(err) {
		// Normal new has no native writer receipt and leaves this inode absent.
		// Do not create one to manufacture a flock proof. The retained real
		// RootSelection is tested explicitly in rootB2HeldProtocol below.
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if held && err == nil {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		t.Fatal("ROOT read lease released before final write")
	}
	if !held && err != nil {
		t.Fatal("ROOT read lease leaked after delivery", err)
	}
	if err == nil {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}
}

type rootB2InspectWriter struct {
	t       *testing.T
	project string
	out     bytes.Buffer
	broken  bool
}

func (w *rootB2InspectWriter) Write(b []byte) (int, error) {
	rootB2AssertLease(w.t, w.project, true)
	if w.broken {
		return 0, io.ErrClosedPipe
	}
	return w.out.Write(b)
}
func rootB2Leaf(t *testing.T, f *rootB2Fixture, req contextcmd.RootSelectionRequest, w io.Writer) error {
	t.Helper()
	c := newContextRootSelectCmd()
	c.SilenceErrors = true
	c.SilenceUsage = true
	c.SetContext(withInvocation(context.Background(), f.in))
	c.SetArgs([]string{"--request=" + string(rootB2JSON(t, req)), "--json"})
	c.SetOut(w)
	c.SetErr(io.Discard)
	return c.Execute()
}
func TestRootB2NormalCreatedRootLeafHoldsLease(t *testing.T) {
	f := normalRootB2Fixture(t)
	before := rootB2Image(t, f.project, f.home, f.install)
	rootB2HeldProtocol(t, f)
	for _, selector := range []string{"base.block.context", "base.skill.review", "base.approach.careful"} {
		w := &rootB2InspectWriter{t: t, project: f.project}
		if err := rootB2Leaf(t, f, rootB2Request(selector), w); err != nil {
			t.Fatal(err)
		}
		rootB2AssertLease(t, f.project, false)
		env, err := resultdto.Decode(w.out.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		var outer resultdto.ContextData
		if err = json.Unmarshal(env.Data, &outer); err != nil || outer.NativeRootSelection == nil {
			t.Fatal("registered ROOT DTO absent", err)
		}
		data := *outer.NativeRootSelection
		want := 1
		if selector != "base.block.context" {
			want = 2
		}
		if len(data.Body.Files) != want || len(data.Body.Graph.Selected) != want || len(data.Body.Packet.RequiredFloor) == 0 {
			t.Fatal("full required closure lost")
		}
		if data.Body.Packet.Sources[0].Anchor.Subject() != f.source.TrustSubject() {
			t.Fatal("pins changed")
		}
		for _, file := range data.Body.Files {
			if evidencecas.Digest(file.Content) != file.ContentSHA256 || file.SelectedIdentity == "" {
				t.Fatal("full image lost")
			}
		}
		t.Logf("normal installed leaf selector=%s files=%d required=%d CLI-frame=%d wire=%d image-output=%d pin=%s", selector, want, len(data.Body.Packet.RequiredFloor), w.out.Len(), data.Delivery.EnvelopeBytes, data.Delivery.Spending.OutputBytes, f.source.TrustSubject().Commit)
	}
	for name, req := range map[string]contextcmd.RootSelectionRequest{
		"unknown":        rootB2Request("base.skill.absent"),
		"duplicate":      rootB2Request("base.skill.review", "base.skill.review"),
		"missing":        {Selections: []exports.Selection{}},
		"stale-snapshot": {Selections: rootB2Request("base.skill.review").Selections, Snapshot: evidencecas.Digest([]byte("old"))},
		"whole-budget":   {Selections: rootB2Request("base.skill.review").Selections, MaxBytes: 100},
	} {
		var out bytes.Buffer
		if err := rootB2Leaf(t, f, req, &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid selection emitted bytes", name, err)
		}
		t.Log("whole refusal", name)
	}

	w := &rootB2InspectWriter{t: t, project: f.project, broken: true}
	if !errors.Is(rootB2Leaf(t, f, rootB2Request("base.block.context"), w), io.ErrClosedPipe) {
		t.Fatal("broken pipe accepted")
	}
	rootB2AssertLease(t, f.project, false)
	if !reflect.DeepEqual(before, rootB2Image(t, f.project, f.home, f.install)) {
		t.Fatal("read-only ROOT mutated state")
	}
	// The direct leaf is separately qualified; installed route acceptance below
	// must pass before claiming CLI/MCP product closure.
}

func TestRootB2InstalledCLIAndMCP(t *testing.T) {
	f := normalRootB2Fixture(t)
	before := rootB2Image(t, f.project, f.home, f.install)
	server := rootB2StartMCP(t, f)
	for i, selectors := range [][]string{{"base.block.context"}, {"base.skill.review"}, {"base.approach.careful"}, {"base.skill.review", "base.block.context"}} {
		req := rootB2Request(selectors...)
		raw, err := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json")
		if err != nil {
			t.Fatalf("installed CLI: %v %s", err, raw)
		}
		cli := rootB2DecodeSuccess(t, f, raw, len(selectors) == 1 && selectors[0] == "base.block.context")
		id := fmt.Sprintf("<ROOT-%d>&\\frame", i)
		frame := server.call(t, id, map[string]any{"action": "select", "rootSelection": req})
		mcpData := rootB2DecodeMCP(t, f, frame, len(selectors) == 1 && selectors[0] == "base.block.context")
		if !reflect.DeepEqual(cli, mcpData) {
			t.Fatal("complete CLI/MCP bodies, floors, graph, images or pins differ")
		}
		if len(frame) > 32768 {
			t.Fatal("MCP final frame exceeds ceiling")
		}
		t.Logf("actual installed selection=%v CLI=%d MCP=%d outerDTO=%d required=%d graph=%s", selectors, len(raw), len(frame), cli.Bytes, len(cli.NativeRootSelection.Body.Packet.RequiredFloor), cli.NativeRootSelection.Body.Graph.Digest)
		// One source owns all selected exports and the shared prerequisite identity.
		if len(selectors) == 2 {
			found := false
			for _, v := range cli.NativeRootSelection.Body.Graph.Selected {
				if v.Domain == "block" {
					found = true
					if len(v.Chains) != 2 {
						t.Fatal("shared block selection chains incomplete")
					}
				}
			}
			if !found {
				t.Fatal("required block omitted")
			}
		}
	}
	// Require exactly the observed snapshot; neither route may use stale pins.
	req := rootB2Request("base.skill.review")
	raw, e := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json")
	if e != nil {
		t.Fatal(e)
	}
	valid := rootB2DecodeSuccess(t, f, raw, false)
	req.Snapshot = valid.Snapshot
	if out, e := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json"); e != nil {
		t.Fatal("expected current snapshot refused", e, string(out))
	}
	req.Snapshot = evidencecas.Digest([]byte("stale"))
	rootB2RefusedMCP(t, server.call(t, "stale", map[string]any{"action": "select", "rootSelection": req}), contextcmd.Stale)
	if out, e := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json"); e == nil || bytes.Contains(out, []byte(`"nativeRootSelection"`)) {
		t.Fatal("stale installed CLI delivered body")
	}
	for name, args := range map[string]map[string]any{
		"unknown":           {"action": "select", "rootSelection": rootB2Request("base.skill.absent")},
		"duplicate":         {"action": "select", "rootSelection": rootB2Request("base.skill.review", "base.skill.review")},
		"missing":           {"action": "select", "rootSelection": map[string]any{}},
		"request-mix":       {"action": "select", "rootSelection": rootB2Request("base.block.context"), "request": map[string]any{}},
		"request-null":      {"action": "select", "rootSelection": rootB2Request("base.block.context"), "request": nil},
		"preview-null":      {"action": "select", "rootSelection": rootB2Request("base.block.context"), "preview": nil},
		"root-null-query":   {"action": "discover", "rootSelection": nil},
		"preview-mix":       {"action": "select", "rootSelection": rootB2Request("base.block.context"), "preview": map[string]any{}},
		"query-mix":         {"action": "discover", "rootSelection": rootB2Request("base.block.context")},
		"unknown-authority": {"action": "select", "rootSelection": map[string]any{"selections": rootB2Request("base.block.context").Selections, "authenticated": true}},
		"whole-budget":      {"action": "select", "rootSelection": contextcmd.RootSelectionRequest{Selections: rootB2Request("base.skill.review").Selections, MaxBytes: 100}},
	} {
		rootB2RefusedMCP(t, server.call(t, name, args), "")
		t.Log("actual installed whole refusal", name)
	}
	// Find the actual complete MCP frame boundary, with a large escaped ID, while
	// keeping the B1 mandatory local retrieval obligations fully satisfied.
	req = rootB2Request("base.skill.review")
	req.MaxBytes = 32768
	largeID := strings.Repeat("<", 650)
	frame := server.call(t, largeID, map[string]any{"action": "select", "rootSelection": req})
	_ = rootB2DecodeMCP(t, f, frame, false)
	req.MaxBytes = len(frame)
	at := server.call(t, largeID, map[string]any{"action": "select", "rootSelection": req})
	_ = rootB2DecodeMCP(t, f, at, false)
	if len(at) != req.MaxBytes {
		t.Fatalf("actual exact outer boundary changed: %d vs %d", len(at), req.MaxBytes)
	}
	req.MaxBytes--
	rootB2RefusedMCP(t, server.call(t, largeID, map[string]any{"action": "select", "rootSelection": req}), contextcmd.Budget)
	t.Logf("actual full MCP boundary=%d (ID/summary/floor/graph/images/base64/escaping/newline); boundary-1 whole refusal", len(at))
	// Queue two calls together. Correlation and cleanup must preserve each full
	// authenticated body when their installed child processes finish concurrently.
	for _, id := range []string{"concurrent-a", "concurrent-b"} {
		server.write(t, rootB2ToolCall(id, map[string]any{"action": "select", "rootSelection": rootB2Request("base.block.context")}))
	}
	seen := map[string]bool{}
	for range 2 {
		line := server.read(t)
		var response struct {
			ID string `json:"id"`
		}
		json.Unmarshal(line, &response)
		if seen[response.ID] || !strings.HasPrefix(response.ID, "concurrent-") {
			t.Fatal("concurrent correlation crossed")
		}
		seen[response.ID] = true
		_ = rootB2DecodeMCP(t, f, line, true)
	}
	// Cancellation arrives in the same write as the queued request, before the
	// SDK worker necessarily installs its handler context. No cancelled body leaks.
	request := rootB2JSON(t, rootB2ToolCall("cancel-queued", map[string]any{"action": "select", "rootSelection": rootB2Request("base.skill.review")}))
	notify := rootB2JSON(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": "cancel-queued"}})
	joined := append(append(append(request, '\n'), notify...), '\n')
	if _, e = server.stdin.Write(joined); e != nil {
		t.Fatal(e)
	}
	rootB2RefusedMCP(t, server.read(t), "MCP_CANCELLED")
	_ = rootB2DecodeMCP(t, f, server.call(t, "after-cancel", map[string]any{"action": "select", "rootSelection": rootB2Request("base.block.context")}), true)
	server.close(t)
	rootB2InstalledDelivery(t, f)
	rootB2InstalledBrokenMCP(t, f)
	rootB2InstalledOrdinaryBlockedStdout(t, f)
	if !reflect.DeepEqual(before, rootB2Image(t, f.project, f.home, f.install)) {
		t.Fatal("installed CLI/MCP mutated project, home, evidence or source objects")
	}
	t.Log("actual installed CLI + held-stage stdio MCP registered complete ROOT routing, read-only image and cleanup passed")
}

type rootB2MCP struct {
	stdin  io.WriteCloser
	reader *bufio.Reader
	child  *exec.Cmd
	cancel context.CancelFunc
	stderr bytes.Buffer
	closed bool
	stdout io.ReadCloser
}

func rootB2StartMCP(t *testing.T, f *rootB2Fixture) *rootB2MCP {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	c := f.command(ctx, "mcp-server")
	s := &rootB2MCP{child: c, cancel: cancel}
	var err error
	s.stdin, err = c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	s.stdout = stdout
	s.reader = bufio.NewReader(stdout)
	c.Stderr = &s.stderr
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !s.closed {
			s.stdin.Close()
			cancel()
			_ = c.Wait()
		}
	})
	s.write(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "public-root-fixture", "version": "1"}}})
	s.read(t)
	s.write(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return s
}
func (s *rootB2MCP) write(t *testing.T, v any) {
	t.Helper()
	if _, e := s.stdin.Write(append(rootB2JSON(t, v), '\n')); e != nil {
		t.Fatal(e)
	}
}
func (s *rootB2MCP) read(t *testing.T) []byte {
	t.Helper()
	line, e := s.reader.ReadBytes('\n')
	if e != nil {
		t.Fatalf("actual stdio: %v %s", e, s.stderr.String())
	}
	return line
}
func rootB2ToolCall(id string, args map[string]any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "context", "arguments": args}}
}
func (s *rootB2MCP) call(t *testing.T, id string, args map[string]any) []byte {
	t.Helper()
	s.write(t, rootB2ToolCall(id, args))
	line := s.read(t)
	var response struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(line, &response) != nil || response.ID != id {
		t.Fatal("wrong protocol correlation")
	}
	return line
}
func (s *rootB2MCP) close(t *testing.T) {
	t.Helper()
	s.stdin.Close()
	if e := s.child.Wait(); e != nil {
		t.Fatalf("MCP normal cleanup: %v %s", e, s.stderr.String())
	}
	s.cancel()
	s.closed = true
}
func rootB2DecodeSuccess(t *testing.T, f *rootB2Fixture, raw []byte, block bool) resultdto.ContextData {
	t.Helper()
	env, e := resultdto.Decode(raw)
	if e != nil || env.Status != resultdto.StatusOK || env.Operation != resultdto.OperationContextQuery {
		t.Fatal("not a complete successful CLI result", e)
	}
	rootB2ValidateRegisteredSchema(t, raw)
	return rootB2AssertData(t, f, env.Data, block)
}
func rootB2DecodeMCP(t *testing.T, f *rootB2Fixture, frame []byte, block bool) resultdto.ContextData {
	t.Helper()
	var response struct {
		Result struct {
			IsError           bool             `json:"isError"`
			StructuredContent resultdto.Result `json:"structuredContent"`
		} `json:"result"`
	}
	if e := json.Unmarshal(frame, &response); e != nil || response.Result.IsError || response.Result.StructuredContent.Status != resultdto.StatusOK {
		t.Fatalf("actual MCP refused successful complete ROOT request: %s %v", frame, e)
	}
	rootB2ValidateRegisteredSchema(t, rootB2JSON(t, response.Result.StructuredContent))
	return rootB2AssertData(t, f, response.Result.StructuredContent.Data, block)
}
func rootB2AssertData(t *testing.T, f *rootB2Fixture, raw []byte, block bool) resultdto.ContextData {
	t.Helper()
	var outer resultdto.ContextData
	if e := json.Unmarshal(raw, &outer); e != nil || outer.NativeRootSelection == nil {
		t.Fatal("typed outer root DTO absent", e)
	}
	if outer.Action != "select" || outer.Bytes != len(raw) || outer.WindowState != "unknown" || outer.LocalPreview != nil {
		t.Fatal("outer sizing/qualification contract")
	}
	data := outer.NativeRootSelection
	want := 2
	if block {
		want = 1
	}
	if data.Body.Snapshot != outer.Snapshot || len(data.Body.Files) != want || len(data.Body.Graph.Selected) != want || len(data.Body.Packet.RequiredFloor) == 0 {
		t.Fatal("mandatory floor/closure/images missing")
	}
	if data.Body.Packet.Sources[0].Anchor.Subject() != f.source.TrustSubject() {
		t.Fatal("authenticated source pins changed")
	}
	pin := data.Body.Packet.Sources[0].Pin
	if pin.Commit != f.source.Subject.Commit || pin.ContractDigest != f.source.Subject.ContractSHA256 || pin.EvidenceDigest != f.source.EvidenceRefs().StatementCAS || pin.Alias != "base" || pin.ProviderID != "neutral" {
		t.Fatal("complete source evidence pins lost")
	}
	if data.Body.Qualification != "authenticated-installed-native-root" || data.Body.MaterializationScope != "task-context-preview" {
		t.Fatal("root authority qualification")
	}
	for _, file := range data.Body.Files {
		if evidencecas.Digest(file.Content) != file.ContentSHA256 || file.SelectedIdentity == "" || file.Mode != "100644" {
			t.Fatal("full file content, identity or mode lost")
		}
	}
	body, _ := json.Marshal(data.Body)
	if evidencecas.Digest(body) != data.Delivery.BodySHA256 {
		t.Fatal("complete body digest mismatch")
	}
	return outer
}
func rootB2RefusedMCP(t *testing.T, frame []byte, code string) {
	t.Helper()
	var response struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError           bool             `json:"isError"`
			StructuredContent resultdto.Result `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(frame, &response) != nil || (!response.Result.IsError && response.Error == nil) {
		t.Fatalf("invalid ROOT request succeeded: %s", frame)
	}
	if bytes.Contains(frame, []byte(`"nativeRootSelection"`)) {
		t.Fatal("refusal leaked complete or partial ROOT resources")
	}
	if code != "" && !bytes.Contains(frame, []byte(code)) {
		t.Fatalf("expected %s refusal: %s", code, frame)
	}
}

func rootB2HeldProtocol(t *testing.T, f *rootB2Fixture) {
	t.Helper()
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.in.Selection, ProjectKey: "root", Clock: f.in.Clock})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	for _, mode := range []string{"complete", "tampered-lock", "tampered-source", "wrong-correlation", "cancel"} {
		ctx, cancel := context.WithCancel(context.Background())
		selected, err := contextcmd.BeginRootSelection(ctx, runtime, rootB2Request("base.skill.review"))
		if err != nil {
			t.Fatal(err)
		}
		token := strings.Repeat("ab", 32)
		digest := evidencecas.Digest(rootB2JSON(t, selected.Result()))
		controlReader, controlWriter := io.Pipe()
		replyReader, replyWriter := io.Pipe()
		done := make(chan error, 1)
		go func() {
			defer selected.Close()
			defer controlReader.Close()
			defer replyWriter.Close()
			done <- serveRootDelivery(ctx, selected, controlReader, replyWriter, token, digest)
		}()
		message := rootDeliveryMessage{rootDeliveryVersion, token, 1, "recheck", digest}
		var saved []byte
		lockPath := filepath.Join(f.project, ".tplaiter", "root-template.lock.json")
		if mode == "tampered-lock" {
			saved, err = os.ReadFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(lockPath, append(append([]byte(nil), saved...), ' '), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if mode == "tampered-source" {
			lockPath = filepath.Join(f.objects, f.source.Subject.Commit)
			saved, err = os.ReadFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			changed := append([]byte(nil), saved...)
			changed[len(changed)-1] ^= 1
			if err = os.WriteFile(lockPath, changed, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if mode == "wrong-correlation" {
			message.Token = strings.Repeat("cd", 32)
		}
		if mode == "cancel" {
			cancel()
		} else {
			if _, err = controlWriter.Write(append(rootB2JSON(t, message), '\n')); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(replyReader)
			line, e := reader.ReadBytes('\n')
			if mode == "complete" {
				if e != nil {
					t.Fatal(e)
				}
				var reply rootDeliveryMessage
				if json.Unmarshal(line, &reply) != nil || reply.Action != "ready" {
					t.Fatal("missing ready reply")
				}
				// This is the same real carrier retained by the child protocol, authenticated
				// from the normal installed project. It survives ready and the final write.
				if err = selected.Recheck(ctx); err != nil || len(selected.Result().Body.Files) != 2 {
					t.Fatal("actual ROOT read session ended before final write", err)
				}
				var final bytes.Buffer
				if err = writeRootFrame(&final, rootB2JSON(t, selected.Result())); err != nil {
					t.Fatal(err)
				}
				if len(selected.Result().Body.Files) != 2 {
					t.Fatal("actual ROOT session ended during final write")
				}
				message.Sequence = 2
				message.Action = "complete"
				if _, err = controlWriter.Write(append(rootB2JSON(t, message), '\n')); err != nil {
					t.Fatal(err)
				}
				line, e = reader.ReadBytes('\n')
				if e != nil || json.Unmarshal(line, &reply) != nil || reply.Action != "closed" {
					t.Fatal("complete did not close retained session", e)
				}
			} else if e == nil {
				t.Fatal("invalid final recheck accepted", mode)
			}
		}
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("ROOT protocol did not release", mode)
		}
		if mode == "complete" && err != nil {
			t.Fatal(err)
		}
		if mode != "complete" && err == nil {
			t.Fatal("negative accepted", mode)
		}
		if len(selected.Result().Body.Files) != 0 {
			t.Fatal("actual retained source authority leaked", mode)
		}
		cancel()
		controlWriter.Close()
		replyReader.Close()
		if saved != nil {
			if err = os.WriteFile(lockPath, saved, 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Log("actual normal ROOT carrier ready/write/close counter", mode)
	}
}

func TestRootB2NormalCreatedMissingRequiredBlock(t *testing.T) {
	f := normalRootB2Variant(t, "missing-floor")
	var out bytes.Buffer
	if err := rootB2Leaf(t, f, rootB2Request("base.skill.review"), &out); err == nil || out.Len() != 0 {
		t.Fatal("skill missing signed required block was delivered", err)
	}
	req := rootB2Request("base.skill.review")
	if raw, err := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json"); err == nil || bytes.Contains(raw, []byte(`"nativeRootSelection"`)) {
		t.Fatal("registered CLI delivered missing mandatory block", err)
	}
	server := rootB2StartMCP(t, f)
	rootB2RefusedMCP(t, server.call(t, "missing-floor", map[string]any{"action": "select", "rootSelection": req}), "")
	server.close(t)
	t.Log("normal enrolled ROOT skill without declared required block: whole refusal, zero resource bytes")
}

// This is the normally compiled, installed CLI child used by MCP, with the
// same closed fd3/fd4 delivery contract. No test binary replaces admission.
func rootB2InstalledDelivery(t *testing.T, f *rootB2Fixture) {
	t.Helper()
	for _, mode := range []string{"complete", "source-tamper", "lock-tamper", "cancel", "deadline", "broken-output", "wrong-digest", "duplicate-sequence"} {
		deadline := 8 * time.Second
		if mode == "deadline" {
			deadline = 3 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		input, control, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		replies, response, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		token := strings.Repeat("ab", 32)
		child := f.command(ctx, "context", "select", "--request="+string(rootB2JSON(t, rootB2Request("base.skill.review"))), "--json", "--root-delivery-token="+token)
		child.ExtraFiles = []*os.File{input, response}
		stdout, e := child.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		var stderr bytes.Buffer
		child.Stderr = &stderr
		if mode == "broken-output" {
			stdout.Close()
		}
		if e = child.Start(); e != nil {
			t.Fatal(e)
		}
		input.Close()
		response.Close()
		done := make(chan error, 1)
		go func() { done <- child.Wait() }()
		var saved []byte
		changedPath := ""
		if mode != "broken-output" {
			frame, e := bufio.NewReader(stdout).ReadBytes('\n')
			if e != nil {
				t.Fatalf("actual installed held child: %v %s", e, stderr.String())
			}
			_ = rootB2DecodeSuccess(t, f, frame, false)
			select {
			case e = <-done:
				t.Fatalf("actual ROOT child exited before final delivery: %v %s", e, stderr.String())
			default:
			}
			message := rootDeliveryMessage{rootDeliveryVersion, token, 1, "recheck", evidencecas.Digest(frame)}
			if mode == "source-tamper" {
				changedPath = filepath.Join(f.objects, f.source.Subject.Commit)
			}
			if mode == "lock-tamper" {
				changedPath = filepath.Join(f.project, ".tplaiter", "root-template.lock.json")
			}
			if changedPath != "" {
				saved, e = os.ReadFile(changedPath)
				if e != nil {
					t.Fatal(e)
				}
				changed := append([]byte(nil), saved...)
				if mode == "source-tamper" {
					changed[len(changed)-1] ^= 1
				} else {
					changed = append(changed, ' ')
				}
				if e = os.WriteFile(changedPath, changed, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "cancel" || mode == "deadline" {
				// Both cancel and expiration close the actual inherited control pipe,
				// causing the held installed read to terminate without a complete receipt.
				if mode == "cancel" {
					cancel()
				} // Deadline mode expires its real CommandContext above.
			} else {
				if mode == "wrong-digest" {
					message.Digest = evidencecas.Digest([]byte("different frame"))
				}
				if _, e = control.Write(append(rootB2JSON(t, message), '\n')); e != nil {
					t.Fatal(e)
				}
				reader := bufio.NewReader(replies)
				reply, e := reader.ReadBytes('\n')
				if mode == "complete" || mode == "duplicate-sequence" {
					var ready rootDeliveryMessage
					if e != nil || json.Unmarshal(reply, &ready) != nil || ready.Action != "ready" {
						t.Fatal("actual installed final recheck did not acknowledge", e)
					}
					select {
					case e = <-done:
						t.Fatalf("installed ROOT carrier released at ready: %v", e)
					default:
					}
					if mode == "complete" {
						// Final output consumes the exact complete captured CLI frame, including
						// its mandatory body, floor, graph, images and newline while child lives.
						var final bytes.Buffer
						if e = writeRootFrame(&final, frame); e != nil || !bytes.Equal(final.Bytes(), frame) {
							t.Fatal("final whole write failed", e)
						}
						select {
						case e = <-done:
							t.Fatalf("installed ROOT carrier released during write: %v", e)
						default:
						}
						message.Sequence = 2
						message.Action = "complete"
					}
					if _, e = control.Write(append(rootB2JSON(t, message), '\n')); e != nil {
						t.Fatal(e)
					}
					reply, e = reader.ReadBytes('\n')
					if mode == "complete" {
						if e != nil || json.Unmarshal(reply, &ready) != nil || ready.Action != "closed" {
							t.Fatal("completion did not close actual ROOT carrier", e)
						}
					} else if e == nil {
						t.Fatal("duplicate sequence accepted")
					}
				} else if e == nil {
					t.Fatal("actual installed tamper/control counter accepted", mode)
				}
			}
		}
		select {
		case e = <-done:
		case <-time.After(3 * time.Second):
			cancel()
			control.Close()
			stdout.Close()
			t.Fatal("installed ROOT child did not terminate", mode)
		}
		if mode == "complete" && e != nil {
			t.Fatalf("complete child failed: %v %s", e, stderr.String())
		}
		if mode != "complete" && e == nil {
			t.Fatal("invalid held delivery succeeded", mode)
		}
		cancel()
		control.Close()
		replies.Close()
		stdout.Close()
		if saved != nil {
			if e = os.WriteFile(changedPath, saved, 0600); e != nil {
				t.Fatal(e)
			}
		}
		t.Log("actual installed retained read final-write/recheck/cleanup", mode)
	}
}
func rootB2InstalledBrokenMCP(t *testing.T, f *rootB2Fixture) {
	t.Helper()
	s := rootB2StartMCP(t, f)
	// Break the real client's response pipe before a ROOT response is emitted.
	// EOF on request input then lets ServeStdio finish and reap its held children.
	s.stdout.Close()
	s.write(t, rootB2ToolCall("broken-client", map[string]any{"action": "select", "rootSelection": rootB2Request("base.skill.review")}))
	s.close(t)
	t.Log("actual installed MCP broken client output -> EOF -> held-child/stage cleanup")
}

func rootB2InstalledOrdinaryBlockedStdout(t *testing.T, f *rootB2Fixture) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	// Fill the real inherited stdout pipe before starting the ordinary CLI.
	// No control pipes, delivery token, fake lock or substitute runtime is used.
	fd := int(write.Fd())
	if err = syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	filled := 0
	for {
		n, e := syscall.Write(fd, bytes.Repeat([]byte{'x'}, 4096))
		if n > 0 {
			filled += n
		}
		if e == syscall.EAGAIN {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if err = syscall.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := f.command(ctx, "context", "select", "--request="+string(rootB2JSON(t, rootB2Request("base.skill.review"))), "--json")
	child.Stdout = write
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	// The child changes stdout to pollable mode only immediately before writing,
	// after normal admission, complete materialization and the final real recheck.
	deadline := time.Now().Add(4 * time.Second)
	for {
		flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if e != nil {
			t.Fatal(e)
		}
		if flags&syscall.O_NONBLOCK != 0 {
			break
		}
		if time.Now().After(deadline) {
			child.Process.Kill()
			child.Wait()
			t.Fatal("ordinary installed CLI did not reach blocked final write", stderr.String())
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case err = <-done:
		t.Fatal("full stdout pipe did not block ordinary ROOT delivery", err)
	default:
	}
	started := time.Now()
	if err = child.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("cancelled blocked CLI reported successful delivery")
		}
	case <-time.After(3 * time.Second):
		child.Process.Kill()
		<-done
		t.Fatal("blocked ordinary CLI cancellation did not clean up within bound")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&syscall.O_NONBLOCK != 0 {
		t.Fatal("ordinary stdout mode not restored", err)
	}
	write.Close()
	raw, err := io.ReadAll(read)
	if err != nil || len(raw) != filled || bytes.Contains(raw, []byte(`"apiVersion"`)) {
		t.Fatal("partial/second ROOT frame escaped full-pipe cancellation", len(raw), filled, err)
	}
	t.Logf("actual ordinary installed CLI blocked final stdout; SIGINT reaped in %s; zero ROOT bytes, restored mode; no control token", time.Since(started))
}

func TestRootB2InstalledMalformedCatalog(t *testing.T) {
	f := normalRootB2Variant(t, "malformed-duplicate")
	before := rootB2Image(t, f.project, f.home, f.install)
	req := rootB2Request("base.skill.review")
	if raw, err := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json"); err == nil || bytes.Contains(raw, []byte(`"nativeRootSelection"`)) {
		t.Fatal("registered CLI admitted malformed catalog", err)
	}
	server := rootB2StartMCP(t, f)
	rootB2RefusedMCP(t, server.call(t, "malformed-catalog", map[string]any{"action": "select", "rootSelection": req}), "")
	server.close(t)
	if !reflect.DeepEqual(before, rootB2Image(t, f.project, f.home, f.install)) {
		t.Fatal("malformed catalog refusal mutated installed data")
	}
	t.Log("normally enrolled malformed duplicate catalog refused by actual registered CLI and stdio MCP")
}

func rootB2ValidateRegisteredSchema(t *testing.T, raw []byte) {
	t.Helper()
	full, err := mcpsrv.ContextFullSchema()
	if err != nil {
		t.Fatal(err)
	}
	var descriptor struct {
		Output json.RawMessage `json:"output"`
	}
	if err = json.Unmarshal(full, &descriptor); err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(descriptor.Output))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err = compiler.AddResource("context.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("context.json")
	if err != nil {
		t.Fatal(err)
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err = schema.Validate(value); err != nil {
		t.Fatal("actual complete ROOT result violates registered output schema", err)
	}
}
