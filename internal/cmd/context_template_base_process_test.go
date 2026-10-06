package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/mcpsrv"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const templateBasePublishedCommit = "aa9134f8d8633f3c9def858ffad1b8453a2584d5"
const templateBasePublicOrigin = "https://github.com/tplAIter/template-base.git"

var templateBaseProcess = flag.Bool("template-base-published-process", false, "Run explicitly opted-in published HTTPS source installation/process proof")
var templateBaseReceipts = flag.String("template-base-process-receipts", "", "Existing external directory for public raw process receipts")

func templateBaseReceipt(t *testing.T, name string, raw []byte) {
	t.Helper()
	if *templateBaseReceipts == "" {
		t.Fatal("external receipt directory required")
	}
	if err := os.WriteFile(filepath.Join(*templateBaseReceipts, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

// All authority is produced by normal installation from captured immutable Git
// data. No source flag, handwritten lock, provider executable or test renderer
// substitutes for the installed runtime. This operator attests bytes, not upstream authorship.
func templateBaseInstalledFixture(t *testing.T) *rootB2Fixture {
	t.Helper()
	testfixture.RequireTrustStore(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(base, "public-source")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	clone := exec.CommandContext(ctx, "/usr/bin/git", "clone", templateBasePublicOrigin, repo)
	raw, err := clone.CombinedOutput()
	templateBaseReceipt(t, "https-clone.log", raw)
	if err != nil {
		t.Fatalf("ordinary HTTPS clone: %v %s", err, raw)
	}
	git := func(args ...string) []byte {
		t.Helper()
		c := exec.Command("/usr/bin/git", append([]string{"-C", repo}, args...)...)
		r, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("public Git %v: %v %s", args, e, r)
		}
		return r
	}
	if strings.TrimSpace(string(git("rev-parse", "refs/remotes/origin/main"))) != templateBasePublishedCommit {
		t.Fatal("published main differs from approved C")
	}
	git("checkout", "--detach", templateBasePublishedCommit)
	if len(git("status", "--porcelain")) != 0 {
		t.Fatal("public source dirty")
	}
	if _, err = os.Lstat(filepath.Join(repo, ".git", "objects", "info", "alternates")); !os.IsNotExist(err) {
		t.Fatal("source clone is not independent")
	}
	capture := sourcepackage.CaptureInput{RepositoryPath: repo, Origin: templateBasePublicOrigin, TemplatePath: ".", Commit: templateBasePublishedCommit}
	captured, err := sourcepackage.Capture(ctx, capture)
	if err != nil {
		t.Fatal(err)
	}
	templateBaseReceipt(t, "captured-subject.json", rootB2JSON(t, captured.Subject))
	home := filepath.Join(base, "home")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	install := filepath.Join(base, "trust")
	prefix := filepath.Join(base, "prefix")
	sources := filepath.Join(base, "local-sources.json")
	projects := filepath.Join(base, "project-contexts.json")
	sourceJSON := rootB2JSON(t, []sourcepackage.CaptureInput{capture})
	contexts := rootB2JSON(t, []trustload.ProjectContext{{Key: "root", ProjectID: "project-template-base", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: project}})
	for p, b := range map[string][]byte{sources: sourceJSON, projects: contexts} {
		if err = os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	templateBaseReceipt(t, "capture-input.json", sourceJSON)
	templateBaseReceipt(t, "project-contexts.json", contexts)
	for _, p := range []string{install, prefix, project} {
		if _, err = os.Lstat(p); !os.IsNotExist(err) {
			t.Fatal("normal install target must be absent", p)
		}
	}
	build := exec.CommandContext(ctx, "/usr/bin/make", "install", "BIN="+filepath.Join(base, "build", "tplaiter"), "PREFIX="+prefix, "TRUST_ROOT="+install, "TRUST_LOCAL_SOURCES="+sources, "TRUST_PROJECT_CONTEXTS="+projects)
	build.Dir = testfixture.ModuleRoot(t)
	cachePaths := func(key string) string {
		t.Helper()
		output, e := exec.Command(testfixture.GoBinary(t), "env", key).Output()
		if e != nil {
			t.Fatal("existing Go cache location unavailable", e)
		}
		return strings.TrimSpace(string(output))
	}
	build.Env = []string{"PATH=" + filepath.Join(testfixture.GoRoot(t), "bin") + ":/usr/bin:/bin", "HOME=" + home, "GOCACHE=" + cachePaths("GOCACHE"), "GOMODCACHE=" + cachePaths("GOMODCACHE"), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off", "CGO_ENABLED=0"}
	raw, err = build.CombinedOutput()
	templateBaseReceipt(t, "make-install.log", raw)
	if err != nil {
		t.Fatalf("real make install: %v %s", err, raw)
	}
	registrationRaw, err := os.ReadFile(filepath.Join(install, ossinstall.RegistrationFile))
	if err != nil {
		t.Fatal(err)
	}
	registration, err := ossinstall.DecodeRegistration(registrationRaw)
	if err != nil {
		t.Fatal(err)
	}
	templateBaseReceipt(t, "registration.json", registrationRaw)
	selectionRaw, err := os.ReadFile(filepath.Join(install, "config", "source-selections.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selections []operationtrust.SourceSelection
	if err = json.Unmarshal(selectionRaw, &selections); err != nil || len(selections) != 1 {
		t.Fatal("normal generated source selection", err)
	}
	if selections[0].TrustSubject() != captured.Subject {
		t.Fatal("enrollment altered captured subject")
	}
	templateBaseReceipt(t, "source-selections.json", selectionRaw)
	selectionPath := filepath.Join(base, "source-selection.json")
	if err = os.WriteFile(selectionPath, rootB2JSON(t, selections[0]), 0600); err != nil {
		t.Fatal(err)
	}
	f := &rootB2Fixture{bin: filepath.Join(prefix, "bin", "tplaiter"), base: base, project: project, home: home, install: install, source: selections[0], in: invocation{Selection: registration.Selection(), ProjectKey: "root", Clock: bootstrap.ClockFunc(time.Now)}}
	for _, v := range []struct {
		name string
		args []string
	}{{"trust-provision", []string{"trust", "provision"}}, {"normal-new", []string{"new", templateBasePublishedCommit, "project", "--dir", project, "--source-input", selectionPath, "--defaults", "--no-hooks", "--json"}}} {
		raw, err = f.run(v.args...)
		templateBaseReceipt(t, v.name+".json", raw)
		if err != nil {
			t.Fatalf("normal %s: %v %s", v.name, err, raw)
		}
	}
	loaded, err := trustload.Load(context.Background(), registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	f.objects = loaded.Install.ObjectOrigins[0].RootPath
	binary, err := os.ReadFile(f.bin)
	if err != nil {
		t.Fatal(err)
	}
	templateBaseReceipt(t, "installation-pins.json", rootB2JSON(t, map[string]any{"binarySHA256": evidencecas.Digest(binary), "registrationSHA256": evidencecas.Digest(registrationRaw), "subject": captured.Subject, "authority": "configured-local-operator; no upstream or organization claim"}))
	t.Logf("real HTTPS C -> CaptureInput -> make install -> provision -> normal new; binary=%s registration=%s source=%s tree=%s contract=%s", evidencecas.Digest(binary), evidencecas.Digest(registrationRaw), captured.Subject.Commit, captured.Subject.TreeSHA256, captured.Subject.ContractSHA256)
	return f
}

func templateBaseAssertData(t *testing.T, f *rootB2Fixture, raw []byte) resultdto.ContextData {
	t.Helper()
	var out resultdto.ContextData
	if err := json.Unmarshal(raw, &out); err != nil || out.NativeRootSelection == nil {
		t.Fatal("complete typed ROOT data absent", err)
	}
	body := out.NativeRootSelection.Body
	if body.APIVersion != resultdto.ContextRootV2 {
		t.Fatal("ROOT v2 required")
	}
	var wire struct {
		NativeRootSelection struct {
			Body struct {
				Packet json.RawMessage `json:"packet"`
			} `json:"body"`
		} `json:"nativeRootSelection"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	restored, err := contextindex.DecodeRootFactsV2(wire.NativeRootSelection.Body.Packet)
	if err != nil || !bytes.Equal(rootB2JSON(t, restored), rootB2JSON(t, body.Packet)) {
		t.Fatal("logical C03 packet/Bytes not losslessly restored", err)
	}
	guard, err := resultdto.RootGuardV2(body)
	if err != nil {
		t.Fatal(err)
	}
	receipt := rootB2JSON(t, resultdto.RootDeliveryReceiptV2{APIVersion: resultdto.RootReceiptV2, BodySHA256: out.NativeRootSelection.Delivery.BodySHA256, PacketSHA256: evidencecas.Digest(rootB2JSON(t, body.Packet)), GuardSHA256: evidencecas.Digest(guard), ImagesSHA256: evidencecas.Digest(rootB2JSON(t, body.Files)), FileCount: len(body.Files)})
	delivery := out.NativeRootSelection.Delivery
	if delivery.ResponseSHA256 != evidencecas.Digest(receipt) || delivery.OutputByteReserve != int64(len(receipt)) || delivery.Spending.OutputBytes != int64(len(receipt)) || delivery.Spending.InputBytes != int64(delivery.EnvelopeBytes) {
		t.Fatal("receipt not actually measured")
	}

	if out.Action != "select" || out.Bytes != len(raw) || out.Snapshot != body.Snapshot || out.WindowState != "unknown" || body.Qualification != "authenticated-installed-native-root" {
		t.Fatal("ROOT sizing or qualification changed")
	}
	if len(body.Packet.Sources) != 1 || body.Packet.Sources[0].Anchor.Subject() != f.source.TrustSubject() {
		t.Fatal("authenticated captured source pins changed")
	}
	pin := body.Packet.Sources[0].Pin
	if pin.Commit != templateBasePublishedCommit || pin.ProviderID != "template-base" || pin.Alias != "base" || pin.ContractDigest != f.source.Subject.ContractSHA256 || pin.EvidenceDigest != f.source.EvidenceRefs().StatementCAS {
		t.Fatal("source/evidence pins changed")
	}
	wanted := map[string]bool{"template.manifest.yaml": true, "template.contract.json": true, "catalog/context-root-bindings.v1.json": true, "catalog/entries.json": true, "catalog/tool-contract.md": true}
	expectedFiles := map[string]exports.PayloadFile{}
	for _, s := range body.Graph.Selected {
		p := filepath.Join("catalog", "payloads", s.ID+".json")
		wanted[p] = true
		b, err := os.ReadFile(filepath.Join(f.base, "public-source", p))
		if err != nil {
			t.Fatal(err)
		}
		if evidencecas.Digest(b) != s.ContentDigest {
			t.Fatal("export content digest differs from C")
		}
		payload, err := exports.ParseExportPayload(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range payload.Files {
			expectedFiles[file.TargetPath] = file
			wanted[file.SourcePath] = true
		}
	}
	if len(body.Files) != len(expectedFiles) {
		t.Fatal("required image omitted/duplicated")
	}
	for _, file := range body.Files {
		expected, ok := expectedFiles[file.TargetPath]
		if !ok || file.SourcePath != expected.SourcePath || file.Mode != expected.Mode || file.ContentSHA256 != expected.ContentSHA256 || file.SelectedIdentity == "" {
			t.Fatal("selected identity/path/mode/hash changed")
		}
		original, err := os.ReadFile(filepath.Join(f.base, "public-source", file.SourcePath))
		if err != nil || !bytes.Equal(original, file.Content) || evidencecas.Digest(file.Content) != file.ContentSHA256 {
			t.Fatal("image not exact published bytes", file.SourcePath, err)
		}
	}
	floor := map[string]bool{}
	for _, id := range body.Packet.RequiredFloor {
		floor[id] = true
	}
	observed := map[string]bool{}
	for _, record := range body.Packet.Records {
		if record.Descriptor != nil {
			d := record.Descriptor
			if !floor[record.ItemID] {
				t.Fatal("required source record absent from floor")
			}
			observed[d.SourcePath] = true
		}
	}
	for p := range wanted {
		if !observed[p] {
			t.Fatal("required body/metadata not delivered", p)
		}
	}
	if len(floor) < len(wanted) || body.Packet.OmittedMatches != 0 {
		t.Fatal("mandatory floor truncated")
	}
	if evidencecas.Digest(rootB2JSON(t, body)) != out.NativeRootSelection.Delivery.BodySHA256 {
		t.Fatal("complete body digest changed")
	}
	return out
}
func templateBaseDecodeSuccess(t *testing.T, f *rootB2Fixture, raw []byte, _ bool) resultdto.ContextData {
	t.Helper()
	env, err := resultdto.Decode(raw)
	if err != nil || env.Status != resultdto.StatusOK {
		t.Fatal("successful CLI frame absent", err)
	}
	rootB2ValidateRegisteredSchema(t, raw)
	return templateBaseAssertData(t, f, env.Data)
}
func templateBaseDecodeMCP(t *testing.T, f *rootB2Fixture, raw []byte) resultdto.ContextData {
	t.Helper()
	var response struct {
		Result struct {
			IsError           bool             `json:"isError"`
			StructuredContent resultdto.Result `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || response.Result.IsError || response.Result.StructuredContent.Status != resultdto.StatusOK {
		t.Fatal("successful MCP frame absent", err)
	}
	rootB2ValidateRegisteredSchema(t, rootB2JSON(t, response.Result.StructuredContent))
	return templateBaseAssertData(t, f, response.Result.StructuredContent.Data)
}

func TestTemplateBasePublishedInstalledContext(t *testing.T) {
	if !*templateBaseProcess {
		t.Skip("explicit HTTPS published-source process proof; use -template-base-published-process")
	}
	f := templateBaseInstalledFixture(t)
	before := rootB2Image(t, f.project, f.home, f.install)
	selectors := []string{"base.block.task-context", "base.block.rule-overrides", "base.skill.context-selection", "base.approach.transparent-overrides"}
	var baseData resultdto.ContextData
	for i, selector := range selectors {
		server := rootB2StartMCP(t, f)
		req := rootB2Request(selector)
		req.MaxRecords = 256
		req.MaxBytes = 32768
		raw, err := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json")
		templateBaseReceipt(t, fmt.Sprintf("selector-%d-cli.json", i), raw)
		frame := server.call(t, fmt.Sprintf("<C-%d>&\\frame", i), map[string]any{"action": "select", "rootSelection": req})
		templateBaseReceipt(t, fmt.Sprintf("selector-%d-mcp.json", i), frame)
		if err != nil {
			templateBaseBudgetRefusal(t, frame)
			if !templateBaseBudgetCode(raw) || bytes.Contains(raw, []byte(`"nativeRootSelection"`)) {
				t.Fatal("unexpected or partial CLI refusal", err, string(raw))
			}
			t.Errorf("individual published selector cannot fit complete 32768-byte bound: %s CLI=%d MCP=%d", selector, len(raw), len(frame))
			continue
		}
		cli := templateBaseDecodeSuccess(t, f, raw, false)
		mcp := templateBaseDecodeMCP(t, f, frame)
		if !reflect.DeepEqual(cli, mcp) || len(raw) > 32768 || len(frame) > 32768 {
			t.Fatal("complete CLI/MCP mismatch or oversized frame")
		}
		want := []int{1, 1, 4, 2}[i]
		selected := []int{1, 1, 2, 2}[i]
		if len(cli.NativeRootSelection.Body.Files) != want || len(cli.NativeRootSelection.Body.Graph.Selected) != selected {
			t.Fatal("required selected closure absent")
		}
		if i >= 2 && len(cli.NativeRootSelection.Body.Graph.Edges) != 1 {
			t.Fatal("typed prerequisite edge missing")
		}
		if i == 0 {
			baseData = cli
		}
		t.Logf("published selector=%s files=%d floor=%d CLI=%d MCP=%d outer=%d", selector, want, len(cli.NativeRootSelection.Body.Packet.RequiredFloor), len(raw), len(frame), cli.Bytes)
		templateBaseInstalledBoundary(t, f, server, req, i)
		server.close(t)

	}
	server := rootB2StartMCP(t, f)
	req := rootB2Request(selectors...)
	req.MaxRecords = 256
	req.MaxBytes = 32768
	raw, err := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json")
	templateBaseReceipt(t, "batch-cli.json", raw)
	frame := server.call(t, "batch", map[string]any{"action": "select", "rootSelection": req})
	templateBaseReceipt(t, "batch-mcp.json", frame)
	if err != nil {
		templateBaseBudgetRefusal(t, frame)
		if !templateBaseBudgetCode(raw) || bytes.Contains(raw, []byte(`"nativeRootSelection"`)) {
			t.Fatal("batch did not wholly refuse")
		}
		t.Logf("full six-image batch: honest complete budget refusal CLI=%d MCP=%d", len(raw), len(frame))
	} else {
		cli := templateBaseDecodeSuccess(t, f, raw, false)
		mcp := templateBaseDecodeMCP(t, f, frame)
		if !reflect.DeepEqual(cli, mcp) || len(cli.NativeRootSelection.Body.Files) != 6 || len(raw) > 32768 || len(frame) > 32768 {
			t.Fatal("batch incomplete or oversized")
		}
		for _, s := range cli.NativeRootSelection.Body.Graph.Selected {
			if s.Domain == "block" && len(s.Chains) != 2 {
				t.Fatal("batch shared chains incomplete")
			}
		}
	}
	for name, req := range map[string]contextcmd.RootSelectionRequest{"stale": {Selections: rootB2Request(selectors[0]).Selections, Snapshot: evidencecas.Digest([]byte("stale"))}, "budget": {Selections: rootB2Request(selectors[0]).Selections, MaxBytes: 100}, "unknown": rootB2Request("base.skill.absent"), "duplicate": rootB2Request(selectors[0], selectors[0])} {
		raw, err := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json")
		templateBaseReceipt(t, name+"-cli.json", raw)
		if err == nil || bytes.Contains(raw, []byte(`"nativeRootSelection"`)) {
			t.Fatal("negative CLI leaked resources", name)
		}
		frame := server.call(t, name, map[string]any{"action": "select", "rootSelection": req})
		templateBaseReceipt(t, name+"-mcp.json", frame)
		rootB2RefusedMCP(t, frame, "")
	}
	// Exercise the actual SDK malformed-_meta slot leak counter on this installed binary.
	for i := 0; i < 64; i++ {
		call := rootB2ToolCall(fmt.Sprintf("bad-meta-%d", i), map[string]any{"action": "select", "rootSelection": rootB2Request(selectors[0])})
		call["params"].(map[string]any)["_meta"] = 1
		server.write(t, call)
		response := server.read(t)
		templateBaseReceipt(t, fmt.Sprintf("malformed-meta-%d.json", i), response)
		var protocol struct {
			Error json.RawMessage `json:"error"`
		}
		if json.Unmarshal(response, &protocol) != nil || len(protocol.Error) == 0 || bytes.Contains(response, []byte(`"nativeRootSelection"`)) {
			t.Fatal("malformed SDK counter", string(response))
		}
	}
	recovered := server.call(t, "after-64-malformed", map[string]any{"action": "select", "rootSelection": rootB2Request(selectors[0])})
	templateBaseReceipt(t, "after-64-malformed.json", recovered)
	templateBaseDecodeMCP(t, f, recovered)
	t.Log("64 actual malformed params._meta SDK terminals followed by successful installed ROOT call; slot recovery")
	request := rootB2JSON(t, rootB2ToolCall("cancel-C", map[string]any{"action": "select", "rootSelection": rootB2Request(selectors[0])}))
	notify := rootB2JSON(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": "cancel-C"}})
	if _, err = server.stdin.Write(append(append(append(request, '\n'), notify...), '\n')); err != nil {
		t.Fatal(err)
	}
	cancelled := server.read(t)
	templateBaseReceipt(t, "cancel-mcp.json", cancelled)
	rootB2RefusedMCP(t, cancelled, "MCP_CANCELLED")
	templateBaseDecodeMCP(t, f, server.call(t, "after-cancel", map[string]any{"action": "select", "rootSelection": rootB2Request(selectors[0])}))
	server.close(t)
	templateBaseInstalledDelivery(t, f)
	templateBaseInstalledOrdinaryBlockedStdout(t, f)
	broken := rootB2StartMCP(t, f)
	broken.stdout.Close()
	broken.write(t, rootB2ToolCall("broken-C", map[string]any{"action": "select", "rootSelection": rootB2Request(selectors[0])}))
	broken.close(t)
	after := rootB2Image(t, f.project, f.home, f.install)
	if !reflect.DeepEqual(before, after) {
		templateBaseReceipt(t, "nonmutation-before.json", rootB2JSON(t, before))
		templateBaseReceipt(t, "nonmutation-after.json", rootB2JSON(t, after))
		for p, value := range before {
			if after[p] != value {
				t.Logf("state changed: %s before=%s after=%s", p, value, after[p])
			}
		}
		for p, value := range after {
			if _, ok := before[p]; !ok {
				t.Logf("state added: %s %s", p, value)
			}
		}
		t.Fatal("read-only source selection mutated installed state")
	}
	templateBaseModifiers(t, baseData)
	t.Log("published C process cleanup/nonmutation proved; local operator attestation only")
}

// Composition consumes facts from the actual successful authenticated ROOT
// response. It stays a pure calculation; no modifier is applied to the project.
func templateBaseModifiers(t *testing.T, data resultdto.ContextData) {
	t.Helper()
	if data.NativeRootSelection == nil {
		t.Fatal("actual export facts absent")
	}
	pin := data.NativeRootSelection.Body.Packet.Sources[0].Pin
	selected := data.NativeRootSelection.Body.Graph.Selected[0]
	digest := selected.ContentDigest
	source := exports.SourcePin{Alias: pin.Alias, ProviderID: pin.ProviderID, Origin: pin.Origin, TemplatePath: pin.TemplatePath, RequestedRef: pin.RequestedRef, CommitAlgorithm: pin.CommitAlgorithm, Commit: pin.Commit, TreeDigest: pin.TreeDigest, ContentDigest: pin.ContentDigest, ContractDigest: pin.ContractDigest, EvidenceDigest: pin.EvidenceDigest}
	initial := exports.RuleSet{Rules: []exports.Rule{{ID: "context-default", Digest: digest, Version: "0.1.0", Provider: "base"}}, Required: []exports.Capability{}, Tombstones: []exports.Tombstone{}, Exports: map[string]exports.ExportFact{"base.block.task-context": {ContractDigest: pin.ContractDigest, Version: "0.1.0"}}}
	var base exports.RuleSet
	if err := json.Unmarshal(rootB2JSON(t, initial), &base); err != nil {
		t.Fatal(err)
	}
	modifier := exports.Modifier{APIVersion: "tplaiter.dev/modifier/v1", Kind: "Modifier", Metadata: exports.Metadata{ID: "context-explicit", Version: "0.1.0"}, Compatibility: exports.Compatibility{MinimumCLI: "0.0.0", PortableAPI: "tplaiter.dev/portable/v1", Runtimes: []string{"metadata"}, Layouts: []string{"files"}}, Sources: []exports.SourcePin{source}, SelfSource: "base", Requires: exports.Requires{Exports: []exports.ExportRequirement{{Selector: "base.block.task-context", ContractDigest: pin.ContractDigest, CompatibleRange: ">=0.1.0 <0.2.0"}}, Capabilities: []exports.Capability{}}, Provides: []exports.ProvidedCapability{}, Conflicts: []exports.Capability{}, Replaces: []exports.Replacement{}, Bindings: []exports.Binding{}, ToolConstraints: []exports.ToolConstraint{}, Renames: []exports.Rename{}, Rules: []exports.Operation{{ID: "context-explicit", Op: "replace", Target: "context-default", ExpectedDigest: digest, ExpectedVersion: "0.1.0", Export: "base.block.task-context", Before: []string{}, After: []string{}}, {ID: "context-notes", Op: "add", Export: "base.block.task-context", Before: []string{}, After: []string{"context-explicit"}}}}
	parse := func(m exports.Modifier) exports.Modifier {
		t.Helper()
		p, e := exports.Parse(rootB2JSON(t, m))
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	parsed := parse(modifier)
	out, err := exports.ResolveModifiers(base, []exports.Modifier{parsed})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != 2 || len(out.Tombstones) != 1 || out.Tombstones[0].Digest != digest || out.Tombstones[0].ReplacedBy != "context-explicit" || len(out.Ordered) != 2 || out.Ordered[0].ID != "context-explicit" || out.Ordered[1].ID != "context-notes" {
		t.Fatal("replace/add typed composition mismatch")
	}
	next := exports.RuleSet{Rules: out.Rules, Tombstones: out.Tombstones, Required: []exports.Capability{}, Exports: base.Exports}
	var notes string
	for _, r := range out.Rules {
		if r.ID == "context-notes" {
			notes = r.Digest
		}
		if r.Digest == digest {
			t.Fatal("new composition digest not derived")
		}
	}
	removal := modifier
	removal.Rules = []exports.Operation{{ID: "context-remove", Op: "remove", Target: "context-notes", ExpectedDigest: notes, ExpectedVersion: "0.1.0", Before: []string{}, After: []string{}}}
	retired, err := exports.ResolveModifiers(next, []exports.Modifier{parse(removal)})
	if err != nil || len(retired.Rules) != 1 || len(retired.Tombstones) != 2 || retired.Digest == out.Digest {
		t.Fatal("remove/tombstone composition mismatch", err)
	}
	stale := modifier
	stale.Rules = append([]exports.Operation{}, modifier.Rules...)
	stale.Rules[0].ExpectedDigest = evidencecas.Digest([]byte("stale"))
	if _, err = exports.ResolveModifiers(base, []exports.Modifier{parse(stale)}); err == nil || !strings.Contains(err.Error(), "RULE_PRECONDITION") {
		t.Fatal("stale modifier accepted", err)
	}
	cyclic := modifier
	cyclic.Rules = append([]exports.Operation{}, modifier.Rules...)
	cyclic.Rules[0].After = []string{"context-notes"}
	if _, err = exports.ResolveModifiers(base, []exports.Modifier{parse(cyclic)}); err == nil || !strings.Contains(err.Error(), "RULE_ORDER: cycle") {
		t.Fatal("cyclic modifier accepted", err)
	}
	revival := modifier
	revival.Rules = []exports.Operation{{ID: "context-notes", Op: "add", Export: "base.block.task-context", Before: []string{}, After: []string{}}}
	if _, err = exports.ResolveModifiers(exports.RuleSet{Rules: retired.Rules, Tombstones: retired.Tombstones, Exports: base.Exports}, []exports.Modifier{parse(revival)}); err == nil || !strings.Contains(err.Error(), "RULE_TOMBSTONE") {
		t.Fatal("retired ID accepted", err)
	}
	templateBaseReceipt(t, "typed-composition-io.json", rootB2JSON(t, map[string]any{"ruleSet": base, "modifier": parsed, "composition": out, "removal": parse(removal), "removed": retired, "sourceQualification": "facts from normal admitted published C ROOT response; pure modifier API, no project application"}))
	t.Logf("real parsed typed modifier: replace/add2 rules1 tombstone=%s; remove1 rule2 tombstones=%s; stale/cycle/revival refused", out.Digest, retired.Digest)
}

func templateBaseInstalledDelivery(t *testing.T, f *rootB2Fixture) {
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
		child := f.command(ctx, "context", "select", "--request="+string(rootB2JSON(t, rootB2Request("base.block.task-context"))), "--json", "--root-delivery-token="+token)
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
			_ = templateBaseDecodeSuccess(t, f, frame, false)
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
func templateBaseInstalledOrdinaryBlockedStdout(t *testing.T, f *rootB2Fixture) {
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
	child := f.command(ctx, "context", "select", "--request="+string(rootB2JSON(t, rootB2Request("base.block.task-context"))), "--json")
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

func templateBaseBudgetCode(raw []byte) bool {
	return bytes.Contains(raw, []byte(contextcmd.Budget)) || bytes.Contains(raw, []byte("CONTEXT_INDEX_BUDGET"))
}
func templateBaseBudgetRefusal(t *testing.T, raw []byte) {
	t.Helper()
	rootB2RefusedMCP(t, raw, "")
	if !templateBaseBudgetCode(raw) {
		t.Fatal("not a typed complete budget refusal", string(raw))
	}
}

func templateBaseInstalledBoundary(t *testing.T, f *rootB2Fixture, server *rootB2MCP, req contextcmd.RootSelectionRequest, index int) {
	t.Helper()
	low, high := 1, 32768
	for low < high {
		mid := (low + high) / 2
		candidate := req
		candidate.MaxBytes = mid
		raw, e := f.run("context", "select", "--request="+string(rootB2JSON(t, candidate)), "--json")
		if e == nil {
			if len(raw) > mid {
				t.Fatal("boundary frame overflow")
			}
			high = mid
		} else {
			if !templateBaseBudgetCode(raw) || bytes.Contains(raw, []byte(`"nativeRootSelection"`)) {
				t.Fatal("boundary unexpected refusal", string(raw))
			}
			low = mid + 1
		}
	}
	minimum := low
	req.MaxBytes = minimum
	raw, e := f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json")
	templateBaseReceipt(t, fmt.Sprintf("selector-%d-min-cli.json", index), raw)
	if e != nil || len(raw) > minimum {
		t.Fatal("exact installed CLI minimum", minimum, e)
	}
	observed := templateBaseDecodeSuccess(t, f, raw, false)
	frame := server.call(t, fmt.Sprintf("min-%d", index), map[string]any{"action": "select", "rootSelection": req})
	templateBaseReceipt(t, fmt.Sprintf("selector-%d-min-mcp.json", index), frame)
	if len(frame) > minimum {
		t.Fatal("exact MCP frame bound")
	}
	templateBaseDecodeMCP(t, f, frame)
	req.MaxBytes--
	raw, e = f.run("context", "select", "--request="+string(rootB2JSON(t, req)), "--json")
	templateBaseReceipt(t, fmt.Sprintf("selector-%d-minus-one-cli.json", index), raw)
	if e == nil || !templateBaseBudgetCode(raw) || bytes.Contains(raw, []byte(`"nativeRootSelection"`)) {
		t.Fatal("one-byte-below CLI did not wholly refuse")
	}
	frame = server.call(t, fmt.Sprintf("short-%d", index), map[string]any{"action": "select", "rootSelection": req})
	templateBaseReceipt(t, fmt.Sprintf("selector-%d-minus-one-mcp.json", index), frame)
	templateBaseBudgetRefusal(t, frame)
	templateBaseReceipt(t, fmt.Sprintf("selector-%d-boundary.json", index), rootB2JSON(t, map[string]any{"minimum": minimum, "below": minimum - 1, "selector": req.Selections[0].Selector, "receiptBytes": observed.NativeRootSelection.Delivery.Spending.OutputBytes}))
	// Receipt bytes come from the actual measured six-field receipt, never a grant.
	t.Logf("actual installed CLI/MCP exact minimum=%d and one-byte-short whole refusal selector=%s", minimum, req.Selections[0].Selector)
}

func TestTemplateBaseRootV2Other29Descriptors(t *testing.T) {
	if !*templateBaseProcess {
		t.Skip("explicit published-source evidence export")
	}
	s := mcpsrv.New("/nonexistent", "test", nil)
	tools := s.MCP().ListTools()
	other := map[string]json.RawMessage{}
	// Preserve the original30 inventory; additions are separately accepted domain tools.
	for _, name := range []string{"graph_source", "dependency_graph", "graph_exports", "graph_ast", "graph_stats"} {
		if tools[name] == nil {
			t.Fatal("missing registered graph domain")
		}
		delete(tools, name)
	}
	for name, v := range tools {
		if name != "context" {
			other[name] = rootB2JSON(t, v.Tool)
		}
	}
	if len(tools) != 30 || len(other) != 29 || other["project_link"] == nil {
		t.Fatal("tool inventory changed")
	}
	templateBaseReceipt(t, "other29-descriptors.json", rootB2JSON(t, other))
}
