package cmd

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphcmd"
	"github.com/tplAIter/tplaiter/internal/mcpsrv"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"golang.org/x/sys/unix"
	"io"
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

var graphProcess = flag.Bool("graph-installed-process", false, "Run finite configured synthetic-operator graph CLI/MCP acceptance on the combined registry candidate")
var graphReceipts = flag.String("graph-process-receipts", "", "Existing external raw-receipt directory")

func graphReceipt(t *testing.T, name string, b []byte) {
	t.Helper()
	if *graphReceipts == "" {
		t.Fatal("external receipt directory required")
	}
	if e := os.WriteFile(filepath.Join(*graphReceipts, name), b, 0600); e != nil {
		t.Fatal(e)
	}
}
func graphSyntheticSource(t *testing.T, repo string, variant string) string {
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
	files[contextsource.ContextSourceBindingsPath] = rootB2JSON(t, contextsource.ContextSourceBindings{APIVersion: contextsource.ContextSourceBindingsAPIVersion, Kind: "ContextSourceBindings", Source: contextsource.ContextCatalogBinding{Alias: "base", ProviderID: "neutral", Parameters: []deps.Parameter{}, EntriesPath: "catalog/entries.json", PayloadDirectory: "catalog/payloads", ToolPath: "catalog/tool.md"}, Dependencies: []contextsource.ContextDependencyBinding{}})
	files["files/service.go.tmpl"] = []byte("package service\nfunc Handle() {}\n")
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
			var id string
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

// Synthetic source bytes are public test data, with real Capture/Generate
// operator enrollment. No project lock pair or authenticated carrier is forged.
func graphInstalledFixture(t *testing.T) (*rootB2Fixture, string) {
	t.Helper()
	testfixture.RequireTrustStore(t)
	base, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	repo := filepath.Join(base, "source")
	commit := graphSyntheticSource(t, repo, "")
	project := filepath.Join(base, "project")
	home := filepath.Join(base, "home")
	if e = os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	capture := sourcepackage.CaptureInput{RepositoryPath: repo, Origin: "https://example.test/public-graph-fixture", TemplatePath: ".", Commit: commit}
	captured, e := sourcepackage.Capture(context.Background(), capture)
	if e != nil {
		t.Fatal(e)
	}
	graphReceipt(t, "captured-subject.json", rootB2JSON(t, captured.Subject))
	generated, e := ossinstall.GenerateWithContext(context.Background(), ossinstall.Options{Root: filepath.Join(base, "install"), LocalSources: []sourcepackage.CaptureInput{capture}, ProjectContexts: []trustload.ProjectContext{{Key: "root", ProjectID: "project-graph-fixture", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: project}}})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(generated.RegistrationPath)
	if e != nil {
		t.Fatal(e)
	}
	registration, e := ossinstall.DecodeRegistration(raw)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = os.ReadFile(generated.SelectionsPath)
	if e != nil {
		t.Fatal(e)
	}
	var selections []operationtrust.SourceSelection
	if e = json.Unmarshal(raw, &selections); e != nil || len(selections) != 1 {
		t.Fatal("normal enrollment", e)
	}
	source := selections[0]
	creation := filepath.Join(base, "creation.json")
	if e = os.WriteFile(creation, rootB2JSON(t, source), 0600); e != nil {
		t.Fatal(e)
	}
	// Closed v2 transport locates the same generated v1 subject/evidence. It is
	// reverified by the opaque carrier, not granted authority by this projection.
	input := contextsource.ContextSourceSelection{APIVersion: contextsource.ContextSourceSelectionAPIVersion, Root: contextsource.ContextSourceProof{Subject: source.Subject, Evidence: source.Evidence}, Sources: []contextsource.ContextSourceProof{}}
	graphSource := filepath.Join(base, "graph-source.json")
	if e = os.WriteFile(graphSource, rootB2JSON(t, input), 0600); e != nil {
		t.Fatal(e)
	}
	graphReceipt(t, "source-selection-transport.json", rootB2JSON(t, input))
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-trimpath", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+generated.RegistrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+generated.RegistrationSHA256, "-o", bin, ".")
	build.Dir = testfixture.ModuleRoot(t)
	build.Env = testBuildEnv(home)
	out, e := build.CombinedOutput()
	graphReceipt(t, "installed-build.log", out)
	if e != nil {
		t.Fatalf("installed build: %v %s", e, out)
	}
	f := &rootB2Fixture{bin: bin, base: base, project: project, home: home, install: generated.Root, in: invocation{Selection: registration.Selection(), ProjectKey: "root", Clock: bootstrap.ClockFunc(time.Now)}, source: source}
	out, e = f.run("trust", "provision")
	graphReceipt(t, "provision.json", out)
	if e != nil {
		t.Fatalf("provision: %v %s", e, out)
	}
	out, e = f.run("new", commit, "project", "--dir", project, "--source-input", creation, "--defaults", "--no-hooks", "--json")
	graphReceipt(t, "normal-new.json", out)
	if e != nil {
		t.Fatalf("normal New: %v %s", e, out)
	}
	graphReceipt(t, "installed-registration.json", rawRegistration(t, generated.RegistrationPath))
	image, e := os.ReadFile(bin)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("installed image=%s registration=%s source=%s domainContract=%s", evidencecas.Digest(image), generated.RegistrationSHA256, commit, source.Subject.ContractSHA256)
	return f, graphSource
}
func rawRegistration(t *testing.T, p string) []byte {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func graphDecodeSuccess(t *testing.T, raw []byte) resultdto.GraphData {
	t.Helper()
	env, e := resultdto.Decode(raw)
	if e != nil || env.Status != resultdto.StatusOK {
		t.Fatalf("result: %v %s", e, raw)
	}
	d, e := resultdto.DecodeGraphData(env.Data)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestGraphInstalledConfiguredOperatorCLIAndMCP(t *testing.T) {
	if !*graphProcess {
		t.Skip("explicit finite installed proof")
	}
	s := mcpsrv.New("/not-executable", "test", nil)
	if s.MCP().ListTools()["graph_source"] == nil {
		t.Fatal("combined integration registrar required")
	}
	s.Close()
	f, input := graphInstalledFixture(t)
	before := rootB2Image(t, f.project, f.home, f.install)
	cli := map[string]resultdto.GraphData{}
	for _, layer := range []string{"source", "exports", "ast", "stats"} {
		args := []string{"graph", layer, "--dir", f.project, "--max-bytes", "32768", "--representation", "whole", "--json"}
		if layer == "source" || layer == "exports" {
			args = append(args, "--source-input", input)
		}
		if layer == "exports" {
			args = append(args, "--select", "base.skill.review", "--select", "base.approach.careful")
		}
		out, e := f.run(args...)
		graphReceipt(t, "cli-"+layer+".json", out)
		if e != nil {
			t.Fatalf("CLI %s: %v %s", layer, e, out)
		}
		cli[layer] = graphDecodeSuccess(t, out)
		if len(out) > 32768 {
			t.Fatal("whole envelope overflow")
		}
		t.Logf("actual CLI %s bytes=%d records=%d digest=%s", layer, len(out), cli[layer].Page.Returned, cli[layer].FullGraphDigest)
	}
	if len(cli["source"].Records) != 1 || len(cli["source"].Records[0].Pins) != 1 {
		t.Fatal("source pins lost")
	}
	pin := cli["source"].Records[0].Pins[0]
	if pin.Commit != f.source.Subject.Commit || pin.TreeDigest != f.source.Subject.TreeSHA256 || pin.ContractDigest != f.source.Subject.ContractSHA256 || pin.ProviderID != "neutral" || pin.Alias != "base" {
		t.Fatal("source projection does not match original admitted pins")
	}
	if cli["exports"].Page.Total != 5 {
		t.Fatal("missing coalesced mandatory floor or edges")
	}
	if cli["ast"].Stats["ast"].Nodes < 3 || cli["stats"].CacheState != "missing" {
		t.Fatal("no useful AST/stats")
	}
	out, e := f.run("deps", "graph", "--dir", f.project, "--source-input", input, "--representation", "whole", "--max-bytes", "32768", "--json")
	graphReceipt(t, "cli-dependency-graph.json", out)
	if e != nil || graphDecodeSuccess(t, out).FullGraphDigest != cli["source"].FullGraphDigest {
		t.Fatal("alias diverged", e)
	}
	server := rootB2StartMCP(t, f)
	for _, tool := range []string{"graph_source", "dependency_graph", "graph_exports", "graph_ast", "graph_stats"} {
		layer := strings.TrimPrefix(tool, "graph_")
		if tool == "dependency_graph" {
			layer = "source"
		}
		a := map[string]any{"dir": f.project, "maxBytes": 32768, "representation": "whole"}
		if layer == "source" || layer == "exports" {
			a["sourceInput"] = input
		}
		if layer == "exports" {
			a["selectors"] = []string{"base.skill.review", "base.approach.careful"}
		}
		server.write(t, map[string]any{"jsonrpc": "2.0", "id": tool + "<\\&", "method": "tools/call", "params": map[string]any{"name": tool, "arguments": a}})
		frame := server.read(t)
		graphReceipt(t, "mcp-"+tool+".json", frame)
		var response struct {
			Error  json.RawMessage `json:"error"`
			Result struct {
				IsError           bool            `json:"isError"`
				StructuredContent json.RawMessage `json:"structuredContent"`
			} `json:"result"`
		}
		if e = json.Unmarshal(frame, &response); e != nil || len(response.Error) > 0 || response.Result.IsError {
			t.Fatalf("MCP %s: %v %s", tool, e, frame)
		}
		data := graphDecodeSuccess(t, response.Result.StructuredContent)
		if data.FullGraphDigest != cli[layer].FullGraphDigest {
			t.Fatal("CLI/MCP graph mismatch")
		}
		t.Logf("actual MCP %s frame=%d records=%d", tool, len(frame), data.Page.Returned)
	}
	server.close(t)
	if !reflect.DeepEqual(before, rootB2Image(t, f.project, f.home, f.install)) {
		t.Fatal("readonly graph mutated source/project/install/home")
	}
	// Real whole-envelope minimum and one below, followed by distinct input refusals.
	raw, e := f.run("graph", "exports", "--dir", f.project, "--source-input", input, "--select", "base.skill.review", "--select", "base.approach.careful", "--representation", "whole", "--max-bytes", "32768", "--json")
	if e != nil {
		t.Fatal(e)
	}
	minimum := len(raw)
	for _, delta := range []int{0, -1} {
		out, e = f.run("graph", "exports", "--dir", f.project, "--source-input", input, "--select", "base.skill.review", "--select", "base.approach.careful", "--representation", "whole", "--max-bytes", strconv.Itoa(minimum+delta), "--json")
		graphReceipt(t, fmt.Sprintf("whole-boundary-%d.json", delta), out)
		if delta == 0 && e != nil || delta < 0 && (e == nil || !bytes.Contains(out, []byte("GRAPH_OUTPUT_BUDGET"))) {
			t.Fatal("boundary not honest", delta, e)
		}
	}
	for _, selectors := range [][]string{{"base.skill.unknown"}, {"base.skill.review", "base.skill.review"}} {
		args := []string{"graph", "exports", "--dir", f.project, "--source-input", input, "--json"}
		for _, v := range selectors {
			args = append(args, "--select", v)
		}
		out, e = f.run(args...)
		graphReceipt(t, fmt.Sprintf("selector-refusal-%d.json", len(selectors)), out)
		if e == nil || !bytes.Contains(out, []byte("GRAPH_SELECTOR_INVALID")) {
			t.Fatal("selector refusal missing", e)
		}
	}
	out, e = f.run("graph", "source", "--dir", f.project, "--source-input", input, "--expected-digest", "sha256:"+strings.Repeat("f", 64), "--json")
	graphReceipt(t, "stale-query.json", out)
	if e == nil || !bytes.Contains(out, []byte("GRAPH_SOURCE_STALE")) {
		t.Fatal("stale query accepted")
	}
	bad := contextsource.ContextSourceSelection{APIVersion: contextsource.ContextSourceSelectionAPIVersion, Root: contextsource.ContextSourceProof{Subject: f.source.Subject, Evidence: f.source.Evidence}, Sources: []contextsource.ContextSourceProof{}}
	bad.Root.Subject.TreeSHA256 = "sha256:" + strings.Repeat("f", 64)
	badPath := filepath.Join(f.base, "bad-pins.json")
	if e = os.WriteFile(badPath, rootB2JSON(t, bad), 0600); e != nil {
		t.Fatal(e)
	}
	out, e = f.run("graph", "source", "--dir", f.project, "--source-input", badPath, "--json")
	graphReceipt(t, "source-pin-refusal.json", out)
	if e == nil || !bytes.Contains(out, []byte("GRAPH_SOURCE_ADMISSION")) {
		t.Fatal("mismatched source pin admitted")
	}
	out, e = f.run("graph", "ast", "--dir", f.project, "--cache", "refresh", "--json")
	graphReceipt(t, "cache-refresh.json", out)
	if e != nil || graphDecodeSuccess(t, out).CacheState != "recomputed" {
		t.Fatal("refresh not materialized", e)
	}
	out, e = f.run("graph", "ast", "--dir", f.project, "--json")
	graphReceipt(t, "cache-hit.json", out)
	if e != nil || graphDecodeSuccess(t, out).CacheState != "hit" {
		t.Fatal("cache not consumed", e)
	}
	r, e := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.in.Selection, ProjectKey: "root", Clock: f.in.Clock})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	o, e := graphcmd.Prepare(context.Background(), r, graphcmd.Query{Layer: "ast"}, runtimeassembly.Options{})
	if e != nil {
		t.Fatal(e)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if e = o.Recheck(cancelled); e == nil {
		t.Fatal("cancel accepted")
	}
	o.Close()
	rootB2AssertLease(t, f.project, false)
	if _, e = o.Result(); e == nil {
		t.Fatal("closed observation still usable")
	}
	graphInstalledBlockedStdout(t, f)
	t.Logf("configured synthetic operator; Capture -> Generate -> provision -> normal action-free New -> CLI/MCP five tools; root-only enrolled source, not normal nonempty project dependency delivery; whole minimum=%d", minimum)
}

func graphInstalledBlockedStdout(t *testing.T, f *rootB2Fixture) {
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
	child := f.command(ctx, "graph", "ast", "--dir", f.project, "--cache", "off", "--representation", "whole", "--json")
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
			if waitErr := child.Wait(); waitErr != nil {
				var exitErr *exec.ExitError
				if !errors.As(waitErr, &exitErr) {
					t.Fatalf("ordinary installed CLI terminal wait: %v", waitErr)
				}
			}
			t.Fatal("ordinary installed CLI did not reach blocked final write", stderr.String())
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case err = <-done:
		t.Fatal("full stdout pipe did not block ordinary graph delivery", err)
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
		t.Fatal("partial/second graph frame escaped full-pipe cancellation", len(raw), filled, err)
	}
	t.Logf("actual ordinary installed CLI blocked final stdout; SIGINT reaped in %s; zero graph bytes, restored mode; no control token", time.Since(started))
}

func TestGraphRefreshAdmissionNoWritesInstalled(t *testing.T) {
	if !*graphProcess {
		t.Skip("requires explicit installed process proof")
	}
	f, _ := graphInstalledFixture(t)
	raw, err := f.run("graph", "ast", "--dir", f.project, "--limit", "1", "--json")
	if err != nil {
		t.Fatal(err)
	}
	cursor := graphDecodeSuccess(t, raw).Page.NextCursor
	if cursor == "" {
		t.Fatal("actual page cursor missing")
	}
	for _, existing := range []bool{false, true} {
		if existing {
			raw, err = f.run("graph", "ast", "--dir", f.project, "--cache", "refresh", "--json")
			if err != nil {
				t.Fatal(err)
			}
			graphReceipt(t, "refresh-positive.json", raw)
		}
		for _, counter := range []struct{ name, flag, value, code string }{
			{"digest", "--expected-digest", "sha256:" + strings.Repeat("f", 64), "GRAPH_SOURCE_STALE"},
			{"cursor", "--cursor", cursor, "GRAPH_CURSOR_STALE"},
		} {
			before := rootB2Image(t, f.project, f.home, f.install)
			raw, err = f.run("graph", "ast", "--dir", f.project, "--cache", "refresh", "--limit", "1", counter.flag, counter.value, "--json")
			graphReceipt(t, fmt.Sprintf("refresh-%s-existing-%t.json", counter.name, existing), raw)
			if err == nil || !bytes.Contains(raw, []byte(counter.code)) {
				t.Fatal("missing refresh refusal", counter.name, err)
			}
			if !reflect.DeepEqual(before, rootB2Image(t, f.project, f.home, f.install)) {
				t.Fatal("refused refresh wrote state", counter.name, existing)
			}
			t.Logf("actual installed refresh %s existing=%t: %s; complete project/home/install image unchanged", counter.name, existing, counter.code)
		}
	}
}

func TestGraphMCPFinalFrameInstalled(t *testing.T) {
	if !*graphProcess {
		t.Skip("explicit installed process proof required")
	}
	f, input := graphInstalledFixture(t)
	transport := rootB2StartMCP(t, f)
	defer transport.close(t)
	call := func(id any, tool string, args map[string]any) []byte {
		transport.write(t, map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
		raw := transport.read(t)
		if len(raw) > 32768 {
			t.Fatal("actual final MCP frame exceeds32768", len(raw))
		}
		return raw
	}
	for _, tool := range []string{"graph_source", "dependency_graph", "graph_exports", "graph_ast", "graph_stats"} {
		args := map[string]any{"dir": f.project, "maxBytes": 32768, "representation": "whole"}
		if tool == "graph_source" || tool == "dependency_graph" || tool == "graph_exports" {
			args["sourceInput"] = input
		}
		if tool == "graph_exports" {
			args["selectors"] = []string{"base.skill.review", "base.approach.careful"}
		}
		raw := call(tool+"<\\\"&\n\té", tool, args)
		graphReceipt(t, "p1-installed-"+tool+".json", raw)
		var response struct {
			Error  json.RawMessage `json:"error"`
			Result struct {
				IsError           bool            `json:"isError"`
				StructuredContent json.RawMessage `json:"structuredContent"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw, &response); err != nil || len(response.Error) != 0 || response.Result.IsError {
			t.Fatal("actual graph failed", tool, string(raw), err)
		}
		graphDecodeSuccess(t, response.Result.StructuredContent)
		t.Logf("actual installed complete MCP %s bytes=%d <=32768", tool, len(raw))
	}
	args := map[string]any{"dir": f.project, "sourceInput": input, "selectors": []string{"base.skill.review", "base.approach.careful"}, "maxBytes": 32768, "representation": "whole"}
	id := "whole-a<\\\"&\né"
	raw := call(id, "graph_exports", args)
	minimum := len(raw)
	for _, delta := range []int{0, -1} {
		args["maxBytes"] = minimum + delta
		raw = call(strings.Replace(id, "whole-a", fmt.Sprintf("whole-%c", 'b'+rune(-delta)), 1), "graph_exports", args)
		graphReceipt(t, fmt.Sprintf("p1-mcp-whole-%d.json", delta), raw)
		if len(raw) > minimum+delta {
			t.Fatal("requested complete MCP bound not enforced")
		}
		if delta == 0 {
			var response struct {
				Result struct {
					StructuredContent json.RawMessage `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal(raw, &response); err != nil {
				t.Fatal(err)
			}
			graphDecodeSuccess(t, response.Result.StructuredContent)
			if len(raw) != minimum {
				t.Fatal("actual exact minimum changed", len(raw), minimum)
			}
		} else if !bytes.Contains(raw, []byte("GRAPH_OUTPUT_BUDGET")) {
			t.Fatal("one below whole did not refuse", string(raw))
		}
	}
	args["representation"] = "page"
	args["maxBytes"] = minimum - 64
	raw = call("page-one<\\\"&\né", "graph_exports", args)
	graphReceipt(t, "p1-mcp-page.json", raw)
	var response struct {
		Result struct {
			StructuredContent json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	page := graphDecodeSuccess(t, response.Result.StructuredContent)
	if page.Page.NextCursor == "" || page.Page.Returned == page.Page.Total {
		t.Fatal("page was not shrunk at actual MCP ceiling")
	}
	args["cursor"] = page.Page.NextCursor
	raw = call("page-two<\\\"&\né", "graph_exports", args)
	graphReceipt(t, "p1-mcp-page-next.json", raw)
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	next := graphDecodeSuccess(t, response.Result.StructuredContent)
	if next.FullGraphDigest != page.FullGraphDigest {
		t.Fatal("next page graph changed")
	}
	// Wrapper-only insufficiency must refuse refresh BEFORE publication.
	before := rootB2Image(t, f.project, f.home, f.install)
	raw = call(strings.Repeat("<\\\"&", 4000), "graph_ast", map[string]any{"dir": f.project, "cache": "refresh", "maxBytes": 32768})
	graphReceipt(t, "p1-mcp-outer-metadata-refusal.json", raw)
	if !bytes.Contains(raw, []byte(`"id":null`)) || !bytes.Contains(raw, []byte("GRAPH_OUTPUT_BUDGET")) {
		t.Fatal("outer metadata null refusal missing")
	}
	if !reflect.DeepEqual(before, rootB2Image(t, f.project, f.home, f.install)) {
		t.Fatal("outer refusal caused effects")
	}
	raw = call(strings.Repeat("x", 1200), "graph_ast", map[string]any{"dir": f.project, "cache": "refresh", "maxBytes": 2000, "representation": "whole"})
	graphReceipt(t, "p1-mcp-refresh-frame-refusal.json", raw)
	if !bytes.Contains(raw, []byte("GRAPH_OUTPUT_BUDGET")) {
		t.Fatal("refresh frame budget did not refuse", string(raw))
	}
	if !reflect.DeepEqual(before, rootB2Image(t, f.project, f.home, f.install)) {
		t.Fatal("wrapper/frame refusal published cache")
	}
	t.Logf("actual installed escaped-ID MCP whole minimum=%d; one below wholly refuses; page/next complete; outer and refresh whole refusals leave full project/home/install unchanged", minimum)
}
