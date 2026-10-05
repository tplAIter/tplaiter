package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/mcpsrv"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

func buildFixtureChain(t *testing.T) ([]byte, []ossinstall.ExecutionEvidence) {
	t.Helper()
	index := trustload.ToolchainIndex{APIVersion: trustload.ToolchainIndexVersion, GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	chunks := map[string][]byte{}
	root := runtime.GOROOT()
	selected := func(p string) bool {
		return p == "bin/go" || p == "VERSION" || strings.HasPrefix(p, "src/") || strings.HasPrefix(p, "pkg/include/") || p == "pkg/tool/"+runtime.GOOS+"_"+runtime.GOARCH+"/compile" || p == "pkg/tool/"+runtime.GOOS+"_"+runtime.GOARCH+"/link" || p == "pkg/tool/"+runtime.GOOS+"_"+runtime.GOARCH+"/asm"
	}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "src/cmd" || strings.Contains(rel, "/testdata") || strings.HasPrefix(rel, "test/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !selected(rel) || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("fixture symlink %s", rel)
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		mode := "100644"
		if rel == "bin/go" || strings.HasPrefix(rel, "pkg/tool/") {
			mode = "100755"
		}
		f := trustload.ToolchainFile{Path: rel, Mode: mode, SHA256: evidencecas.Digest(b), Size: int64(len(b)), Chunks: []string{}}
		for off := 0; off < len(b); off += 4 << 20 {
			end := off + (4 << 20)
			if end > len(b) {
				end = len(b)
			}
			part := b[off:end]
			ref := evidencecas.Digest(part)
			chunks[ref] = part
			f.Chunks = append(f.Chunks, ref)
		}
		index.Files = append(index.Files, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(index.Files, func(i, j int) bool { return index.Files[i].Path < index.Files[j].Path })
	raw := t6BJSON(t, index)
	refs := make([]string, 0, len(chunks))
	for r := range chunks {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	evidence := []ossinstall.ExecutionEvidence{}
	for _, r := range refs {
		evidence = append(evidence, ossinstall.ExecutionEvidence{SHA256: r, DataBase64: base64.StdEncoding.EncodeToString(chunks[r])})
	}
	return raw, evidence
}
func buildFixturePackage(t *testing.T, index []byte, timeout int64) (ossinstall.Publisher, ossinstall.SourcePackage) {
	t.Helper()
	origin := "https://example.test/project-build"
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: project-build\n  version: 1.0.0\n  description: synthetic public build\nengine:\n  type: gotemplate\n  root: files\ncommands:\n  build:\n    run: go build -mod=readonly -buildvcs=false ./...\n    description: Compile current pure-Go project\n")
	contract := t6BJSON(t, operationtrust.NativeContract{APIVersion: operationtrust.NativeContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: []string{}})
	action := t6BJSON(t, operationtrust.ProjectBuildAction{APIVersion: "tplaiter.dev/project-build-action/v1", Adapter: "go-project-build-v1", CommandName: "build", Argv: operationtrust.ProjectBuildArguments(), TimeoutMillis: timeout, ToolchainIndexSHA256: evidencecas.Digest(index)})
	files := map[string][]byte{"template.manifest.yaml": manifest, "template.contract.json": contract, "toolchain/index.json": index, "actions/run/build.json": action, "files/go.mod.tmpl": []byte("module example.invalid/projectbuild\n\ngo 1.26\n"), "files/main.go.tmpl": []byte("package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"synthetic\")}\n")}
	objects := map[string][]byte{}
	entries := []trustverify.SourceEntry{}
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
				names[strings.Split(strings.TrimPrefix(p, prefix), "/")[0]] = true
			}
		}
		ordered := []string{}
		for n := range names {
			ordered = append(ordered, n)
		}
		sort.Strings(ordered)
		nodes := []t6BTreeEntry{}
		for _, n := range ordered {
			p := prefix + n
			if b, ok := files[p]; ok {
				id := add("blob", b)
				nodes = append(nodes, t6BTreeEntry{mode: "100644", name: n, oid: id})
				entries = append(entries, trustverify.SourceEntry{Path: p, Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(b)})
			} else {
				entries = append(entries, trustverify.SourceEntry{Path: p, Kind: "directory", Mode: "40000"})
				nodes = append(nodes, t6BTreeEntry{mode: "40000", name: n, oid: tree(p + "/")})
			}
		}
		return t6BTree(add, nodes)
	}
	treeID := tree("")
	commit := add("commit", []byte("tree "+treeID+"\n\nsynthetic immutable object only\n"))
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	treeDigest, _ := bootstrap.DomainDigest("tplaiter.dev/source-content-tree/v1", struct {
		APIVersion string                    `json:"apiVersion"`
		Entries    []trustverify.SourceEntry `json:"entries"`
	}{"tplaiter.dev/source-content-tree/v1", entries})
	contractDigest, _ := bootstrap.DomainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", evidencecas.Digest(contract)})
	key := ed25519.NewKeyFromSeed([]byte("project-build-publisher-test-onl"))
	pub := key.Public().(ed25519.PublicKey)
	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://local.tplaiter.invalid/policy", Issuer: "build-publisher", Predicate: "https://local.tplaiter.invalid/predicate/template-source", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: origin, TemplatePath: ".", Commit: commit, TreeSHA256: treeDigest, ContractSHA256: contractDigest}}
	raw := t6BJSON(t, statement)
	digest, _ := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	msg, _ := hex.DecodeString(digest[7:])
	return ossinstall.Publisher{Issuer: statement.Issuer, PublicKeyBase64: base64.StdEncoding.EncodeToString(pub), SourceOrigin: origin, TemplatePath: "."}, ossinstall.SourcePackage{APIVersion: ossinstall.SourcePackageAPIVersion, Statement: raw, Signature: bootstrap.EncodeSignature(ed25519.Sign(key, msg)), KeyFingerprint: bootstrap.Fingerprint(pub), Objects: objects}
}
func fixtureApproval(t *testing.T, policy *trustverify.ExecutionPolicy, req trustverify.ExecutionRequest, key ed25519.PrivateKey) []byte {
	a := trustverify.ExecutionApproval{APIVersion: trustverify.ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: req.RequestSHA256, ProfileBindingSHA256: req.ProfileBindingSHA256, OperationInputsSHA256: req.OperationInputsSHA256, ProjectID: req.ProjectID, Scope: req.Scope, ApproverID: policy.Approvers[0].ID, IdentityClass: "operator", ExecutionPolicySHA256: policy.PolicySHA256, Validity: policy.Approvers[0].Validity, KeyFingerprint: policy.Approvers[0].KeyFingerprint}
	a.GrantSHA256, _ = a.ComputeGrantSHA256()
	b, _ := hex.DecodeString(a.GrantSHA256[7:])
	sig := bootstrap.EncodeSignature(ed25519.Sign(key, b))
	a.SignatureCAS = evidencecas.Digest([]byte(sig))
	return t6BJSON(t, ossinstall.ApprovalImport{Approval: t6BJSON(t, a), Signature: sig})
}
func TestNativeProjectBuildInstalledCLI(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("first reviewed Go-build OS guard is Darwin arm64")
	}
	base := t6BTempDir(t)
	home := filepath.Join(base, "isolated-home")
	if e := os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	index, chunks := buildFixtureChain(t)
	pub, pkg := buildFixturePackage(t, index, 120000)
	key := ed25519.NewKeyFromSeed([]byte("project-build-approver-test-only"))
	public := key.Public().(ed25519.PublicKey)
	now := time.Now()
	valid := trustverify.Validity{NotBefore: now.Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: now.Add(time.Hour).UTC().Format(time.RFC3339)}
	project := filepath.Join(base, "project")
	install := filepath.Join(base, "install")
	approver := trustverify.Approver{ID: "build-operator", PrincipalID: "principal:build-operator", IdentityClass: "operator", PublicKeyBase64: base64.StdEncoding.EncodeToString(public), KeyFingerprint: bootstrap.Fingerprint(public), Validity: valid, Scopes: []trustverify.ApprovalScope{{ProjectID: "build-project", OperationScope: "run", ActionKind: "command", Origin: pub.SourceOrigin, TemplatePath: "."}}}
	result, e := ossinstall.GenerateWithContext(context.Background(), ossinstall.Options{Root: install, Publishers: []ossinstall.Publisher{pub}, SourcePackages: []ossinstall.SourcePackage{pkg}, ProjectContexts: []trustload.ProjectContext{{Key: "build", ProjectID: "build-project", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: project}}, Approvers: []trustverify.Approver{approver}, ExecutionEvidence: chunks})
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(base, "tplaiter")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", binary, "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+result.RegistrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+result.RegistrationSHA256, "../..")
	build.Env = testBuildEnv(home)
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("binary: %v %s", e, out)
	}
	image, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("installed fixture image SHA256 %s; toolchain %s %s/%s", evidencecas.Digest(image), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	call := func(args ...string) (string, int) {
		t.Helper()
		c := exec.Command(binary, args...)
		c.Dir = base
		c.Env = testProcessEnv(home)
		out, e := c.CombinedOutput()
		exit := 0
		if e != nil {
			if x, ok := e.(*exec.ExitError); ok {
				exit = x.ExitCode()
			} else {
				t.Fatal(e)
			}
		}
		return string(out), exit
	}
	if out, exit := call("trust", "provision"); exit != 0 {
		t.Fatalf("provision %d %s", exit, out)
	}
	selectionsRaw, e := os.ReadFile(result.SelectionsPath)
	if e != nil {
		t.Fatal(e)
	}
	var selections []operationtrust.SourceSelection
	if e = json.Unmarshal(selectionsRaw, &selections); e != nil {
		t.Fatal(e)
	}
	selectionPath := filepath.Join(base, "source.json")
	os.WriteFile(selectionPath, t6BJSON(t, selections[0]), 0600)
	if out, exit := call("new", selections[0].Subject.Commit, "project", "--dir", project, "--source-input", selectionPath, "--defaults", "--no-hooks", "--json"); exit != 0 {
		t.Fatalf("new %d %s", exit, out)
	}
	loaded, e := trustload.Load(context.Background(), func() trustload.LaunchSelection {
		raw, _ := os.ReadFile(result.RegistrationPath)
		reg, _ := ossinstall.DecodeRegistration(raw)
		return reg.Selection()
	}())
	if e != nil {
		t.Fatal(e)
	}
	policy, e := trustverify.DecodeExecutionPolicy(loaded.PolicyJSON)
	if e != nil {
		t.Fatal(e)
	}
	prepare := func() trustverify.ExecutionRequest {
		t.Helper()
		out, exit := call("run", "build", "--prepare", "--json")
		if exit != 0 {
			for _, name := range []string{"go.mod", "main.go"} {
				b, e := os.ReadFile(filepath.Join(project, name))
				t.Logf("synthetic %s: %q %v", name, b, e)
			}
			t.Fatalf("prepare %d %s", exit, out)
		}
		env, e := resultdto.Decode([]byte(out))
		if e != nil {
			t.Fatal(e)
		}
		var data resultdto.ProjectRunData
		if e = json.Unmarshal(env.Data, &data); e != nil || data.PreparedRequest == nil {
			t.Fatalf("request %s %v", out, e)
		}
		return *data.PreparedRequest
	}
	req := prepare()
	if out, exit := call("run", "build", "--json"); exit == 0 {
		t.Fatalf("unapproved build accepted %s", out)
	} else {
		assertProjectBuildRefusal(t, out)
		t.Log("unapproved build refused", out)
	}
	grant := filepath.Join(base, "grant.json")
	os.WriteFile(grant, fixtureApproval(t, policy, req, key), 0600)
	if out, exit := call("run", "build", "--approval-input", grant, "--json"); exit != 0 {
		t.Fatalf("real build %d %s", exit, out)
	} else {
		assertProjectBuildReceipt(t, out, req, 0)
		t.Log("real installed build", out)
	}
	projectBuildMCP(t, binary, base, home, project, grant, req)
	projectBuildCancellation(t, binary, base, home, loaded.Install.ScratchRoot, grant, req)
	os.WriteFile(filepath.Join(project, "main.go"), []byte("package main\nfunc main(){ syntax error }\n"), 0600)
	if out, exit := call("run", "build", "--approval-input", grant, "--json"); exit == 0 {
		t.Fatalf("stale grant accepted %s", out)
	} else {
		assertProjectBuildRefusal(t, out)
		t.Log("stale current-input grant refused", out)
	}
	req = prepare()
	os.WriteFile(grant, fixtureApproval(t, policy, req, key), 0600)
	out, exit := call("run", "build", "--approval-input", grant, "--json")
	if exit != 10 {
		t.Fatalf("syntax compiler outcome %d %s", exit, out)
	}
	assertProjectBuildReceipt(t, out, req, 1)
	t.Log("real syntax failure", out)
}

func assertProjectBuildReceipt(t *testing.T, out string, req trustverify.ExecutionRequest, exit int) resultdto.ProjectRunData {
	t.Helper()
	env, e := resultdto.Decode([]byte(out))
	if e != nil {
		t.Fatal(e)
	}
	var data resultdto.ProjectRunData
	if e = json.Unmarshal(env.Data, &data); e != nil {
		t.Fatal(e)
	}
	r := data.ProcessReceipt
	if r == nil || r.RequestSHA256 != req.RequestSHA256 || r.InputClosureSHA256 != req.Action.ContentClosureSHA256 || r.ExitCode != exit || data.ChildExitCode != exit || r.StdoutSHA256 != evidencecas.Digest([]byte(r.Stdout)) || r.StderrSHA256 != evidencecas.Digest([]byte(r.Stderr)) {
		t.Fatalf("invalid real receipt %s", out)
	}
	return data
}

func projectBuildMCP(t *testing.T, binary, base, home, project, grant string, req trustverify.ExecutionRequest) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, binary, "mcp-server")
	c.Dir = base
	c.Env = testProcessEnv(home)
	in, e := c.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := c.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var serr bytes.Buffer
	c.Stderr = &serr
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { in.Close(); c.Wait() }()
	enc, dec := json.NewEncoder(in), json.NewDecoder(out)
	request := func(id int, method string, params any) map[string]any {
		t.Helper()
		if e := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); e != nil {
			t.Fatal(e)
		}
		var r map[string]any
		if e := dec.Decode(&r); e != nil {
			t.Fatalf("MCP %v %s", e, serr.String())
		}
		if r["error"] != nil {
			t.Fatalf("MCP error %+v", r)
		}
		return r
	}
	request(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "approved-build-fixture", "version": "1"}})
	enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}})
	r := request(2, "tools/call", map[string]any{"name": "run", "arguments": map[string]any{"dir": project, "command": "build", "approvalInput": grant}})
	result, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result %+v", r)
	}
	raw, e := json.Marshal(result["structuredContent"])
	if e != nil {
		t.Fatal(e)
	}
	assertProjectBuildReceipt(t, string(raw), req, 0)
	t.Logf("real MCP build %s", raw)
}

func projectBuildCancellation(t *testing.T, binary, base, home, scratch, grant string, req trustverify.ExecutionRequest) {
	t.Helper()
	c := exec.Command(binary, "run", "build", "--approval-input", grant, "--json")
	c.Dir = base
	c.Env = testProcessEnv(home)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if e := c.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	started := false
	for !started {
		select {
		case e := <-done:
			t.Fatalf("build completed before cancellation probe %v %s", e, out.String())
		case <-deadline.C:
			c.Process.Kill()
			<-done
			t.Fatal("compiler never reached isolated cache")
		case <-tick.C:
			stages, _ := filepath.Glob(filepath.Join(scratch, ".tplaiter-go-build-*", "cache", "README"))
			started = len(stages) > 0
		}
	}
	if e := c.Process.Signal(syscall.SIGINT); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		c.Process.Kill()
		<-done
		t.Fatal("cancel did not reap compiler")
	}
	data := assertProjectBuildReceipt(t, out.String(), req, 130)
	if !data.ProcessReceipt.Cancelled || data.ProcessReceipt.TimedOut {
		t.Fatalf("bad cancellation %s", out.String())
	}
	t.Log("real cancelled build", out.String())
}

// Emit the run entry only: integration merges this into its current tool golden
// while preserving the independently owned settings_edit entry and total count.
func TestNativeProjectBuildRunSchemaFragment(t *testing.T) {
	tool, ok := mcpsrv.New("/nonexistent/tplaiter", "schema-fixture", nil).MCP().ListTools()["run"]
	if !ok {
		t.Fatal("run tool missing")
	}
	raw, e := json.Marshal(tool.Tool)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("RUN_SCHEMA_FRAGMENT %s", raw)
}

func assertProjectBuildRefusal(t *testing.T, out string) {
	t.Helper()
	raw := strings.SplitN(out, "\n", 2)[0]
	env, e := resultdto.Decode([]byte(raw))
	if e != nil {
		t.Fatalf("refusal not structured: %v %s", e, out)
	}
	if env.Operation != resultdto.OperationProjectRun || env.Status != resultdto.StatusBlocked || len(env.Diagnostics) == 0 {
		t.Fatalf("not a native guard refusal: %s", out)
	}
	var data resultdto.ProjectRunData
	if len(env.Data) > 0 {
		if e = json.Unmarshal(env.Data, &data); e != nil {
			t.Fatal(e)
		}
	}
	if data.ProcessReceipt != nil {
		t.Fatalf("refused request issued receipt: %s", out)
	}
	if !strings.HasPrefix(env.Diagnostics[0].Code, "TRUST_APPROVAL_") {
		t.Fatalf("wrong refusal guard: %s", out)
	}
}
