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
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPublicTemporalRender(t *testing.T) {
	source := os.Getenv("TPLAITER_PUBLIC_TEMPORAL_TEMPLATE")
	target := os.Getenv("TPLAITER_PUBLIC_TEMPORAL_RENDER")
	if source == "" || target == "" {
		t.Skip("explicit public template and owned render paths required")
	}
	raw, err := os.ReadFile(filepath.Join(source, "template.manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := settings.Resolve(tpl, settings.Values{"workflow": true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Render(engine.Options{Source: os.DirFS(source), Target: target, Partials: []fs.FS{os.DirFS(filepath.Join(source, "partials"))}, Template: tpl, Resolved: resolved, Project: manifest.ProjectInfo{Name: "Temporal public proof", Slug: "temporal-public-proof", Module: "example.com/temporal-public-proof"}, Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: "https://github.com/tplAIter/template-go.git"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicTemporalCaptureClosure(t *testing.T) {
	packet := os.Getenv("TPLAITER_PUBLIC_TEMPORAL_PACKET")
	if packet == "" {
		t.Skip("explicit owned acquisition packet required")
	}
	raw, err := os.ReadFile(filepath.Join(packet, "module-download.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	type download struct{ Path, Version, Dir, Sum, GoModSum string }
	downloads := []download{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		var d download
		if e := decoder.Decode(&d); e == io.EOF {
			break
		} else if e != nil {
			t.Fatal(e)
		}
		downloads = append(downloads, d)
	}
	mod, err := os.ReadFile(filepath.Join(packet, "rendered/go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(filepath.Join(packet, "rendered/go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	index := trustload.GoModuleIndex{APIVersion: trustload.GoModuleIndexVersion, GoModSHA256: trustload.GoModuleProjectDigest(mod), GoSumSHA256: evidencecas.Digest(sum), Modules: []trustload.GoModulePin{}, Files: []trustload.ToolchainFile{}}
	chunks := map[string][]byte{}
	root := filepath.Join(packet, "acquisition-modules")
	capture := func(filename string) {
		info, e := os.Lstat(filename)
		if e != nil || !info.Mode().IsRegular() {
			t.Fatalf("unsafe acquisition input %s: %v", filename, e)
		}
		b, e := os.ReadFile(filename)
		if e != nil {
			t.Fatal(e)
		}
		rel, _ := filepath.Rel(root, filename)
		f := trustload.ToolchainFile{Path: filepath.ToSlash(rel), Mode: "100644", Size: int64(len(b)), SHA256: evidencecas.Digest(b), Chunks: []string{}}
		if len(b) == 0 {
			ref := evidencecas.Digest(b)
			chunks[ref] = b
			f.Chunks = append(f.Chunks, ref)
		}
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
	}
	for _, d := range downloads {
		index.Modules = append(index.Modules, trustload.GoModulePin{Path: d.Path, Version: d.Version, Sum: d.Sum, GoModSum: d.GoModSum})
		e := filepath.WalkDir(d.Dir, func(name string, entry os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if !entry.IsDir() {
				capture(name)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	e := filepath.WalkDir(filepath.Join(root, "cache/download"), func(name string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !entry.IsDir() && (strings.HasSuffix(name, ".mod") || strings.HasSuffix(name, ".info") || strings.HasSuffix(name, ".ziphash")) {
			capture(name)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	sort.Slice(index.Modules, func(i, j int) bool { return index.Modules[i].Path < index.Modules[j].Path })
	sort.Slice(index.Files, func(i, j int) bool { return index.Files[i].Path < index.Files[j].Path })
	b := t6BJSON(t, index)
	if e := trustload.ValidateGoModuleIndex(b); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(packet, "module-index.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	chain, evidence := buildFixtureChain(t)
	if e := os.WriteFile(filepath.Join(packet, "toolchain-index.json"), chain, 0600); e != nil {
		t.Fatal(e)
	}
	refs := []string{}
	for ref := range chunks {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		evidence = append(evidence, ossinstall.ExecutionEvidence{SHA256: ref, DataBase64: base64.StdEncoding.EncodeToString(chunks[ref])})
	}
	if e := os.WriteFile(filepath.Join(packet, "execution-evidence.json"), t6BJSON(t, evidence), 0600); e != nil {
		t.Fatal(e)
	}
	t.Logf("actual public Temporal SDK v1.29.1 compiler closure: %d modules, %d files, index %s, authenticated non-Go assets included; %d CAS chunks including toolchain", len(index.Modules), len(index.Files), evidencecas.Digest(b), len(evidence))
}

func publicTemporalFixturePackage(t *testing.T, templateRoot string) (ossinstall.Publisher, ossinstall.SourcePackage) {
	t.Helper()
	origin := "https://local.tplaiter.invalid/public-temporal-metadata-fixture"
	files := map[string][]byte{}
	// Local signed metadata overlay fixture: NEVER claim its commit is public main.
	// The retained public render/module bytes are imported without alteration.
	e := filepath.WalkDir(templateRoot, func(name string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(templateRoot, name)
		if rel == ".git" && !d.IsDir() {
			return nil
		}
		if d.IsDir() {
			if rel == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("fixture source symlink")
		}
		b, e := os.ReadFile(name)
		if e != nil {
			return e
		}
		files[filepath.ToSlash(rel)] = b
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	manifest := files["template.manifest.yaml"]
	contract := files["template.contract.json"]
	_ = manifest
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
	commit := add("commit", []byte("tree "+treeID+"\n\nLOCAL FIXTURE v3 metadata overlay of public template 5713671; not a published GitHub commit\n"))
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

func TestPublicTemporalInstalledCLIAndMCP(t *testing.T) {
	if base := os.Getenv("TPLAITER_PUBLIC_BUILD_GEN_SUMMARY_BASE"); base != "" {
		publicBuildCommittedGenSummaryProof(t, base)
		return
	}
	workflow := os.Getenv("TPLAITER_PUBLIC_BUILD_WORKFLOW") != "false"
	variantExpected := "workflow-true"
	if !workflow {
		variantExpected = "workflow-false"
	}
	packet, templateRoot := os.Getenv("TPLAITER_PUBLIC_TEMPORAL_PACKET"), os.Getenv("TPLAITER_PUBLIC_TEMPORAL_TEMPLATE")
	if packet == "" || templateRoot == "" {
		t.Skip("explicit owned public acquisition and metadata fixture required")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("bounded Darwin arm64 proof")
	}
	base := os.Getenv("TPLAITER_PUBLIC_TEMPORAL_REUSE_BASE")
	reuse := base != ""
	var e error
	if reuse {
		if !strings.HasPrefix(base, filepath.Join(packet, "installed-proof-")) {
			t.Fatal("reuse must be this packet owned proof")
		}
	} else {
		base, e = os.MkdirTemp(packet, "installed-proof-")
	}
	if e != nil {
		t.Fatal(e)
	}
	base, e = filepath.EvalSymlinks(base)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("retained proof %s; PUBLIC ASSETS from 5713671 plus LOCAL unpublished signed v3 metadata fixture; not a GitHub metadata publication certificate", base)
	home := filepath.Join(base, "home")
	if e = os.Mkdir(home, 0700); e != nil && !(reuse && os.IsExist(e)) {
		t.Fatal(e)
	}
	acquisition := os.Getenv("TPLAITER_PUBLIC_BUILD_ACQUISITION_PACKET")
	if acquisition == "" {
		acquisition = packet
	}
	raw, e := os.ReadFile(filepath.Join(acquisition, "execution-evidence.json"))
	if e != nil {
		t.Fatal(e)
	}
	var chunks []ossinstall.ExecutionEvidence
	if e = json.Unmarshal(raw, &chunks); e != nil {
		t.Fatal(e)
	}
	pub, pkg := publicTemporalFixturePackage(t, templateRoot)
	key := ed25519.NewKeyFromSeed([]byte("project-build-approver-test-only"))
	public := key.Public().(ed25519.PublicKey)
	now := time.Now()
	valid := trustverify.Validity{NotBefore: now.Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: now.Add(time.Hour).UTC().Format(time.RFC3339)}
	project := filepath.Join(base, "project")
	approver := trustverify.Approver{ID: "build-operator", PrincipalID: "principal:build-operator", IdentityClass: "operator", PublicKeyBase64: base64.StdEncoding.EncodeToString(public), KeyFingerprint: bootstrap.Fingerprint(public), Validity: valid, Scopes: []trustverify.ApprovalScope{{ProjectID: "temporal-project", OperationScope: "gen", ActionKind: "command", Origin: pub.SourceOrigin, TemplatePath: "."}, {ProjectID: "temporal-project", OperationScope: "run", ActionKind: "command", Origin: pub.SourceOrigin, TemplatePath: "."}}}
	var result ossinstall.Result
	if reuse {
		path := filepath.Join(base, "install/registration.json")
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result = ossinstall.Result{Root: filepath.Join(base, "install"), RegistrationPath: path, RegistrationSHA256: evidencecas.Digest(b), SelectionsPath: filepath.Join(base, "install/config/source-selections.json")}
	} else {
		result, e = ossinstall.GenerateWithContext(context.Background(), ossinstall.Options{Root: filepath.Join(base, "install"), Publishers: []ossinstall.Publisher{pub}, SourcePackages: []ossinstall.SourcePackage{pkg}, ProjectContexts: []trustload.ProjectContext{{Key: "temporal", ProjectID: "temporal-project", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: project}}, Approvers: []trustverify.Approver{approver}, ExecutionEvidence: chunks})
	}
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(base, "tplaiter")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), "build", "-o", binary, "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+result.RegistrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+result.RegistrationSHA256, "../..")
	build.Env = testBuildEnv(home)
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("binary %v %s", e, b)
	}
	image, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("installed image %s", evidencecas.Digest(image))
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
	if !reuse {
		newArgs := []string{"new", selections[0].Subject.Commit, "temporal-public-proof", "--dir", project, "--module", "example.com/temporal-public-proof", "--source-input", selectionPath, "--defaults", "--no-hooks", "--json"}
		if workflow {
			newArgs = append(newArgs, "--set", "workflow=true")
		}
		if out, exit := call(newArgs...); exit != 0 {
			t.Fatalf("new %d %s", exit, out)
		}
	}
	// Actual Temporal-enabled go.mod/go.sum must equal the retained public render.
	for _, name := range []string{"go.mod", "go.sum"} {
		want, e := os.ReadFile(filepath.Join(acquisition, "rendered", name))
		if !workflow {
			e = nil
			if name == "go.mod" {
				want = []byte("module example.com/temporal-public-proof\n\ngo 1.26\n")
			} else {
				want = []byte("\n")
			}
		}
		if e != nil {
			t.Fatal(e)
		}
		actual, e := os.ReadFile(filepath.Join(project, name))
		if e != nil || !bytes.Equal(want, actual) {
			t.Fatalf("public render drift %s %v", name, e)
		}
	}
	regRaw, e := os.ReadFile(result.RegistrationPath)
	if e != nil {
		t.Fatal(e)
	}
	reg, e := ossinstall.DecodeRegistration(regRaw)
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := trustload.Load(context.Background(), reg.Selection())
	if e != nil {
		t.Fatal(e)
	}
	policy, e := trustverify.DecodeExecutionPolicy(loaded.PolicyJSON)
	if e != nil {
		t.Fatal(e)
	}
	prepare := func(args ...string) trustverify.ExecutionRequest {
		t.Helper()
		out, exit := call(append(args, "--prepare", "--json")...)
		if exit != 0 {
			t.Fatalf("prepare %d %s", exit, out)
		}
		env, e := resultdto.Decode([]byte(out))
		if e != nil {
			t.Fatal(e)
		}
		var data struct {
			PreparedRequest *trustverify.ExecutionRequest `json:"preparedRequest"`
		}
		if e = json.Unmarshal(env.Data, &data); e != nil || data.PreparedRequest == nil {
			t.Fatalf("prepare data %v %s", e, out)
		}
		return *data.PreparedRequest
	}
	req := prepare("run", "build")
	grant := filepath.Join(base, "run-grant.json")
	os.WriteFile(grant, fixtureApproval(t, policy, req, key), 0600)
	if out, exit := call("run", "build", "--json"); exit == 0 {
		t.Fatalf("unsigned accepted %s", out)
	} else {
		assertProjectBuildRefusal(t, out)
		t.Log("unsigned public dependency build refused", out)
	}
	out, exit := call("run", "build", "--approval-input", grant, "--json")
	if exit != 0 {
		t.Fatalf("actual dependency CLI %d %s", exit, out)
	}
	data := assertProjectBuildReceipt(t, out, req, 0)
	if workflow && data.ProcessReceipt.ModuleIndexSHA256 == "" {
		t.Fatal("missing dependency digest")
	}
	if data.ProcessReceipt.BuildVariant != variantExpected || data.ProcessReceipt.BuildVariantSHA256 == "" || (!workflow && data.ProcessReceipt.ModuleIndexSHA256 != "") {
		t.Fatalf("wrong variant receipt %s", out)
	}
	t.Log("actual selected variant CLI build", out)
	if os.Getenv("TPLAITER_PUBLIC_BUILD_TEMPORAL_FOCUSED") != "1" {
		projectBuildMCP(t, binary, base, home, project, grant, req)
	}
	// Default generation is a separate gen-scoped projected-input grant.
	entity := os.Getenv("TPLAITER_PUBLIC_TEMPORAL_ENTITY")
	if entity == "" {
		entity = "Ride"
	}
	args := []string{"gen", "entity", entity, "--dir", project}
	genReq := prepare(args...)
	genGrant := filepath.Join(base, "gen-grant.json")
	os.WriteFile(genGrant, fixtureApproval(t, policy, genReq, key), 0600)
	if out, exit := call(append(args, "--json")...); exit == 0 {
		t.Fatalf("unsigned default gen accepted %s", out)
	}
	out, exit = call(append(args, "--approval-input", genGrant, "--json")...)
	if exit != 0 {
		t.Fatalf("default gen %d %s", exit, out)
	}
	env, e := resultdto.Decode([]byte(out))
	if e != nil {
		t.Fatal(e)
	}
	var gd resultdto.GenRunData
	if e = json.Unmarshal(env.Data, &gd); e != nil || gd.NoBuild || gd.ProcessReceipt == nil || gd.ProcessReceipt.ExitCode != 0 || gd.ProcessReceipt.RequestSHA256 != genReq.RequestSHA256 || gd.ProcessReceipt.ModuleIndexSHA256 != data.ProcessReceipt.ModuleIndexSHA256 {
		t.Fatalf("default gen receipt %v %s", e, out)
	}
	assertNativeGenCommittedSummary(t, env, gd)
	if gd.ProcessReceipt.BuildVariant != variantExpected || gd.ProcessReceipt.BuildVariantSHA256 != data.ProcessReceipt.BuildVariantSHA256 {
		t.Fatalf("wrong Gen variant %s", out)
	}
	t.Log("actual selected variant default Gen build", out)
	mcpArgs := []string{"gen", "entity", "Flight", "--dir", project}
	mcpReq := prepare(mcpArgs...)
	mcpGrant := filepath.Join(base, "gen-mcp-grant.json")
	if e := os.WriteFile(mcpGrant, fixtureApproval(t, policy, mcpReq, key), 0600); e != nil {
		t.Fatal(e)
	}
	if os.Getenv("TPLAITER_PUBLIC_BUILD_TEMPORAL_FOCUSED") != "1" {
		publicTemporalMCPGen(t, binary, base, home, project, mcpGrant, "Flight", mcpReq, data.ProcessReceipt.ModuleIndexSHA256)
	}
	// Concrete no-spawn mutations never select a fallback case.
	if os.Getenv("TPLAITER_PUBLIC_BUILD_WORKFLOW") != "" {
		publicBuildVariantCounterproof(t, call, project, base, grant, workflow, policy, key, reg.Selection())
	}
	// Reusing the previous run grant after generation must fail before execution.
	if out, exit := call("run", "build", "--approval-input", grant, "--json"); exit == 0 {
		t.Fatalf("stale run grant accepted %s", out)
	} else {
		assertProjectBuildRefusal(t, out)
		t.Log("stale dependency build grant refused", out)
	}
}

func publicTemporalMCPGen(t *testing.T, binary, base, home, project, grant, name string, req trustverify.ExecutionRequest, moduleDigest string) {
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
	schemas := request(2, "tools/list", map[string]any{})
	if e := os.WriteFile(filepath.Join(base, "tools-list.json"), t6BJSON(t, schemas), 0600); e != nil {
		t.Fatal(e)
	}
	r := request(3, "tools/call", map[string]any{"name": "gen", "arguments": map[string]any{"dir": project, "kind": "entity", "name": name, "approvalInput": grant}})
	result, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result %+v", r)
	}
	raw, e := json.Marshal(result["structuredContent"])
	if e != nil {
		t.Fatal(e)
	}
	env, e := resultdto.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	var data resultdto.GenRunData
	if e = json.Unmarshal(env.Data, &data); e != nil || data.NoBuild || data.ProcessReceipt == nil || data.ProcessReceipt.ExitCode != 0 || data.ProcessReceipt.RequestSHA256 != req.RequestSHA256 || data.ProcessReceipt.ModuleIndexSHA256 != moduleDigest {
		t.Fatalf("MCP Gen receipt %v %s", e, raw)
	}
	assertNativeGenCommittedSummary(t, env, data)
	t.Logf("real Temporal MCP default Gen build %s", raw)
}

// Retains selected closure/CAS/grant counterproof using only this packet's
// synthetic installation. No ambient installation or credentials participate.
func TestPublicTemporalInstalledCounterproof(t *testing.T) {
	packet := os.Getenv("TPLAITER_PUBLIC_TEMPORAL_PACKET")
	base := os.Getenv("TPLAITER_PUBLIC_TEMPORAL_REUSE_BASE")
	if packet == "" || base == "" || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("owned installed Temporal proof required")
	}
	if !strings.HasPrefix(base, filepath.Join(packet, "installed-proof-")) {
		t.Fatal("foreign installation refused")
	}
	home, project := filepath.Join(base, "home"), filepath.Join(base, "project")
	binary := filepath.Join(base, "tplaiter-counterproof")
	regPath := filepath.Join(base, "install/registration.json")
	regRaw, e := os.ReadFile(regPath)
	if e != nil {
		t.Fatal(e)
	}
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), "build", "-o", binary, "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+regPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+evidencecas.Digest(regRaw), "../..")
	build.Env = testBuildEnv(home)
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build %v %s", e, out)
	}
	image, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	t.Log("counterproof installed image", evidencecas.Digest(image))
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
	reg, e := ossinstall.DecodeRegistration(regRaw)
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := trustload.Load(context.Background(), reg.Selection())
	if e != nil {
		t.Fatal(e)
	}
	policy, e := trustverify.DecodeExecutionPolicy(loaded.PolicyJSON)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed([]byte("project-build-approver-test-only"))
	// The actual embedded protobuf binary is required by the compiler graph.
	indexRaw, e := os.ReadFile(filepath.Join(packet, "module-index.json"))
	if e != nil {
		t.Fatal(e)
	}
	var index trustload.GoModuleIndex
	if e = json.Unmarshal(indexRaw, &index); e != nil {
		t.Fatal(e)
	}
	var ref string
	for _, f := range index.Files {
		if strings.HasSuffix(f.Path, "internal/editiondefaults/editions_defaults.binpb") {
			ref = f.Chunks[0]
			break
		}
	}
	if ref == "" {
		t.Fatal("actual required non-Go asset absent")
	}
	hash := strings.TrimPrefix(ref, "sha256:")
	casPath := filepath.Join(base, "install/evidence/sha256", hash[:2], hash[2:])
	saved, e := os.ReadFile(casPath)
	if e != nil {
		t.Fatal(e)
	}
	t.Run("missing embedded module CAS", func(t *testing.T) {
		if e := os.Rename(casPath, casPath+".counterproof"); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if e := os.Rename(casPath+".counterproof", casPath); e != nil {
				t.Fatal(e)
			}
		}()
		out, exit := call("run", "build", "--prepare", "--json")
		if exit == 0 {
			t.Fatalf("missing CAS accepted %s", out)
		}
		assertTemporalClosureRefusal(t, out)
		t.Log("missing required module CAS refused", out)
	})
	actual, e := os.ReadFile(casPath)
	if e != nil || !bytes.Equal(actual, saved) {
		t.Fatal("CAS restore failed", e)
	}
	t.Run("changed go.sum", func(t *testing.T) {
		name := filepath.Join(project, "go.sum")
		raw, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			if e := os.WriteFile(name, raw, 0600); e != nil {
				t.Fatal(e)
			}
		}()
		if e := os.WriteFile(name, append(append([]byte(nil), raw...), '\n'), 0600); e != nil {
			t.Fatal(e)
		}
		out, exit := call("run", "build", "--prepare", "--json")
		if exit == 0 {
			t.Fatalf("sum drift accepted %s", out)
		}
		assertTemporalClosureRefusal(t, out)
		t.Log("selected go.sum drift refused", out)
	})
	// A concrete compiler failure after applying a generation must roll back the
	// generation, retain the caller's prior syntax edit, and report a real receipt.
	mainPath := filepath.Join(project, "broken.go")
	if _, e := os.Lstat(mainPath); !os.IsNotExist(e) {
		t.Fatal("counterproof path already exists", e)
	}
	defer func() {
		if e := os.Remove(mainPath); e != nil {
			t.Fatal(e)
		}
	}()
	if e := os.WriteFile(mainPath, []byte("package broken\nfunc broken( {\n"), 0600); e != nil {
		t.Fatal(e)
	}
	before := temporalRollbackTree(t, project)
	args := []string{"gen", "entity", "FailedProof", "--dir", project}
	out, exit := call(append(args, "--prepare", "--json")...)
	if exit != 0 {
		t.Fatalf("failed compilation prepare %d %s", exit, out)
	}
	env, e := resultdto.Decode([]byte(out))
	if e != nil {
		t.Fatal(e)
	}
	var prepared resultdto.GenRunData
	if e = json.Unmarshal(env.Data, &prepared); e != nil || prepared.PreparedRequest == nil {
		t.Fatal("no prepared gen", e)
	}
	grant := filepath.Join(base, "gen-failure-grant.json")
	if e := os.WriteFile(grant, fixtureApproval(t, policy, *prepared.PreparedRequest, key), 0600); e != nil {
		t.Fatal(e)
	}
	out, exit = call(append(args, "--approval-input", grant, "--json")...)
	if exit != int(resultdto.ExitChild) {
		t.Fatalf("expected compiler failure %d %s", exit, out)
	}
	env, e = resultdto.Decode([]byte(out))
	if e != nil {
		t.Fatal(e)
	}
	var failed resultdto.GenRunData
	if e = json.Unmarshal(env.Data, &failed); e != nil || failed.ProcessReceipt == nil || failed.ProcessReceipt.ExitCode != 1 || failed.ProcessReceipt.RequestSHA256 != prepared.PreparedRequest.RequestSHA256 || failed.ProcessReceipt.ModuleIndexSHA256 != evidencecas.Digest(indexRaw) || env.Summary.FilesChanged != 0 || len(env.Changes) != 0 || len(failed.Created) != 0 {
		t.Fatalf("failure receipt %v %s", e, out)
	}
	after := temporalRollbackTree(t, project)
	if !reflect.DeepEqual(before, after) {
		changed := []string{}
		for path, value := range before {
			if after[path] != value {
				changed = append(changed, path)
			}
		}
		for path := range after {
			if _, ok := before[path]; !ok {
				changed = append(changed, path)
			}
		}
		sort.Strings(changed)
		t.Fatalf("compiler failure did not restore project preimage: %v", changed)
	}
	t.Log("actual Temporal Gen compiler exit 1, exact rollback, retained receipt", out)
}

func assertTemporalClosureRefusal(t *testing.T, out string) {
	t.Helper()
	var raw json.RawMessage
	if e := json.NewDecoder(strings.NewReader(out)).Decode(&raw); e != nil {
		t.Fatal(e)
	}
	env, e := resultdto.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	if env.Status != resultdto.StatusBlocked || len(env.Diagnostics) != 1 || env.Diagnostics[0].Code != "TRUST_GO_MODULE_CLOSURE_UNAVAILABLE" || bytes.Contains(env.Data, []byte("processReceipt")) {
		t.Fatalf("wrong closure refusal %s", out)
	}
}

func temporalRollbackTree(t *testing.T, project string) map[string]string {
	tree := nativeGenTree(t, project)
	// The native owner intentionally retains terminal transaction audit history.
	// Exclude only that history, preserving all project files and stable metadata.
	for name := range tree {
		if name == ".tplaiter/project-transactions" || strings.HasPrefix(name, ".tplaiter/project-transactions/") {
			delete(tree, name)
		}
	}
	return tree
}
