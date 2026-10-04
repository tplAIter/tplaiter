//go:build darwin || linux

package e2e

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	stockGoCommit = "d0179547cd2e47b7564b0011bc5045799fc036bd"
	stockGoOrigin = "https://github.com/tplAIter/template-go"
)

// Actual make install, official process-generated local-operator publication,
// installed CLI/MCP creation, and offline stdlib build. No fixture trust keys.
func TestStockInstalledPublicGo(t *testing.T) {
	requireGit(t)
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
	env = append(env, "PATH="+os.Getenv("PATH"), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "config"), "XDG_DATA_HOME="+filepath.Join(home, "data"), "XDG_CACHE_HOME="+filepath.Join(home, "cache"), "TPLAITER_HOME="+stateHome, "GOMODCACHE="+caches[0], "GOCACHE="+caches[1], "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=-buildvcs=false", "NO_COLOR=1", "SHELL=/bin/sh", "CGO_ENABLED=0", "GIT_CONFIG_NOSYSTEM=1")
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
	expected := stockPublicObjects(t, repo, source)
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
	args := []string{"new", stockGoCommit, "CLI Display", "--dir", targets[0], "--project-context", "a", "--source-input", selection, "--defaults", "--no-hooks", "--no-deps-check", "--no-env-setup", "--json"}
	c := startMCP(t, env, binary, "mcp-server")
	c.initialize()
	mcpArgs := map[string]any{"ref": stockGoCommit, "name": "MCP Display", "dir": cwd, "targetDir": targets[1], "projectContext": "b", "sourceInput": selection, "defaults": true, "noHooks": true, "noDepsCheck": true, "noEnvSetup": true}
	// Context refusals precede creation: ordinary occupied-target replay cannot
	// hide missing context routing. Both registered target roots remain absent.
	preCreate := stockSnapshot(t, stateHome, trust, cwd)
	unchangedAbsent := func() {
		t.Helper()
		if !reflect.DeepEqual(preCreate, stockSnapshot(t, stateHome, trust, cwd)) {
			t.Fatal("context refusal changed state before creation")
		}
		for _, target := range targets {
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatalf("context refusal materialized target: %s (%v)", target, err)
			}
		}
	}
	wrong := append([]string(nil), args...)
	for i, v := range wrong {
		if v == "--project-context" {
			wrong[i+1] = "b"
		}
	}
	wrongRaw, wrongErr := run(cwd, binary, wrong...)
	if wrongErr == nil {
		t.Fatalf("CLI accepted wrong context: %s", wrongRaw)
	}
	stockContextResult(t, wrongRaw, "TRUST_PROJECT_CONTEXT_MISMATCH")
	unchangedAbsent()
	stockWrite(t, filepath.Join(base, "cli-context-refusal.txt"), wrongRaw)
	mcpArgs["projectContext"] = "unknown"
	unknown := c.callTool("project_new", mcpArgs)
	if !unknown.IsError {
		t.Fatal("MCP accepted unknown context")
	}
	requireEnvelope(t, "project_new", unknown)
	unknownRaw, err := json.Marshal(unknown.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	stockContextResult(t, unknownRaw, "TRUST_PROVENANCE_UNAVAILABLE")
	unchangedAbsent()
	stockJSON(t, filepath.Join(base, "mcp-context-refusal.json"), unknown)
	mcpArgs["projectContext"] = "b"
	// Retain a nonempty unrelated cwd observation from BEFORE either create.
	stockWrite(t, filepath.Join(cwd, "foreign.txt"), []byte("unrelated child cwd remains owned by its caller\n"))
	childBefore := stockSnapshot(t, cwd)
	stockJSON(t, filepath.Join(base, "child-cwd-before.json"), childBefore)
	cli := must(cwd, binary, args...)
	stockResult(t, cli, "stock-go-a", targets[0], "CLI Display")
	if !reflect.DeepEqual(childBefore, stockSnapshot(t, cwd)) {
		t.Fatal("CLI creation changed unrelated child cwd")
	}
	stockWrite(t, filepath.Join(base, "cli-new.json"), cli)
	result := c.callTool("project_new", mcpArgs)
	if result.IsError {
		t.Fatalf("MCP creation: %+v", result)
	}
	requireEnvelope(t, "project_new", result)
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	stockResult(t, raw, "stock-go-b", targets[1], "MCP Display")
	if !reflect.DeepEqual(childBefore, stockSnapshot(t, cwd)) {
		t.Fatal("MCP creation changed unrelated child cwd")
	}
	stockJSON(t, filepath.Join(base, "child-cwd-after.json"), stockSnapshot(t, cwd))
	stockWrite(t, filepath.Join(base, "mcp-new.json"), raw)
	helper := filepath.Join(build, "cmd", "stock-go-observer", "main.go")
	stockWrite(t, helper, stockRead(t, filepath.Join(repo, "tests", "testdata", "stock-go", "verify.go.txt")))
	for i, target := range targets {
		stockResources(t, target, expected)
		must(build, "go", "run", "./cmd/stock-go-observer", filepath.Join(trust, "registration.json"), []string{"a", "b"}[i], stateHome)
		must(target, "go", "build", "./...")
		must(target, "go", "test", "./...")
	}
	before := stockSnapshot(t, targets[0], targets[1], stateHome, trust, cwd)
	cross, crossErr := run(build, "go", "run", "./cmd/stock-go-observer", filepath.Join(trust, "registration.json"), "a", stateHome, targets[1])
	if crossErr == nil || !bytes.Contains(cross, []byte("project identity")) {
		t.Fatalf("stable verifier accepted cross-context project: %s", cross)
	}
	if !reflect.DeepEqual(before, stockSnapshot(t, targets[0], targets[1], stateHome, trust, cwd)) {
		t.Fatal("cross-context observer changed state")
	}
	stockWrite(t, filepath.Join(base, "stable-cross-context.txt"), cross)
	refused := func(argv ...string) []byte {
		t.Helper()
		out, err := run(cwd, binary, argv...)
		if err == nil {
			t.Fatalf("CLI accepted refusal: %s", out)
		}
		if !reflect.DeepEqual(before, stockSnapshot(t, targets[0], targets[1], stateHome, trust, cwd)) {
			t.Fatal("CLI refusal changed accepted state")
		}
		return out
	}
	cliReplay := refused(args...)
	replay := c.callTool("project_new", mcpArgs)
	if !replay.IsError {
		t.Fatal("MCP accepted replay")
	}
	if !reflect.DeepEqual(before, stockSnapshot(t, targets[0], targets[1], stateHome, trust, cwd)) {
		t.Fatal("MCP replay changed accepted state")
	}
	// Probe the review's bad oracle with actual occupied-target failures.
	// Both old predicates (nonzero / IsError) accept these substitutes, while
	// the exact context oracle must reject them even when used as denial evidence.
	replayRaw, err := json.Marshal(replay.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if stockProjectEnvelope(cliReplay, "blocked", "TRUST_PROJECT_CONTEXT_MISMATCH", "", "", "") == nil || stockProjectEnvelope(replayRaw, "blocked", "TRUST_PROVENANCE_UNAVAILABLE", "", "", "") == nil {
		t.Fatal("context oracle accepted ordinary replay substitute")
	}
	stockJSON(t, filepath.Join(base, "context-oracle-probe.json"), map[string]any{"oldNonzeroCLIOracleAccepted": true, "oldIsErrorMCPOracleAccepted": replay.IsError, "strictCLIContextOracleRejected": true, "strictMCPContextOracleRejected": true, "actualCLIReplay": json.RawMessage(bytes.SplitN(cliReplay, []byte("\n"), 2)[0]), "actualMCPReplay": replay.StructuredContent})
	t.Log("STOCK_GO strict context oracle rejects actual replay substitutes accepted by old nonzero/IsError predicates")
	stockWrite(t, selection, []byte(`{"authority":"development"}`))
	invalidArgs := append(append([]string(nil), args...), "--dry-run")
	out, invalidErr := run(cwd, binary, invalidArgs...)
	if invalidErr == nil || !bytes.Contains(out, []byte("TRUST_SOURCE_ADAPTER_UNSUPPORTED")) {
		t.Fatalf("invalid source was not verified/refused: %s", out)
	}
	refused(invalidArgs...)
	mcpArgs["dryRun"] = true
	mcpArgs["projectContext"] = "b"
	invalid := c.callTool("project_new", mcpArgs)
	_, _, codes := requireEnvelope(t, "project_new", invalid)
	if !invalid.IsError || len(codes) != 1 || codes[0] != "TRUST_SOURCE_ADAPTER_UNSUPPORTED" {
		t.Fatalf("MCP invalid source: %+v", invalid)
	}
	stockJSON(t, filepath.Join(base, "mcp-refusals.json"), []toolResult{replay, invalid})
	if !reflect.DeepEqual(before, stockSnapshot(t, targets[0], targets[1], stateHome, trust, cwd)) {
		t.Fatal("MCP refusal changed accepted state")
	}
	stockJSON(t, filepath.Join(base, "accepted-state.json"), before)
	t.Log("STOCK_GO accepted CLI/MCP create; source removed; six inert resources; stable registry; offline build/test; replay/refusal unchanged")
}

func stockCopySource(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".beads" || d.Name() == "bin" || d.Name() == ".cache") {
			return filepath.SkipDir
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(out, raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func stockWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func stockRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func stockJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	stockWrite(t, path, raw)
}

func stockDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func stockPublicObjects(t *testing.T, repo, source string) map[string][]byte {
	t.Helper()
	var f struct {
		Commit, Origin string
		Objects        map[string][]byte
	}
	if err := json.Unmarshal(stockRead(t, filepath.Join(repo, "internal", "newcmd", "testdata", "nativecreationfixtures", "template-go-d017.json")), &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != stockGoCommit || f.Origin != stockGoOrigin {
		t.Fatal("public fixture identity")
	}
	blobs := map[string][]byte{}
	for oid, raw := range f.Objects {
		sum := sha1.Sum(raw)
		if hex.EncodeToString(sum[:]) != oid {
			t.Fatal("public Git frame hash")
		}
		var compressed bytes.Buffer
		zw := zlib.NewWriter(&compressed)
		if _, err := zw.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		stockWrite(t, filepath.Join(source, ".git", "objects", oid[:2], oid[2:]), compressed.Bytes())
		header, data, ok := bytes.Cut(raw, []byte{0})
		if !ok {
			t.Fatal("Git frame")
		}
		if strings.HasPrefix(string(header), "blob ") {
			blobs[stockDigest(data)] = data
		}
	}
	stockWrite(t, filepath.Join(source, ".git", "config"), []byte("[core]\nrepositoryformatversion=0\nbare=false\n"))
	return blobs
}

// stockProjectEnvelope validates the complete project.new result/v1 envelope.
// It returns errors so the actual-replay bad-oracle probe exercises the same
// predicate as the context assertions, without intentionally failing the test.
func stockProjectEnvelope(raw []byte, status, code, id, root, name string) error {
	raw = bytes.SplitN(bytes.TrimSpace(raw), []byte("\n"), 2)[0] // CLI stderr follows its JSON line.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return err
	}
	for _, key := range envelopeRequiredKeys {
		if _, ok := top[key]; !ok {
			return fmt.Errorf("envelope lacks %s", key)
		}
	}
	var r struct {
		APIVersion, Kind, Operation, Status string
		Project                             *struct{ ID, Root string }
		TransactionID                       json.RawMessage
		Summary                             struct{ FilesChanged, BlocksChanged, Conflicts *int }
		Changes, Artifacts                  []json.RawMessage
		Diagnostics                         []struct {
			Code, Severity, Message string
			Details                 map[string]any
		}
		Meta struct {
			TplaiterVersion string
			SchemaVersion   int
		}
		Data *struct {
			DryRun    *bool
			Ref, Name string
		}
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	if r.APIVersion != "tplaiter.dev/result/v1" || r.Kind != "ProjectNew" || r.Operation != "project.new" || r.Status != status || r.Meta.SchemaVersion != 1 || r.Meta.TplaiterVersion != "v1.0.0" {
		return fmt.Errorf("result version/type/operation/status mismatch: %s", raw)
	}
	if string(r.TransactionID) != "null" || r.Changes == nil || len(r.Changes) != 0 || r.Artifacts == nil || len(r.Artifacts) != 0 || r.Diagnostics == nil {
		return errors.New("invalid transaction/change/artifact/diagnostic envelope")
	}
	for _, count := range []*int{r.Summary.FilesChanged, r.Summary.BlocksChanged, r.Summary.Conflicts} {
		if count == nil || *count != 0 {
			return errors.New("invalid result summary")
		}
	}
	if status == "ok" {
		if r.Project == nil || r.Project.ID != id || r.Project.Root != root || !filepath.IsAbs(r.Project.Root) || len(r.Diagnostics) != 0 || r.Data == nil || r.Data.DryRun == nil || *r.Data.DryRun || r.Data.Ref != stockGoCommit || r.Data.Name != name {
			return fmt.Errorf("positive result scope/data mismatch: %s", raw)
		}
	} else {
		if status != "blocked" || r.Project != nil || r.Data != nil || len(r.Diagnostics) != 1 || r.Diagnostics[0].Code != code || r.Diagnostics[0].Severity != "error" || r.Diagnostics[0].Message == "" || r.Diagnostics[0].Details == nil {
			return fmt.Errorf("exact context refusal mismatch: %s", raw)
		}
	}
	return nil
}

func stockResult(t *testing.T, raw []byte, id, root, name string) {
	t.Helper()
	if err := stockProjectEnvelope(raw, "ok", "", id, root, name); err != nil {
		t.Fatal(err)
	}
}

func stockContextResult(t *testing.T, raw []byte, code string) {
	t.Helper()
	if err := stockProjectEnvelope(raw, "blocked", code, "", "", ""); err != nil {
		t.Fatal(err)
	}
}

func stockResources(t *testing.T, target string, blobs map[string][]byte) {
	t.Helper()
	root := stockRead(t, filepath.Join(target, ".tplaiter", "root-template.lock.json"))
	var lock struct {
		Version        int
		RootLockSHA256 string
		TrustProfile   json.RawMessage
		Artifacts      []struct {
			Path, SourcePath, SHA256 string
			Mode                     uint32
			Source, Provider         json.RawMessage
		}
	}
	if err := json.Unmarshal(stockRead(t, filepath.Join(target, ".tplaiter", "resources.lock.json")), &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Version != 2 || len(lock.Artifacts) != 6 {
		t.Fatal("resource lock binding")
	}
	var rootValue struct {
		TrustProfile   json.RawMessage
		RootLockSHA256 string
		Root           json.RawMessage
	}
	if err := json.Unmarshal(root, &rootValue); err != nil {
		t.Fatal(err)
	}
	if lock.RootLockSHA256 != rootValue.RootLockSHA256 || !bytes.Equal(lock.TrustProfile, rootValue.TrustProfile) {
		t.Fatal("resource profile binding")
	}
	var inventory struct {
		Artifacts []struct {
			Path, SHA256, Kind, Target string
			Mode                       uint32
		}
	}
	ownership := stockRead(t, filepath.Join(target, ".tplaiter", "ownership.json"))
	if err := json.Unmarshal(ownership, &inventory); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ownership, []byte(`"provider"`)) || bytes.Contains(ownership, []byte(`"source"`)) {
		t.Fatal("ownership carries provenance")
	}
	seen := map[string]bool{}
	expectedNames := map[string]bool{"generators/entity/assembly.go.tmpl": true, "generators/entity/controller.go.tmpl": true, "generators/entity/repository.go.tmpl": true, "generators/entity/service.go.tmpl": true, "generators/entity/types.go.tmpl": true, "generators/entity/wiring.go.tmpl": true}
	for _, a := range lock.Artifacts {
		if seen[a.Path] || a.Path != ".tplaiter/generators/"+a.SourcePath {
			t.Fatal("resource path")
		}
		seen[a.Path] = true
		if !expectedNames[a.SourcePath] {
			t.Fatal("unexpected resource snippet")
		}
		delete(expectedNames, a.SourcePath)
		actual := stockRead(t, filepath.Join(target, a.Path))
		if !bytes.Equal(actual, blobs[a.SHA256]) || stockDigest(actual) != a.SHA256 {
			t.Fatal("resource exact public bytes")
		}
		info, err := os.Lstat(filepath.Join(target, a.Path))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
			t.Fatal("resource file mode")
		}
		if !bytes.Equal(a.Source, rootValue.Root) {
			t.Fatal("resource source differs from sealed root")
		}
		if !bytes.Contains(a.Source, []byte(stockGoCommit)) || !bytes.Contains(a.Source, []byte(stockGoOrigin)) || !bytes.Contains(a.Provider, []byte(stockGoCommit)) {
			t.Fatalf("resource provenance: %s %s", a.Source, a.Provider)
		}
		found := false
		for _, own := range inventory.Artifacts {
			if own.Path == a.Path && own.SHA256 == strings.TrimPrefix(a.SHA256, "sha256:") && own.Mode == a.Mode && own.Kind == "" && own.Target == "" {
				found = true
			}
		}
		if !found {
			t.Fatal("resource ownership")
		}
	}
	if string(stockRead(t, filepath.Join(target, ".tplaiter", "generator-targets.lock.json"))) != `{"targets":[],"version":1}` {
		t.Fatal("generator recorded execution")
	}
}

func stockSnapshot(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if d.IsDir() {
				out[path] = "dir:" + info.Mode().String()
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("unexpected nonregular %s", path)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[path] = info.Mode().String() + ":" + stockDigest(raw)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}
