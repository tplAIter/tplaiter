package resources

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type nativeObjectFixture map[string]trustverify.GitObject

func (f nativeObjectFixture) ReadObject(_ context.Context, _ trustverify.SourceOrigin, id trustverify.ObjectID) (trustverify.GitObject, error) {
	b, ok := f[string(id)]
	if !ok {
		return trustverify.GitObject{}, errors.New("missing object")
	}
	return b, nil
}

func nativeSnapshotFixture(t *testing.T, extra string, files map[string][]byte, executable bool, modes ...string) (*trustverify.SourceSnapshot, error) {
	t.Helper()
	rawManifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: inert\n  version: 1.0.0\n  description: inert fixture\nengine:\n  type: gotemplate\n  root: files\n" + extra)
	contract := []byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"` + evidencecas.Digest(rawManifest) + `","dependencies":[]}`)
	blobs := map[string][]byte{"template.manifest.yaml": rawManifest, "template.contract.json": contract, "files/output.txt": []byte("rendered")}
	for p, b := range files {
		blobs[p] = b
	}
	objects := nativeObjectFixture{}
	add := func(kind string, b []byte) string {
		raw := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(b))), b...)
		sum := sha1.Sum(raw)
		id := hex.EncodeToString(sum[:])
		objects[id] = trustverify.GitObject{Kind: kind, Data: append([]byte(nil), b...)}
		return id
	}
	type node struct {
		children map[string]*node
		data     []byte
		file     bool
	}
	root := &node{children: map[string]*node{}}
	for p, b := range blobs {
		n := root
		for _, part := range strings.Split(p, "/") {
			if n.children[part] == nil {
				n.children[part] = &node{children: map[string]*node{}}
			}
			n = n.children[part]
		}
		n.data = b
		n.file = true
	}
	var entries []trustverify.SourceEntry
	var tree func(*node, string) string
	tree = func(n *node, prefix string) string {
		names := make([]string, 0, len(n.children))
		for k := range n.children {
			names = append(names, k)
		}
		sort.Strings(names)
		var raw []byte
		for _, name := range names {
			child := n.children[name]
			p := prefix + name
			mode, kind := "40000", "directory"
			var id, digest string
			if child.file {
				mode = "100644"
				if executable && strings.HasPrefix(p, "generators/") {
					mode = "100755"
				}
				if len(modes) > 0 && strings.HasPrefix(p, "generators/") {
					mode = modes[0]
				}
				kind = "file"
				id = add("blob", child.data)
				digest = evidencecas.Digest(child.data)
			} else {
				id = tree(child, p+"/")
			}
			entries = append(entries, trustverify.SourceEntry{Path: p, Kind: kind, Mode: mode, ContentSHA256: digest})
			oid, _ := hex.DecodeString(id)
			raw = append(raw, []byte(mode+" "+name+"\x00")...)
			raw = append(raw, oid...)
		}
		return add("tree", raw)
	}
	rootID := tree(root, "")
	commit := add("commit", []byte("tree "+rootID+"\n\nfixture\n"))
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	treeDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-content-tree/v1", struct {
		APIVersion string                    `json:"apiVersion"`
		Entries    []trustverify.SourceEntry `json:"entries"`
	}{"tplaiter.dev/source-content-tree/v1", entries})
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", evidencecas.Digest(contract)})
	if err != nil {
		t.Fatal(err)
	}
	return trustverify.VerifySource(context.Background(), objects, trustverify.Subject{Origin: "https://example.test/source", TemplatePath: ".", Commit: commit, RequestedRef: commit, TreeSHA256: treeDigest, ContractSHA256: contractDigest})
}

func singleNativeDeclaration(ref string) string {
	return "generators:\n  - kind: entity\n    snippet: '" + ref + "'\n    target: internal/{{ .Name.Snake }}/entity.go\n"
}

func TestNativeGeneratorExactDeclaredClosure(t *testing.T) {
	raw := []byte("{{ never evaluate me }}\n\x00bytes\n")
	snapshot, err := nativeSnapshotFixture(t, singleNativeDeclaration("generators/one.tmpl"), map[string][]byte{"generators/one.tmpl": raw, "generators/undeclared.tmpl": []byte("exclude")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNativeGenerators(snapshot); err != nil {
		t.Fatal(err)
	}
	files, err := nativeGeneratorFiles(snapshot)
	if err != nil || len(files) != 1 || string(files[nativeGeneratorPrefix+"generators/one.tmpl"]) != string(raw) {
		t.Fatalf("exact bytes: %v %v", files, err)
	}
	src, err := retainSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, mutable := any(src).(interface{ WriteFile(string, []byte) error }); mutable {
		t.Fatal("writable snapshot exposed")
	}
}

func TestNativeGeneratorDeclarationRefusals(t *testing.T) {
	for _, ref := range []string{"../escape", "/absolute", "generators/../escape", ".tplaiter/project.yaml", "generators/.TPLAITER/project.yaml", "generators/.git/config", "generators/x\\y", "generators/x:y", "generators/space name", "generators/missing", "generators", "generators/x.", strings.Repeat("a", 256)} {
		t.Run(ref, func(t *testing.T) {
			snapshot, err := nativeSnapshotFixture(t, singleNativeDeclaration(ref), map[string][]byte{"generators/one.tmpl": []byte("inert")}, false)
			if err != nil {
				t.Fatal(err)
			}
			if ValidateNativeGenerators(snapshot) == nil {
				t.Fatal("invalid resource accepted")
			}
		})
	}
	for _, extra := range []string{"requires:\n  tools:\n    - name: git\n", "environment:\n  playbooks:\n    - name: setup\n      file: ansible/setup.yml\n", "hooks:\n  postCreate:\n    - run: echo forbidden\n", "hooks:\n  postUpdate:\n    - run: echo forbidden\n", "aiConfig:\n  path: ai\n", "commands:\n  - name: run\n    run: echo forbidden\n", "---\nkind: Template\n"} {
		t.Run(extra, func(t *testing.T) {
			snapshot, err := nativeSnapshotFixture(t, extra, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if ValidateNativeGenerators(snapshot) == nil {
				t.Fatal("unsupported metadata accepted")
			}
		})
	}
}

func TestNativeGeneratorImageBoundsModesAndCollisions(t *testing.T) {
	for _, name := range []string{"executable", "large", "case", "ancestor-case", "managed", "count", "aggregate", "directory-case", "symlink"} {
		t.Run(name, func(t *testing.T) {
			extra := singleNativeDeclaration("generators/one.tmpl")
			files := map[string][]byte{"generators/one.tmpl": []byte("inert")}
			executable := false
			mode := ""
			switch name {
			case "symlink":
				mode = "120000"
			case "directory-case":
				extra = "generators:\n  - kind: entity\n    targets:\n      - snippet: generators/one.tmpl\n        target: a.go\n      - snippet: Generators/other.tmpl\n        target: b.go\n"
				files["Generators/other.tmpl"] = []byte("other")
			case "executable":
				executable = true
			case "large":
				files["generators/one.tmpl"] = make([]byte, maxNativeResourceBytes+1)
			case "managed":
				files["generators/one.tmpl"] = []byte("tplater:managed-begin")
			case "case":
				extra = "generators:\n  - kind: entity\n    targets:\n      - snippet: generators/one.tmpl\n        target: a.go\n      - snippet: generators/ONE.tmpl\n        target: b.go\n"
				files["generators/ONE.tmpl"] = []byte("other")
			case "ancestor-case":
				extra = "generators:\n  - kind: entity\n    targets:\n      - snippet: generators/one.tmpl\n        target: a.go\n      - snippet: Generators/ONE.TMPL/child\n        target: b.go\n"
				files["Generators/ONE.TMPL/child"] = []byte("other")
			case "count", "aggregate":
				extra = "generators:\n  - kind: entity\n    targets:\n"
				count := maxNativeResources + 1
				if name == "aggregate" {
					count = 17
				}
				var declaration strings.Builder
				declaration.WriteString(extra)
				for i := 0; i < count; i++ {
					ref := fmt.Sprintf("generators/%03d.tmpl", i)
					_, _ = fmt.Fprintf(&declaration, "      - snippet: %s\n        target: out%d.go\n", ref, i)
					files[ref] = []byte("inert")
					if name == "aggregate" {
						files[ref] = make([]byte, maxNativeResourceBytes)
					}
				}
				extra = declaration.String()
			}
			var snapshot *trustverify.SourceSnapshot
			var err error
			if mode != "" {
				snapshot, err = nativeSnapshotFixture(t, extra, files, executable, mode)
			} else {
				snapshot, err = nativeSnapshotFixture(t, extra, files, executable)
			}
			if name == "symlink" {
				if err == nil {
					t.Fatal("symlink source accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ValidateNativeGenerators(snapshot) == nil {
				t.Fatal("unsafe image accepted")
			}
		})
	}
	if ValidateNativeGenerators(nil) == nil {
		t.Fatal("nil snapshot")
	}
}

func TestNativeResourceClosedDecode(t *testing.T) {
	for _, raw := range []string{`{"version":2,"artifacts":[]}`, `{"version":2,"artifacts":null}`, `{"version":2,"version":2,"artifacts":[]}`, `{"version":2,"artifacts":[],"trusted":true}`, `{}`} {
		if _, err := DecodeResourceLockV2([]byte(raw)); err == nil {
			t.Fatal("unbound/unknown wire accepted")
		}
	}
}

// Admission is inert: this fixture contains no host executable or execution
// policy/approval. Acceptance can only expose the declared generator bytes.
func TestNativeGeneratorProjectBuildAdmission(t *testing.T) {
	idx := trustload.ToolchainIndex{APIVersion: trustload.ToolchainIndexVersion, GoVersion: "go1.27.1", GOOS: "darwin", GOARCH: "arm64"}
	for _, name := range []string{"VERSION", "bin/go", "pkg/tool/darwin_arm64/asm", "pkg/tool/darwin_arm64/compile", "pkg/tool/darwin_arm64/link", "src/runtime/runtime.go"} {
		mode := "100644"
		if name == "bin/go" || strings.HasPrefix(name, "pkg/tool/") {
			mode = "100755"
		}
		idx.Files = append(idx.Files, trustload.ToolchainFile{Path: name, Mode: mode, Size: 1, SHA256: evidencecas.Digest([]byte("inert")), Chunks: []string{evidencecas.Digest([]byte("unavailable inert CAS"))}})
	}
	index, _ := json.Marshal(idx)
	action := operationtrust.ProjectBuildAction{APIVersion: "tplaiter.dev/project-build-action/v1", Adapter: "go-project-build-v1", CommandName: "build", Argv: operationtrust.ProjectBuildArguments(), TimeoutMillis: 1000, ToolchainIndexSHA256: evidencecas.Digest(index)}
	encode := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	exact := "commands:\n  build:\n    run: go build -mod=readonly -buildvcs=false ./...\n"
	for _, name := range []string{"empty", "exact", "malformed-toolchain", "unknown-command", "shell", "extra-argv", "wrong-adapter", "wrong-command-record", "index-drift", "missing-record", "foreign-policy", "unknown-shell-record", "tools", "playbooks", "hooks", "ai"} {
		t.Run(name, func(t *testing.T) {
			extra := exact
			a := action
			a.Argv = append([]string(nil), action.Argv...)
			files := map[string][]byte{"toolchain/index.json": index}
			switch name {
			case "malformed-toolchain":
				files["toolchain/index.json"] = []byte(`{"shell":true}`)
				a.ToolchainIndexSHA256 = evidencecas.Digest(files["toolchain/index.json"])
			case "empty":
				extra = ""
			case "unknown-command":
				extra = "commands:\n  deploy:\n    run: go build -mod=readonly -buildvcs=false ./...\n"
			case "shell":
				extra = exact + "    shell: true\n"
			case "extra-argv":
				a.Argv = append(a.Argv, "-o", "outside")
			case "wrong-adapter":
				a.Adapter = "native-snapshot-tool-v1"
			case "wrong-command-record":
				a.CommandName = "deploy"
			case "index-drift":
				a.ToolchainIndexSHA256 = evidencecas.Digest([]byte("other source"))
			case "tools":
				extra += "requires:\n  tools:\n    - name: git\n"
			case "playbooks":
				extra += "environment:\n  playbooks:\n    - name: setup\n      file: setup.yml\n"
			case "hooks":
				extra += "hooks:\n  postCreate:\n    - run: forbidden\n"
			case "ai":
				extra += "aiConfig:\n  path: ai\n"
			}
			raw := encode(a)
			if name == "foreign-policy" || name == "unknown-shell-record" {
				var obj map[string]any
				json.Unmarshal(raw, &obj)
				if name == "foreign-policy" {
					obj["policy"] = "caller-choice"
				} else {
					obj["shell"] = true
				}
				raw = encode(obj)
			}
			if name != "missing-record" {
				files[operationtrust.ProjectBuildActionPath] = raw
			}
			snapshot, e := nativeSnapshotFixture(t, extra, files, false)
			if e != nil {
				t.Fatal(e)
			}
			got, e := nativeGeneratorFiles(snapshot)
			allowed := name == "empty" || name == "exact"
			if allowed {
				if e != nil || len(got) != 0 {
					t.Fatalf("inert admission: %v %v", got, e)
				}
			} else if e == nil {
				t.Fatal("unsafe declaration admitted")
			}
		})
	}
}

func TestNativeGeneratorBuildCannotUseForeignManifest(t *testing.T) {
	snapshot, e := nativeSnapshotFixture(t, "", nil, false)
	if e != nil {
		t.Fatal(e)
	}
	foreign, e := manifest.ParseTemplate([]byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: foreign\n  version: 1.0.0\n  description: foreign fixture\nengine:\n  type: gotemplate\n  root: files\n"))
	if e != nil {
		t.Fatal(e)
	}
	if operationtrust.ValidateProjectBuildDeclaration(snapshot, foreign) == nil {
		t.Fatal("foreign caller manifest admitted")
	}
}
