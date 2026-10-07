package envcontract

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

func TestDecodeActionsAndRuntimePositiveAndDefensiveCopies(t *testing.T) {
	runtime := RuntimeDocument{
		APIVersion: RuntimeAPIVersion, GOOS: "darwin", GOARCH: "arm64", ToolID: "python-ansible", Version: "3.13.0",
		Driver: FilePin{Path: "runtime/bin/driver", Mode: "100755", SHA256: Digest([]byte("driver"))},
		Files: []RuntimeFile{
			{Path: "runtime/bin/driver", Mode: "100755", SHA256: Digest([]byte("driver")), Bytes: 6, ChunkCount: 1, Chunks: []ChunkPin{{SHA256: Digest([]byte("driver")), Bytes: 6}}},
			{Path: "runtime/lib/site.py", Mode: "100644", SHA256: Digest([]byte("site")), Bytes: 4, ChunkCount: 1, Chunks: []ChunkPin{{SHA256: Digest([]byte("site")), Bytes: 4}}},
		}, TotalBytes: 10,
	}
	runtimeRaw, err := CanonicalRuntime(runtime)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw := []byte("manifest")
	files := []SnapshotFile{{Path: "template.manifest.yaml", Mode: "100644", SHA256: Digest(manifestRaw), Bytes: manifestRaw}}
	for _, p := range []string{"playbooks/site.yml", "inventory/hosts", "ansible.cfg", "runtime/environment/index.json"} {
		b := []byte(p)
		files = append(files, SnapshotFile{Path: p, Mode: "100644", SHA256: Digest(b), Bytes: b})
	}
	action := Action{Name: "site", PlaybookFile: "playbooks/site.yml", Files: []FilePin{
		{Path: "ansible.cfg", Mode: "100644", SHA256: Digest([]byte("ansible.cfg"))},
		{Path: "inventory/hosts", Mode: "100644", SHA256: Digest([]byte("inventory/hosts"))},
		{Path: "playbooks/site.yml", Mode: "100644", SHA256: Digest([]byte("playbooks/site.yml"))},
		{Path: "runtime/environment/index.json", Mode: "100644", SHA256: Digest([]byte("runtime/environment/index.json"))},
	}, RuntimeIndexPath: "runtime/environment/index.json", RuntimeIndexSHA256: Digest([]byte("runtime/environment/index.json")), Argv: []string{"python"}, TimeoutMillis: 1000, ExecutionProfile: ExecutionProfile, Effects: HostEffects, InventoryPath: "inventory/hosts", ConfigPath: "ansible.cfg"}
	doc := ActionsDocument{APIVersion: ActionsAPIVersion, Actions: []Action{action}}
	raw, err := CanonicalActions(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeActions(raw, []ManifestPlaybook{{Name: "site", File: "playbooks/site.yml"}}, SourceSnapshot{ManifestPath: "template.manifest.yaml", ManifestSHA256: Digest(manifestRaw), Files: files})
	if err != nil {
		t.Fatal(err)
	}
	got.Actions[0].Files[0].Path = "changed"
	if doc.Actions[0].Files[0].Path == "changed" {
		t.Fatal("decoder did not return independent action files")
	}
	decodedRuntime, err := DecodeRuntime(runtimeRaw)
	if err != nil {
		t.Fatal(err)
	}
	decodedRuntime.Files[0].Chunks[0].SHA256 = "changed"
	if runtime.Files[0].Chunks[0].SHA256 == "changed" {
		t.Fatal("runtime copy was not defensive")
	}
}

func TestDecodeActionsAllowsIdenticalSharedPinsAndRequiresEachClosure(t *testing.T) {
	manifestRaw := []byte("manifest")
	snapshot := SourceSnapshot{ManifestPath: "manifest", ManifestSHA256: Digest(manifestRaw), Files: []SnapshotFile{{Path: "manifest", Mode: "100644", SHA256: Digest(manifestRaw), Bytes: manifestRaw}}}
	for _, p := range []string{"one.yml", "two.yml", "inventory", "config", "one.json", "two.json"} {
		b := []byte(p)
		snapshot.Files = append(snapshot.Files, SnapshotFile{Path: p, Mode: "100644", SHA256: Digest(b), Bytes: b})
	}
	pin := func(path string) FilePin { return FilePin{Path: path, Mode: "100644", SHA256: Digest([]byte(path))} }
	action := func(name, playbook, index string) Action {
		files := []FilePin{pin("config"), pin("inventory"), pin(index), pin(playbook)}
		return Action{Name: name, PlaybookFile: playbook, Files: files, RuntimeIndexPath: index, RuntimeIndexSHA256: Digest([]byte(index)), Argv: []string{"--config", configValue(name)}, TimeoutMillis: 1, ExecutionProfile: ExecutionProfile, Effects: HostEffects, InventoryPath: "inventory", ConfigPath: "config"}
	}
	doc := ActionsDocument{APIVersion: ActionsAPIVersion, Actions: []Action{action("one", "one.yml", "one.json"), action("two", "two.yml", "two.json")}}
	raw, err := CanonicalActions(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeActions(raw, []ManifestPlaybook{{Name: "one", File: "one.yml"}, {Name: "two", File: "two.yml"}}, snapshot); err != nil {
		t.Fatalf("shared identical pins rejected: %v", err)
	}
	missing := CloneActions(doc)
	missing.Actions[1].Files = missing.Actions[1].Files[:3]
	missingRaw, _ := CanonicalActions(missing)
	if _, err := DecodeActions(missingRaw, []ManifestPlaybook{{Name: "one", File: "one.yml"}, {Name: "two", File: "two.yml"}}, snapshot); err == nil {
		t.Fatal("accepted action missing its own playbook")
	}
	collision := snapshot
	collision.Files = append(append([]SnapshotFile(nil), snapshot.Files...), SnapshotFile{Path: "CONFIG", Mode: "100644", SHA256: Digest([]byte("CONFIG")), Bytes: []byte("CONFIG")})
	collisionDoc := CloneActions(doc)
	collisionDoc.Actions[1].ConfigPath = "CONFIG"
	collisionDoc.Actions[1].Files = append(collisionDoc.Actions[1].Files, pin("CONFIG"))
	sort.Slice(collisionDoc.Actions[1].Files, func(i, j int) bool {
		return collisionDoc.Actions[1].Files[i].Path < collisionDoc.Actions[1].Files[j].Path
	})
	collisionRaw, _ := CanonicalActions(collisionDoc)
	if _, err := DecodeActions(collisionRaw, []ManifestPlaybook{{Name: "one", File: "one.yml"}, {Name: "two", File: "two.yml"}}, collision); err == nil || !strings.Contains(err.Error(), "colliding or ancestor paths") {
		t.Fatalf("source collision diagnostic=%v", err)
	}
}

func configValue(name string) string { return "config-" + name }

func TestCloneHelpersPreserveCanonicalEmptyAndNestedCopies(t *testing.T) {
	empty := ActionsDocument{APIVersion: ActionsAPIVersion, Actions: []Action{}}
	emptyRaw, _ := CanonicalActions(empty)
	manifestBytes := []byte("manifest")
	if _, err := DecodeActions(emptyRaw, nil, SourceSnapshot{ManifestPath: "manifest", ManifestSHA256: Digest(manifestBytes), Files: []SnapshotFile{{Path: "manifest", Mode: "100644", SHA256: Digest(manifestBytes), Bytes: manifestBytes}}}); err != nil {
		t.Fatalf("zero-action baseline rejected: %v", err)
	}
	clone := CloneActions(empty)
	if clone.Actions == nil {
		t.Fatal("clone lost nonnil empty actions slice")
	}
	original, _ := CanonicalActions(empty)
	copyRaw, _ := CanonicalActions(clone)
	if !bytes.Equal(original, copyRaw) {
		t.Fatalf("empty clone changed canonical bytes: %s != %s", original, copyRaw)
	}
	if got, _ := ActionsDigest(empty); got != Digest(original) {
		t.Fatalf("empty clone digest basis changed: %s", got)
	}
	withNested := ActionsDocument{APIVersion: ActionsAPIVersion, Actions: []Action{{Argv: []string{"x"}, Files: []FilePin{{Path: "x", Mode: "100644", SHA256: Digest([]byte("x"))}}}}}
	withNestedClone := CloneActions(withNested)
	withNestedClone.Actions[0].Argv[0] = "changed"
	withNestedClone.Actions[0].Files[0].Path = "changed"
	if withNested.Actions[0].Argv[0] == "changed" || withNested.Actions[0].Files[0].Path == "changed" {
		t.Fatal("action clone aliases nested slices")
	}
	runtime := RuntimeDocument{Files: []RuntimeFile{{Chunks: []ChunkPin{}}}}
	runtimeClone := CloneRuntime(runtime)
	if runtimeClone.Files == nil || runtimeClone.Files[0].Chunks == nil {
		t.Fatal("runtime clone lost nonnil empty slices")
	}
	nonEmptyRuntime := RuntimeDocument{Files: []RuntimeFile{{Chunks: []ChunkPin{{SHA256: Digest([]byte("x")), Bytes: 1}}}}}
	nonEmptyClone := CloneRuntime(nonEmptyRuntime)
	nonEmptyClone.Files[0].Chunks[0].Bytes = 2
	if nonEmptyRuntime.Files[0].Chunks[0].Bytes != 1 {
		t.Fatal("runtime clone aliases nonempty chunks")
	}
}

func TestDecodeActionsRejectsClosedAndSemanticViolations(t *testing.T) {
	manifestRaw := []byte("manifest")
	base := SourceSnapshot{ManifestPath: "template.manifest.yaml", ManifestSHA256: Digest(manifestRaw), Files: []SnapshotFile{{Path: "template.manifest.yaml", Mode: "100644", SHA256: Digest(manifestRaw), Bytes: manifestRaw}}}
	valid := ActionsDocument{APIVersion: ActionsAPIVersion, Actions: []Action{{Name: "a", PlaybookFile: "playbook.yml", Files: []FilePin{
		{Path: "config", Mode: "100644", SHA256: Digest([]byte("config"))},
		{Path: "inventory", Mode: "100644", SHA256: Digest([]byte("inventory"))},
		{Path: "playbook.yml", Mode: "100644", SHA256: Digest([]byte("playbook.yml"))},
		{Path: "runtime.json", Mode: "100644", SHA256: Digest([]byte("runtime.json"))},
	}, RuntimeIndexPath: "runtime.json", RuntimeIndexSHA256: Digest([]byte("runtime.json")), Argv: []string{"driver"}, TimeoutMillis: 1, ExecutionProfile: ExecutionProfile, Effects: HostEffects, InventoryPath: "inventory", ConfigPath: "config"}}}
	for _, p := range []string{"playbook.yml", "runtime.json", "inventory", "config"} {
		b := []byte(p)
		base.Files = append(base.Files, SnapshotFile{Path: p, Mode: "100644", SHA256: Digest(b), Bytes: b})
	}
	raw, err := CanonicalActions(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeActions(raw, []ManifestPlaybook{{Name: "a", File: "playbook.yml"}}, base); err != nil {
		t.Fatalf("semantic baseline rejected: %v", err)
	}
	bad := []struct{ name, raw string }{
		{"unknown", `{"actions":[],"apiVersion":"tplaiter.dev/environment-actions/v1","extra":1}`},
		{"duplicate", `{"actions":[],"apiVersion":"tplaiter.dev/environment-actions/v1","apiVersion":"tplaiter.dev/environment-actions/v1"}`},
		{"null", `{"actions":null,"apiVersion":"tplaiter.dev/environment-actions/v1"}`},
		{"case", `{"actions":[],"apiVersion":"tplaiter.dev/environment-actions/v1","APIVersion":"tplaiter.dev/environment-actions/v1"}`},
		{"unicode", string([]byte{'{', '"', 'a', 'c', 't', 'i', 'o', 'n', 's', '"', ':', '[', ']', ',', '"', 'a', 'p', 'i', 'V', 'e', 'r', 's', 'i', 'o', 'n', '"', ':', '"', 0xff, '"', '}'})},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeActions([]byte(tc.raw), nil, base); err == nil {
				t.Fatal("accepted malformed closed input")
			}
		})
	}
	for _, test := range []struct {
		name, want string
		mutate     func(*ActionsDocument)
	}{
		{"escape", "invalid relative path", func(v *ActionsDocument) { v.Actions[0].Files[0].Path = "../config" }},
		{"duplicate closure", "duplicate closure path", func(v *ActionsDocument) {
			v.Actions[0].Files = []FilePin{v.Actions[0].Files[0], v.Actions[0].Files[1], v.Actions[0].Files[2], v.Actions[0].Files[2], v.Actions[0].Files[3]}
		}},
		{"profile", "invalid action execution metadata", func(v *ActionsDocument) { v.Actions[0].ExecutionProfile = "run/v1" }},
		{"empty argv", "invalid action argv", func(v *ActionsDocument) { v.Actions[0].Argv = []string{""} }},
		{"argv count", "invalid action execution metadata", func(v *ActionsDocument) {
			v.Actions[0].Argv = make([]string, MaxArgvItems+1)
			for i := range v.Actions[0].Argv {
				v.Actions[0].Argv[i] = "arg"
			}
		}},
		{"name", "invalid token", func(v *ActionsDocument) { v.Actions[0].Name = "A" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := valid
			copy.Actions = append([]Action(nil), valid.Actions...)
			copy.Actions[0].Files = append([]FilePin(nil), valid.Actions[0].Files...)
			test.mutate(&copy)
			b, _ := CanonicalActions(copy)
			if _, err := DecodeActions(b, []ManifestPlaybook{{Name: "a", File: "playbook.yml"}}, base); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("semantic diagnostic=%v want=%q", err, test.want)
			}
		})
	}
	for _, omitted := range []string{"inventory", "config", "runtime.json"} {
		copy := CloneActions(valid)
		filtered := copy.Actions[0].Files[:0]
		for _, pin := range copy.Actions[0].Files {
			if pin.Path != omitted {
				filtered = append(filtered, pin)
			}
		}
		copy.Actions[0].Files = filtered
		b, _ := CanonicalActions(copy)
		if _, err := DecodeActions(b, []ManifestPlaybook{{Name: "a", File: "playbook.yml"}}, base); err == nil {
			t.Fatalf("accepted action missing %s", omitted)
		}
	}
	mutatedNumber := strings.Replace(string(raw), `"timeoutMillis":1`, `"timeoutMillis":1.0`, 1)
	if _, err := DecodeActions([]byte(mutatedNumber), []ManifestPlaybook{{Name: "a", File: "playbook.yml"}}, base); err == nil || !strings.Contains(err.Error(), "noncanonical JSON") {
		t.Fatalf("nested integer diagnostic=%v", err)
	}
}

func TestDecodeRuntimeRejectsBoundsOrderingAndChunkMismatches(t *testing.T) {
	base := RuntimeDocument{APIVersion: RuntimeAPIVersion, GOOS: "linux", GOARCH: "amd64", ToolID: "driver", Version: "1", Driver: FilePin{Path: "bin/driver", Mode: "100755", SHA256: Digest([]byte("x"))}, Files: []RuntimeFile{{Path: "bin/driver", Mode: "100755", SHA256: Digest([]byte("x")), Bytes: 1, ChunkCount: 1, Chunks: []ChunkPin{{SHA256: Digest([]byte("x")), Bytes: 1}}}, {Path: "lib/a", Mode: "100644", SHA256: Digest([]byte("y")), Bytes: 1, ChunkCount: 1, Chunks: []ChunkPin{{SHA256: Digest([]byte("y")), Bytes: 1}}}}, TotalBytes: 2}
	valid, err := CanonicalRuntime(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRuntime(valid); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, want string
		mutate     func(*RuntimeDocument)
	}{
		{"duplicate-path", "duplicate runtime path", func(v *RuntimeDocument) {
			v.Files = append([]RuntimeFile{v.Files[0]}, v.Files...)
			v.TotalBytes++
		}},
		{"chunk-total", "chunk total mismatch", func(v *RuntimeDocument) { v.Files[0].Chunks[0].Bytes = 2 }},
		{"file-digest", "invalid file digest", func(v *RuntimeDocument) {
			v.Files[1].SHA256 = "sha256:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		}},
		{"platform", "invalid runtime identity", func(v *RuntimeDocument) { v.GOOS = "windows" }},
		{"tool-nul", "invalid runtime identity", func(v *RuntimeDocument) { v.ToolID = "driver\x00" }},
		{"driver-mode", "driver must be 100755", func(v *RuntimeDocument) { v.Driver.Mode = "100644" }},
		{"runtime-unicode-collision", "colliding or ancestor paths", func(v *RuntimeDocument) {
			v.Files = []RuntimeFile{v.Files[0], {Path: "lib/S", Mode: "100644", SHA256: Digest([]byte("s")), Bytes: 1, ChunkCount: 1, Chunks: []ChunkPin{{SHA256: Digest([]byte("s")), Bytes: 1}}}, {Path: "lib/ſ", Mode: "100644", SHA256: Digest([]byte("long-s")), Bytes: 1, ChunkCount: 1, Chunks: []ChunkPin{{SHA256: Digest([]byte("long-s")), Bytes: 1}}}}
			v.TotalBytes = 3
		}},
		{"runtime-ancestor", "colliding or ancestor paths", func(v *RuntimeDocument) {
			v.Files = []RuntimeFile{v.Files[0], v.Files[1], {Path: "lib/a/child", Mode: "100644", SHA256: Digest([]byte("child")), Bytes: 1, ChunkCount: 1, Chunks: []ChunkPin{{SHA256: Digest([]byte("child")), Bytes: 1}}}}
			v.TotalBytes = 3
		}},
		{"escape", "invalid relative path", func(v *RuntimeDocument) { v.Files[0].Path = "../driver" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := base
			copy.Files = append([]RuntimeFile(nil), base.Files...)
			copy.Files[0].Chunks = append([]ChunkPin(nil), base.Files[0].Chunks...)
			test.mutate(&copy)
			b, _ := CanonicalRuntime(copy)
			if _, err := DecodeRuntime(b); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runtime diagnostic=%v want=%q", err, test.want)
			}
		})
	}
	repeated := base
	repeated.Files = []RuntimeFile{{Path: "bin/driver", Mode: "100755", SHA256: Digest([]byte("x")), Bytes: 2, ChunkCount: 2, Chunks: []ChunkPin{{SHA256: Digest([]byte("x")), Bytes: 1}, {SHA256: Digest([]byte("x")), Bytes: 1}}}}
	repeated.TotalBytes = 2
	repeatedRaw, _ := CanonicalRuntime(repeated)
	if _, err := DecodeRuntime(repeatedRaw); err != nil {
		t.Fatalf("repeated CAS chunk at distinct offsets rejected: %v", err)
	}
	ordered := repeated
	ordered.Files = []RuntimeFile{{Path: "bin/driver", Mode: "100755", SHA256: Digest([]byte("ab")), Bytes: 2, ChunkCount: 2, Chunks: []ChunkPin{{SHA256: Digest([]byte("a")), Bytes: 1}, {SHA256: Digest([]byte("b")), Bytes: 1}}}}
	ordered.Driver.SHA256 = Digest([]byte("ab"))
	orderedRaw, _ := CanonicalRuntime(ordered)
	if _, err := DecodeRuntime(orderedRaw); err != nil {
		t.Fatalf("ordered distinct chunks rejected: %v", err)
	}
}

func TestDigestIsCanonicalAndStable(t *testing.T) {
	b, err := canonicaljson.Canonical(map[string]any{"b": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if Digest(b) != Digest(append([]byte(nil), b...)) || !strings.HasPrefix(Digest(b), "sha256:") {
		t.Fatal("unstable digest")
	}
	if !bytes.Equal(b, []byte(`{"a":1,"b":2}`)) {
		t.Fatalf("canonical=%s", b)
	}
}
