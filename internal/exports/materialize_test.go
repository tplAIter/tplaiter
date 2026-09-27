package exports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
)

func TestParseExportPayloadGolden(t *testing.T) {
	raw := []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"data","files":[{"contentSHA256":"sha256:73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac","mode":"100644","sourcePath":"files/data.txt","targetPath":"data.txt"}],"slots":[]}`)
	p, err := ParseExportPayload(raw)
	if err != nil || len(p.Files) != 1 || p.Files[0].TargetPath != "data.txt" {
		t.Fatalf("payload: %#v %v", p, err)
	}
	if _, err := ParseExportPayload(append(raw, '\n')); err != nil {
		t.Fatalf("JSON whitespace: %v", err)
	}
}

const (
	rawPayloadDigest   = "sha256:36b173e794e25984fb612dc7355b2d94098d58a00b13c3cc374b78cc94c4900c"
	rawPayloadLFDigest = "sha256:eaef4e90eaba087490ffd9ed941ed7c07737cf0ebc76530fb8cfa4223311073a"
)

func materialPayload(exportID, sourcePath, targetPath string, content []byte, mode string) []byte {
	return []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"` + exportID + `","files":[{"contentSHA256":"` + digestBytes(content) + `","mode":"` + mode + `","sourcePath":"` + sourcePath + `","targetPath":"` + targetPath + `"}],"slots":[]}`)
}

func materialSelected(exportID string, payload []byte) SelectedExport {
	return SelectedExport{Source: "sha256:" + strings.Repeat("0", 64), Provider: "provider", ID: exportID, Domain: "package", Name: exportID, Version: "1.0.0", ContentDigest: digestBytes(payload), ContractDigest: "sha256:" + strings.Repeat("1", 64), BindingSHA256: "sha256:" + strings.Repeat("2", 64), SourceParameterSHA256: "sha256:" + strings.Repeat("3", 64), ToolDigest: "sha256:" + strings.Repeat("4", 64), Parameters: []ScalarParameter{}, Chains: [][]string{}}
}

func closedMaterialInput() MaterializeInput {
	return MaterializeInput{Sources: []MaterialSource{}, TargetInventory: []InventoryEntry{}, Current: []FileState{}, Owned: []OwnedPreimage{}, Operations: []MaterialOperation{}, Managed: []ManagedCandidate{}}
}

func assertZeroMaterialization(t *testing.T, in MaterializeInput, wantCode string) {
	t.Helper()
	out, err := Materialize(in)
	if err == nil || len(out.Images) != 0 || len(out.Conflicts) != 0 || len(out.Managed) != 0 {
		t.Fatalf("want zero result code=%s, out=%#v err=%v", wantCode, out, err)
	}
	if got := err.Error(); got != wantCode {
		t.Fatalf("want error %s, got %s", wantCode, got)
	}
}

func TestD1PayloadRawDigestLiterals(t *testing.T) {
	raw := []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"data","files":[{"contentSHA256":"sha256:73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac","mode":"100644","sourcePath":"files/data.txt","targetPath":"data.txt"}],"slots":[]}`)
	if got := digestBytes(raw); got != rawPayloadDigest {
		t.Fatalf("PAYLOAD-RAW-1 digest changed: got %s", got)
	}
	if got := digestBytes(append(append([]byte(nil), raw...), '\n')); got != rawPayloadLFDigest {
		t.Fatalf("PAYLOAD-RAW-1 LF digest changed: got %s", got)
	}
	for _, payload := range [][]byte{raw, append(append([]byte(nil), raw...), '\n')} {
		if _, err := ParseExportPayload(payload); err != nil {
			t.Fatalf("literal payload rejected: %v", err)
		}
	}
}

func TestD1ValidReplaceAndRemove(t *testing.T) {
	old := []byte("old\n")
	newContent := []byte("new\n")
	raw := materialPayload("pkg", "src/data", "data.txt", newContent, "100755")
	sel := materialSelected("pkg", raw)
	owner := MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkg"}
	state := FileState{Path: "data.txt", Present: true, Mode: "100644", Content: old, ContentSHA256: digestBytes(old)}
	in := MaterializeInput{Sources: []MaterialSource{{Selected: sel, Payload: raw, Blobs: []MaterialBlob{{Path: "src/data", Mode: "100755", Content: newContent}}}}, TargetInventory: []InventoryEntry{{Path: "data.txt", Kind: "regular"}}, Current: []FileState{state}, Owned: []OwnedPreimage{{Path: "data.txt", Owner: owner, Mode: state.Mode, ContentSHA256: state.ContentSHA256}}, Operations: []MaterialOperation{{Kind: "replace", Path: "data.txt", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: state.ContentSHA256, SourceIndex: 0, EntryIndex: 0}}, Managed: []ManagedCandidate{}}
	out, err := Materialize(in)
	if err != nil || len(out.Images) != 1 || out.Images[0].After.Mode != "100755" || string(out.Images[0].After.Content) != string(newContent) {
		t.Fatalf("replace: %#v %v", out, err)
	}
	in.Sources = nil
	in.Operations = []MaterialOperation{{Kind: "remove", Path: "data.txt", BeforeOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: state.ContentSHA256, SourceIndex: -1, EntryIndex: -1}}
	in.Sources = []MaterialSource{}
	out, err = Materialize(in)
	if err != nil || len(out.Images) != 1 || out.Images[0].After.Present || out.Images[0].After.Mode != "" || len(out.Images[0].After.Content) != 0 {
		t.Fatalf("remove: %#v %v", out, err)
	}
}

func TestD1WholeFileOwnershipPresenceAndPreimage(t *testing.T) {
	old := []byte("old")
	desired := []byte("new")
	raw := materialPayload("pkg", "src/x", "x", desired, "100644")
	source := MaterialSource{Selected: materialSelected("pkg", raw), Payload: raw, Blobs: []MaterialBlob{{Path: "src/x", Mode: "100644", Content: desired}}}
	owner := MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkg"}
	state := FileState{Path: "x", Present: true, Mode: "100644", Content: old, ContentSHA256: digestBytes(old)}
	base := MaterializeInput{Sources: []MaterialSource{source}, TargetInventory: []InventoryEntry{{Path: "x", Kind: "regular"}}, Current: []FileState{state}, Owned: []OwnedPreimage{}, Operations: []MaterialOperation{}, Managed: []ManagedCandidate{}}
	replace := MaterialOperation{Kind: "replace", Path: "x", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: state.ContentSHA256, SourceIndex: 0, EntryIndex: 0}
	remove := MaterialOperation{Kind: "remove", Path: "x", BeforeOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: state.ContentSHA256, SourceIndex: -1, EntryIndex: -1}
	for _, tc := range []struct {
		name      string
		operation MaterialOperation
		wantCode  string
	}{
		{"unowned-replace", replace, "MATERIAL_OWNER_CONFLICT"},
		{"unowned-remove", remove, "MATERIAL_OWNER_CONFLICT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			in.Operations = []MaterialOperation{tc.operation}
			out, err := Materialize(in)
			if err != nil || len(out.Images) != 1 || len(out.Conflicts) != 1 || out.Conflicts[0].Code != tc.wantCode {
				t.Fatalf("ownership conflict preview: %#v %v", out, err)
			}
		})
	}
	add := base
	add.Current = []FileState{{Path: "x", Present: false}}
	add.TargetInventory = []InventoryEntry{}
	add.Owned = []OwnedPreimage{{Path: "x", Owner: owner, Mode: "100644", ContentSHA256: state.ContentSHA256}}
	add.Operations = []MaterialOperation{{Kind: "add", Path: "x", AfterOwner: owner, SourceIndex: 0, EntryIndex: 0}}
	if out, err := Materialize(add); err != nil || len(out.Images) != 1 || len(out.Conflicts) != 1 || out.Conflicts[0].Code != "MATERIAL_OWNER_CONFLICT" {
		t.Fatalf("add with existing owner: %#v %v", out, err)
	}
	stale := base
	stale.Owned = []OwnedPreimage{{Path: "x", Owner: owner, Mode: "100755", ContentSHA256: digestBytes([]byte("stale"))}}
	stale.Operations = []MaterialOperation{replace}
	if out, err := Materialize(stale); err != nil || len(out.Images) != 1 || len(out.Conflicts) != 1 || out.Conflicts[0].Code != "MATERIAL_PREIMAGE_CONFLICT" {
		t.Fatalf("stale owned preimage: %#v %v", out, err)
	}
	valid := base
	valid.Owned = []OwnedPreimage{{Path: "x", Owner: owner, Mode: state.Mode, ContentSHA256: state.ContentSHA256}}
	valid.Operations = []MaterialOperation{replace}
	if out, err := Materialize(valid); err != nil || len(out.Images) != 1 || len(out.Conflicts) != 0 {
		t.Fatalf("valid owned replace: %#v %v", out, err)
	}
}

func TestD1SelectedGrammarAndDuplicateSources(t *testing.T) {
	content := []byte("x")
	raw := materialPayload("pkg", "src/x", "x", content, "100644")
	base := materialSelected("pkg", raw)
	bad := []SelectedExport{
		func() SelectedExport { s := base; s.Provider = "bad provider"; return s }(),
		func() SelectedExport { s := base; s.Version = "1.0.0-01"; return s }(),
		func() SelectedExport { s := base; s.Parameters = nil; return s }(),
		func() SelectedExport { s := base; s.Chains = nil; return s }(),
		func() SelectedExport {
			s := base
			chain := make([]string, 129)
			for i := range chain {
				chain[i] = fmt.Sprintf("x%d", i)
			}
			s.Chains = [][]string{chain}
			return s
		}(),
	}
	for i, selected := range bad {
		t.Run(fmt.Sprintf("hostile-%d", i), func(t *testing.T) {
			in := closedMaterialInput()
			in.Sources = []MaterialSource{{Selected: selected, Payload: raw, Blobs: []MaterialBlob{{Path: "src/x", Mode: "100644", Content: content}}}}
			assertZeroMaterialization(t, in, "MATERIAL_BINDING")
		})
	}
	for _, tc := range []struct {
		name  string
		chain [][]string
	}{
		{"depth-128", [][]string{make([]string, maxExportDependencyDepth)}},
		{"many-short-chains", make([][]string, maxExportDependencyDepth+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := base
			selected.Chains = tc.chain
			for i := range selected.Chains {
				if len(selected.Chains[i]) == 0 {
					selected.Chains[i] = []string{"x"}
				}
				for j := range selected.Chains[i] {
					selected.Chains[i][j] = fmt.Sprintf("x%d", j)
				}
			}
			in := closedMaterialInput()
			in.Sources = []MaterialSource{{Selected: selected, Payload: raw, Blobs: []MaterialBlob{{Path: "src/x", Mode: "100644", Content: content}}}}
			if out, err := Materialize(in); err != nil || len(out.Images) != 0 {
				t.Fatalf("accepted chain boundary rejected: %#v %v", out, err)
			}
		})
	}
	valid := closedMaterialInput()
	valid.Sources = []MaterialSource{{Selected: base, Payload: raw, Blobs: []MaterialBlob{{Path: "src/x", Mode: "100644", Content: content}}}, {Selected: base, Payload: raw, Blobs: []MaterialBlob{{Path: "src/x", Mode: "100644", Content: content}}}}
	valid.Current = []FileState{{Path: "x", Present: false}}
	valid.Operations = []MaterialOperation{{Kind: "add", Path: "x", AfterOwner: MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkg"}, SourceIndex: 1, EntryIndex: 0}}
	out, err := Materialize(valid)
	if err != nil || len(out.Images) != 1 {
		t.Fatalf("equal duplicate source not deduplicated: %#v %v", out, err)
	}
	incompatible := valid
	incompatible.Sources = append([]MaterialSource(nil), valid.Sources...)
	incompatible.Sources[1].Payload = append([]byte(nil), raw...)
	incompatible.Sources[1].Blobs = []MaterialBlob{{Path: "src/x", Mode: "100644", Content: []byte("different")}}
	assertZeroMaterialization(t, incompatible, "MATERIAL_INPUT")
}

func TestD1EachRequiredCollectionNilAndAbsentResidual(t *testing.T) {
	fields := []struct {
		name string
		set  func(*MaterializeInput)
	}{
		{"sources", func(in *MaterializeInput) { in.Sources = nil }},
		{"inventory", func(in *MaterializeInput) { in.TargetInventory = nil }},
		{"current", func(in *MaterializeInput) { in.Current = nil }},
		{"owned", func(in *MaterializeInput) { in.Owned = nil }},
		{"operations", func(in *MaterializeInput) { in.Operations = nil }},
		{"managed", func(in *MaterializeInput) { in.Managed = nil }},
	}
	for _, tc := range fields {
		t.Run(tc.name, func(t *testing.T) {
			in := closedMaterialInput()
			tc.set(&in)
			assertZeroMaterialization(t, in, "MATERIAL_INPUT")
		})
	}
	in := closedMaterialInput()
	in.Current = []FileState{{Path: "empty", Present: false, Mode: "100644"}}
	assertZeroMaterialization(t, in, "MATERIAL_INPUT")
	zero := closedMaterialInput()
	zero.Current = []FileState{{Path: "empty", Present: true, Mode: "100644", ContentSHA256: digestBytes(nil)}}
	zero.TargetInventory = []InventoryEntry{{Path: "empty", Kind: "regular"}}
	out, err := Materialize(zero)
	if err != nil || len(out.Images) != 0 {
		t.Fatalf("zero-byte present state rejected: %#v %v", out, err)
	}
}

func TestD1BlobAndTargetBounds(t *testing.T) {
	content := []byte("x")
	raw := materialPayload("pkg", "src/x", "x", content, "100644")
	sel := materialSelected("pkg", raw)
	large := bytes.Repeat([]byte{'x'}, 16<<20+1)
	in := closedMaterialInput()
	in.Sources = []MaterialSource{{Selected: sel, Payload: raw, Blobs: []MaterialBlob{{Path: "src/x", Mode: "100644", Content: large}}}}
	assertZeroMaterialization(t, in, "MATERIAL_INPUT")
	in = closedMaterialInput()
	part := bytes.Repeat([]byte{'x'}, 16<<20)
	files := make([]string, 5)
	blobs := make([]MaterialBlob, 5)
	for i := range files {
		path := "src/" + string(rune('a'+i))
		files[i] = `{"sourcePath":"` + path + `","targetPath":"` + string(rune('a'+i)) + `","mode":"100644","contentSHA256":"` + digestBytes(part) + `"}`
		blobs[i] = MaterialBlob{Path: path, Mode: "100644", Content: part}
	}
	rawMany := []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"pkg","files":[` + strings.Join(files, ",") + `],"slots":[]}`)
	in.Sources = []MaterialSource{{Selected: materialSelected("pkg", rawMany), Payload: rawMany, Blobs: blobs}}
	assertZeroMaterialization(t, in, "MATERIAL_LIMIT")
	in = closedMaterialInput()
	for i := 0; i < 4097; i++ {
		in.Operations = append(in.Operations, MaterialOperation{Kind: "add", Path: "x" + string(rune('a'+i%26)) + ".txt"})
	}
	assertZeroMaterialization(t, in, "MATERIAL_LIMIT")
}

func TestD1InventoryAncestorAndCaseTopology(t *testing.T) {
	base := closedMaterialInput()
	cases := []struct {
		name       string
		inventory  []InventoryEntry
		current    []FileState
		operations []MaterialOperation
	}{
		{"regular", []InventoryEntry{{Path: "a", Kind: "regular"}}, []FileState{{Path: "a", Present: true, Mode: "100644", ContentSHA256: digestBytes(nil)}}, []MaterialOperation{{Kind: "add", Path: "a/b"}}},
		{"symlink", []InventoryEntry{{Path: "a", Kind: "symlink"}}, []FileState{{Path: "a/b", Present: false}}, []MaterialOperation{{Kind: "add", Path: "a/b"}}},
		{"other", []InventoryEntry{{Path: "a", Kind: "other"}}, []FileState{{Path: "a/b", Present: false}}, []MaterialOperation{{Kind: "add", Path: "a/b"}}},
		{"case-disagree", []InventoryEntry{{Path: "Data.txt", Kind: "regular"}}, []FileState{{Path: "data.txt", Present: true, Mode: "100644", ContentSHA256: digestBytes(nil)}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			in.TargetInventory, in.Current, in.Operations = tc.inventory, tc.current, tc.operations
			want := "MATERIAL_TARGET_CONFLICT"
			if tc.name == "case-disagree" {
				want = "MATERIAL_INPUT"
			}
			assertZeroMaterialization(t, in, want)
		})
	}
}

func TestD1OperationBranchesRejectMalformedWire(t *testing.T) {
	content := []byte("x")
	raw := materialPayload("pkg", "src/x", "x", content, "100644")
	sel := materialSelected("pkg", raw)
	owner := MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkg"}
	base := closedMaterialInput()
	base.Sources = []MaterialSource{{Selected: sel, Payload: raw, Blobs: []MaterialBlob{{Path: "src/x", Mode: "100644", Content: content}}}}
	base.TargetInventory = []InventoryEntry{{Path: "x", Kind: "regular"}}
	base.Current = []FileState{{Path: "x", Present: false}}
	for i, op := range []MaterialOperation{
		{Kind: "add", Path: "x", ExpectedSHA256: digestBytes(nil), AfterOwner: owner, SourceIndex: 0, EntryIndex: 0},
		{Kind: "add", Path: "x", AfterOwner: MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkg"}, SourceIndex: 0},
		{Kind: "add", Path: "x", AfterOwner: owner, SourceIndex: 0, EntryIndex: 0},
	} {
		in := base
		in.Operations = []MaterialOperation{op}
		if op.AfterOwner == owner && op.ExpectedSHA256 == "" {
			in.Current = []FileState{{Path: "x", Present: true, Mode: "100644", Content: content, ContentSHA256: digestBytes(content)}}
		}
		want := "MATERIAL_INPUT"
		if i > 0 {
			want = "MATERIAL_TARGET_CONFLICT"
		}
		assertZeroMaterialization(t, in, want)
	}
	state := FileState{Path: "x", Present: true, Mode: "100644", Content: content, ContentSHA256: digestBytes(content)}
	in := base
	in.Current = []FileState{state}
	in.Operations = []MaterialOperation{{Kind: "replace", Path: "x", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: state.ContentSHA256, SourceIndex: 0, EntryIndex: 1}}
	assertZeroMaterialization(t, in, "MATERIAL_OWNER_CONFLICT")
	in.Operations = []MaterialOperation{{Kind: "remove", Path: "x", BeforeOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: state.ContentSHA256, SourceIndex: 0, EntryIndex: 0}}
	assertZeroMaterialization(t, in, "MATERIAL_INPUT")
}

func TestD1ConflictSortAndAllCopyIsolation(t *testing.T) {
	oldA, oldB := []byte("a"), []byte("b")
	stateA := FileState{Path: "a", Present: true, Mode: "100644", Content: oldA, ContentSHA256: digestBytes(oldA)}
	stateB := FileState{Path: "b", Present: true, Mode: "100644", Content: oldB, ContentSHA256: digestBytes(oldB)}
	owner := MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkg"}
	ownerB := MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkgb"}
	in := closedMaterialInput()
	content := []byte("desired")
	raw := materialPayload("pkg", "src/a", "a", content, "100644")
	in.Sources = []MaterialSource{{Selected: materialSelected("pkg", raw), Payload: raw, Blobs: []MaterialBlob{{Path: "src/a", Mode: "100644", Content: content}}}}
	rawB := materialPayload("pkgb", "src/b", "b", content, "100644")
	selB := materialSelected("pkgb", rawB)
	selB.Source = "sha256:" + strings.Repeat("5", 64)
	in.Sources = append(in.Sources, MaterialSource{Selected: selB, Payload: rawB, Blobs: []MaterialBlob{{Path: "src/b", Mode: "100644", Content: content}}})
	in.TargetInventory = []InventoryEntry{{Path: "a", Kind: "regular"}, {Path: "b", Kind: "regular"}}
	in.Current = []FileState{stateB, stateA}
	in.Owned = []OwnedPreimage{{Path: "a", Owner: owner, Mode: stateA.Mode, ContentSHA256: stateA.ContentSHA256}, {Path: "b", Owner: ownerB, Mode: stateB.Mode, ContentSHA256: stateB.ContentSHA256}}
	in.Operations = []MaterialOperation{{Kind: "replace", Path: "b", BeforeOwner: ownerB, AfterOwner: ownerB, ExpectedMode: "100644", ExpectedSHA256: digestBytes([]byte("drift")), SourceIndex: 1, EntryIndex: 0}, {Kind: "replace", Path: "a", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: stateA.Mode, ExpectedSHA256: stateA.ContentSHA256, SourceIndex: 0, EntryIndex: 0}}
	out, err := Materialize(in)
	if err != nil || len(out.Images) != 2 || len(out.Conflicts) != 1 || out.Images[0].Path != "a" || out.Conflicts[0].Path != "b" {
		t.Fatalf("sorted conflict preview: %#v %v", out, err)
	}
	out.Images[1].After.Content[0] = 'z'
	out.Images[1].BeforeOwners[0].Provider = "changed"
	out.Conflicts[0].Path = "changed"
	if oldA[0] != 'a' || in.Owned[0].Owner.Provider != "provider" {
		t.Fatal("conflict result aliases input")
	}
}

func TestD1ParserOnlyVectorsAndSchemaSemantics(t *testing.T) {
	base := `{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"pkg","files":[],"slots":[{"targetPath":"package.json","pointer":"/scripts/a~1b","value":"x"}],"blocks":[]}`
	for _, raw := range []string{
		strings.Replace(base, `"exportID":"pkg"`, `"exportID":null`, 1),
		strings.Replace(base, `"files":[]`, `"files":1`, 1),
		strings.Replace(base, `"files":[]`, `"files":[] ,"files":[]`, 1),
		"\ufeff" + base,
		base + " trailing",
		strings.Replace(base, `"pointer":"/scripts/a~1b"`, `"pointer":"/scripts/a~2b"`, 1),
		string(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"pkg","files":[{"sourcePath":"src/a","sourcePath":"src/b","targetPath":"a","mode":"100644","contentSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],"slots":[]}`),
		string(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"pkg","files":[{"sourcePath":"src/a","targetPath":"a","mode":"100644","contentSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],"slots":[{"targetPath":"package.json","pointer":"/scripts/a~1b","pointer":"/scripts/a~01b","value":"x"}]}`),
	} {
		if _, err := ParseExportPayload([]byte(raw)); err == nil {
			t.Fatalf("parser accepted hostile wire %q", raw[:min(40, len(raw))])
		}
	}
	// Schema validation is semantic wire-shape evidence; duplicate-key and BOM
	// checks above remain parser-only because JSON Schema receives parsed values.
	if _, err := ParseExportPayload([]byte(strings.Replace(base, `"apiVersion":"tplaiter.dev/export-payload/v1",`, ``, 1))); err == nil {
		t.Fatal("accepted missing required field")
	}
}

func TestParseExportPayloadStrictVectors(t *testing.T) {
	base := `{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"data","files":[],"slots":[{"targetPath":"package.json","pointer":"/scripts/a~1b","value":"x"},{"targetPath":"package.json","pointer":"/scripts/c","value":"y"}]}`
	if p, err := ParseExportPayload([]byte(base)); err != nil || len(p.Slots) != 2 {
		t.Fatalf("distinct slots: %#v %v", p, err)
	}
	for _, bad := range []string{
		strings.Replace(base, `"/scripts/c"`, `"/scripts/a~2b"`, 1),
		strings.Replace(base, `"/scripts/c"`, `"/scripts/a~1b"`, 1),
		strings.Replace(base, `"files":[]`, `"files":null`, 1),
		"\ufeff" + base,
	} {
		if _, err := ParseExportPayload([]byte(bad)); err == nil {
			t.Fatalf("accepted hostile payload %q", bad[:min(20, len(bad))])
		}
	}
	dup := strings.Replace(base, `"files":[]`, `"files":[{"sourcePath":"x","targetPath":"x","mode":"100644","contentSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}]`, 1)
	dup = strings.Replace(dup, `"blocks":[]`, `"blocks":[{"sourcePath":"x","contentSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}]`, 1)
	if _, err := ParseExportPayload([]byte(dup)); err == nil {
		t.Fatal("accepted duplicate logical source")
	}
}

func TestExportPayloadSchemaClosedShape(t *testing.T) {
	b, err := os.ReadFile("../../schema/export-payload.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v["$schema"] != "https://json-schema.org/draft/2020-12/schema" || v["additionalProperties"] != false {
		t.Fatal("schema oracle metadata drift")
	}
}

func TestExportPayloadSchemaOracleMatchesStrictParser(t *testing.T) {
	schemaRaw, err := os.ReadFile("../../schema/export-payload.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	const uri = "https://tplaiter.dev/schema/export-payload.v1.schema.json"
	if err := c.AddResource(uri, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(uri)
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","exportID":"pkg","files":[{"sourcePath":"src/a","targetPath":"a","mode":"100644","contentSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],"slots":[],"blocks":[]}`)
	for _, tc := range []struct {
		name string
		raw  []byte
		good bool
	}{
		{"valid", valid, true},
		{"extra", []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","exportID":"pkg","files":[{"sourcePath":"src/a","targetPath":"a","mode":"100644","contentSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","extra":1}],"slots":[],"blocks":[]}`), false},
		{"null-files", []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","exportID":"pkg","files":null,"slots":[],"blocks":[]}`), false},
		{"numeric-id", []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","exportID":1,"files":[],"slots":[],"blocks":[]}`), false},
		{"reserved-path", []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","exportID":"pkg","files":[{"sourcePath":"CON","targetPath":"a","mode":"100644","contentSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],"slots":[],"blocks":[]}`), false},
	} {
		_, parseErr := ParseExportPayload(tc.raw)
		value, valueErr := js.UnmarshalJSON(strings.NewReader(string(tc.raw)))
		schemaErr := valueErr
		if schemaErr == nil {
			schemaErr = s.Validate(value)
		}
		if tc.good {
			if parseErr != nil || schemaErr != nil {
				t.Fatalf("valid parity parse=%v schema=%v", parseErr, schemaErr)
			}
			continue
		}
		if parseErr == nil {
			t.Fatalf("strict parser accepted hostile wire %s", tc.name)
		}
		// The schema is a wire-shape oracle. Platform-safe path and cross-entry
		// identity checks are deliberately enforced by ParseExportPayload.
		if strings.Contains(string(tc.raw), `"extra"`) && schemaErr == nil {
			t.Fatal("schema accepted extra property")
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestMaterializeWholeFileCopiesBlob(t *testing.T) {
	content := []byte("x\n")
	raw := []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"data","files":[{"contentSHA256":"sha256:73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac","mode":"100644","sourcePath":"files/data.txt","targetPath":"data.txt"}],"slots":[]}`)
	selected := SelectedExport{Source: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Provider: "provider", ID: "data", Domain: "package", Name: "data", Version: "1.0.0", ContentDigest: digestBytes(raw), ContractDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000001", BindingSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000002", SourceParameterSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000003", ToolDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000004", Chains: [][]string{}}
	selected.Parameters = []ScalarParameter{}
	result, err := Materialize(MaterializeInput{Sources: []MaterialSource{{Selected: selected, Payload: raw, Blobs: []MaterialBlob{{Path: "files/data.txt", Mode: "100644", Content: content}}}}, TargetInventory: []InventoryEntry{}, Current: []FileState{{Path: "data.txt", Present: false}}, Owned: []OwnedPreimage{}, Operations: []MaterialOperation{{Kind: "add", Path: "data.txt", AfterOwner: MaterialOwner{Provider: "provider", RuleID: "r", ExportID: "data"}, SourceIndex: 0, EntryIndex: 0}}, Managed: []ManagedCandidate{}})
	if err != nil || len(result.Images) != 1 || string(result.Images[0].After.Content) != "x\n" {
		t.Fatalf("materialize: %#v %v", result, err)
	}
	result.Images[0].After.Content[0] = 'y'
	if string(content) != "x\n" {
		t.Fatal("materialization did not copy blob")
	}
}

func TestMaterializeRequiresClosedInputAndReturnsConflictPreview(t *testing.T) {
	if _, err := Materialize(MaterializeInput{}); err == nil {
		t.Fatal("nil required arrays accepted")
	}
	current := FileState{Path: "x.txt", Present: true, Mode: "100644", Content: []byte("local")}
	current.ContentSHA256 = digestBytes(current.Content)
	content := []byte("new")
	raw := []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"x","files":[{"contentSHA256":"` + digestBytes(content) + `","mode":"100644","sourcePath":"x.txt","targetPath":"x.txt"}],"slots":[]}`)
	selected := SelectedExport{Source: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Provider: "p", ID: "x", Domain: "package", Name: "x", Version: "1.0.0", ContentDigest: digestBytes(raw), ContractDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000001", BindingSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000002", SourceParameterSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000003", ToolDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000004", Parameters: []ScalarParameter{}, Chains: [][]string{}}
	input := MaterializeInput{Sources: []MaterialSource{{Selected: selected, Payload: raw, Blobs: []MaterialBlob{{Path: "x.txt", Mode: "100644", Content: content}}}}, TargetInventory: []InventoryEntry{{Path: "x.txt", Kind: "regular"}}, Current: []FileState{current}, Owned: []OwnedPreimage{}, Operations: []MaterialOperation{{Kind: "replace", Path: "x.txt", BeforeOwner: MaterialOwner{Provider: "p", RuleID: "r", ExportID: "x"}, AfterOwner: MaterialOwner{Provider: "p", RuleID: "r", ExportID: "x"}, ExpectedMode: "100644", ExpectedSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000", SourceIndex: 0, EntryIndex: 0}}, Managed: []ManagedCandidate{}}
	out, err := Materialize(input)
	if err != nil || len(out.Conflicts) != 1 || len(out.Images) != 1 || string(out.Images[0].After.Content) != "local" {
		t.Fatalf("preview=%#v err=%v", out, err)
	}
	out.Images[0].After.Content[0] = 'x'
	if string(current.Content) != "local" {
		t.Fatal("conflict preview aliases current")
	}
}

func TestPayloadAndPathHostileVectors(t *testing.T) {
	for _, path := range []string{"/x", "a/../b", "a\\b", "a:b", ".git/a", "CON/x", "x./a", "x /a", "a//b"} {
		if err := payloadPath(path); err == nil {
			t.Fatalf("accepted hostile path %q", path)
		}
	}
	base := `{"apiVersion":"tplaiter.dev/export-payload/v1","exportID":"x","files":[{"sourcePath":"a","targetPath":"b","mode":"100644","contentSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],"slots":[],"blocks":[]}`
	for _, raw := range []string{strings.Replace(base, `"files":[`, `"files":null`, 1), strings.Replace(base, `"exportID":"x"`, `"exportID":1`, 1), strings.Replace(base, `"blocks":[]`, `"blocks":[],"x":1`, 1), strings.Replace(base, `"sourcePath":"a"`, `"sourcePath":"a","sourcePath":"b"`, 1)} {
		if _, err := ParseExportPayload([]byte(raw)); err == nil {
			t.Fatalf("accepted hostile wire %s", raw)
		}
	}
}

func TestPayloadSimpleFoldAndDuplicateSourcePreflight(t *testing.T) {
	d := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	raw := []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","exportID":"x","files":[{"sourcePath":"a","targetPath":"s","mode":"100644","contentSHA256":"` + d + `"},{"sourcePath":"b","targetPath":"ſ","mode":"100644","contentSHA256":"` + d + `"}],"slots":[],"blocks":[]}`)
	if _, err := ParseExportPayload(raw); err == nil {
		t.Fatal("accepted Unicode simple-fold collision")
	}
	content := []byte("x\n")
	good := []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"data","files":[{"contentSHA256":"sha256:73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac","mode":"100644","sourcePath":"files/data.txt","targetPath":"data.txt"}],"slots":[]}`)
	sel := SelectedExport{Source: d, Provider: "provider", ID: "data", Domain: "package", Name: "data", Version: "1.0.0", ContentDigest: digestBytes(good), ContractDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000001", BindingSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000002", SourceParameterSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000003", ToolDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000004", Parameters: []ScalarParameter{}, Chains: [][]string{}}
	in := MaterializeInput{Sources: []MaterialSource{{Selected: sel, Payload: good, Blobs: []MaterialBlob{{Path: "files/data.txt", Mode: "100644", Content: content}}}, {Selected: sel, Payload: []byte("not json")}}, TargetInventory: []InventoryEntry{}, Current: []FileState{{Path: "data.txt", Present: false}}, Owned: []OwnedPreimage{}, Operations: []MaterialOperation{{Kind: "add", Path: "data.txt", AfterOwner: MaterialOwner{Provider: "provider", RuleID: "r", ExportID: "data"}, SourceIndex: 0, EntryIndex: 0}}, Managed: []ManagedCandidate{}}
	if out, err := Materialize(in); err == nil || len(out.Images) != 0 {
		t.Fatalf("duplicate bypass: %#v %v", out, err)
	}
}

func TestManagedClaimPreflightAndCopy(t *testing.T) {
	b := []byte("// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n")
	state := FileState{Path: "x.go", Present: true, Mode: "100644", Content: b, ContentSHA256: digestBytes(b)}
	in := MaterializeInput{Sources: []MaterialSource{}, TargetInventory: []InventoryEntry{{Path: "x.go", Kind: "regular"}}, Current: []FileState{state}, Owned: []OwnedPreimage{}, Operations: []MaterialOperation{}, Managed: []ManagedCandidate{{Plan: managedblocks.FilePlan{Path: "x.go", Candidate: append([]byte(nil), b...), RenameAliases: map[string]string{}}, Before: state, DesiredMode: "100644"}}}
	out, err := Materialize(in)
	if err != nil || len(out.Managed) != 1 {
		t.Fatalf("managed: %#v %v", out, err)
	}
	out.Managed[0].Candidate[0] = 'x'
	if b[0] != '/' {
		t.Fatal("managed candidate aliases input")
	}
	in.Operations = []MaterialOperation{{Kind: "remove", Path: "x.go", BeforeOwner: MaterialOwner{}, ExpectedMode: "100644", ExpectedSHA256: state.ContentSHA256, SourceIndex: -1, EntryIndex: -1}}
	if _, err := Materialize(in); err == nil {
		t.Fatal("whole-file/managed overlap accepted")
	}
}

func TestMaterializeTopologyAndBranchErrorsHaveZeroResult(t *testing.T) {
	base := MaterializeInput{Sources: []MaterialSource{}, TargetInventory: []InventoryEntry{}, Current: []FileState{}, Owned: []OwnedPreimage{}, Operations: []MaterialOperation{}, Managed: []ManagedCandidate{}}
	for _, in := range []MaterializeInput{
		func() MaterializeInput {
			x := base
			x.Current = []FileState{{Path: "a", Present: false}, {Path: "a/b", Present: false}}
			x.Operations = []MaterialOperation{{Kind: "add", Path: "a"}, {Kind: "add", Path: "a/b"}}
			return x
		}(),
		func() MaterializeInput {
			x := base
			x.TargetInventory = []InventoryEntry{{Path: "a", Kind: "symlink"}}
			x.Current = []FileState{{Path: "a/b", Present: false}}
			x.Operations = []MaterialOperation{{Kind: "add", Path: "a/b"}}
			return x
		}(),
	} {
		out, err := Materialize(in)
		if err == nil || len(out.Images) != 0 || len(out.Conflicts) != 0 {
			t.Fatalf("malformed plan published result: %#v %v", out, err)
		}
	}
}
