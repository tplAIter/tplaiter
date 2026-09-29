package exports

import (
	"errors"
	"strings"
	"testing"
)

func TestPlanJSONSlotsAddReplaceRemoveAndCopy(t *testing.T) {
	owner := MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkg"}
	currentBytes := []byte("{\n  \"scripts\": {\"build\": \"go build\"}, \"keep\": null, \"😀\": \"ok\"\n}\n")
	oldHash, _ := slotHash("go build")
	state := FileState{Path: "package.json", Present: true, Mode: "100755", Content: currentBytes, ContentSHA256: digestBytes(currentBytes)}
	owned := []OwnedPreimage{{Path: state.Path, Pointer: "/scripts/build", Owner: owner, Mode: state.Mode, ContentSHA256: oldHash}}
	image, conflicts, err := PlanJSONSlots(state, owned, []JSONSlotMutation{{Kind: "replace", Pointer: "/scripts/build", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: oldHash, Value: "go test"}})
	if err != nil || len(conflicts) != 0 || string(image.After.Content) == string(state.Content) || image.FormattingOnly {
		t.Fatalf("replace: image=%#v conflicts=%#v err=%v", image, conflicts, err)
	}
	if !strings.Contains(string(image.After.Content), `"keep":null`) || !strings.Contains(string(image.After.Content), `"😀":"ok"`) {
		t.Fatalf("unrelated values lost: %s", image.After.Content)
	}
	image.After.Content[0] = 'x'
	if state.Content[0] != '{' {
		t.Fatal("result aliases current")
	}

	add, conflicts, err := PlanJSONSlots(FileState{Path: "new.json"}, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/dependencies/@scope~1pkg", AfterOwner: owner, ExpectedMode: "", Value: "^1.0.0"}})
	if err != nil || len(conflicts) != 0 || add.After.Mode != "100644" {
		t.Fatalf("add: %#v %#v %v", add, conflicts, err)
	}
	if !strings.Contains(string(add.After.Content), `"@scope/pkg":"^1.0.0"`) {
		t.Fatalf("escaped pointer not decoded: %s", add.After.Content)
	}

	remove, conflicts, err := PlanJSONSlots(state, owned, []JSONSlotMutation{{Kind: "remove", Pointer: "/scripts/build", BeforeOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: oldHash}})
	if err != nil || len(conflicts) != 0 || strings.Contains(string(remove.After.Content), "build") {
		t.Fatalf("remove: %#v %#v %v", remove, conflicts, err)
	}
}

func TestPlanJSONSlotsRejectsDuplicateKeysAndNumbers(t *testing.T) {
	for _, raw := range []string{
		`{"scripts":{"x":"a","x":"b"}}`,
		`{"scripts":{"x":1.0}}`,
		`{"scripts":{"x":9007199254740992}}`,
		`{"scripts":{"x":-0}}`,
	} {
		state := FileState{Path: "package.json", Present: true, Mode: "100644", Content: []byte(raw)}
		state.ContentSHA256 = digestBytes(state.Content)
		_, _, err := PlanJSONSlots(state, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/y", AfterOwner: MaterialOwner{Provider: "p", RuleID: "r", ExportID: "x"}, ExpectedMode: state.Mode, Value: "v"}})
		if err == nil {
			t.Fatalf("accepted hostile JSON %s", raw)
		}
	}
}

func TestPlanJSONSlotsConflictPreservesOriginalBytes(t *testing.T) {
	raw := []byte(`{"scripts":{"x":"a"}}`)
	state := FileState{Path: "package.json", Present: true, Mode: "100644", Content: raw, ContentSHA256: digestBytes(raw)}
	owner := MaterialOwner{Provider: "p", RuleID: "r", ExportID: "x"}
	hash, _ := slotHash("different")
	image, conflicts, err := PlanJSONSlots(state, []OwnedPreimage{{Path: state.Path, Pointer: "/scripts/x", Owner: owner, Mode: state.Mode, ContentSHA256: hash}}, []JSONSlotMutation{{Kind: "replace", Pointer: "/scripts/x", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: hash, Value: "b"}})
	if err != nil || len(conflicts) != 1 || string(image.After.Content) != string(raw) {
		t.Fatalf("conflict: %#v %#v %v", image, conflicts, err)
	}
}

func TestMaterializeIntegratesOwnedJSONSlots(t *testing.T) {
	value := "go build"
	raw := []byte(`{"apiVersion":"tplaiter.dev/export-payload/v1","blocks":[],"exportID":"pkg","files":[],"slots":[{"targetPath":"package.json","pointer":"/scripts/build","value":"` + value + `"}]}`)
	selected := materialSelected("pkg", raw)
	old := []byte(`{"scripts":{"build":"old"}}`)
	oldHash, _ := slotHash("old")
	owner := MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkg"}
	input := closedMaterialInput()
	input.Sources = []MaterialSource{{Selected: selected, Payload: raw, Blobs: []MaterialBlob{}}}
	input.TargetInventory = []InventoryEntry{{Path: "package.json", Kind: "regular"}}
	input.Current = []FileState{{Path: "package.json", Present: true, Mode: "100644", Content: old, ContentSHA256: digestBytes(old)}}
	input.Owned = []OwnedPreimage{{Path: "package.json", Pointer: "/scripts/build", Owner: owner, Mode: "100644", ContentSHA256: oldHash}}
	input.Operations = []MaterialOperation{{Kind: "replace", Path: "package.json", Pointer: "/scripts/build", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: "100644", ExpectedSHA256: oldHash, SourceIndex: 0, EntryIndex: 0}}
	out, err := Materialize(input)
	if err != nil || len(out.Images) != 1 || len(out.Conflicts) != 0 || !strings.Contains(string(out.Images[0].After.Content), `"go build"`) {
		t.Fatalf("materialize slots: %#v %v", out, err)
	}
}

func slotTestState(raw string, mode string) FileState {
	b := []byte(raw)
	return FileState{Path: "package.json", Present: true, Mode: mode, Content: b, ContentSHA256: digestBytes(b)}
}

func slotTestOwner() MaterialOwner {
	return MaterialOwner{Provider: "provider", RuleID: "rule", ExportID: "pkg"}
}

func materialErrorCode(err error) string {
	if err == nil {
		return ""
	}
	e := &MaterialError{}
	if errors.As(err, &e) {
		return e.Code
	}
	return err.Error()
}

func TestPlanJSONSlotsOwnershipAndOriginalPreimageMatrix(t *testing.T) {
	owner := slotTestOwner()
	state := slotTestState(`{"scripts":{"build":"old"}}`, "100644")
	hash, _ := slotHash("old")
	t.Run("owned-replace-and-remove", func(t *testing.T) {
		owned := []OwnedPreimage{{Path: state.Path, Pointer: "/scripts/build", Owner: owner, Mode: state.Mode, ContentSHA256: hash}}
		for _, kind := range []string{"replace", "remove"} {
			m := JSONSlotMutation{Kind: kind, Pointer: "/scripts/build", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: hash, Value: "new"}
			if kind == "remove" {
				m.AfterOwner = MaterialOwner{}
				m.Value = ""
			}
			image, conflicts, err := PlanJSONSlots(state, owned, []JSONSlotMutation{m})
			if err != nil || len(conflicts) != 0 || image.After.ContentSHA256 == state.ContentSHA256 {
				t.Fatalf("%s: %#v %#v %v", kind, image, conflicts, err)
			}
		}
	})
	for _, tc := range []struct {
		name, code string
		owned      []OwnedPreimage
		before     MaterialOwner
	}{
		{"unowned", "MATERIAL_OWNER_CONFLICT", nil, owner},
		{"foreign-owner", "MATERIAL_OWNER_CONFLICT", []OwnedPreimage{{Path: state.Path, Pointer: "/scripts/build", Owner: MaterialOwner{Provider: "other", RuleID: "rule", ExportID: "pkg"}, Mode: state.Mode, ContentSHA256: hash}}, owner},
		{"zero-before-owner", "MATERIAL_OWNER_CONFLICT", []OwnedPreimage{{Path: state.Path, Pointer: "/scripts/build", Owner: owner, Mode: state.Mode, ContentSHA256: hash}}, MaterialOwner{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image, conflicts, err := PlanJSONSlots(state, tc.owned, []JSONSlotMutation{{Kind: "replace", Pointer: "/scripts/build", BeforeOwner: tc.before, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: hash, Value: "new"}})
			if tc.name == "zero-before-owner" {
				if err == nil || len(conflicts) != 0 || image.Path != "" {
					t.Fatalf("zero owner must be malformed input: %#v %#v %v", image, conflicts, err)
				}
				return
			}
			if err != nil || len(conflicts) != 1 || conflicts[0].Code != tc.code || string(image.After.Content) != string(state.Content) {
				t.Fatalf("%#v %#v %v", image, conflicts, err)
			}
		})
	}
	for _, value := range []any{"changed", nil} {
		t.Run("stale-or-nonstring", func(t *testing.T) {
			raw := `{"scripts":{"build":null}}`
			if value == "changed" {
				raw = `{"scripts":{"build":"changed"}}`
			}
			st := slotTestState(raw, state.Mode)
			image, conflicts, err := PlanJSONSlots(st, []OwnedPreimage{{Path: st.Path, Pointer: "/scripts/build", Owner: owner, Mode: st.Mode, ContentSHA256: hash}}, []JSONSlotMutation{{Kind: "replace", Pointer: "/scripts/build", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: st.Mode, ExpectedSHA256: hash, Value: "new"}})
			if err != nil || len(conflicts) != 1 || conflicts[0].Code != "MATERIAL_PREIMAGE_CONFLICT" || string(image.After.Content) != string(st.Content) {
				t.Fatalf("%#v %#v %v", image, conflicts, err)
			}
		})
	}
	for _, raw := range []string{`{"scripts":{"x":"a","x":"b"}}`, `{"nested":{"a":"x","\u0061":"y"}}`} {
		st := slotTestState(raw, state.Mode)
		if _, _, err := PlanJSONSlots(st, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/y", AfterOwner: owner, ExpectedMode: st.Mode, Value: "v"}}); err == nil {
			t.Fatalf("duplicate accepted: %s", raw)
		}
	}
}

func TestPlanJSONSlotsExactPointerAndAtomicPreflight(t *testing.T) {
	owner := slotTestOwner()
	for _, pointer := range []string{"/scripts/0/extra", "/scripts/*", "/scripts", "/scripts/", "/scripts/a~2b", "/scripts/a~"} {
		if _, _, err := PlanJSONSlots(slotTestState(`{"scripts":{}}`, "100644"), nil, []JSONSlotMutation{{Kind: "add", Pointer: pointer, AfterOwner: owner, ExpectedMode: "100644", Value: "v"}}); err == nil {
			t.Fatalf("invalid pointer accepted: %s", pointer)
		}
	}
	if _, _, err := PlanJSONSlots(slotTestState(`{"config":{}}`, "100644"), nil, []JSONSlotMutation{{Kind: "add", Pointer: "/config/x", AfterOwner: owner, ExpectedMode: "100644", Value: "v"}}); err == nil {
		t.Fatal("unsupported root accepted")
	}
	if _, _, err := PlanJSONSlots(slotTestState(`{"dependencies":{}}`, "100644"), nil, []JSONSlotMutation{{Kind: "add", Pointer: "/dependencies/@scope~1pkg", AfterOwner: owner, ExpectedMode: "100644", Value: "v"}}); err != nil {
		t.Fatal(err)
	}
	raw := `{"scripts":{"x":"a"},"dependencies":{}}`
	st := slotTestState(raw, "100644")
	h, _ := slotHash("a")
	image, conflicts, err := PlanJSONSlots(st, []OwnedPreimage{{Path: st.Path, Pointer: "/scripts/x", Owner: owner, Mode: st.Mode, ContentSHA256: h}}, []JSONSlotMutation{{Kind: "add", Pointer: "/dependencies/y", AfterOwner: owner, ExpectedMode: st.Mode, Value: "v"}, {Kind: "replace", Pointer: "/scripts/x", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: st.Mode, ExpectedSHA256: "sha256:" + strings.Repeat("0", 64), Value: "b"}})
	if err != nil || len(conflicts) != 1 || string(image.After.Content) != raw {
		t.Fatalf("atomic conflict: %#v %#v %v", image, conflicts, err)
	}
	for _, raw := range []string{`{"scripts":null}`, `{"scripts":"x"}`, `{"scripts":[]}`} {
		st := slotTestState(raw, "100644")
		image, conflicts, err := PlanJSONSlots(st, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/x", AfterOwner: owner, ExpectedMode: st.Mode, Value: "v"}})
		if err != nil || len(conflicts) != 1 || conflicts[0].Code != "JSON_SHAPE" || string(image.After.Content) != raw {
			t.Fatalf("parent shape: %#v %#v %v", image, conflicts, err)
		}
	}
}

func TestPlanJSONSlotsPresenceAndModeMatrix(t *testing.T) {
	owner := slotTestOwner()
	for _, tc := range []struct {
		name, raw string
		kind      string
		wantCode  string
	}{
		{"absent-add", `{"scripts":{}}`, "add", ""},
		{"empty-replace", `{"scripts":{"x":""}}`, "replace", ""},
		{"null-replace", `{"scripts":{"x":null}}`, "replace", "MATERIAL_PREIMAGE_CONFLICT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := slotTestState(tc.raw, "100755")
			var owned []OwnedPreimage
			var expected string
			if tc.kind == "replace" {
				h, _ := slotHash("")
				if tc.name == "null-replace" {
					h, _ = slotHash("")
				}
				owned = []OwnedPreimage{{Path: st.Path, Pointer: "/scripts/x", Owner: owner, Mode: st.Mode, ContentSHA256: h}}
				expected = h
			}
			m := JSONSlotMutation{Kind: tc.kind, Pointer: "/scripts/x", AfterOwner: owner, ExpectedMode: st.Mode, Value: "v", ExpectedSHA256: expected}
			if tc.kind == "replace" {
				m.BeforeOwner = owner
			}
			image, conflicts, err := PlanJSONSlots(st, owned, []JSONSlotMutation{m})
			if err != nil || (tc.wantCode == "" && len(conflicts) != 0) || (tc.wantCode != "" && (len(conflicts) != 1 || conflicts[0].Code != tc.wantCode)) {
				t.Fatalf("%#v %#v %v", image, conflicts, err)
			}
		})
	}
	absent := FileState{Path: "new.json"}
	image, conflicts, err := PlanJSONSlots(absent, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/x", AfterOwner: owner, Value: "v"}})
	if err != nil || len(conflicts) != 0 || image.After.Mode != "100644" {
		t.Fatalf("absent add: %#v %#v %v", image, conflicts, err)
	}
	for _, kind := range []string{"replace", "remove"} {
		image, conflicts, err = PlanJSONSlots(absent, nil, []JSONSlotMutation{{Kind: kind, Pointer: "/scripts/x", BeforeOwner: owner, ExpectedMode: "", ExpectedSHA256: "sha256:" + strings.Repeat("0", 64)}})
		if err == nil || len(conflicts) != 0 || image.Path != "" {
			t.Fatalf("absent %s: %#v %#v %v", kind, image, conflicts, err)
		}
	}
}

func TestPlanJSONSlotsRawNumberGate(t *testing.T) {
	good := `{"scripts":{},"low":-9007199254740991,"high":9007199254740991}`
	st := slotTestState(good, "100644")
	owner := slotTestOwner()
	image, conflicts, err := PlanJSONSlots(st, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/x", AfterOwner: owner, ExpectedMode: st.Mode, Value: "v"}})
	if err != nil || len(conflicts) != 0 || !strings.Contains(string(image.After.Content), `-9007199254740991`) || !strings.Contains(string(image.After.Content), `9007199254740991`) {
		t.Fatalf("safe boundaries: %#v %#v %v", image, conflicts, err)
	}
	for _, raw := range []string{`{"scripts":{},"n":9007199254740992}`, `{"scripts":{},"n":-9007199254740992}`, `{"scripts":{},"n":1.0}`, `{"scripts":{},"n":1e0}`, `{"scripts":{},"n":-0}`, `{"scripts":{},"n":01}`} {
		st := slotTestState(raw, "100644")
		_, _, err := PlanJSONSlots(st, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/x", AfterOwner: owner, ExpectedMode: st.Mode, Value: "v"}})
		if err == nil {
			t.Fatalf("unsupported number accepted: %s", raw)
		}
	}
}

func TestPlanJSONSlotsUnicodeAndHashDomains(t *testing.T) {
	if got, _ := slotHash("go build"); got != "sha256:52e7e94e408eef671312c717978d999cddd7061efd7300abe50bfd8d2ec27248" {
		t.Fatalf("slot hash drift: %s", got)
	}
	raw := `{"scripts":{},"😀":"x","\uE000":"y","text":"CRLF\r\nзначение"}`
	st := slotTestState(raw, "100644")
	image, conflicts, err := PlanJSONSlots(st, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/x", AfterOwner: slotTestOwner(), ExpectedMode: st.Mode, Value: "v"}})
	if err != nil || len(conflicts) != 0 || !strings.Contains(string(image.After.Content), `"😀":"x"`) || !strings.Contains(string(image.After.Content), "\xEE\x80\x80\":\"y\"") {
		t.Fatalf("unicode: %#v %#v %v", image, conflicts, err)
	}
}

func TestPlanJSONSlotsAndMaterializeCopyIsolation(t *testing.T) {
	owner := slotTestOwner()
	raw := `{"scripts":{"x":"a"}}`
	st := slotTestState(raw, "100644")
	h, _ := slotHash("a")
	owned := []OwnedPreimage{{Path: st.Path, Pointer: "/scripts/x", Owner: owner, Mode: st.Mode, ContentSHA256: h}}
	image, conflicts, err := PlanJSONSlots(st, owned, []JSONSlotMutation{{Kind: "replace", Pointer: "/scripts/x", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: st.Mode, ExpectedSHA256: h, Value: "b"}})
	if err != nil || len(conflicts) != 0 {
		t.Fatal(err)
	}
	image.Before.Content[0] = 'x'
	image.After.Content[0] = 'x'
	image.BeforeOwners[0].Provider = "x"
	if st.Content[0] != '{' || owned[0].Owner.Provider != owner.Provider {
		t.Fatal("input alias")
	}
	invalid := closedMaterialInput()
	invalid.Owned = []OwnedPreimage{{Path: "package.json", Pointer: "/scripts/x", Owner: owner, Mode: "bad", ContentSHA256: h}}
	if out, err := Materialize(invalid); err == nil || len(out.Images) != 0 || len(out.Conflicts) != 0 {
		t.Fatalf("inactive invalid mode accepted: %#v %v", out, err)
	}
	valid := closedMaterialInput()
	valid.Owned = []OwnedPreimage{{Path: "package.json", Pointer: "/scripts/x~01", Owner: owner, Mode: "100644", ContentSHA256: h}}
	if out, err := Materialize(valid); err != nil || len(out.Images) != 0 || len(out.Conflicts) != 0 {
		t.Fatalf("inactive canonical pointer rejected: %#v %v", out, err)
	}
	for _, ownedRecords := range [][]OwnedPreimage{
		{{Path: "package.json", Pointer: "/scripts/x", Owner: owner, Mode: "100644", ContentSHA256: "bad"}},
		{{Path: "package.json", Pointer: "/config/x", Owner: owner, Mode: "100644", ContentSHA256: h}},
		{{Path: "package.json", Pointer: "/scripts/x", Owner: owner, Mode: "100644", ContentSHA256: h}, {Path: "package.json", Pointer: "/scripts/x", Owner: owner, Mode: "100644", ContentSHA256: h}},
	} {
		in := closedMaterialInput()
		in.Owned = ownedRecords
		if out, err := Materialize(in); err == nil || len(out.Images) != 0 || len(out.Conflicts) != 0 {
			t.Fatalf("inactive malformed record accepted: %#v %v", out, err)
		}
	}
}

func TestPlanJSONSlotsReviewMatrixExactAssertions(t *testing.T) {
	owner := slotTestOwner()
	state := slotTestState(`{"scripts":{"x":"a"},"dependencies":{}}`, "100644")
	oldHash, _ := slotHash("a")
	owned := []OwnedPreimage{{Path: state.Path, Pointer: "/scripts/x", Owner: owner, Mode: state.Mode, ContentSHA256: oldHash}}
	t.Run("duplicate-same-pointer", func(t *testing.T) {
		_, _, err := PlanJSONSlots(state, owned, []JSONSlotMutation{{Kind: "replace", Pointer: "/scripts/x", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: oldHash, Value: "b"}, {Kind: "replace", Pointer: "/scripts/x", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: oldHash, Value: "c"}})
		if materialErrorCode(err) != "MATERIAL_TARGET_CONFLICT" {
			t.Fatalf("code=%s err=%v", materialErrorCode(err), err)
		}
	})
	t.Run("empty-parent-and-noop-byte-identity", func(t *testing.T) {
		addState := slotTestState(`{"scripts":{}}`, state.Mode)
		image, conflicts, err := PlanJSONSlots(addState, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/x", AfterOwner: owner, ExpectedMode: state.Mode, Value: ""}})
		if err != nil || len(conflicts) != 0 || string(image.After.Content) != `{"scripts":{"x":""}}`+"\n" {
			t.Fatalf("empty slot: %#v %#v %v", image, conflicts, err)
		}
		image, conflicts, err = PlanJSONSlots(state, owned, nil)
		if err != nil || len(conflicts) != 0 || image.Path != "" {
			t.Fatalf("no-op changed bytes: %#v %#v %v", image, conflicts, err)
		}
	})
	t.Run("diagnostic-codes", func(t *testing.T) {
		cases := []struct{ name, raw, want string }{{"decimal", `{"scripts":{"x":1.0}}`, "JSON_NUMBER_UNSUPPORTED"}, {"exponent", `{"scripts":{"x":1e0}}`, "JSON_NUMBER_UNSUPPORTED"}, {"negative-zero", `{"scripts":{"x":-0}}`, "JSON_NUMBER_UNSUPPORTED"}, {"invalid-leading-zero", `{"scripts":{"x":01}}`, "JSON_SHAPE"}, {"trailing", `{"scripts":{}} trailing`, "JSON_SHAPE"}}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				st := slotTestState(tc.raw, state.Mode)
				_, _, err := PlanJSONSlots(st, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/y", AfterOwner: owner, ExpectedMode: st.Mode, Value: "v"}})
				if materialErrorCode(err) != tc.want {
					t.Fatalf("got=%s want=%s", materialErrorCode(err), tc.want)
				}
			})
		}
	})
	t.Run("literal-canonical-and-hash-goldens", func(t *testing.T) {
		if got, _ := slotHash("go build"); got != "sha256:52e7e94e408eef671312c717978d999cddd7061efd7300abe50bfd8d2ec27248" {
			t.Fatalf("slot hash=%s", got)
		}
		unicodeState := slotTestState(`{"scripts":{},"😀":"x","\uE000":"y"}`, state.Mode)
		image, conflicts, err := PlanJSONSlots(unicodeState, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/x", AfterOwner: owner, ExpectedMode: state.Mode, Value: "go build"}})
		want := "{\"scripts\":{\"x\":\"go build\"},\"😀\":\"x\",\"" + "\xEE\x80\x80" + "\":\"y\"}\n"
		if err != nil || len(conflicts) != 0 || string(image.After.Content) != want {
			t.Fatalf("unicode golden got=%q want=%q", image.After.Content, want)
		}
	})
	t.Run("conflict-sort-and-copy", func(t *testing.T) {
		st := slotTestState(`{"scripts":{"a":"first","b":"second"}}`, state.Mode)
		firstHash, _ := slotHash("first")
		secondHash, _ := slotHash("second")
		owned := []OwnedPreimage{{Path: st.Path, Pointer: "/scripts/a", Owner: owner, Mode: st.Mode, ContentSHA256: firstHash}, {Path: st.Path, Pointer: "/scripts/b", Owner: owner, Mode: st.Mode, ContentSHA256: secondHash}}
		zero := "sha256:" + strings.Repeat("0", 64)
		image, conflicts, err := PlanJSONSlots(st, owned, []JSONSlotMutation{{Kind: "replace", Pointer: "/scripts/b", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: st.Mode, ExpectedSHA256: zero, Value: "b"}, {Kind: "replace", Pointer: "/scripts/a", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: st.Mode, ExpectedSHA256: zero, Value: "a"}})
		if err != nil || len(conflicts) != 2 || conflicts[0].Pointer != "/scripts/a" || conflicts[1].Pointer != "/scripts/b" || string(image.After.Content) != string(st.Content) {
			t.Fatalf("sort: %#v %#v %v", image, conflicts, err)
		}
		image.After.Content[0] = 'x'
		image.BeforeOwners[0].Provider = "changed"
		conflicts[0].Pointer = "changed"
		if st.Content[0] != '{' || owned[0].Owner.Provider != owner.Provider {
			t.Fatal("conflict copies alias input")
		}
	})
	t.Run("unrelated-semantic-preservation", func(t *testing.T) {
		st := slotTestState(`{"scripts":{},"null":null,"bool":false,"array":[null,{"v":true}],"low":-9007199254740991,"high":9007199254740991}`, state.Mode)
		image, conflicts, err := PlanJSONSlots(st, nil, []JSONSlotMutation{{Kind: "add", Pointer: "/scripts/x", AfterOwner: owner, ExpectedMode: st.Mode, Value: "v"}})
		want := "{\"array\":[null,{\"v\":true}],\"bool\":false,\"high\":9007199254740991,\"low\":-9007199254740991,\"null\":null,\"scripts\":{\"x\":\"v\"}}\n"
		if err != nil || len(conflicts) != 0 || string(image.After.Content) != want {
			t.Fatalf("semantic preservation got=%q want=%q", image.After.Content, want)
		}
	})
}

func TestD2RemoveLastKeyKeepsEmptyParentExactBytes(t *testing.T) {
	owner := slotTestOwner()
	raw := []byte(`{"scripts":{"build":"go build"}}`)
	state := FileState{Path: "package.json", Present: true, Mode: "100644", Content: raw, ContentSHA256: "sha256:57fb85873ea8cfbf7137dd64c647b3fc22689ebbf0d83715faba4ddb887b9f7c"}
	image, conflicts, err := PlanJSONSlots(state, []OwnedPreimage{{Path: state.Path, Pointer: "/scripts/build", Owner: owner, Mode: state.Mode, ContentSHA256: "sha256:52e7e94e408eef671312c717978d999cddd7061efd7300abe50bfd8d2ec27248"}}, []JSONSlotMutation{{Kind: "remove", Pointer: "/scripts/build", BeforeOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: "sha256:52e7e94e408eef671312c717978d999cddd7061efd7300abe50bfd8d2ec27248"}})
	want := []byte("{\"scripts\":{}}\n")
	if err != nil || len(conflicts) != 0 || string(image.After.Content) != string(want) || image.After.ContentSHA256 != "sha256:252fb5bcde67a559612afc7500379f4b1dc49f3a1f59ad20aaab29b6f7ce3259" {
		t.Fatalf("remove-last-key: %#v %#v %v", image, conflicts, err)
	}
}

func TestD2IndependentRawAndSlotHashDomains(t *testing.T) {
	owner := slotTestOwner()
	raw := []byte(`{"scripts":{"build":"go build"}}`)
	state := FileState{Path: "package.json", Present: true, Mode: "100644", Content: raw, ContentSHA256: "sha256:57fb85873ea8cfbf7137dd64c647b3fc22689ebbf0d83715faba4ddb887b9f7c"}
	oldSlot := "sha256:52e7e94e408eef671312c717978d999cddd7061efd7300abe50bfd8d2ec27248"
	image, conflicts, err := PlanJSONSlots(state, []OwnedPreimage{{Path: state.Path, Pointer: "/scripts/build", Owner: owner, Mode: state.Mode, ContentSHA256: oldSlot}}, []JSONSlotMutation{{Kind: "replace", Pointer: "/scripts/build", BeforeOwner: owner, AfterOwner: owner, ExpectedMode: state.Mode, ExpectedSHA256: oldSlot, Value: "go test"}})
	if err != nil || len(conflicts) != 0 || image.Before.ContentSHA256 != "sha256:57fb85873ea8cfbf7137dd64c647b3fc22689ebbf0d83715faba4ddb887b9f7c" || image.After.ContentSHA256 != "sha256:207e9c8eaec400d99745d1cd81758cbb02b7ccfc367faa4bb0a1f5b01e03951e" || oldSlot == image.Before.ContentSHA256 || oldSlot == image.After.ContentSHA256 {
		t.Fatalf("hash domains: %#v %#v %v", image, conflicts, err)
	}
}

func TestD2ConflictOwnersAreIndependentCopies(t *testing.T) {
	ownerA := MaterialOwner{Provider: "a", RuleID: "r", ExportID: "x"}
	ownerB := MaterialOwner{Provider: "b", RuleID: "r", ExportID: "x"}
	state := slotTestState(`{"scripts":{"a":"one","b":"two"}}`, "100644")
	hA, _ := slotHash("one")
	hB, _ := slotHash("two")
	owned := []OwnedPreimage{{Path: state.Path, Pointer: "/scripts/a", Owner: ownerA, Mode: state.Mode, ContentSHA256: hA}, {Path: state.Path, Pointer: "/scripts/b", Owner: ownerB, Mode: state.Mode, ContentSHA256: hB}}
	bad := "sha256:" + strings.Repeat("0", 64)
	image, conflicts, err := PlanJSONSlots(state, owned, []JSONSlotMutation{{Kind: "replace", Pointer: "/scripts/a", BeforeOwner: ownerA, AfterOwner: ownerA, ExpectedMode: state.Mode, ExpectedSHA256: bad, Value: "new"}})
	if err != nil || len(conflicts) != 1 || len(image.BeforeOwners) != 2 || len(image.AfterOwners) != 2 {
		t.Fatalf("owner conflict: %#v %#v %v", image, conflicts, err)
	}
	image.BeforeOwners[0].Provider = "changed-before"
	image.AfterOwners[0].Provider = "changed-after"
	if image.BeforeOwners[0].Provider == image.AfterOwners[0].Provider || owned[0].Owner.Provider != "a" {
		t.Fatal("owner arrays or inputs alias")
	}
}
