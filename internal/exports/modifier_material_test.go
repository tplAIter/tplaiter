package exports

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type packageMutation struct {
	pointer, op, before, after string
}

func packagePlan(t *testing.T) ModifierPlan {
	t.Helper()
	mutations := []packageMutation{
		{"/scripts/build", "replace", "tsc -b && vite build", "next build"},
		{"/scripts/dev", "replace", "vite", "next dev"},
		{"/scripts/test", "replace", "vitest run", "vitest run --environment jsdom --globals"},
		{"/scripts/typecheck", "replace", "tsc -b", "tsc --noEmit"},
		{"/dependencies/next", "add", "", "16.3.8"},
		{"/dependencies/react-router", "remove", "8.4.0", ""},
		{"/dependencies/server-only", "add", "", "0.0.1"},
		{"/devDependencies/@eslint~1js", "remove", "9.39.4", ""},
		{"/devDependencies/eslint-config-next", "add", "", "16.3.8"},
		{"/devDependencies/eslint-plugin-react-hooks", "remove", "7.1.1", ""},
		{"/devDependencies/typescript-eslint", "remove", "8.71.1", ""},
		{"/overrides/eslint-plugin-import", "add", "", "2.32.0"},
		{"/overrides/eslint-plugin-jsx-a11y", "add", "", "6.10.2"},
		{"/overrides/eslint-plugin-react", "add", "", "7.37.5"},
		{"/overrides/eslint-plugin-react-hooks", "add", "", "7.1.1"},
		{"/overrides/typescript-eslint", "add", "", "8.71.1"},
	}
	records := make([]ModifierPlanRecord, 0, len(mutations))
	initial := map[string]map[string]string{
		"scripts":         {"build": "tsc -b && vite build", "dev": "vite", "test": "vitest run", "typecheck": "tsc -b"},
		"dependencies":    {"react": "19.3.0", "react-dom": "19.3.0", "react-router": "8.4.0"},
		"devDependencies": {"@eslint/js": "9.39.4", "eslint-plugin-react-hooks": "7.1.1", "typescript-eslint": "8.71.1"},
	}
	final := map[string]map[string]string{}
	for parent, values := range initial {
		final[parent] = map[string]string{}
		for key, value := range values {
			final[parent][key] = value
		}
	}
	for i, mutation := range mutations {
		present := mutation.before != ""
		afterPresent := mutation.after != ""
		parts := strings.Split(mutation.pointer, "/")
		parentName := parts[1]
		key := strings.ReplaceAll(strings.ReplaceAll(parts[2], "~1", "/"), "~0", "~")
		if mutation.op == "add" || mutation.op == "replace" {
			if final[parentName] == nil {
				final[parentName] = map[string]string{}
			}
			final[parentName][key] = mutation.after
		} else if mutation.op == "remove" {
			delete(final[parentName], key)
		}
		record := planRecord("package."+string(rune('a'+i)), mutation.op, mutation.pointer, mutation.before, present, ModifierPlanValue{Present: afterPresent, Value: mutation.after})
		record.ParentOriginal = packageParentJSON(t, initial[parentName], initial[parentName] != nil)
		records = append(records, record)
	}
	for i, mutation := range mutations {
		parentName := strings.Split(mutation.pointer, "/")[1]
		records[i].ParentAfter = packageParentJSON(t, final[parentName], final[parentName] != nil)
	}
	return ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "next.package", Records: records}
}

func packageParentJSON(t *testing.T, parent map[string]string, present bool) json.RawMessage {
	t.Helper()
	if !present {
		return json.RawMessage(`null`)
	}
	raw, err := json.Marshal(parent)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func packageSeed(t *testing.T) ModifierMaterialFile {
	t.Helper()
	root := map[string]any{
		"name":            "tplaiter-web-app",
		"scripts":         map[string]any{"build": "tsc -b && vite build", "dev": "vite", "test": "vitest run", "typecheck": "tsc -b"},
		"dependencies":    map[string]any{"react": "19.3.0", "react-dom": "19.3.0", "react-router": "8.4.0"},
		"devDependencies": map[string]any{"@eslint/js": "9.39.4", "eslint-plugin-react-hooks": "7.1.1", "typescript-eslint": "8.71.1"},
		"userConfig":      map[string]any{"keep": true},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return ModifierMaterialFile{Path: "package.json", Present: true, Mode: "100644", Content: append(raw, '\n')}
}

func TestPlanModifierMaterialPackageSixteenMutationsAndInverse(t *testing.T) {
	plan := packagePlan(t)
	input := ModifierMaterialInput{Files: []ModifierMaterialFile{packageSeed(t)}, UserOwned: []ModifierOwnedPath{}}
	out, err := PlanModifierMaterial(plan, input)
	if err != nil || len(out.Conflicts) != 0 || len(out.Images) != 1 {
		t.Fatalf("package material: %#v %v", out, err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Images[0].After.Content, &got); err != nil {
		t.Fatal(err)
	}
	if got["userConfig"] == nil || got["overrides"] == nil {
		t.Fatalf("unowned or new parent lost: %s", out.Images[0].After.Content)
	}
	if got["dependencies"].(map[string]any)["react-router"] != nil || got["dependencies"].(map[string]any)["next"] != "16.3.8" {
		t.Fatalf("dependency transform incorrect: %s", out.Images[0].After.Content)
	}
	inverse, err := InvertModifierPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	back, err := PlanModifierMaterial(inverse, ModifierMaterialInput{Files: []ModifierMaterialFile{out.Images[0].After}, UserOwned: []ModifierOwnedPath{}})
	if err != nil || len(back.Conflicts) != 0 || len(back.Images) != 1 {
		t.Fatalf("inverse material: %#v %v", back, err)
	}
	var gotSeed, wantSeed map[string]any
	if err := json.Unmarshal(back.Images[0].After.Content, &gotSeed); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(packageSeed(t).Content, &wantSeed); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotSeed, wantSeed) {
		t.Fatalf("inverse did not restore seed:\n%s", back.Images[0].After.Content)
	}
}

func TestPlanModifierMaterialRejectsUserOwnedAndWholeParentConflicts(t *testing.T) {
	plan := packagePlan(t)
	plan.Records = plan.Records[:1]
	out, err := PlanModifierMaterial(plan, ModifierMaterialInput{Files: []ModifierMaterialFile{packageSeed(t)}, UserOwned: []ModifierOwnedPath{{Path: "package.json", Pointer: "/scripts/build"}}})
	if err != nil || len(out.Conflicts) != 1 || out.Conflicts[0].Code != "MATERIAL_USER_OWNED" {
		t.Fatalf("user-owned slot: %#v %v", out, err)
	}
	whole := plan
	whole.Records = append(append([]ModifierPlanRecord{}, plan.Records...), planRecord("whole", "replace", "", "", true, ModifierPlanValue{Present: true, Value: "whole"}))
	if _, err := PlanModifierMaterial(whole, ModifierMaterialInput{Files: []ModifierMaterialFile{packageSeed(t)}, UserOwned: []ModifierOwnedPath{}}); err == nil || !strings.Contains(err.Error(), "WHOLE_PARENT_CONFLICT") {
		t.Fatalf("whole-parent conflict accepted: %v", err)
	}
}

func TestPlanModifierMaterialRejectsGlobalDuplicateIDsAcrossTargets(t *testing.T) {
	first := planRecord("same", "replace", "/scripts/build", "old", true, ModifierPlanValue{Present: true, Value: "new"})
	second := planRecord("same", "replace", "/dependencies/react", "old", true, ModifierPlanValue{Present: true, Value: "new"})
	first.Target = "package.json"
	second.Target = "other.json"
	if _, err := PlanModifierMaterial(ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "p", Records: []ModifierPlanRecord{first, second}}, ModifierMaterialInput{Files: []ModifierMaterialFile{}, UserOwned: []ModifierOwnedPath{}}); err == nil || !strings.Contains(err.Error(), "PLAN_DUPLICATE_ID") {
		t.Fatalf("cross-target duplicate ID accepted: %v", err)
	}
	if _, err := InvertModifierPlan(ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "p", Records: []ModifierPlanRecord{first, second}}); err == nil || !strings.Contains(err.Error(), "PLAN_DUPLICATE_ID") {
		t.Fatalf("inverse accepted cross-target duplicate ID: %v", err)
	}
}

func TestParseModifierPlanRejectsNullPrimitiveFields(t *testing.T) {
	raw := `{"apiVersion":"tplaiter.dev/modifier-plan/v1","kind":"ModifierPlan","id":"p","records":[{"id":"r","source":"S","parentOriginal":null,"parentAfter":null,"target":"package.json","pointer":"/scripts/build","op":"keep","expectedPresence":null,"expectedValue":null,"successorSelector":null,"before":{"present":null,"value":null},"after":{"present":null,"value":null}}]}`
	if _, err := ParseModifierPlan([]byte(raw)); err == nil || !strings.Contains(err.Error(), "PLAN_SHAPE") {
		t.Fatalf("null primitive fields accepted: %v", err)
	}
}

func TestPlanModifierMaterialPreservesOriginallyPresentEmptyParent(t *testing.T) {
	plan := ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "shape", Records: []ModifierPlanRecord{
		{ID: "add", Source: "C2", ParentOriginal: json.RawMessage(`{}`), ParentAfter: json.RawMessage(`{"x":"1"}`), Target: "package.json", Pointer: "/scripts/x", Op: "add", SuccessorSelector: "next", Before: ModifierPlanValue{Present: false}, After: ModifierPlanValue{Present: true, Value: "1"}},
	}}
	input := ModifierMaterialInput{Files: []ModifierMaterialFile{{Path: "package.json", Present: true, Mode: "100644", Content: []byte("{\"scripts\":{}}\n")}}, UserOwned: []ModifierOwnedPath{}}
	out, err := PlanModifierMaterial(plan, input)
	if err != nil || len(out.Conflicts) != 0 || len(out.Images) != 1 {
		t.Fatalf("add material: %#v %v", out, err)
	}
	inverse, err := InvertModifierPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	back, err := PlanModifierMaterial(inverse, ModifierMaterialInput{Files: []ModifierMaterialFile{{Path: "package.json", Present: true, Mode: "100644", Content: out.Images[0].After.Content}}, UserOwned: []ModifierOwnedPath{}})
	if err != nil || len(back.Conflicts) != 0 || !strings.Contains(string(back.Images[0].After.Content), `"scripts":{}`) {
		t.Fatalf("inverse lost empty parent: %#v %v", back, err)
	}
}

func TestPlanModifierMaterialComparesParentOriginalAndKeepsUnownedSiblings(t *testing.T) {
	plan := ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "parent", Records: []ModifierPlanRecord{
		{ID: "replace", Source: "C2", ParentOriginal: json.RawMessage(`{"build":"old","keep":"sibling"}`), ParentAfter: json.RawMessage(`{"build":"new","keep":"sibling"}`), Target: "package.json", Pointer: "/scripts/build", Op: "replace", ExpectedPresence: true, ExpectedValue: "old", SuccessorSelector: "next", Before: ModifierPlanValue{Present: true, Value: "old"}, After: ModifierPlanValue{Present: true, Value: "new"}},
	}}
	input := ModifierMaterialInput{Files: []ModifierMaterialFile{{Path: "package.json", Present: true, Mode: "100644", Content: []byte("{\"scripts\":{\"build\":\"old\",\"keep\":\"sibling\"}}\n")}}, UserOwned: []ModifierOwnedPath{}}
	out, err := PlanModifierMaterial(plan, input)
	if err != nil || len(out.Conflicts) != 0 || !strings.Contains(string(out.Images[0].After.Content), `"keep":"sibling"`) {
		t.Fatalf("authorized sibling rejected or lost: %#v %v", out, err)
	}
	plan.Records[0].ParentOriginal = json.RawMessage(`{"build":"different","keep":"sibling"}`)
	out, err = PlanModifierMaterial(plan, input)
	if err != nil || len(out.Conflicts) != 1 || out.Conflicts[0].Code != "MATERIAL_PARENT_PREIMAGE" {
		t.Fatalf("ParentOriginal mismatch not reported: %#v %v", out, err)
	}
}

func TestPlanModifierMaterialReversesWholeFileRetire(t *testing.T) {
	plan := ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "retire", Records: []ModifierPlanRecord{
		{ID: "retire", Source: "C2", ParentOriginal: json.RawMessage(`null`), ParentAfter: json.RawMessage(`null`), Target: "old.txt", Op: "retire", ExpectedPresence: true, ExpectedValue: "old", SuccessorSelector: "next", Before: ModifierPlanValue{Present: true, Value: "old"}, After: ModifierPlanValue{Present: false}},
	}}
	input := ModifierMaterialInput{Files: []ModifierMaterialFile{{Path: "old.txt", Present: true, Mode: "100644", Content: []byte("old")}}, UserOwned: []ModifierOwnedPath{}}
	out, err := PlanModifierMaterial(plan, input)
	if err != nil || len(out.Conflicts) != 0 || len(out.Images) != 1 || out.Images[0].After.Present {
		t.Fatalf("forward retire: %#v %v", out, err)
	}
	inverse, err := InvertModifierPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	back, err := PlanModifierMaterial(inverse, ModifierMaterialInput{Files: []ModifierMaterialFile{{Path: "old.txt", Present: false}}, UserOwned: []ModifierOwnedPath{}})
	if err != nil || len(back.Conflicts) != 0 || len(back.Images) != 1 || !back.Images[0].After.Present || string(back.Images[0].After.Content) != "old" {
		t.Fatalf("inverse retire: %#v %v", back, err)
	}
}

func TestPlanModifierMaterialInverseRetainsSiblingsAddedAfterForward(t *testing.T) {
	plan := ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "retention", Records: []ModifierPlanRecord{
		{ID: "script", Source: "C2", ParentOriginal: json.RawMessage(`{"build":"old"}`), ParentAfter: json.RawMessage(`{"build":"new"}`), Target: "package.json", Pointer: "/scripts/build", Op: "replace", ExpectedPresence: true, ExpectedValue: "old", SuccessorSelector: "next", Before: ModifierPlanValue{Present: true, Value: "old"}, After: ModifierPlanValue{Present: true, Value: "new"}},
		{ID: "override", Source: "C2", ParentOriginal: json.RawMessage(`null`), ParentAfter: json.RawMessage(`{"managed":"1"}`), Target: "package.json", Pointer: "/overrides/managed", Op: "add", SuccessorSelector: "next", Before: ModifierPlanValue{Present: false}, After: ModifierPlanValue{Present: true, Value: "1"}},
	}}
	input := ModifierMaterialInput{Files: []ModifierMaterialFile{{Path: "package.json", Present: true, Mode: "100644", Content: []byte("{\"scripts\":{\"build\":\"old\"}}\n")}}, UserOwned: []ModifierOwnedPath{}}
	out, err := PlanModifierMaterial(plan, input)
	if err != nil || len(out.Conflicts) != 0 {
		t.Fatalf("forward retention setup: %#v %v", out, err)
	}
	var changed map[string]any
	if err := json.Unmarshal(out.Images[0].After.Content, &changed); err != nil {
		t.Fatal(err)
	}
	changed["scripts"].(map[string]any)["lint"] = "eslint ."
	changed["overrides"].(map[string]any)["manual"] = "2"
	changedBytes, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	inverse, err := InvertModifierPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	back, err := PlanModifierMaterial(inverse, ModifierMaterialInput{Files: []ModifierMaterialFile{{Path: "package.json", Present: true, Mode: "100644", Content: append(changedBytes, '\n')}}, UserOwned: []ModifierOwnedPath{}})
	if err != nil || len(back.Conflicts) != 0 || len(back.Images) != 1 {
		t.Fatalf("inverse rejected unrelated siblings: %#v %v", back, err)
	}
	var restored map[string]any
	if err := json.Unmarshal(back.Images[0].After.Content, &restored); err != nil {
		t.Fatal(err)
	}
	if restored["scripts"].(map[string]any)["build"] != "old" || restored["scripts"].(map[string]any)["lint"] != "eslint ." || restored["overrides"].(map[string]any)["manual"] != "2" {
		t.Fatalf("inverse did not retain siblings: %s", back.Images[0].After.Content)
	}
}

func TestPlanModifierMaterialInverseRefusesChangedOwnedLeaf(t *testing.T) {
	plan := ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "owned", Records: []ModifierPlanRecord{
		{ID: "script", Source: "C2", ParentOriginal: json.RawMessage(`{"build":"old"}`), ParentAfter: json.RawMessage(`{"build":"new"}`), Target: "package.json", Pointer: "/scripts/build", Op: "replace", ExpectedPresence: true, ExpectedValue: "old", SuccessorSelector: "next", Before: ModifierPlanValue{Present: true, Value: "old"}, After: ModifierPlanValue{Present: true, Value: "new"}},
	}}
	inverse, err := InvertModifierPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	input := ModifierMaterialInput{Files: []ModifierMaterialFile{{Path: "package.json", Present: true, Mode: "100644", Content: []byte("{\"scripts\":{\"build\":\"user-change\"}}\n")}}, UserOwned: []ModifierOwnedPath{}}
	out, err := PlanModifierMaterial(inverse, input)
	if err != nil || len(out.Conflicts) != 1 || out.Conflicts[0].Code != "MATERIAL_PREIMAGE_MISMATCH" {
		t.Fatalf("changed owned leaf was not refused: %#v %v", out, err)
	}
}

func TestDirectWholeAndInverseRejectNonObjectParents(t *testing.T) {
	record := planRecord("whole", "replace", "", "old", true, ModifierPlanValue{Present: true, Value: "new"})
	record.ParentOriginal = json.RawMessage(`1`)
	record.ParentAfter = json.RawMessage(`[]`)
	plan := ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "whole", Records: []ModifierPlanRecord{record}}
	input := ModifierMaterialInput{Files: []ModifierMaterialFile{{Path: "a.txt", Present: true, Mode: "100644", Content: []byte("old")}}, UserOwned: []ModifierOwnedPath{}}
	if _, err := PlanModifierMaterial(plan, input); err == nil || !strings.Contains(err.Error(), "PLAN_PARENT_TYPE") {
		t.Fatalf("direct whole accepted malformed parents: %v", err)
	}
	if _, err := InvertModifierPlan(plan); err == nil || !strings.Contains(err.Error(), "PLAN_PARENT_TYPE") {
		t.Fatalf("inverse accepted malformed parents: %v", err)
	}
}
