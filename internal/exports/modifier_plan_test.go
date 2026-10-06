package exports

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func planRecord(id, op, pointer, expected string, present bool, after ModifierPlanValue) ModifierPlanRecord {
	return ModifierPlanRecord{
		ID: id, Source: "C2", ParentOriginal: json.RawMessage(`{}`), ParentAfter: json.RawMessage(`{}`), Target: "package.json",
		Pointer: pointer, Op: op, ExpectedPresence: present, ExpectedValue: expected,
		SuccessorSelector: "next.package", Before: ModifierPlanValue{Present: present, Value: expected}, After: after,
	}
}

func TestParseModifierPlanFiniteRFC6901Examples(t *testing.T) {
	good := []string{"/dependencies/@scope~1package", "/overrides/eslint-plugin-react"}
	for _, pointer := range good {
		record := planRecord("slot", "replace", pointer, "old", true, ModifierPlanValue{Present: true, Value: "new"})
		raw, err := json.Marshal(ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "next", Records: []ModifierPlanRecord{record}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseModifierPlan(raw); err != nil {
			t.Fatalf("accepted pointer %q: %v", pointer, err)
		}
	}
	for _, pointer := range []string{"/scripts/build/extra", "/scripts/~2", "/scripts/", "/scripts/-", "/config/x"} {
		record := planRecord("slot", "replace", pointer, "old", true, ModifierPlanValue{Present: true, Value: "new"})
		raw, _ := json.Marshal(ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "next", Records: []ModifierPlanRecord{record}})
		if _, err := ParseModifierPlan(raw); err == nil {
			t.Fatalf("accepted invalid pointer %q", pointer)
		}
	}
}

func TestParseModifierPlanRejectsClosedShapeFailures(t *testing.T) {
	record := planRecord("slot", "replace", "/scripts/build", "old", true, ModifierPlanValue{Present: true, Value: "new"})
	raw, _ := json.Marshal(ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "next", Records: []ModifierPlanRecord{record}})
	duplicateRaw, _ := json.Marshal(ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "next", Records: []ModifierPlanRecord{record, record}})
	for name, bad := range map[string]string{
		"unknown top-level":   strings.Replace(string(raw), `"records"`, `"permit":true,"records"`, 1),
		"unknown record":      strings.Replace(string(raw), `"source":"C2"`, `"authority":true,"source":"C2"`, 1),
		"duplicate record id": string(duplicateRaw),
		"duplicate JSON key":  strings.Replace(string(raw), `"kind":"ModifierPlan"`, `"kind":"ModifierPlan","kind":"ModifierPlan"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseModifierPlan([]byte(bad)); err == nil {
				t.Fatal("accepted closed-shape failure")
			}
		})
	}
}

func TestInvertModifierPlanSwapsPresenceAndOperations(t *testing.T) {
	plan := ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "next", Records: []ModifierPlanRecord{
		planRecord("add", "add", "/dependencies/next", "", false, ModifierPlanValue{Present: true, Value: "16.3.8"}),
		planRecord("remove", "remove", "/dependencies/react-router", "8.4.0", true, ModifierPlanValue{}),
		planRecord("replace", "replace", "/scripts/build", "vite", true, ModifierPlanValue{Present: true, Value: "next build"}),
	}}
	inverse, err := InvertModifierPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if inverse.ID != "next.inverse" || inverse.Records[0].Op != "remove" || !inverse.Records[0].ExpectedPresence || inverse.Records[0].ExpectedValue != "16.3.8" {
		t.Fatalf("bad add inverse: %#v", inverse.Records[0])
	}
	if inverse.Records[1].Op != "add" || inverse.Records[1].ExpectedPresence {
		t.Fatalf("bad remove inverse: %#v", inverse.Records[1])
	}
	if inverse.Records[2].ExpectedValue != "next build" || inverse.Records[2].After.Value != "vite" {
		t.Fatalf("bad replace inverse: %#v", inverse.Records[2])
	}
}

func TestInvertModifierPlanKeepsBoundaryIDsParseable(t *testing.T) {
	for _, length := range []int{120, 121, 128} {
		id := "p" + strings.Repeat("x", length-1)
		record := planRecord("r", "replace", "/scripts/build", "old", true, ModifierPlanValue{Present: true, Value: "new"})
		plan := ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: id, Records: []ModifierPlanRecord{record}}
		inverse, err := InvertModifierPlan(plan)
		if err != nil || len(inverse.ID) > 128 {
			t.Fatalf("boundary %d produced invalid inverse ID %q: %v", length, inverse.ID, err)
		}
		wire, err := json.Marshal(inverse)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseModifierPlan(wire); err != nil {
			t.Fatalf("boundary %d inverse did not parse: %v", length, err)
		}
		again, err := InvertModifierPlan(plan)
		if err != nil || again.ID != inverse.ID {
			t.Fatalf("boundary %d inverse ID is not deterministic: %q / %q", length, inverse.ID, again.ID)
		}
	}
}

func TestInvertModifierPlanDeepCopiesParentFacts(t *testing.T) {
	plan := ModifierPlan{APIVersion: ModifierPlanAPIVersion, Kind: "ModifierPlan", ID: "copy", Records: []ModifierPlanRecord{
		planRecord("r", "replace", "/scripts/build", "old", true, ModifierPlanValue{Present: true, Value: "new"}),
	}}
	plan.Records[0].ParentOriginal = json.RawMessage(`{"build":"old"}`)
	plan.Records[0].ParentAfter = json.RawMessage(`{"build":"new"}`)
	inverse, err := InvertModifierPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	originalBefore := append([]byte(nil), inverse.Records[0].ParentOriginal...)
	originalAfter := append([]byte(nil), inverse.Records[0].ParentAfter...)
	plan.Records[0].ParentOriginal[2] = 'X'
	plan.Records[0].ParentAfter[2] = 'Y'
	if !bytes.Equal(inverse.Records[0].ParentOriginal, originalBefore) || !bytes.Equal(inverse.Records[0].ParentAfter, originalAfter) {
		t.Fatalf("inverse parent buffers alias input: %#v", inverse.Records[0])
	}
}
