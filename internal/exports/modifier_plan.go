package exports

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const ModifierPlanAPIVersion = "tplaiter.dev/modifier-plan/v1"

// ModifierPlan is closed inert data. It describes intended transformations;
// it contains no target lease, permit, writer, or authority capability.
type ModifierPlan struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	ID         string               `json:"id"`
	Records    []ModifierPlanRecord `json:"records"`
}

type ModifierPlanRecord struct {
	ID                string            `json:"id"`
	Source            string            `json:"source"`
	ParentOriginal    json.RawMessage   `json:"parentOriginal"`
	ParentAfter       json.RawMessage   `json:"parentAfter"`
	Target            string            `json:"target"`
	Pointer           string            `json:"pointer"`
	Op                string            `json:"op"`
	ExpectedPresence  bool              `json:"expectedPresence"`
	ExpectedValue     string            `json:"expectedValue"`
	SuccessorSelector string            `json:"successorSelector"`
	Before            ModifierPlanValue `json:"before"`
	After             ModifierPlanValue `json:"after"`
}

type ModifierPlanValue struct {
	Present bool   `json:"present"`
	Value   string `json:"value"`
}

var modifierPlanOps = map[string]bool{
	"add": true, "replace": true, "remove": true, "keep": true,
	"compose": true, "retire": true, "replace-definition": true,
	"replace-active-association": true, "string-slots": true,
}

// ParseModifierPlan accepts one canonical JSON plan and rejects unknown or
// duplicate fields, unknown operation names, duplicate records, and malformed
// two-segment string-leaf pointers.
func ParseModifierPlan(raw []byte) (ModifierPlan, error) {
	var plan ModifierPlan
	if len(raw) == 0 || len(raw) > 1<<20 {
		return plan, modifierPlanError("PLAN_BOUND")
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return plan, modifierPlanError("PLAN_JSON")
	}
	if err := validateModifierPlanWire(canonical); err != nil {
		return plan, modifierPlanError("PLAN_SHAPE")
	}
	if err := json.Unmarshal(canonical, &plan); err != nil {
		return plan, modifierPlanError("PLAN_SHAPE")
	}
	if plan.APIVersion != ModifierPlanAPIVersion || plan.Kind != "ModifierPlan" || !modifierPlanToken(plan.ID) || len(plan.Records) == 0 || len(plan.Records) > 256 {
		return ModifierPlan{}, modifierPlanError("PLAN_SHAPE")
	}
	if err := validateModifierPlanRecords(plan.Records); err != nil {
		return ModifierPlan{}, err
	}
	return plan, nil
}

func validateModifierPlanRecords(records []ModifierPlanRecord) error {
	seen := map[string]bool{}
	seenSelectors := map[string]bool{}
	for i := range records {
		if err := validateModifierPlanRecord(&records[i]); err != nil {
			return err
		}
		if seen[records[i].ID] {
			return modifierPlanError("PLAN_DUPLICATE_ID")
		}
		seen[records[i].ID] = true
		selector := records[i].Target + "\x00" + records[i].Pointer
		if seenSelectors[selector] {
			return modifierPlanError("PLAN_DUPLICATE_SELECTOR")
		}
		seenSelectors[selector] = true
	}
	return nil
}

func validateModifierPlanWire(raw []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return err
	}
	if len(top) != 4 {
		return modifierPlanError("PLAN_FIELDS")
	}
	for _, key := range []string{"apiVersion", "kind", "id", "records"} {
		if _, ok := top[key]; !ok {
			return modifierPlanError("PLAN_FIELDS")
		}
	}
	var records []map[string]json.RawMessage
	if err := json.Unmarshal(top["records"], &records); err != nil {
		return err
	}
	for _, record := range records {
		if len(record) != 12 {
			return modifierPlanError("PLAN_RECORD_FIELDS")
		}
		for _, key := range []string{"id", "source", "parentOriginal", "parentAfter", "target", "pointer", "op", "expectedPresence", "expectedValue", "successorSelector", "before", "after"} {
			if _, ok := record[key]; !ok {
				return modifierPlanError("PLAN_RECORD_FIELDS")
			}
		}
		for _, key := range []string{"id", "source", "target", "pointer", "op", "expectedValue", "successorSelector"} {
			var value string
			if err := json.Unmarshal(record[key], &value); err != nil || bytes.Equal(bytes.TrimSpace(record[key]), []byte("null")) {
				return modifierPlanError("PLAN_SCALAR_TYPE")
			}
		}
		var expectedPresence bool
		if err := json.Unmarshal(record["expectedPresence"], &expectedPresence); err != nil || bytes.Equal(bytes.TrimSpace(record["expectedPresence"]), []byte("null")) {
			return modifierPlanError("PLAN_SCALAR_TYPE")
		}
		for _, stateKey := range []string{"before", "after"} {
			var state map[string]json.RawMessage
			if err := json.Unmarshal(record[stateKey], &state); err != nil || len(state) != 2 {
				return modifierPlanError("PLAN_VALUE_FIELDS")
			}
			if _, ok := state["present"]; !ok {
				return modifierPlanError("PLAN_VALUE_FIELDS")
			}
			if _, ok := state["value"]; !ok {
				return modifierPlanError("PLAN_VALUE_FIELDS")
			}
			var present bool
			var value string
			if err := json.Unmarshal(state["present"], &present); err != nil || bytes.Equal(bytes.TrimSpace(state["present"]), []byte("null")) {
				return modifierPlanError("PLAN_SCALAR_TYPE")
			}
			if err := json.Unmarshal(state["value"], &value); err != nil || bytes.Equal(bytes.TrimSpace(state["value"]), []byte("null")) {
				return modifierPlanError("PLAN_SCALAR_TYPE")
			}
		}
		for _, key := range []string{"parentOriginal", "parentAfter"} {
			trimmed := bytes.TrimSpace(record[key])
			if bytes.Equal(trimmed, []byte("null")) {
				continue
			}
			var parent map[string]json.RawMessage
			if err := json.Unmarshal(trimmed, &parent); err != nil || parent == nil {
				return modifierPlanError("PLAN_PARENT_TYPE")
			}
		}
	}
	return nil
}

func validateModifierPlanRecord(r *ModifierPlanRecord) error {
	if !modifierPlanToken(r.ID) || !modifierPlanSource(r.Source) || !modifierPlanTarget(r.Target) || !modifierPlanOps[r.Op] || len(r.SuccessorSelector) > 512 || !utf8.ValidString(r.SuccessorSelector) || len(r.ParentOriginal) == 0 {
		return modifierPlanError("PLAN_RECORD")
	}
	if _, err := canonicaljson.Canonicalize(r.ParentOriginal); err != nil {
		return modifierPlanError("PLAN_RECORD")
	}
	if _, err := canonicaljson.Canonicalize(r.ParentAfter); err != nil {
		return modifierPlanError("PLAN_RECORD")
	}
	if err := validateModifierParentShape(r.ParentOriginal); err != nil {
		return err
	}
	if err := validateModifierParentShape(r.ParentAfter); err != nil {
		return err
	}
	if r.Pointer != "" {
		if _, _, err := modifierPointerParts(r.Pointer); err != nil {
			return err
		}
	}
	if r.Before.Present != r.ExpectedPresence || r.Before.Value != r.ExpectedValue {
		return modifierPlanError("PLAN_BEFORE")
	}
	if !r.ExpectedPresence && r.ExpectedValue != "" {
		return modifierPlanError("PLAN_EXPECTED_VALUE")
	}
	if (r.Op == "add" && (r.Before.Present || !r.After.Present)) || (r.Op == "remove" && (r.After.Present || !r.Before.Present)) || (r.Op == "replace" && (!r.Before.Present || !r.After.Present)) {
		return modifierPlanError("PLAN_BEFORE")
	}
	if !r.Before.Present && r.Before.Value != "" || !r.After.Present && r.After.Value != "" {
		return modifierPlanError("PLAN_VALUE")
	}
	return nil
}

func modifierPlanToken(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
				return false
			}
			continue
		}
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func modifierPlanSource(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for i, r := range s {
		if i == 0 && !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
			return false
		}
		if i > 0 && !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func modifierPlanTarget(s string) bool {
	if s == "" || len(s) > 4096 || !utf8.ValidString(s) || strings.HasPrefix(s, "/") || strings.ContainsAny(s, `\\:`) {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." || strings.EqualFold(p, ".git") || strings.EqualFold(p, ".tplater") || strings.EqualFold(p, ".tplaiter") {
			return false
		}
	}
	return true
}

func modifierPlanError(code string) error { return fmt.Errorf("modifier plan: %s", code) }

func validateModifierParentShape(raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
		return modifierPlanError("PLAN_PARENT_TYPE")
	}
	return nil
}

func modifierInverseID(id string) string {
	candidate := id + ".inverse"
	if len(candidate) <= 128 {
		return candidate
	}
	digest := sha256.Sum256([]byte(id))
	return "inverse-" + hex.EncodeToString(digest[:])
}

// InvertModifierPlan returns a data-only reverse description. It does not
// assert ownership or authorize applying the reverse description.
func InvertModifierPlan(plan ModifierPlan) (ModifierPlan, error) {
	if plan.APIVersion != ModifierPlanAPIVersion || plan.Kind != "ModifierPlan" || !modifierPlanToken(plan.ID) || len(plan.Records) == 0 || len(plan.Records) > 256 {
		return ModifierPlan{}, modifierPlanError("PLAN_INPUT")
	}
	if err := validateModifierPlanRecords(plan.Records); err != nil {
		return ModifierPlan{}, err
	}
	out := plan
	out.ID = modifierInverseID(plan.ID)
	out.Records = make([]ModifierPlanRecord, len(plan.Records))
	for i, record := range plan.Records {
		out.Records[i] = record
		out.Records[i].Before, out.Records[i].After = record.After, record.Before
		out.Records[i].ParentOriginal = append(json.RawMessage(nil), record.ParentAfter...)
		out.Records[i].ParentAfter = append(json.RawMessage(nil), record.ParentOriginal...)
		out.Records[i].ExpectedPresence = record.After.Present
		out.Records[i].ExpectedValue = record.After.Value
		switch record.Op {
		case "add":
			out.Records[i].Op = "remove"
		case "remove":
			out.Records[i].Op = "add"
		case "replace", "string-slots", "keep", "compose", "retire", "replace-definition", "replace-active-association":
			// The operation remains a data description; the swapped pre/post
			// values provide the inverse material facts.
		default:
			return ModifierPlan{}, modifierPlanError("PLAN_OPERATION")
		}
	}
	return out, nil
}

func modifierPlanEqualJSON(a, b json.RawMessage) bool { return bytes.Equal(a, b) }

var modifierPlanRoots = map[string]bool{
	"scripts": true, "dependencies": true, "devDependencies": true,
	"peerDependencies": true, "optionalDependencies": true, "overrides": true,
}

func modifierPointerParts(pointer string) (string, string, error) {
	if pointer == "" || len(pointer) > 512 || !utf8.ValidString(pointer) || !strings.HasPrefix(pointer, "/") {
		return "", "", modifierPlanError("PLAN_POINTER")
	}
	parts := strings.Split(pointer, "/")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return "", "", modifierPlanError("PLAN_POINTER")
	}
	decode := func(part string) (string, bool) {
		var out strings.Builder
		for i := 0; i < len(part); i++ {
			if part[i] != '~' {
				out.WriteByte(part[i])
				continue
			}
			if i+1 >= len(part) || (part[i+1] != '0' && part[i+1] != '1') {
				return "", false
			}
			if part[i+1] == '0' {
				out.WriteByte('~')
			} else {
				out.WriteByte('/')
			}
			i++
		}
		return out.String(), true
	}
	root, rootOK := decode(parts[1])
	key, keyOK := decode(parts[2])
	if !rootOK || !keyOK || !modifierPlanRoots[root] || key == "*" || key == "-" || strings.Contains(key, "\x00") {
		return "", "", modifierPlanError("PLAN_POINTER")
	}
	escape := func(part string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(part) }
	if "/"+escape(root)+"/"+escape(key) != pointer {
		return "", "", modifierPlanError("PLAN_POINTER")
	}
	return root, key, nil
}
