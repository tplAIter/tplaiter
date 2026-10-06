package exports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

// ModifierMaterialInput contains source-derived current bytes and explicit
// user-owned facts. It is data only; it cannot construct a target lease.
type ModifierMaterialInput struct {
	Files     []ModifierMaterialFile `json:"files"`
	UserOwned []ModifierOwnedPath    `json:"userOwned"`
}

type ModifierMaterialFile struct {
	Path    string
	Present bool
	Mode    string
	Content []byte
}

type ModifierOwnedPath struct {
	Path    string
	Pointer string
}

type ModifierMaterial struct {
	Images    []ModifierMaterialImage
	Conflicts []ModifierMaterialConflict
}

type ModifierMaterialImage struct {
	Path      string
	Before    ModifierMaterialFile
	After     ModifierMaterialFile
	RecordIDs []string
}

type ModifierMaterialConflict struct {
	Code      string
	Path      string
	Pointer   string
	RecordIDs []string
}

// PlanModifierMaterial computes intended pre/postimages for a closed plan.
// It preserves unknown JSON siblings and returns conflicts as data. It never
// claims ownership, constructs a permit, or invokes a writer.
func PlanModifierMaterial(plan ModifierPlan, input ModifierMaterialInput) (ModifierMaterial, error) {
	if plan.APIVersion != ModifierPlanAPIVersion || plan.Kind != "ModifierPlan" || !modifierPlanToken(plan.ID) || len(plan.Records) == 0 || len(plan.Records) > 256 {
		return ModifierMaterial{}, modifierPlanError("MATERIAL_PLAN")
	}
	files, owned, err := validateModifierMaterialInput(input)
	if err != nil {
		return ModifierMaterial{}, err
	}
	byTarget := map[string][]ModifierPlanRecord{}
	for _, record := range plan.Records {
		byTarget[record.Target] = append(byTarget[record.Target], record)
	}
	if err := validateModifierPlanRecords(plan.Records); err != nil {
		return ModifierMaterial{}, err
	}
	targets := make([]string, 0, len(byTarget))
	for target := range byTarget {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	out := ModifierMaterial{Images: []ModifierMaterialImage{}, Conflicts: []ModifierMaterialConflict{}}
	for _, target := range targets {
		records := byTarget[target]
		if err := validateModifierTargetRecords(records); err != nil {
			return ModifierMaterial{}, err
		}
		current := files[target]
		if !current.Present && current.Mode == "" {
			current.Path = target
		}
		if conflict, ok := ownedTargetConflict(target, records, owned); ok {
			out.Conflicts = append(out.Conflicts, conflict)
			continue
		}
		whole, slots := splitModifierRecords(records)
		if len(slots) > 0 {
			image, conflict, ok := planModifierSlots(current, slots)
			if conflict != nil {
				out.Conflicts = append(out.Conflicts, *conflict)
				continue
			}
			if ok {
				out.Images = append(out.Images, image)
			}
			continue
		}
		image, conflict, ok := planModifierWholeFile(current, whole)
		if conflict != nil {
			out.Conflicts = append(out.Conflicts, *conflict)
			continue
		}
		if ok {
			out.Images = append(out.Images, image)
		}
	}
	sort.Slice(out.Images, func(i, j int) bool { return out.Images[i].Path < out.Images[j].Path })
	sort.Slice(out.Conflicts, func(i, j int) bool {
		if out.Conflicts[i].Path != out.Conflicts[j].Path {
			return out.Conflicts[i].Path < out.Conflicts[j].Path
		}
		return out.Conflicts[i].Pointer < out.Conflicts[j].Pointer
	})
	return out, nil
}

func validateModifierMaterialInput(input ModifierMaterialInput) (map[string]ModifierMaterialFile, map[string]bool, error) {
	if input.Files == nil || input.UserOwned == nil || len(input.Files) > 4096 || len(input.UserOwned) > 4096 {
		return nil, nil, modifierPlanError("MATERIAL_INPUT")
	}
	files := map[string]ModifierMaterialFile{}
	for _, file := range input.Files {
		if !modifierPlanTarget(file.Path) || files[file.Path].Path != "" || file.Present && file.Mode != "100644" && file.Mode != "100755" {
			return nil, nil, modifierPlanError("MATERIAL_INPUT")
		}
		if !file.Present && (file.Mode != "" || len(file.Content) != 0) {
			return nil, nil, modifierPlanError("MATERIAL_INPUT")
		}
		file.Content = append([]byte(nil), file.Content...)
		files[file.Path] = file
	}
	owned := map[string]bool{}
	for _, item := range input.UserOwned {
		if !modifierPlanTarget(item.Path) {
			return nil, nil, modifierPlanError("MATERIAL_INPUT")
		}
		if item.Pointer != "" {
			if _, _, err := modifierPointerParts(item.Pointer); err != nil {
				return nil, nil, err
			}
		}
		key := item.Path + "\x00" + item.Pointer
		if owned[key] {
			return nil, nil, modifierPlanError("MATERIAL_DUPLICATE_OWNER_FACT")
		}
		owned[key] = true
	}
	return files, owned, nil
}

func validateModifierTargetRecords(records []ModifierPlanRecord) error {
	whole := false
	slot := false
	seenIDs := map[string]bool{}
	seenPointers := map[string]bool{}
	for _, record := range records {
		if seenIDs[record.ID] {
			return modifierPlanError("MATERIAL_DUPLICATE_RECORD")
		}
		seenIDs[record.ID] = true
		if record.Pointer == "" {
			whole = true
		} else {
			slot = true
			if seenPointers[record.Pointer] {
				return modifierPlanError("MATERIAL_DUPLICATE_POINTER")
			}
			seenPointers[record.Pointer] = true
		}
	}
	if whole && slot {
		return modifierPlanError("MATERIAL_WHOLE_PARENT_CONFLICT")
	}
	return nil
}

func splitModifierRecords(records []ModifierPlanRecord) (whole, slots []ModifierPlanRecord) {
	for _, record := range records {
		if record.Pointer == "" {
			whole = append(whole, record)
		} else {
			slots = append(slots, record)
		}
	}
	return whole, slots
}

func ownedTargetConflict(target string, records []ModifierPlanRecord, owned map[string]bool) (ModifierMaterialConflict, bool) {
	for _, record := range records {
		if owned[target+"\x00"] || owned[target+"\x00"+record.Pointer] {
			return ModifierMaterialConflict{Code: "MATERIAL_USER_OWNED", Path: target, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, true
		}
	}
	return ModifierMaterialConflict{}, false
}

func planModifierWholeFile(current ModifierMaterialFile, records []ModifierPlanRecord) (ModifierMaterialImage, *ModifierMaterialConflict, bool) {
	if len(records) != 1 {
		return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_DUPLICATE_TARGET", Path: current.Path}, false
	}
	record := records[0]
	if current.Present != record.Before.Present {
		if record.Before.Present {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PREIMAGE_ABSENT", Path: current.Path, RecordIDs: []string{record.ID}}, false
		}
		return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_TARGET_PRESENT", Path: current.Path, RecordIDs: []string{record.ID}}, false
	}
	if current.Present && string(current.Content) != record.Before.Value {
		return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PREIMAGE_MISMATCH", Path: current.Path, RecordIDs: []string{record.ID}}, false
	}
	after := current
	after.Content = []byte(record.After.Value)
	after.Present = record.After.Present
	if after.Present && after.Mode == "" {
		after.Mode = "100644"
	}
	if !after.Present {
		after.Content = nil
		after.Mode = ""
	}
	return ModifierMaterialImage{Path: current.Path, Before: cloneModifierFile(current), After: cloneModifierFile(after), RecordIDs: []string{record.ID}}, nil, true
}

func planModifierSlots(current ModifierMaterialFile, records []ModifierPlanRecord) (ModifierMaterialImage, *ModifierMaterialConflict, bool) {
	if current.Present && current.Mode != "100644" && current.Mode != "100755" {
		return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_MODE", Path: current.Path}, false
	}
	root := map[string]any{}
	if current.Present {
		var err error
		root, err = parseModifierJSONObject(current.Content)
		if err != nil {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_JSON", Path: current.Path}, false
		}
	}
	parentNames := map[string]bool{}
	type parentFact struct {
		present bool
		value   []byte
	}
	original := map[string]parentFact{}
	afterExpected := map[string]parentFact{}
	for _, record := range records {
		parentName, _, _ := modifierPointerParts(record.Pointer)
		parentNames[parentName] = true
		beforePresent, beforeValue, err := modifierParentFact(record.ParentOriginal)
		if err != nil {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PARENT_PREIMAGE", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
		}
		afterPresent, afterValue, err := modifierParentFact(record.ParentAfter)
		if err != nil {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PARENT_POSTIMAGE", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
		}
		if prior, ok := original[parentName]; ok && (prior.present != beforePresent || !bytes.Equal(prior.value, beforeValue)) {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PARENT_PREIMAGE", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
		}
		if prior, ok := afterExpected[parentName]; ok && (prior.present != afterPresent || !bytes.Equal(prior.value, afterValue)) {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PARENT_POSTIMAGE", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
		}
		original[parentName] = parentFact{present: beforePresent, value: beforeValue}
		afterExpected[parentName] = parentFact{present: afterPresent, value: afterValue}
	}
	for _, record := range records {
		parentName, key, _ := modifierPointerParts(record.Pointer)
		parent, exists := root[parentName]
		obj, object := parent.(map[string]any)
		if !exists {
			if record.Op != "add" {
				return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PARENT_ABSENT", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
			}
			obj = map[string]any{}
			root[parentName] = obj
		} else if !object {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PARENT_SHAPE", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
		}
		declaredBeforePresent, declaredBeforeValue, err := modifierParentLeaf(record.ParentOriginal, key)
		if err != nil || declaredBeforePresent != record.Before.Present || (declaredBeforePresent && declaredBeforeValue != record.Before.Value) {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PARENT_PREIMAGE", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
		}
		declaredAfterPresent, declaredAfterValue, err := modifierParentLeaf(record.ParentAfter, key)
		if err != nil || declaredAfterPresent != record.After.Present || (declaredAfterPresent && declaredAfterValue != record.After.Value) {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PARENT_POSTIMAGE", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
		}
		old, present := obj[key]
		oldString, isString := old.(string)
		if present != record.ExpectedPresence || (present && !isString) || (present && oldString != record.ExpectedValue) {
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_PREIMAGE_MISMATCH", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
		}
		switch record.Op {
		case "add", "replace", "string-slots":
			if !record.After.Present {
				return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_AFTER_SHAPE", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
			}
			obj[key] = record.After.Value
		case "remove":
			if record.After.Present {
				return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_AFTER_SHAPE", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
			}
			delete(obj, key)
		default:
			return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_SLOT_OPERATION", Path: current.Path, Pointer: record.Pointer, RecordIDs: []string{record.ID}}, false
		}
	}
	for parentName := range parentNames {
		if obj, ok := root[parentName].(map[string]any); ok && len(obj) == 0 && !afterExpected[parentName].present {
			delete(root, parentName)
		}
	}
	encoded, err := canonicaljson.Canonical(root)
	if err != nil {
		return ModifierMaterialImage{}, &ModifierMaterialConflict{Code: "MATERIAL_JSON", Path: current.Path}, false
	}
	encoded = append(encoded, '\n')
	after := current
	after.Path = current.Path
	after.Present = true
	after.Content = encoded
	if after.Mode == "" {
		after.Mode = "100644"
	}
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	sort.Strings(ids)
	return ModifierMaterialImage{Path: current.Path, Before: cloneModifierFile(current), After: cloneModifierFile(after), RecordIDs: ids}, nil, true
}

func modifierParentFact(raw json.RawMessage) (bool, []byte, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, nil, nil
	}
	parent, err := parseModifierJSONObject(raw)
	if err != nil {
		return false, nil, err
	}
	encoded, err := canonicaljson.Canonical(parent)
	return true, encoded, err
}

func modifierParentLeaf(raw json.RawMessage, key string) (bool, string, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, "", nil
	}
	parent, err := parseModifierJSONObject(raw)
	if err != nil {
		return false, "", err
	}
	value, present := parent[key]
	if !present {
		return false, "", nil
	}
	text, ok := value.(string)
	if !ok {
		return false, "", fmt.Errorf("modifier material: JSON_PARENT_LEAF")
	}
	return true, text, nil
}

func modifierParentValue(value any, present bool) ([]byte, error) {
	if !present {
		return nil, nil
	}
	parent, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("modifier material: JSON_PARENT")
	}
	return canonicaljson.Canonical(parent)
}

func cloneModifierFile(file ModifierMaterialFile) ModifierMaterialFile {
	file.Content = append([]byte(nil), file.Content...)
	return file
}

func parseModifierJSONObject(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return nil, fmt.Errorf("modifier material: JSON_SHAPE")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := scanModifierJSON(dec, 0); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("modifier material: JSON_TRAILING")
	}
	var value any
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("modifier material: JSON_ROOT")
	}
	return root, nil
}

func scanModifierJSON(dec *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("modifier material: JSON_DEPTH")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				name, ok := mustJSONName(dec.Token())
				if !ok || seen[name] {
					return fmt.Errorf("modifier material: JSON_DUPLICATE_KEY")
				}
				seen[name] = true
				if err := scanModifierJSON(dec, depth+1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := scanModifierJSON(dec, depth+1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
	}
	return nil
}

func mustJSONName(tok json.Token, err error) (string, bool) {
	if err != nil {
		return "", false
	}
	s, ok := tok.(string)
	return s, ok
}
