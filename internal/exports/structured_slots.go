package exports

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

var slotNumberRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

var slotRoots = map[string]bool{
	"scripts": true, "dependencies": true, "devDependencies": true,
	"peerDependencies": true, "optionalDependencies": true,
}

const (
	maxJSONBytes  = 1 << 20
	maxJSONDepth  = 64
	maxJSONValues = 65536
)

type slotDocument struct {
	value any
	count int
}

func parseSlotDocument(raw []byte) (slotDocument, error) {
	if len(raw) > maxJSONBytes {
		return slotDocument{}, merr("MATERIAL_LIMIT", "", "")
	}
	if !utf8.Valid(raw) {
		return slotDocument{}, merr("JSON_SHAPE", "", "")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	count := 0
	if err := scanSlotValue(dec, 0, &count); err != nil {
		return slotDocument{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return slotDocument{}, merr("JSON_SHAPE", "", "")
	}
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return slotDocument{}, merr("JSON_SHAPE", "", "")
	}
	var value any
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return slotDocument{}, merr("JSON_SHAPE", "", "")
	}
	if _, ok := value.(map[string]any); !ok {
		return slotDocument{}, merr("JSON_SHAPE", "", "")
	}
	return slotDocument{value: value, count: count}, nil
}

func scanSlotValue(dec *json.Decoder, depth int, count *int) error {
	if depth > maxJSONDepth {
		return merr("MATERIAL_LIMIT", "", "")
	}
	t, err := dec.Token()
	if err != nil {
		return merr("JSON_SHAPE", "", "")
	}
	*count++
	if *count > maxJSONValues {
		return merr("MATERIAL_LIMIT", "", "")
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				tok, tokErr := dec.Token()
				name, ok := tok.(string)
				if tokErr != nil {
					return merr("JSON_SHAPE", "", "")
				}
				if !ok {
					return merr("JSON_SHAPE", "", "")
				}
				if _, exists := seen[name]; exists {
					return merr("JSON_DUPLICATE_KEY", "", "")
				}
				seen[name] = struct{}{}
				if err := scanSlotValue(dec, depth+1, count); err != nil {
					return err
				}
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return merr("JSON_SHAPE", "", "")
			}
		case '[':
			for dec.More() {
				if err := scanSlotValue(dec, depth+1, count); err != nil {
					return err
				}
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return merr("JSON_SHAPE", "", "")
			}
		default:
			return merr("JSON_SHAPE", "", "")
		}
	case json.Number:
		if string(v) == "-0" || !slotNumberRE.MatchString(string(v)) {
			return merr("JSON_NUMBER_UNSUPPORTED", "", "")
		}
		i, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || i < -9007199254740991 || i > 9007199254740991 {
			return merr("JSON_NUMBER_UNSUPPORTED", "", "")
		}
	case nil:
		// null is retained for unrelated values.
	case string, bool:
	default:
		return merr("JSON_SHAPE", "", "")
	}
	return nil
}

func slotObject(root map[string]any, name string, create bool) (map[string]any, bool) {
	v, ok := root[name]
	if !ok && create {
		v = map[string]any{}
		root[name] = v
		return v.(map[string]any), true
	}
	m, ok := v.(map[string]any)
	return m, ok
}

func slotHash(value string) (string, error) {
	b, err := canonicaljson.Canonical(value)
	if err != nil {
		return "", err
	}
	return digestBytes(b), nil
}

func slotMutationKey(path, pointer string) string { return path + "\x00" + pointer }

func slotPointerParts(pointer string) (string, string, error) {
	if err := slotPointer(pointer); err != nil {
		return "", "", err
	}
	parts := strings.Split(pointer, "/")
	decode := func(s string) string {
		return strings.NewReplacer("~1", "/", "~0", "~").Replace(s)
	}
	return decode(parts[1]), decode(parts[2]), nil
}

func PlanJSONSlots(current FileState, owned []OwnedPreimage, mutations []JSONSlotMutation) (FileImage, []MaterialConflict, error) {
	if err := payloadPath(current.Path); err != nil {
		return FileImage{}, nil, err
	}
	if current.Present && (current.Mode != "100644" && current.Mode != "100755") {
		return FileImage{}, nil, merr("MATERIAL_INPUT", current.Path, "")
	}
	if current.Present && digestBytes(current.Content) != current.ContentSHA256 {
		return FileImage{}, nil, merr("MATERIAL_INPUT", current.Path, "")
	}
	if !current.Present && (current.Mode != "" || current.ContentSHA256 != "" || len(current.Content) != 0) {
		return FileImage{}, nil, merr("MATERIAL_INPUT", current.Path, "")
	}
	ownedByKey := map[string]OwnedPreimage{}
	for _, o := range owned {
		if o.Path != current.Path || o.Pointer == "" {
			continue
		}
		if _, exists := ownedByKey[slotMutationKey(o.Path, o.Pointer)]; exists {
			return FileImage{}, nil, merr("MATERIAL_INPUT", o.Path, o.Pointer)
		}
		rootName, _, pointerErr := slotPointerParts(o.Pointer)
		if pointerErr != nil || !slotRoots[rootName] || !validOwner(o.Owner) || o.Mode != current.Mode || !materialDigestRE.MatchString(o.ContentSHA256) {
			return FileImage{}, nil, merr("MATERIAL_INPUT", o.Path, o.Pointer)
		}
		ownedByKey[slotMutationKey(o.Path, o.Pointer)] = o
	}
	if len(mutations) == 0 {
		return FileImage{}, nil, nil
	}
	seen := map[string]bool{}
	for _, m := range mutations {
		if err := slotPointer(m.Pointer); err != nil || !slotRoots[strings.Split(m.Pointer, "/")[1]] {
			return FileImage{}, nil, merr("MATERIAL_PATH", current.Path, m.Pointer)
		}
		key := slotMutationKey(current.Path, m.Pointer)
		if seen[key] {
			return FileImage{}, nil, merr("MATERIAL_TARGET_CONFLICT", current.Path, m.Pointer)
		}
		seen[key] = true
		if m.Kind != "add" && m.Kind != "replace" && m.Kind != "remove" || !validOwner(m.AfterOwner) && m.Kind != "remove" {
			return FileImage{}, nil, merr("MATERIAL_INPUT", current.Path, m.Pointer)
		}
		if m.Kind == "add" && (m.BeforeOwner != (MaterialOwner{}) || m.ExpectedSHA256 != "" || m.ExpectedMode != current.Mode) {
			return FileImage{}, nil, merr("MATERIAL_INPUT", current.Path, m.Pointer)
		}
		if m.Kind != "add" && (!validOwner(m.BeforeOwner) || !materialDigestRE.MatchString(m.ExpectedSHA256) || m.ExpectedMode != current.Mode) {
			return FileImage{}, nil, merr("MATERIAL_INPUT", current.Path, m.Pointer)
		}
		if m.Kind == "remove" && (m.AfterOwner != (MaterialOwner{}) || m.Value != "") {
			return FileImage{}, nil, merr("MATERIAL_INPUT", current.Path, m.Pointer)
		}
	}
	var doc slotDocument
	var err error
	if current.Present {
		doc, err = parseSlotDocument(current.Content)
		if err != nil {
			if me, ok := err.(*MaterialError); ok {
				me.Path = current.Path
			}
			return FileImage{}, nil, err
		}
	} else {
		doc = slotDocument{value: map[string]any{}}
		for _, m := range mutations {
			if m.Kind != "add" {
				return FileImage{}, nil, merr("MATERIAL_PREIMAGE_CONFLICT", current.Path, m.Pointer)
			}
		}
	}
	root := doc.value.(map[string]any)
	conflicts := make([]MaterialConflict, 0)
	for _, m := range mutations {
		rootName, keyName, _ := slotPointerParts(m.Pointer)
		decoded := []string{rootName, keyName}
		parent, ok := slotObject(root, decoded[0], m.Kind == "add")
		if !ok {
			conflicts = append(conflicts, MaterialConflict{Code: "JSON_SHAPE", Path: current.Path, Pointer: m.Pointer})
			continue
		}
		old, present := parent[decoded[1]]
		oldString, isString := old.(string)
		oldHash := ""
		if isString {
			oldHash, _ = slotHash(oldString)
		}
		owner, hasOwner := ownedByKey[slotMutationKey(current.Path, m.Pointer)]
		code := ""
		switch m.Kind {
		case "add":
			if present || hasOwner {
				code = "MATERIAL_OWNER_CONFLICT"
			}
		case "replace":
			if !hasOwner || owner.Owner != m.BeforeOwner {
				code = "MATERIAL_OWNER_CONFLICT"
			} else if !present || !isString || oldHash != m.ExpectedSHA256 {
				code = "MATERIAL_PREIMAGE_CONFLICT"
			}
		case "remove":
			if !hasOwner || owner.Owner != m.BeforeOwner {
				code = "MATERIAL_OWNER_CONFLICT"
			} else if !present || !isString || oldHash != m.ExpectedSHA256 {
				code = "MATERIAL_PREIMAGE_CONFLICT"
			}
		}
		if code != "" {
			conflicts = append(conflicts, MaterialConflict{Code: code, Path: current.Path, Pointer: m.Pointer})
			continue
		}
		if m.Kind == "remove" {
			delete(parent, decoded[1])
		} else {
			parent[decoded[1]] = m.Value
		}
	}
	if len(conflicts) != 0 {
		sortSlotConflicts(conflicts)
		owners := make([]MaterialOwner, 0, len(ownedByKey))
		for _, o := range ownedByKey {
			owners = append(owners, o.Owner)
		}
		owners = uniqueSortedOwners(owners)
		return FileImage{Path: current.Path, Before: cloneState(current), After: cloneState(current), BeforeOwners: owners, AfterOwners: append([]MaterialOwner(nil), owners...), Reason: "structured-slots"}, conflicts, nil
	}
	afterBytes, err := canonicaljson.Canonical(root)
	if err != nil {
		return FileImage{}, nil, merr("JSON_SHAPE", current.Path, "")
	}
	afterBytes = append(afterBytes, '\n')
	after := FileState{Path: current.Path, Present: true, Mode: current.Mode, Content: afterBytes, ContentSHA256: digestBytes(afterBytes)}
	if !current.Present {
		after.Mode = "100644"
	}
	beforeOwners := make([]MaterialOwner, 0, len(ownedByKey))
	for _, o := range ownedByKey {
		beforeOwners = append(beforeOwners, o.Owner)
	}
	afterOwners := append([]MaterialOwner(nil), beforeOwners...)
	for _, m := range mutations {
		for i := range afterOwners {
			if afterOwners[i] == m.BeforeOwner {
				afterOwners = append(afterOwners[:i], afterOwners[i+1:]...)
				break
			}
		}
		if m.Kind != "remove" {
			afterOwners = append(afterOwners, m.AfterOwner)
		}
	}
	beforeOwners = uniqueSortedOwners(beforeOwners)
	afterOwners = uniqueSortedOwners(afterOwners)
	return FileImage{Path: current.Path, Before: cloneState(current), After: after, BeforeOwners: beforeOwners, AfterOwners: afterOwners, Reason: "structured-slots", FormattingOnly: current.Present && semanticEqualJSON(current.Content, afterBytes)}, nil, nil
}

func uniqueSortedOwners(in []MaterialOwner) []MaterialOwner {
	seen := map[MaterialOwner]bool{}
	out := make([]MaterialOwner, 0, len(in))
	for _, o := range in {
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].ExportID < out[j].ExportID
	})
	return out
}

func semanticEqualJSON(a, b []byte) bool {
	x, ex := parseSlotDocument(a)
	y, ey := parseSlotDocument(b)
	if ex != nil || ey != nil {
		return false
	}
	ca, ea := canonicaljson.Canonical(x.value)
	cb, eb := canonicaljson.Canonical(y.value)
	return ea == nil && eb == nil && bytes.Equal(ca, cb) && !bytes.Equal(a, b)
}

func sortSlotConflicts(c []MaterialConflict) {
	sort.Slice(c, func(i, j int) bool {
		if c[i].Path != c[j].Path {
			return c[i].Path < c[j].Path
		}
		if c[i].Pointer != c[j].Pointer {
			return c[i].Pointer < c[j].Pointer
		}
		return c[i].Code < c[j].Code
	})
}
