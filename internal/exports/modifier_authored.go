package exports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/tplAIter/tplaiter/internal/blockexport"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const AuthoredModifierAPIVersion = "tplaiter.dev/modifier-authored/v2"

// AuthoredSourceConstraint describes content and declaration equality, not admission.
// Runtime provider labels and statement evidence are deliberately not authored.
type AuthoredSourceConstraint struct {
	Alias           string           `json:"alias"`
	Origin          string           `json:"origin"`
	TemplatePath    string           `json:"templatePath"`
	CommitAlgorithm string           `json:"commitAlgorithm"`
	Commit          string           `json:"commit"`
	TreeDigest      string           `json:"treeDigest"`
	ContentDigest   string           `json:"contentDigest"`
	ContractDigest  string           `json:"contractDigest"`
	Parameters      []deps.Parameter `json:"parameters"`
	Dependencies    []string         `json:"dependencies"`
}

type AuthoredOperation struct {
	ID       string              `json:"id"`
	Op       string              `json:"op"`
	Before   []string            `json:"before"`
	After    []string            `json:"after"`
	Source   string              `json:"source"`
	Kind     string              `json:"kind"`
	Original json.RawMessage     `json:"original"`
	Export   string              `json:"export"`
	Plan     *ModifierPlanRecord `json:"plan,omitempty"`
}

type AuthoredModifier struct {
	APIVersion      string                     `json:"apiVersion"`
	Kind            string                     `json:"kind"`
	Metadata        Metadata                   `json:"metadata"`
	Compatibility   Compatibility              `json:"compatibility"`
	Sources         []AuthoredSourceConstraint `json:"sourceConstraints"`
	SelfSource      string                     `json:"selfSource"`
	Requires        Requires                   `json:"requires"`
	Provides        []ProvidedCapability       `json:"provides"`
	Conflicts       []Capability               `json:"conflicts"`
	Replaces        []Replacement              `json:"replaces"`
	Bindings        []Binding                  `json:"bindings"`
	ToolConstraints []ToolConstraint           `json:"toolConstraints"`
	Renames         []Rename                   `json:"renames"`
	Rules           []AuthoredOperation        `json:"ruleConstraints"`
}

// ParseAuthoredModifier accepts inert closed author data. It cannot issue source
// authority or an effect permit. Full record equality is checked at projection.
func ParseAuthoredModifier(raw []byte) (AuthoredModifier, error) {
	var a AuthoredModifier
	if len(raw) == 0 || len(raw) > 1<<20 {
		return a, fmt.Errorf("AUTHORED_BOUND")
	}
	if _, e := canonicaljson.Canonicalize(raw); e != nil {
		return a, e
	}
	keys := []string{"apiVersion", "kind", "metadata", "compatibility", "sourceConstraints", "selfSource", "requires", "provides", "conflicts", "replaces", "bindings", "toolConstraints", "renames", "ruleConstraints"}
	if e := authoredDecode(raw, &a); e != nil {
		return a, e
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return a, e
	}
	for _, k := range keys {
		if _, ok := fields[k]; !ok {
			return a, fmt.Errorf("AUTHORED_MISSING_FIELD")
		}
	}
	if a.APIVersion != AuthoredModifierAPIVersion || a.Kind != "Modifier" || len(a.Sources) < 1 || len(a.Sources) > 16 || len(a.Rules) < 1 || len(a.Rules) > 256 || a.Requires.Exports == nil || a.Requires.Capabilities == nil || a.Provides == nil || a.Conflicts == nil || a.Replaces == nil || a.Bindings == nil || a.ToolConstraints == nil || a.Renames == nil {
		return a, fmt.Errorf("AUTHORED_SHAPE")
	}
	if !tokenRE.MatchString(a.Metadata.ID) || !strictSemver(a.Metadata.Version) || !strictSemver(a.Compatibility.MinimumCLI) || a.Compatibility.PortableAPI != "tplaiter.dev/portable/v1" || len(a.Compatibility.Runtimes) == 0 || len(a.Compatibility.Layouts) == 0 {
		return a, fmt.Errorf("AUTHORED_METADATA")
	}
	if len(a.Requires.Exports) > 256 || len(a.Renames) > 256 {
		return a, fmt.Errorf("AUTHORED_COLLECTION_BOUND")
	}
	envelope := Modifier{Compatibility: a.Compatibility, Requires: a.Requires, Provides: a.Provides, Conflicts: a.Conflicts, Replaces: a.Replaces, Bindings: a.Bindings, ToolConstraints: a.ToolConstraints, Renames: a.Renames}
	if e := validateModifierCollections(envelope); e != nil {
		return a, e
	}
	var nested struct {
		Sources []map[string]json.RawMessage `json:"sourceConstraints"`
		Rules   []map[string]json.RawMessage `json:"ruleConstraints"`
	}
	if e := json.Unmarshal(raw, &nested); e != nil {
		return a, e
	}
	for _, row := range nested.Sources {
		if e := authoredFields(row, []string{"alias", "origin", "templatePath", "commitAlgorithm", "commit", "treeDigest", "contentDigest", "contractDigest", "parameters", "dependencies"}); e != nil {
			return a, e
		}
	}
	for _, row := range nested.Rules {
		if e := authoredFieldsOptional(row, []string{"id", "op", "before", "after", "source", "kind", "original", "export"}, "plan"); e != nil {
			return a, e
		}
	}
	aliases := map[string]bool{}
	for _, s := range a.Sources {
		if !aliasRE.MatchString(s.Alias) || aliases[s.Alias] || s.Origin == "" || len(s.Origin) > 1024 || s.Parameters == nil || s.Dependencies == nil || len(s.Parameters) > 256 || len(s.Dependencies) > 16 {
			return a, fmt.Errorf("AUTHORED_SOURCE")
		}
		if e := validateRelativePath(s.TemplatePath, true); e != nil {
			return a, e
		}
		if !digestRE.MatchString(s.TreeDigest) || !digestRE.MatchString(s.ContentDigest) || !digestRE.MatchString(s.ContractDigest) {
			return a, fmt.Errorf("AUTHORED_SOURCE")
		}
		n := 40
		if s.CommitAlgorithm == "sha256" {
			n = 64
		} else if s.CommitAlgorithm != "sha1" {
			return a, fmt.Errorf("AUTHORED_SOURCE")
		}
		if len(s.Commit) != n {
			return a, fmt.Errorf("AUTHORED_SOURCE")
		}
		for _, c := range s.Commit {
			if !bytes.ContainsRune([]byte("0123456789abcdef"), c) {
				return a, fmt.Errorf("AUTHORED_SOURCE")
			}
		}
		if e := ValidateSourceOrigin(s.Origin); e != nil {
			return a, e
		}
		seenParams := map[string]bool{}
		for _, param := range s.Parameters {
			if !aliasRE.MatchString(param.Name) || seenParams[param.Name] {
				return a, fmt.Errorf("AUTHORED_PARAMETER")
			}
			seenParams[param.Name] = true
			var v any
			d := json.NewDecoder(bytes.NewReader(param.Value))
			d.UseNumber()
			if e := d.Decode(&v); e != nil {
				return a, e
			}
			switch v.(type) {
			case string, bool, json.Number:
			default:
				return a, fmt.Errorf("AUTHORED_PARAMETER")
			}
		}
		seenDeps := map[string]bool{}
		for _, dependency := range s.Dependencies {
			if !aliasRE.MatchString(dependency) || seenDeps[dependency] {
				return a, fmt.Errorf("AUTHORED_DEPENDENCY")
			}
			seenDeps[dependency] = true
		}
		aliases[s.Alias] = true
	}
	for _, s := range a.Sources {
		for _, d := range s.Dependencies {
			if !aliases[d] || d == s.Alias {
				return a, fmt.Errorf("AUTHORED_DEPENDENCY")
			}
		}
	}
	if !aliases[a.SelfSource] {
		return a, fmt.Errorf("AUTHORED_SELF_SOURCE")
	}
	ids := map[string]bool{}
	for _, op := range a.Rules {
		if !tokenRE.MatchString(op.ID) || ids[op.ID] || op.Before == nil || op.After == nil || len(op.Before) > 256 || len(op.After) > 256 || !aliases[op.Source] {
			return a, fmt.Errorf("AUTHORED_OPERATION")
		}
		ids[op.ID] = true
		switch op.Op {
		case "add":
			if strings.Split(op.Export, ".")[0] != op.Source {
				return a, fmt.Errorf("AUTHORED_ADD_SOURCE")
			}
			if op.Kind != "" || !bytes.Equal(bytes.TrimSpace(op.Original), []byte("null")) || !selectorRE.MatchString(op.Export) {
				return a, fmt.Errorf("AUTHORED_ADD")
			}
		case "replace", "remove":
			if e := validateAuthoredOriginal(op.Kind, op.Original); e != nil {
				return a, e
			}
			if op.Op == "remove" && op.Export != "" {
				return a, fmt.Errorf("AUTHORED_REMOVE")
			}
			if op.Op == "replace" && !selectorRE.MatchString(op.Export) {
				return a, fmt.Errorf("AUTHORED_EXPORT")
			}
		case "keep", "compose", "retire", "replace-definition", "replace-active-association", "string-slots":
			if e := validateAuthoredOriginal(op.Kind, op.Original); e != nil {
				return a, e
			}
			if op.Plan == nil {
				return a, fmt.Errorf("AUTHORED_PLAN_REQUIRED")
			}
		default:
			return a, fmt.Errorf("AUTHORED_OPERATION")
		}
		if op.Plan != nil {
			if op.Plan.ID != op.ID || op.Plan.Source != op.Source || op.Plan.Op != op.Op {
				return a, fmt.Errorf("AUTHORED_PLAN_IDENTITY")
			}
			if e := validateModifierPlanRecord(op.Plan); e != nil {
				return a, fmt.Errorf("AUTHORED_PLAN: %w", e)
			}
			if op.Plan.Pointer != "" {
				parent, key, e := modifierPointerParts(op.Plan.Pointer)
				if e != nil || parent == "" || key == "" {
					return a, fmt.Errorf("AUTHORED_PLAN_POINTER")
				}
				beforePresent, beforeValue, e := modifierParentLeaf(op.Plan.ParentOriginal, key)
				if e != nil || beforePresent != op.Plan.Before.Present || (beforePresent && beforeValue != op.Plan.Before.Value) {
					return a, fmt.Errorf("AUTHORED_PLAN_BEFORE_PARENT")
				}
				afterPresent, afterValue, e := modifierParentLeaf(op.Plan.ParentAfter, key)
				if e != nil || afterPresent != op.Plan.After.Present || (afterPresent && afterValue != op.Plan.After.Value) {
					return a, fmt.Errorf("AUTHORED_PLAN_AFTER_PARENT")
				}
			}
		}
	}
	return a, nil
}

func validateAuthoredOriginal(kind string, raw json.RawMessage) error {
	if len(raw) == 0 || len(raw) > 256<<10 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("AUTHORED_ORIGINAL")
	}
	var shape any
	var keys []string
	switch kind {
	case "file":
		keys = []string{"Entry", "Target"}
		shape = &struct {
			Entry  trustverify.SourceEntry
			Target string
		}{}
	case "generator":
		keys = []string{"Generator", "Resources"}
		shape = &struct {
			Generator manifest.Generator
			Resources []trustverify.SourceEntry
		}{}
	case "export":
		keys = []string{"Entry", "Path", "Payload", "Blocks"}
		shape = &struct {
			Entry   ExportEntry
			Path    string
			Payload ExportPayload
			Blocks  []blockexport.BlockExport
		}{}
	default:
		return fmt.Errorf("AUTHORED_ORIGINAL_KIND")
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	if len(fields) != len(keys) {
		return fmt.Errorf("AUTHORED_ORIGINAL_FIELDS")
	}
	for _, k := range keys {
		if _, ok := fields[k]; !ok {
			return fmt.Errorf("AUTHORED_ORIGINAL_FIELDS")
		}
	}
	return authoredDecode(raw, shape)
}

func authoredFields(row map[string]json.RawMessage, keys []string) error {
	if len(row) != len(keys) {
		return fmt.Errorf("AUTHORED_FIELDS")
	}
	for _, k := range keys {
		if _, ok := row[k]; !ok {
			return fmt.Errorf("AUTHORED_FIELDS")
		}
	}
	return nil
}

func authoredFieldsOptional(row map[string]json.RawMessage, keys []string, optional ...string) error {
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for _, key := range keys {
		if _, ok := row[key]; !ok {
			return fmt.Errorf("AUTHORED_FIELDS")
		}
	}
	for key := range row {
		if !allowed[key] {
			return fmt.Errorf("AUTHORED_FIELDS")
		}
	}
	return nil
}

// authoredDecode retains producer-emitted null slices/default data in complete
// original records. It does not normalize them, and rejects unknown/folded keys.
// Required author collections are separately required to be non-null above.
func authoredDecode(raw []byte, dst any) error {
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return err
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return err
	}
	if err := authoredShape(value, reflect.TypeOf(dst).Elem()); err != nil {
		return err
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
func authoredShape(value any, typ reflect.Type) error {
	if typ == reflect.TypeOf(json.RawMessage{}) || typ.Kind() == reflect.Interface {
		return nil
	}
	if value == nil {
		if typ.Kind() == reflect.Slice {
			return nil
		}
		return fmt.Errorf("AUTHORED_NULL_FIELD")
	}
	switch typ.Kind() {
	case reflect.Pointer:
		return authoredShape(value, typ.Elem())
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("AUTHORED_OBJECT")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			tags := strings.Split(field.Tag.Get("json"), ",")
			name := tags[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
			optional := false
			for _, tag := range tags[1:] {
				if tag == "omitempty" {
					optional = true
				}
			}
			if _, exists := object[name]; !exists && !optional {
				return fmt.Errorf("AUTHORED_MISSING_FIELD")
			}
		}
		for name, child := range object {
			field, ok := fields[name]
			if !ok {
				return fmt.Errorf("AUTHORED_UNKNOWN_FIELD")
			}
			if err := authoredShape(child, field); err != nil {
				return err
			}
		}
	case reflect.Slice:
		array, ok := value.([]any)
		if !ok {
			return fmt.Errorf("AUTHORED_ARRAY")
		}
		for _, child := range array {
			if err := authoredShape(child, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("AUTHORED_MAP")
		}
		for _, child := range object {
			if err := authoredShape(child, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
