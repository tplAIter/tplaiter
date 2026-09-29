package exports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

func normalizeDocument(data []byte) ([]byte, error) {
	trim := bytes.TrimSpace(data)
	if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') {
		return trim, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var node yaml.Node
	if err := dec.Decode(&node); err != nil {
		return nil, fmt.Errorf("modifier: YAML decode: %w", err)
	}
	if node.Kind == 0 {
		return nil, errors.New("modifier: empty document")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != nil {
		if err.Error() != "EOF" {
			return nil, fmt.Errorf("modifier: YAML multiple documents: %w", err)
		}
	} else {
		return nil, errors.New("modifier: YAML multiple documents")
	}
	if err := validateYAMLNode(&node, true); err != nil {
		return nil, err
	}
	v, err := yamlValue(&node)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// validateYAMLNode applies the syntax policy to every AST node before conversion.
func validateYAMLNode(n *yaml.Node, document bool) error {
	if n == nil || n.Anchor != "" || n.Kind == yaml.AliasNode {
		return errors.New("modifier: YAML anchors and aliases rejected")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if !document || n.Tag != "" || len(n.Content) != 1 {
			return errors.New("modifier: invalid YAML document")
		}
		return validateYAMLNode(n.Content[0], false)
	case yaml.MappingNode:
		if n.Tag != "!!map" || len(n.Content)%2 != 0 {
			return errors.New("modifier: unsupported YAML mapping")
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if err := validateYAMLNode(k, false); err != nil {
				return err
			}
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
				return errors.New("modifier: YAML merge, duplicate, or non-string key rejected")
			}
			seen[k.Value] = true
			if err := validateYAMLNode(v, false); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return errors.New("modifier: unsupported YAML sequence")
		}
		for _, c := range n.Content {
			if err := validateYAMLNode(c, false); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if n.Tag != "!!str" && n.Tag != "!!bool" && n.Tag != "!!int" {
			return fmt.Errorf("modifier: unsupported YAML scalar tag %q", n.Tag)
		}
	default:
		return errors.New("modifier: unsupported YAML node")
	}
	return nil
}

func yamlValue(n *yaml.Node) (any, error) {
	if n.Kind == yaml.DocumentNode {
		return yamlValue(n.Content[0])
	}
	switch n.Kind {
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			x, e := yamlValue(v)
			if e != nil {
				return nil, e
			}
			out[k.Value] = x
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, len(n.Content))
		for i, c := range n.Content {
			x, e := yamlValue(c)
			if e != nil {
				return nil, e
			}
			out[i] = x
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!null":
			return nil, nil
		case "!!bool":
			var x bool
			if _, e := fmt.Sscan(n.Value, &x); e != nil {
				return nil, e
			}
			return x, nil
		case "!!int":
			var x int64
			if _, e := fmt.Sscan(n.Value, &x); e != nil {
				return nil, e
			}
			return x, nil
		case "!!str":
			return n.Value, nil
		default:
			return nil, fmt.Errorf("modifier: unsupported YAML scalar tag %q", n.Tag)
		}
	default:
		return nil, errors.New("modifier: unsupported YAML node")
	}
}

func strictSemver(v string) bool {
	if !semverRE.MatchString(v) {
		return false
	}
	parts := strings.SplitN(v, "+", 2)
	if len(parts) == 2 {
		for _, p := range strings.Split(parts[1], ".") {
			if p == "" {
				return false
			}
			for _, r := range p {
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
					return false
				}
			}
		}
	}
	core := strings.SplitN(parts[0], "-", 2)
	for _, p := range strings.Split(core[0], ".") {
		if len(p) > 1 && p[0] == '0' {
			return false
		}
	}
	if len(core) > 1 {
		for _, p := range strings.Split(core[1], ".") {
			if p == "" {
				return false
			}
			if allDigits(p) && len(p) > 1 && p[0] == '0' {
				return false
			}
			for _, r := range p {
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
					return false
				}
			}
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validateRequiredShape(data []byte) error {
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&top); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("modifier: multiple JSON values")
	}
	all := []string{"apiVersion", "kind", "metadata", "compatibility", "sources", "selfSource", "requires", "provides", "conflicts", "replaces", "bindings", "rules", "toolConstraints", "renames"}
	if err := wireKeys(top, all, all); err != nil {
		return err
	}
	if err := wireRawString(top["apiVersion"], 0, 0, nil); err != nil {
		return err
	}
	if err := wireRawString(top["kind"], 0, 0, nil); err != nil {
		return err
	}
	if err := wireMetadata(top["metadata"]); err != nil {
		return err
	}
	if err := wireCompatibility(top["compatibility"]); err != nil {
		return err
	}
	if err := wireSources(top["sources"]); err != nil {
		return err
	}
	if err := wireRequires(top["requires"]); err != nil {
		return err
	}
	if err := wireNamedArrays(top["provides"], 0, 256, []string{"name", "value", "ruleId"}); err != nil {
		return err
	}
	if err := wireNamedArrays(top["conflicts"], 0, 256, []string{"name", "value"}); err != nil {
		return err
	}
	if err := wireNamedArrays(top["replaces"], 0, 256, []string{"name", "value", "providerRule", "withRule"}); err != nil {
		return err
	}
	if err := wireBindings(top["bindings"]); err != nil {
		return err
	}
	if err := wireOperations(top["rules"]); err != nil {
		return err
	}
	if err := wireTools(top["toolConstraints"]); err != nil {
		return err
	}
	return wireRenames(top["renames"])
}

func wireObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, errors.New("modifier: expected object")
	}
	return m, nil
}

func wireKeys(m map[string]json.RawMessage, required, allowed []string) error {
	set := map[string]bool{}
	for _, k := range allowed {
		set[k] = true
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("modifier: missing required field %q", k)
		}
	}
	for k := range m {
		if !set[k] {
			return fmt.Errorf("modifier: unknown field %q", k)
		}
	}
	return nil
}

func wireRawString(raw json.RawMessage, minimum, maximum int, re *regexp.Regexp) error {
	var s string
	if json.Unmarshal(raw, &s) != nil || utf8.RuneCountInString(s) < minimum || (maximum > 0 && utf8.RuneCountInString(s) > maximum) || (re != nil && !re.MatchString(s)) {
		return errors.New("modifier: invalid string facet")
	}
	return nil
}

func wireArray(raw json.RawMessage, minimum, maximum int) ([]json.RawMessage, error) {
	var a []json.RawMessage
	if json.Unmarshal(raw, &a) != nil || a == nil || len(a) < minimum || len(a) > maximum {
		return nil, errors.New("modifier: invalid array facet")
	}
	seen := map[string]bool{}
	for _, x := range a {
		c, e := canonicaljson.Canonicalize(x)
		if e != nil {
			return nil, e
		}
		if seen[string(c)] {
			return nil, errors.New("modifier: duplicate array item")
		}
		seen[string(c)] = true
	}
	return a, nil
}

func wireMetadata(raw json.RawMessage) error {
	m, e := wireObject(raw)
	if e != nil {
		return e
	}
	if e = wireKeys(m, []string{"id", "version"}, []string{"id", "version"}); e != nil {
		return e
	}
	if e = wireRawString(m["id"], 0, 0, tokenRE); e != nil {
		return e
	}
	return wireRawString(m["version"], 0, 0, semverRE)
}

func wireCompatibility(raw json.RawMessage) error {
	m, e := wireObject(raw)
	if e != nil {
		return e
	}
	if e = wireKeys(m, []string{"minimumCLI", "portableAPI", "runtimes", "layouts"}, []string{"minimumCLI", "portableAPI", "runtimes", "layouts"}); e != nil {
		return e
	}
	if e = wireRawString(m["minimumCLI"], 0, 0, semverRE); e != nil {
		return e
	}
	var p string
	if json.Unmarshal(m["portableAPI"], &p) != nil || p != "tplaiter.dev/portable/v1" {
		return errors.New("modifier: invalid portable API")
	}
	for _, k := range []string{"runtimes", "layouts"} {
		a, x := wireArray(m[k], 1, 32)
		if x != nil {
			return x
		}
		for _, z := range a {
			if x = wireRawString(z, 0, 0, tokenRE); x != nil {
				return x
			}
		}
	}
	return nil
}

func wireSources(raw json.RawMessage) error {
	a, e := wireArray(raw, 1, 256)
	if e != nil {
		return e
	}
	keys := []string{"alias", "providerId", "origin", "templatePath", "requestedRef", "treeDigest", "contentDigest", "contractDigest", "evidenceDigest", "commitAlgorithm", "commit"}
	for _, x := range a {
		m, y := wireObject(x)
		if y != nil {
			return y
		}
		if y = wireKeys(m, keys, keys); y != nil {
			return y
		}
		if y = wireRawString(m["alias"], 0, 0, aliasRE); y != nil {
			return y
		}
		if y = wireRawString(m["providerId"], 0, 0, tokenRE); y != nil {
			return y
		}
		for _, k := range []string{"origin", "templatePath", "requestedRef"} {
			if y = wireRawString(m[k], 1, 1024, nil); y != nil {
				return y
			}
		}
		for _, k := range []string{"treeDigest", "contentDigest", "contractDigest", "evidenceDigest"} {
			if y = wireRawString(m[k], 0, 0, digestRE); y != nil {
				return y
			}
		}
		var alg string
		if json.Unmarshal(m["commitAlgorithm"], &alg) != nil {
			return errors.New("modifier: invalid commit algorithm")
		}
		re := regexp.MustCompile("^[0-9a-f]{40}$")
		if alg == "sha256" {
			re = regexp.MustCompile("^[0-9a-f]{64}$")
		} else if alg != "sha1" {
			return errors.New("modifier: invalid commit algorithm")
		}
		if y = wireRawString(m["commit"], 0, 0, re); y != nil {
			return y
		}
	}
	return nil
}

func wireRequires(raw json.RawMessage) error {
	m, e := wireObject(raw)
	if e != nil {
		return e
	}
	if e = wireKeys(m, []string{"exports", "capabilities"}, []string{"exports", "capabilities"}); e != nil {
		return e
	}
	a, e := wireArray(m["exports"], 0, 4096)
	if e != nil {
		return e
	}
	for _, x := range a {
		z, y := wireObject(x)
		if y != nil {
			return y
		}
		ks := []string{"selector", "contractDigest", "compatibleRange"}
		if y = wireKeys(z, ks, ks); y != nil {
			return y
		}
		if y = wireRawString(z["selector"], 0, 0, selectorRE); y != nil {
			return y
		}
		if y = wireRawString(z["contractDigest"], 0, 0, digestRE); y != nil {
			return y
		}
		if y = wireRawString(z["compatibleRange"], 1, 1024, nil); y != nil {
			return y
		}
	}
	return wireNamedArrays(m["capabilities"], 0, 256, []string{"name", "value"})
}

func wireNamedArrays(raw json.RawMessage, minimum, maximum int, keys []string) error { //nolint:unparam // shared shape validator; minimum is part of its contract
	a, e := wireArray(raw, minimum, maximum)
	if e != nil {
		return e
	}
	for _, x := range a {
		m, y := wireObject(x)
		if y != nil {
			return y
		}
		if y = wireKeys(m, keys, keys); y != nil {
			return y
		}
		for _, k := range keys {
			re := tokenRE
			if k == "id" {
				re = aliasRE
			}
			if y = wireRawString(m[k], 0, 0, re); y != nil {
				return y
			}
		}
	}
	return nil
}

func wireBindings(raw json.RawMessage) error {
	a, e := wireArray(raw, 0, 256)
	if e != nil {
		return e
	}
	for _, x := range a {
		m, y := wireObject(x)
		if y != nil {
			return y
		}
		if y = wireKeys(m, []string{"name", "value"}, []string{"name", "value"}); y != nil {
			return y
		}
		if y = wireRawString(m["name"], 0, 0, aliasRE); y != nil {
			return y
		}
		var s string
		if json.Unmarshal(m["value"], &s) == nil {
			if utf8.RuneCountInString(s) > 32768 {
				return errors.New("modifier: binding string too long")
			}
			continue
		}
		var b bool
		if json.Unmarshal(m["value"], &b) == nil {
			continue
		}
		var n json.Number
		d := json.NewDecoder(bytes.NewReader(m["value"]))
		d.UseNumber()
		if d.Decode(&n) == nil {
			if _, y := bindingScalar(Binding{Value: m["value"]}); y == nil {
				continue
			}
		}
		return errors.New("modifier: invalid binding value")
	}
	return nil
}

func wireOperations(raw json.RawMessage) error {
	a, e := wireArray(raw, 1, 4096)
	if e != nil {
		return e
	}
	for _, x := range a {
		m, y := wireObject(x)
		if y != nil {
			return y
		}
		var op string
		if json.Unmarshal(m["op"], &op) != nil {
			return errors.New("modifier: invalid operation")
		}
		req := []string{"id", "before", "after", "op"}
		allow := append([]string{}, req...)
		switch op {
		case "add":
			req = append(req, "export")
			allow = append(allow, "export")
		case "replace":
			req = append(req, "target", "expectedDigest", "export")
			allow = append(allow, "target", "expectedDigest", "expectedVersion", "export")
		case "remove":
			req = append(req, "target", "expectedDigest")
			allow = append(allow, "target", "expectedDigest", "expectedVersion")
		default:
			return errors.New("modifier: invalid operation")
		}
		if y = wireKeys(m, req, allow); y != nil {
			return y
		}
		if y = wireRawString(m["id"], 0, 0, tokenRE); y != nil {
			return y
		}
		for _, k := range []string{"before", "after"} {
			edges, z := wireArray(m[k], 0, 256)
			if z != nil {
				return z
			}
			for _, q := range edges {
				if z = wireRawString(q, 0, 0, tokenRE); z != nil {
					return z
				}
			}
		}
		if op != "add" {
			if y = wireRawString(m["target"], 0, 0, tokenRE); y != nil {
				return y
			}
			if y = wireRawString(m["expectedDigest"], 0, 0, digestRE); y != nil {
				return y
			}
			if q, ok := m["expectedVersion"]; ok {
				if y = wireRawString(q, 0, 0, semverRE); y != nil {
					return y
				}
			}
		}
		if op != "remove" {
			if y = wireRawString(m["export"], 0, 0, selectorRE); y != nil {
				return y
			}
		}
	}
	return nil
}

func wireTools(raw json.RawMessage) error {
	a, e := wireArray(raw, 0, 256)
	if e != nil {
		return e
	}
	for _, x := range a {
		m, y := wireObject(x)
		if y != nil {
			return y
		}
		ks := []string{"id", "compatibleRange", "optionsDigest"}
		if y = wireKeys(m, ks, ks); y != nil {
			return y
		}
		if y = wireRawString(m["id"], 0, 0, aliasRE); y != nil {
			return y
		}
		if y = wireRawString(m["compatibleRange"], 1, 1024, nil); y != nil {
			return y
		}
		if y = wireRawString(m["optionsDigest"], 0, 0, digestRE); y != nil {
			return y
		}
	}
	return nil
}

func wireRenames(raw json.RawMessage) error {
	a, e := wireArray(raw, 0, 4096)
	if e != nil {
		return e
	}
	for _, x := range a {
		m, y := wireObject(x)
		if y != nil {
			return y
		}
		ks := []string{"path", "oldBlockId", "newBlockId", "expectedBaselineDigest", "expectedSourceDigest"}
		if y = wireKeys(m, ks, ks); y != nil {
			return y
		}
		if y = wireRawString(m["path"], 1, 1024, nil); y != nil {
			return y
		}
		for _, k := range []string{"oldBlockId", "newBlockId"} {
			if y = wireRawString(m[k], 0, 0, tokenRE); y != nil {
				return y
			}
		}
		for _, k := range []string{"expectedBaselineDigest", "expectedSourceDigest"} {
			if y = wireRawString(m[k], 0, 0, digestRE); y != nil {
				return y
			}
		}
	}
	return nil
}

func validateModifierCollections(m Modifier) error {
	if len(m.Sources) > 256 || len(m.Compatibility.Runtimes) > 32 || len(m.Compatibility.Layouts) > 32 || len(m.Requires.Exports) > 4096 || len(m.Requires.Capabilities) > 256 || len(m.Provides) > 256 || len(m.Conflicts) > 256 || len(m.Replaces) > 256 || len(m.Bindings) > 256 || len(m.Rules) > 4096 || len(m.ToolConstraints) > 256 || len(m.Renames) > 4096 {
		return errors.New("modifier: collection limit exceeded")
	}
	if !uniqueStrings(m.Compatibility.Runtimes) || !uniqueStrings(m.Compatibility.Layouts) {
		return errors.New("modifier: duplicate compatibility value")
	}
	for _, v := range append(append([]string{}, m.Compatibility.Runtimes...), m.Compatibility.Layouts...) {
		if !tokenRE.MatchString(v) {
			return errors.New("modifier: invalid compatibility token")
		}
	}
	seenBindings := map[string]bool{}
	for _, b := range m.Bindings {
		if seenBindings[b.Name] {
			return fmt.Errorf("modifier: duplicate binding %q", b.Name)
		}
		seenBindings[b.Name] = true
	}
	seenExports := map[string]bool{}
	for _, r := range m.Requires.Exports {
		if seenExports[r.Selector] {
			return errors.New("modifier: duplicate export requirement")
		}
		seenExports[r.Selector] = true
	}
	seenCaps := map[string]bool{}
	for _, c := range append(append([]Capability{}, m.Requires.Capabilities...), m.Conflicts...) {
		k := c.Name + "\x00" + c.Value
		if seenCaps[k] {
			return errors.New("modifier: duplicate capability")
		}
		seenCaps[k] = true
	}
	seenProvided := map[string]bool{}
	for _, c := range m.Provides {
		k := c.Name + "\x00" + c.Value + "\x00" + c.RuleID
		if seenProvided[k] {
			return errors.New("modifier: duplicate provided capability")
		}
		seenProvided[k] = true
	}
	seenTools := map[string]bool{}
	for _, c := range m.ToolConstraints {
		if seenTools[c.ID] {
			return errors.New("modifier: duplicate tool constraint")
		}
		seenTools[c.ID] = true
	}
	for _, s := range m.Sources {
		if err := ValidateSourceOrigin(s.Origin); err != nil {
			return err
		}
	}
	for _, r := range m.Requires.Exports {
		if !selectorRE.MatchString(r.Selector) || !digestRE.MatchString(r.ContractDigest) || runeLen(r.CompatibleRange) < 1 || runeLen(r.CompatibleRange) > 1024 {
			return errors.New("modifier: invalid export requirement")
		}
		if !sourceAlias(m, strings.Split(r.Selector, ".")[0]) {
			return errors.New("modifier: export selector references unknown source")
		}
	}
	seenReplaces := map[string]bool{}
	for _, r := range m.Replaces {
		if !tokenRE.MatchString(r.Name) || !tokenRE.MatchString(r.Value) || !tokenRE.MatchString(r.ProviderRule) || !tokenRE.MatchString(r.WithRule) {
			return errors.New("modifier: invalid replacement mapping")
		}
		key := r.Name + "\x00" + r.Value + "\x00" + r.ProviderRule + "\x00" + r.WithRule
		if seenReplaces[key] {
			return errors.New("modifier: duplicate replacement mapping")
		}
		seenReplaces[key] = true
	}
	for _, p := range m.Provides {
		if !tokenRE.MatchString(p.Name) || !tokenRE.MatchString(p.Value) || !tokenRE.MatchString(p.RuleID) {
			return errors.New("modifier: invalid provided capability")
		}
	}
	for _, t := range m.ToolConstraints {
		if !aliasRE.MatchString(t.ID) || runeLen(t.CompatibleRange) < 1 || runeLen(t.CompatibleRange) > 1024 || !digestRE.MatchString(t.OptionsDigest) {
			return errors.New("modifier: invalid tool constraint")
		}
	}
	seenRenames := map[string]bool{}
	for _, n := range m.Renames {
		if err := validateRelativePath(n.Path, false); err != nil {
			return err
		}
		if !tokenRE.MatchString(n.OldBlockID) || !tokenRE.MatchString(n.NewBlockID) || !digestRE.MatchString(n.ExpectedBaselineDigest) || !digestRE.MatchString(n.ExpectedSourceDigest) {
			return errors.New("modifier: invalid rename")
		}
		key := n.Path + "\x00" + n.OldBlockID + "\x00" + n.NewBlockID + "\x00" + n.ExpectedBaselineDigest + "\x00" + n.ExpectedSourceDigest
		if seenRenames[key] {
			return errors.New("modifier: duplicate rename")
		}
		seenRenames[key] = true
	}
	return nil
}

func validateRelativePath(p string, allowDot bool) error {
	if p == "" || runeLen(p) > 1024 || strings.Contains(p, "\\") || path.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || strings.Contains(p, "//") || strings.Contains(p, "/./") || (!allowDot && p == ".") {
		return fmt.Errorf("modifier: unsafe relative path %q", p)
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return errors.New("modifier: control character in path")
		}
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			if allowDot && p == "." {
				continue
			}
			return fmt.Errorf("modifier: noncanonical relative path %q", p)
		}
	}
	return nil
}

// ValidateSourceOrigin applies the credential-free origin boundary used by the
// authoring contract. Network access and origin equivalence are adapter work.
func ValidateSourceOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || runeLen(origin) > 1024 || u.Scheme == "" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || !utf8.ValidString(origin) {
		return errors.New("modifier: unsafe source origin")
	}
	return nil
}

func bindingScalar(b Binding) (any, error) { //nolint:unparam // callers use the error only today; the value is the validator result
	if len(b.Value) > 512<<10 || !utf8.Valid(b.Value) {
		return nil, errors.New("invalid binding bytes")
	}
	if _, err := canonicaljson.Canonicalize(b.Value); err != nil {
		return nil, err
	}
	var v any
	d := json.NewDecoder(strings.NewReader(string(b.Value)))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("multiple JSON values")
	}
	switch x := v.(type) {
	case string, bool:
		if s, ok := x.(string); ok && runeLen(s) > 32768 {
			return nil, errors.New("string too long")
		}
		return x, nil
	case json.Number:
		if strings.ContainsAny(x.String(), ".eE") {
			return nil, errors.New("not integer")
		}
		var n int64
		if _, err := fmt.Sscan(x.String(), &n); err != nil || n > 9007199254740991 || n < -9007199254740991 {
			return nil, errors.New("integer out of range")
		}
		return n, nil
	default:
		return nil, errors.New("must be scalar")
	}
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

func uniqueStrings(values []string) bool {
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

func sourceAlias(m Modifier, alias string) bool {
	for _, s := range m.Sources {
		if s.Alias == alias {
			return true
		}
	}
	return false
}
