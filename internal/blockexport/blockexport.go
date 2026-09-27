// Package blockexport defines the pure, read-only BlockExport v1 contract.
package blockexport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	APIVersion         = "tplater.dev/block-export/v1"
	Kind               = "BlockExport"
	MergeStrategy      = "managed-blocks-v1"
	MarkerSchema       = "tplater.dev/managed-block/v1"
	MaxTargets         = 256
	MaxBlocksPerTarget = 512
	MaxBlocks          = 4096
	MaxPathLength      = 1024
	MinOrder           = -9007199254740991
	MaxOrder           = 9007199254740991
)

type BlockExport struct {
	APIVersion    string        `yaml:"apiVersion" json:"apiVersion"`
	Kind          string        `yaml:"kind" json:"kind"`
	Metadata      Metadata      `yaml:"metadata" json:"metadata"`
	Compatibility Compatibility `yaml:"compatibility" json:"compatibility"`
	MergeStrategy string        `yaml:"mergeStrategy" json:"mergeStrategy"`
	Formatter     Formatter     `yaml:"formatter" json:"formatter"`
	Targets       []Target      `yaml:"targets" json:"targets"`
}
type Metadata struct {
	ID      string `yaml:"id" json:"id"`
	Version string `yaml:"version" json:"version"`
}
type Compatibility struct {
	Tplater      string `yaml:"tplater" json:"tplater"`
	MarkerSchema string `yaml:"markerSchema" json:"markerSchema"`
}
type Formatter struct {
	Adapter       string `yaml:"adapter" json:"adapter"`
	OptionsDigest string `yaml:"optionsDigest" json:"optionsDigest"`
}
type Target struct {
	Path   string  `yaml:"path" json:"path"`
	Blocks []Block `yaml:"blocks" json:"blocks"`
}
type Block struct {
	ID       string   `yaml:"id" json:"id"`
	Provider string   `yaml:"provider" json:"provider"`
	Layout   string   `yaml:"layout" json:"layout"`
	Body     string   `yaml:"body" json:"body"`
	Order    int      `yaml:"order" json:"order"`
	Anchor   Anchor   `yaml:"anchor,omitempty" json:"anchor,omitempty"`
	Replaces []string `yaml:"replaces,omitempty" json:"replaces,omitempty"`
}
type Anchor struct {
	Before  string `yaml:"before,omitempty" json:"before,omitempty"`
	After   string `yaml:"after,omitempty" json:"after,omitempty"`
	Present bool   `yaml:"-" json:"-"`
}

func (a *Anchor) UnmarshalJSON(data []byte) error {
	type wire struct {
		Before string `json:"before"`
		After  string `json:"after"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	a.Before, a.After, a.Present = w.Before, w.After, true
	return nil
}
func (a *Anchor) UnmarshalYAML(value *yaml.Node) error {
	type wire struct {
		Before string `yaml:"before"`
		After  string `yaml:"after"`
	}
	var w wire
	if err := value.Decode(&w); err != nil {
		return err
	}
	a.Before, a.After, a.Present = w.Before, w.After, true
	return nil
}

func (b Block) MarshalJSON() ([]byte, error) {
	type wire struct {
		ID       string   `json:"id"`
		Provider string   `json:"provider"`
		Layout   string   `json:"layout"`
		Body     string   `json:"body"`
		Order    int      `json:"order"`
		Anchor   *Anchor  `json:"anchor,omitempty"`
		Replaces []string `json:"replaces,omitempty"`
	}
	var a *Anchor
	if b.Anchor.Present {
		a = &b.Anchor
	}
	return json.Marshal(wire{b.ID, b.Provider, b.Layout, b.Body, b.Order, a, b.Replaces})
}

var (
	idRE       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)
	providerRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._/-]{0,127}$`)
	digestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	semverRE   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
)

func Parse(data []byte) (BlockExport, error) {
	wire, err := normalizeWire(data)
	if err != nil {
		return BlockExport{}, err
	}
	if err := validateWire(wire); err != nil {
		return BlockExport{}, err
	}
	var e BlockExport
	if err := json.Unmarshal(wire, &e); err != nil {
		return BlockExport{}, fmt.Errorf("block export: decode: %w", err)
	}
	return e, Validate(e)
}
func normalizeWire(data []byte) ([]byte, error) {
	trim := bytes.TrimSpace(data)
	if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') {
		if _, err := yamlJSONCheck(trim); err != nil {
			return nil, err
		}
		return trim, nil
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	var n yaml.Node
	if err := d.Decode(&n); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("block export: multiple YAML documents are not permitted")
	}
	if err := validateYAMLNode(&n); err != nil {
		return nil, err
	}
	v, err := yamlNodeValue(&n)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
func yamlJSONCheck(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("block export: multiple JSON documents")
	}
	return v, nil
}
func validateYAMLNode(n *yaml.Node) error {
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return fmt.Errorf("block export: YAML anchors and aliases are forbidden")
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) != 1 {
			return fmt.Errorf("block export: invalid YAML document")
		}
		return validateYAMLNode(n.Content[0])
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			return fmt.Errorf("block export: unsupported YAML map tag")
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if err := validateYAMLNode(k); err != nil {
				return err
			}
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" {
				return fmt.Errorf("block export: invalid YAML key")
			}
			if seen[k.Value] {
				return fmt.Errorf("block export: duplicate YAML key")
			}
			seen[k.Value] = true
			if err := validateYAMLNode(v); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return fmt.Errorf("block export: unsupported YAML sequence tag")
		}
		for _, c := range n.Content {
			if err := validateYAMLNode(c); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if n.Tag != "!!str" && n.Tag != "!!int" && n.Tag != "!!bool" && n.Tag != "!!null" {
			return fmt.Errorf("block export: unsupported YAML scalar tag %q", n.Tag)
		}
	}
	return nil
}
func yamlNodeValue(n *yaml.Node) (any, error) {
	if n.Kind == yaml.DocumentNode {
		return yamlNodeValue(n.Content[0])
	}
	switch n.Kind {
	case yaml.MappingNode:
		o := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			x, e := yamlNodeValue(n.Content[i+1])
			if e != nil {
				return nil, e
			}
			o[n.Content[i].Value] = x
		}
		return o, nil
	case yaml.SequenceNode:
		a := make([]any, len(n.Content))
		for i, c := range n.Content {
			x, e := yamlNodeValue(c)
			if e != nil {
				return nil, e
			}
			a[i] = x
		}
		return a, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!null":
			return nil, nil
		case "!!bool":
			return n.Value == "true", nil
		case "!!int":
			i, e := strconv.ParseInt(n.Value, 10, 64)
			if e != nil {
				return nil, e
			}
			if i < MinOrder || i > MaxOrder {
				return nil, fmt.Errorf("block export: integer order out of safe range")
			}
			return i, nil
		default:
			return n.Value, nil
		}
	}
	return nil, fmt.Errorf("block export: unsupported YAML node")
}
func validateWire(data []byte) error {
	v, err := yamlJSONCheck(data)
	if err != nil {
		return err
	}
	top, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("block export: document must be object")
	}
	req := []string{"apiVersion", "kind", "metadata", "compatibility", "mergeStrategy", "formatter", "targets"}
	for _, k := range req {
		if _, ok := top[k]; !ok {
			return fmt.Errorf("block export: missing %s", k)
		}
	}
	if err := obj(top, "apiVersion", "kind", "metadata", "compatibility", "mergeStrategy", "formatter", "targets"); err != nil {
		return err
	}
	if !str(top["apiVersion"]) || !str(top["kind"]) || !str(top["mergeStrategy"]) {
		return fmt.Errorf("block export: invalid envelope types")
	}
	if err := validateMetadata(top["metadata"]); err != nil {
		return err
	}
	if err := validateCompat(top["compatibility"]); err != nil {
		return err
	}
	if err := validateFormatter(top["formatter"]); err != nil {
		return err
	}
	targets, ok := top["targets"].([]any)
	if !ok || len(targets) < 1 || len(targets) > MaxTargets {
		return fmt.Errorf("block export: invalid targets")
	}
	for _, x := range targets {
		m, ok := x.(map[string]any)
		if !ok {
			return fmt.Errorf("block export: target must object")
		}
		if err := obj(m, "path", "blocks"); err != nil {
			return err
		}
		if !str(m["path"]) {
			return fmt.Errorf("block export: path type")
		}
		bs, ok := m["blocks"].([]any)
		if !ok || len(bs) < 1 || len(bs) > MaxBlocksPerTarget {
			return fmt.Errorf("block export: blocks type/bounds")
		}
		for _, y := range bs {
			if err := validateBlockWire(y); err != nil {
				return err
			}
		}
	}
	return nil
}
func obj(m map[string]any, allowed ...string) error {
	set := map[string]bool{}
	for _, k := range allowed {
		set[k] = true
	}
	for k := range m {
		if !set[k] {
			return fmt.Errorf("block export: unknown field %s", k)
		}
	}
	return nil
}
func str(v any) bool { _, ok := v.(string); return ok }
func validateMetadata(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("block export: metadata type")
	}
	if err := obj(m, "id", "version"); err != nil {
		return err
	}
	if !str(m["id"]) || !str(m["version"]) {
		return fmt.Errorf("block export: metadata field type")
	}
	return nil
}
func validateCompat(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("block export: compatibility type")
	}
	if err := obj(m, "tplater", "markerSchema"); err != nil {
		return err
	}
	if !str(m["tplater"]) || !str(m["markerSchema"]) {
		return fmt.Errorf("block export: compatibility field type")
	}
	return nil
}
func validateFormatter(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("block export: formatter type")
	}
	if err := obj(m, "adapter", "optionsDigest"); err != nil {
		return err
	}
	if !str(m["adapter"]) || !str(m["optionsDigest"]) {
		return fmt.Errorf("block export: formatter field type")
	}
	return nil
}
func validateBlockWire(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("block export: block type")
	}
	if err := obj(m, "id", "provider", "layout", "body", "order", "anchor", "replaces"); err != nil {
		return err
	}
	for _, k := range []string{"id", "provider", "layout", "body"} {
		if !str(m[k]) {
			return fmt.Errorf("block export: block field type")
		}
	}
	n, ok := m["order"].(json.Number)
	if !ok {
		if _, yes := m["order"].(int64); !yes {
			return fmt.Errorf("block export: order type")
		}
	} else {
		i, e := strconv.ParseInt(n.String(), 10, 64)
		if e != nil || i < MinOrder || i > MaxOrder || strings.ContainsAny(n.String(), ".eE") {
			return fmt.Errorf("block export: order type")
		}
	}
	if a, exists := m["anchor"]; exists {
		am, ok := a.(map[string]any)
		if !ok || len(am) != 1 {
			return fmt.Errorf("block export: anchor shape")
		}
		if err := obj(am, "before", "after"); err != nil {
			return err
		}
		for _, x := range am {
			if !str(x) {
				return fmt.Errorf("block export: anchor type")
			}
		}
	}
	if r, exists := m["replaces"]; exists {
		rs, ok := r.([]any)
		if !ok || len(rs) != 1 || !str(rs[0]) {
			return fmt.Errorf("block export: replacements shape")
		}
	}
	return nil
}
func Validate(e BlockExport) error {
	if e.APIVersion != APIVersion || e.Kind != Kind {
		return fmt.Errorf("block export: invalid apiVersion/kind")
	}
	if !idRE.MatchString(e.Metadata.ID) || !strictSemver(e.Metadata.Version) {
		return fmt.Errorf("block export: invalid metadata")
	}
	if strings.TrimSpace(e.Compatibility.Tplater) == "" || e.Compatibility.MarkerSchema != MarkerSchema {
		return fmt.Errorf("block export: invalid compatibility")
	}
	if e.MergeStrategy != MergeStrategy || strings.TrimSpace(e.Formatter.Adapter) == "" || !digestRE.MatchString(e.Formatter.OptionsDigest) {
		return fmt.Errorf("block export: invalid formatter")
	}
	if len(e.Targets) < 1 || len(e.Targets) > MaxTargets {
		return fmt.Errorf("block export: invalid targets")
	}
	seen := map[string]bool{}
	total := 0
	for _, t := range e.Targets {
		if seen[t.Path] {
			return fmt.Errorf("block export: duplicate target")
		}
		seen[t.Path] = true
		if err := validateTarget(t); err != nil {
			return err
		}
		total += len(t.Blocks)
		if total > MaxBlocks {
			return fmt.Errorf("block export: too many blocks")
		}
	}
	return nil
}
func validateTarget(t Target) error {
	if !safePath(t.Path) || len(t.Blocks) < 1 || len(t.Blocks) > MaxBlocksPerTarget {
		return fmt.Errorf("block export: invalid target %q", t.Path)
	}
	seen := map[string]bool{}
	for _, b := range t.Blocks {
		if !idRE.MatchString(b.ID) || !providerRE.MatchString(b.Provider) || (b.Layout != "per_entity" && b.Layout != "layer_files") || !safePath(b.Body) || b.Body == "" {
			return fmt.Errorf("block export: invalid block %q", b.ID)
		}
		if seen[b.ID] {
			return fmt.Errorf("block export: duplicate block %q", b.ID)
		}
		seen[b.ID] = true
		if (b.Anchor.Present && b.Anchor.Before == "" && b.Anchor.After == "") || (b.Anchor.Before != "" && b.Anchor.After != "") || (b.Anchor.Before != "" && !idRE.MatchString(b.Anchor.Before)) || (b.Anchor.After != "" && !idRE.MatchString(b.Anchor.After)) {
			return fmt.Errorf("block export: invalid anchor")
		}
		if b.Anchor.Before == b.ID || b.Anchor.After == b.ID {
			return fmt.Errorf("block export: self anchor")
		}
		if len(b.Replaces) > 1 || (len(b.Replaces) == 1 && (!idRE.MatchString(b.Replaces[0]) || b.Replaces[0] == b.ID)) {
			return fmt.Errorf("block export: invalid replacement")
		}
	}
	return nil
}
func safePath(p string) bool {
	if p == "" || utf8.RuneCountInString(p) > MaxPathLength || strings.ContainsAny(p, "\r\n\\\x00") || path.IsAbs(p) || strings.Contains(p, "//") || strings.Contains(p, "/./") || p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") {
		return false
	}
	for _, x := range strings.Split(p, "/") {
		if x == "" || x == "." || x == ".." {
			return false
		}
	}
	return true
}
func strictSemver(v string) bool {
	if !semverRE.MatchString(v) {
		return false
	}
	parts := strings.SplitN(v, "+", 2)
	if len(parts) == 2 {
		for _, x := range strings.Split(parts[1], ".") {
			if x == "" {
				return false
			}
		}
	}
	core := strings.SplitN(parts[0], "-", 2)
	for _, x := range strings.Split(core[0], ".") {
		if len(x) > 1 && x[0] == '0' {
			return false
		}
	}
	return true
}

type ResolvedTarget struct {
	Path   string
	Blocks []Block
}

func Resolve(in []BlockExport) ([]ResolvedTarget, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("block export: no exports")
	}
	files := map[string][]Block{}
	strategy, marker, adapter, digest := "", "", "", ""
	for _, e := range in {
		if err := Validate(e); err != nil {
			return nil, err
		}
		if strategy == "" {
			strategy, marker, adapter, digest = e.MergeStrategy, e.Compatibility.MarkerSchema, e.Formatter.Adapter, e.Formatter.OptionsDigest
		} else if e.MergeStrategy != strategy || e.Compatibility.MarkerSchema != marker || e.Formatter.Adapter != adapter || e.Formatter.OptionsDigest != digest {
			return nil, fmt.Errorf("TPL-E-EXPORT-COLLISION-001: producer contract mismatch")
		}
		for _, t := range e.Targets {
			files[t.Path] = append(files[t.Path], t.Blocks...)
		}
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := make([]ResolvedTarget, 0, len(paths))
	for _, p := range paths {
		b := files[p]
		seen := map[string]bool{}
		for _, x := range b {
			if seen[x.ID] {
				return nil, fmt.Errorf("TPL-E-EXPORT-COLLISION-001: duplicate block %q", x.ID)
			}
			seen[x.ID] = true
		}
		if err := validateReplacements(b); err != nil {
			return nil, err
		}
		ordered, err := order(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, ResolvedTarget{p, ordered})
	}
	return out, nil
}
func validateReplacements(b []Block) error {
	ids := map[string]bool{}
	for _, x := range b {
		ids[x.ID] = true
	}
	old := map[string]string{}
	for _, x := range b {
		if len(x.Replaces) == 0 {
			continue
		}
		r := x.Replaces[0]
		if ids[r] {
			return fmt.Errorf("TPL-E-EXPORT-COLLISION-001: replacement alias emitted")
		}
		if old[r] != "" && old[r] != x.ID {
			return fmt.Errorf("TPL-E-EXPORT-COLLISION-001: ambiguous replacement")
		}
		old[r] = x.ID
	}
	for a := range old {
		if _, ok := old[old[a]]; ok {
			return fmt.Errorf("TPL-E-EXPORT-COLLISION-001: replacement chain")
		}
	}
	return nil
}
func order(in []Block) ([]Block, error) {
	by := map[string]Block{}
	indeg := map[string]int{}
	next := map[string][]string{}
	incoming, outgoing := map[string]bool{}, map[string]bool{}
	for _, b := range in {
		by[b.ID] = b
		indeg[b.ID] = 0
	}
	for _, b := range in {
		if b.Anchor.After != "" {
			if _, ok := by[b.Anchor.After]; !ok {
				return nil, fmt.Errorf("TPL-E-BLOCK-ORDER-001: unknown anchor")
			}
			if incoming[b.ID] || outgoing[b.Anchor.After] {
				return nil, fmt.Errorf("TPL-E-BLOCK-ORDER-001: overlapping anchor relation")
			}
			next[b.Anchor.After] = append(next[b.Anchor.After], b.ID)
			incoming[b.ID] = true
			outgoing[b.Anchor.After] = true
			indeg[b.ID]++
		}
		if b.Anchor.Before != "" {
			if _, ok := by[b.Anchor.Before]; !ok {
				return nil, fmt.Errorf("TPL-E-BLOCK-ORDER-001: unknown anchor")
			}
			if incoming[b.Anchor.Before] || outgoing[b.ID] {
				return nil, fmt.Errorf("TPL-E-BLOCK-ORDER-001: overlapping anchor relation")
			}
			next[b.ID] = append(next[b.ID], b.Anchor.Before)
			incoming[b.Anchor.Before] = true
			outgoing[b.ID] = true
			indeg[b.Anchor.Before]++
		}
	}
	less := func(a, b string) bool {
		if by[a].Order != by[b].Order {
			return by[a].Order < by[b].Order
		}
		return a < b
	}
	ready := []string{}
	for id, n := range indeg {
		if n == 0 {
			ready = append(ready, id)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return less(ready[i], ready[j]) })
	out := []Block{}
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		out = append(out, by[id])
		for _, to := range next[id] {
			indeg[to]--
			if indeg[to] == 0 {
				ready = append(ready, to)
				sort.Slice(ready, func(i, j int) bool { return less(ready[i], ready[j]) })
			}
		}
	}
	if len(out) != len(in) {
		return nil, fmt.Errorf("TPL-E-BLOCK-ORDER-001: anchor cycle")
	}
	return out, nil
}
