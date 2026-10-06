package exports

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/blockexport"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const SourceLocalExportIndexAPIVersion = "tplaiter.dev/source-local-export-index/v1"
const RootRuleDomain = "tplaiter.dev/root-rule/v1"

// SourceLocalExportIndex is authored metadata, never an installed catalog or
// source admission. Source/provider/node identities are deliberately absent.
type SourceLocalExportIndex struct {
	APIVersion string        `json:"apiVersion"`
	Exports    []ExportEntry `json:"exports"`
}

func ParseSourceLocalExportIndex(raw []byte) (SourceLocalExportIndex, error) {
	var index SourceLocalExportIndex
	if len(raw) == 0 || len(raw) > 64<<10 {
		return index, rootError("INDEX_BOUND")
	}
	if err := decodeClosed(raw, []string{"apiVersion", "exports"}, &index); err != nil {
		return index, err
	}
	if index.APIVersion != SourceLocalExportIndexAPIVersion || len(index.Exports) == 0 || len(index.Exports) > 256 {
		return index, rootError("INDEX_SHAPE")
	}
	var fields struct {
		Exports []map[string]json.RawMessage `json:"exports"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return index, err
	}
	ids, selectors := map[string]bool{}, map[string]bool{}
	prev := ""
	for i, e := range index.Exports {
		row := fields.Exports[i]
		for _, key := range []string{"id", "domain", "name", "version", "contentDigest", "requires", "parameters", "toolDigest"} {
			if _, ok := row[key]; !ok {
				return index, rootError("INDEX_MISSING_FIELD")
			}
		}
		if len(row) != 8 {
			return index, rootError("INDEX_UNKNOWN_FIELD")
		}
		if err := e.Validate(); err != nil {
			return index, err
		}
		if len(e.Requires) > 256 || len(e.Parameters) > 256 {
			return index, rootError("INDEX_BOUND")
		}
		if ids[e.ID] || selectors[e.Domain+"."+e.Name] || eKey(e) <= prev {
			return index, rootError("INDEX_IDENTITY")
		}
		ids[e.ID] = true
		selectors[e.Domain+"."+e.Name] = true
		prev = eKey(e)
	}
	return index, nil
}

// RootOwnership is complete original DATA. It does not convey writer authority.
type RootOwnership struct {
	RuleID   string          `json:"ruleID"`
	Kind     string          `json:"kind"`
	Original json.RawMessage `json:"original"`
}
type RootRulePreparation struct {
	Rules         RuleSet
	SourcePin     deps.PinnedSource
	Index         SourceLocalExportIndex
	ClosureDigest string
	Ownership     []RootOwnership
	source        *deps.VerifiedSource
}

type rootNativeContract struct {
	APIVersion     string   `json:"apiVersion"`
	Kind           string   `json:"kind"`
	ManifestPath   string   `json:"manifestPath"`
	ManifestSHA256 string   `json:"manifestSHA256"`
	Dependencies   []string `json:"dependencies"`
}
type rootInput struct {
	pin     deps.PinnedSource
	wire    SourcePin
	entries []trustverify.SourceEntry
	files   map[string]trustverify.SourceEntry
	source  *deps.VerifiedSource
}

func rootError(code string) error { return fmt.Errorf("ROOT_RULE_%s", code) }

// PrepareRootRules derives inert identities only from SourceReader's retained
// source and accepted pin. All mappings must close before any rules are returned.
func PrepareRootRules(ctx context.Context, source *deps.VerifiedSource, pin SourcePin) (RootRulePreparation, error) {
	var zero RootRulePreparation
	if ctx == nil || source == nil {
		return zero, rootError("SOURCE_REQUIRED")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	accepted, ok := source.AcceptedPin()
	if !ok {
		return zero, rootError("SOURCE_REQUIRED")
	}
	wire := rootWirePin(accepted)
	a, err := canonicaljson.Canonical(wire)
	if err != nil {
		return zero, err
	}
	b, err := canonicaljson.Canonical(pin)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(a, b) {
		return zero, rootError("PIN_MISMATCH")
	}
	if err := validateSource(pin); err != nil {
		return zero, err
	}
	entries := source.Entries()
	if len(entries) == 0 || len(entries) > 8192 || !sort.SliceIsSorted(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path }) {
		return zero, rootError("ENTRIES")
	}
	input := rootInput{pin: accepted, wire: wire, entries: entries, files: map[string]trustverify.SourceEntry{}, source: source}
	prev := ""
	for _, e := range entries {
		if e.Path <= prev || ValidatePortablePath(e.Path) != nil {
			return zero, rootError("ENTRY_PATH")
		}
		prev = e.Path
		if e.Kind == "directory" {
			if e.Mode != "40000" {
				return zero, rootError("ENTRY_KIND")
			}
			continue
		}
		if e.Kind != "file" || (e.Mode != "100644" && e.Mode != "100755") {
			return zero, rootError("ENTRY_KIND")
		}
		raw, ok := source.Blob(e.Path)
		if !ok || digestBytes(raw) != e.ContentSHA256 {
			return zero, rootError("CONTENT")
		}
		input.files[e.Path] = e
	}
	content, err := deps.SnapshotContentDigest(entries)
	if err != nil || content != accepted.ContentDigest {
		return zero, rootError("CONTENT")
	}
	manifestRaw, err := input.blob("template.manifest.yaml")
	if err != nil {
		return zero, err
	}
	contractRaw := source.ContractBytes()
	if len(contractRaw) == 0 || len(contractRaw) > 1<<20 {
		return zero, rootError("CONTRACT")
	}
	var contract rootNativeContract
	if err := decodeClosed(contractRaw, []string{"apiVersion", "kind", "manifestPath", "manifestSHA256", "dependencies"}, &contract); err != nil {
		return zero, err
	}
	if contract.APIVersion != "tplaiter.dev/native-template-contract/v1" || contract.Kind != "NativeTemplate" || contract.ManifestPath != "template.manifest.yaml" || contract.ManifestSHA256 != digestBytes(manifestRaw) || contract.Dependencies == nil || len(contract.Dependencies) != 0 {
		return zero, rootError("NATIVE_UNSUPPORTED")
	}
	m, err := manifest.ParseTemplate(manifestRaw)
	if err != nil {
		return zero, err
	}
	if err = m.Validate(); err != nil {
		return zero, err
	}
	// These sections need setting/render/lifecycle interpretation. Refuse them,
	// rather than publish an unconditional ownership projection of their effects.
	if m.Engine.Type != "gotemplate" || ValidatePortablePath(m.Engine.Root) != nil || m.Engine.Root == "." || len(m.Settings) != 0 || len(m.Files) != 0 || len(m.Constraints) != 0 || len(m.Migrations) != 0 || m.ManagedBlocks != nil || len(m.Engine.PostReplace) != 0 || len(m.Engine.CopyWithoutRender) != 0 || len(m.Commands) != 0 || !rootEmpty(m.Hooks) || !rootEmpty(m.AIConfig) || !rootEmpty(m.Environment) || !rootEmpty(m.Requires) || !rootEmpty(m.Lint) {
		return zero, rootError("MANIFEST_UNSUPPORTED")
	}
	indexRaw, err := input.blob("exports/catalog.source.json")
	if err != nil {
		return zero, rootError("INDEX_REQUIRED")
	}
	index, err := ParseSourceLocalExportIndex(indexRaw)
	if err != nil {
		return zero, err
	}
	payloads := map[string]ExportPayload{}
	blockRecords := map[string][]blockexport.BlockExport{}
	payloadRaw := map[string][]byte{}
	payloadPath := map[string]string{}
	for name := range input.files {
		if !strings.HasPrefix(name, "exports/") {
			continue
		}
		if name == "exports/catalog.source.json" {
			continue
		}
		if !strings.HasSuffix(name, ".payload.json") || strings.Count(name, "/") != 1 {
			return zero, rootError("EXPORT_MAPPING")
		}
		raw, _ := input.blob(name)
		payload, e := ParseExportPayload(raw)
		if e != nil {
			return zero, e
		}
		if _, ok := payloads[payload.ExportID]; ok {
			return zero, rootError("EXPORT_IDENTITY")
		}
		payloads[payload.ExportID] = payload
		payloadRaw[payload.ExportID] = raw
		payloadPath[payload.ExportID] = name
	}
	if len(payloads) != len(index.Exports) {
		return zero, rootError("EXPORT_OMISSION")
	}
	lockRaw, err := input.blob(m.Engine.Root + "/bun.lock")
	if err != nil {
		return zero, rootError("TOOL_MAPPING")
	}
	for _, e := range index.Exports {
		p, ok := payloads[e.ID]
		if !ok || digestBytes(payloadRaw[e.ID]) != e.ContentDigest || e.ToolDigest != digestBytes(lockRaw) {
			return zero, rootError("EXPORT_MAPPING")
		}
		if len(e.Parameters) != 0 || len(e.Requires) != 0 {
			return zero, rootError("EXPORT_MAPPING_UNSUPPORTED")
		}
		for _, f := range p.Files {
			expectedTarget := f.SourcePath
			if strings.HasPrefix(f.SourcePath, m.Engine.Root+"/") {
				expectedTarget = strings.TrimSuffix(strings.TrimPrefix(f.SourcePath, m.Engine.Root+"/"), ".tmpl")
			}
			if f.TargetPath != expectedTarget {
				return zero, rootError("EXPORT_TARGET")
			}
			entry, ok := input.files[f.SourcePath]
			if !ok || entry.Mode != f.Mode || entry.ContentSHA256 != f.ContentSHA256 {
				return zero, rootError("EXPORT_FILE")
			}
		}
		for _, block := range p.Blocks {
			entry, ok := input.files[block.SourcePath]
			if !ok || entry.ContentSHA256 != block.ContentSHA256 {
				return zero, rootError("EXPORT_BLOCK")
			}
			raw, _ := input.blob(block.SourcePath)
			descriptor, err := blockexport.Parse(raw)
			if err != nil {
				return zero, err
			}
			for _, target := range descriptor.Targets {
				if ValidatePortablePath(target.Path) != nil {
					return zero, rootError("BLOCK_TARGET")
				}
				for _, b := range target.Blocks {
					if _, err := input.blob(b.Body); err != nil {
						return zero, rootError("BLOCK_BODY")
					}
				}
			}
			blockRecords[e.ID] = append(blockRecords[e.ID], descriptor)

		}
		for _, slot := range p.Slots {
			raw, e := input.outputBlob(m.Engine.Root, slot.TargetPath)
			if e != nil || !rootSlotMatches(raw, slot.Pointer, slot.Value) {
				return zero, rootError("EXPORT_SLOT")
			}
		}
	}
	common := struct {
		Domain        string
		Pin           deps.PinnedSource
		Subject       trustverify.Subject
		Entries       []trustverify.SourceEntry
		Manifest      json.RawMessage
		ManifestBytes []byte
		ContractBytes []byte
		Index         json.RawMessage
	}{RootRuleDomain, accepted, source.Subject(), entries, nil, manifestRaw, contractRaw, indexRaw}
	common.Manifest, err = canonicaljson.Canonical(m)
	if err != nil {
		return zero, err
	}
	commonRaw, err := canonicaljson.Canonical(common)
	if err != nil {
		return zero, err
	}
	result := RootRulePreparation{Rules: RuleSet{Rules: []Rule{}, Required: []Capability{}, Tombstones: []Tombstone{}, Exports: map[string]ExportFact{}, Tools: map[string]ToolFact{}}, SourcePin: accepted, Index: index, ClosureDigest: digestBytes(commonRaw), Ownership: []RootOwnership{}, source: source}
	ids := map[string]bool{}
	appendRule := func(kind string, original any) error {
		record, e := canonicaljson.Canonical(original)
		if e != nil {
			return e
		}
		id, digest, e := rootRuleIdentity(commonRaw, kind, record)
		if e != nil {
			return e
		}
		if ids[id] {
			return rootError("ID_COLLISION")
		}
		ids[id] = true
		result.Rules.Rules = append(result.Rules.Rules, Rule{ID: id, Digest: digest, Version: m.Metadata.Version, Provider: wire.Alias, Capabilities: []Capability{}, Sources: []SourcePin{wire}, Bindings: []Binding{{Name: "root.original", Value: record}, {Name: "root.closure", Value: json.RawMessage(fmt.Sprintf("%q", result.ClosureDigest))}}, Tools: []ToolConstraint{}})
		result.Ownership = append(result.Ownership, RootOwnership{id, kind, record})
		return nil
	}
	rootCount := 0
	targets := map[string]bool{}
	for _, entry := range entries {
		if entry.Kind != "file" || !strings.HasPrefix(entry.Path, m.Engine.Root+"/") {
			continue
		}
		target := strings.TrimSuffix(strings.TrimPrefix(entry.Path, m.Engine.Root+"/"), ".tmpl")
		if strings.Contains(target, "{{") || ValidatePortablePath(target) != nil || targets[target] {
			return zero, rootError("FILE_MAPPING")
		}
		targets[target] = true
		rootCount++
		if err := appendRule("file", struct {
			Entry  trustverify.SourceEntry
			Target string
		}{entry, target}); err != nil {
			return zero, err
		}
	}
	if rootCount == 0 {
		return zero, rootError("ROOT_EMPTY")
	}
	kinds := map[string]bool{}
	generatorFiles := map[string]bool{}
	for _, g := range m.Generators {
		if kinds[g.Kind] {
			return zero, rootError("GENERATOR_IDENTITY")
		}
		kinds[g.Kind] = true
		resources := []trustverify.SourceEntry{}
		seen := map[string]bool{}
		take := func(name string) error {
			entry, ok := input.files[name]
			if !ok {
				return rootError("GENERATOR_RESOURCE")
			}
			generatorFiles[name] = true
			if !seen[name] {
				resources = append(resources, entry)
				seen[name] = true
			}
			return nil
		}
		if g.Snippet != "" {
			if err := take(g.Snippet); err != nil {
				return zero, err
			}
			if err := rootTarget(g.Target); err != nil {
				return zero, err
			}
		}
		for _, t := range g.Targets {
			if err := take(t.Snippet); err != nil {
				return zero, err
			}
			if err := rootTarget(t.Target); err != nil {
				return zero, err
			}
		}
		for _, a := range g.Anchors {
			if err := take(a.Insert); err != nil {
				return zero, err
			}
			body, e := input.outputBlob(m.Engine.Root, a.File)
			if e != nil || !targets[a.File] || a.Anchor == "" || bytes.Count(body, []byte(a.Anchor)) != 1 {
				return zero, rootError("ANCHOR_MAPPING")
			}
		}
		sort.Slice(resources, func(i, j int) bool { return resources[i].Path < resources[j].Path })
		if err := appendRule("generator", struct {
			Generator manifest.Generator
			Resources []trustverify.SourceEntry
		}{g, resources}); err != nil {
			return zero, err
		}
	}
	// Exactly one explicitly authored export must cover the full generator
	// resource set, with identity target paths and no unrelated files or slots.
	if len(generatorFiles) > 0 {
		matched := 0
		for _, p := range payloads {
			if len(p.Files) != len(generatorFiles) || len(p.Slots) != 0 || len(p.Blocks) != 0 {
				continue
			}
			seen := map[string]bool{}
			for _, f := range p.Files {
				if generatorFiles[f.SourcePath] && f.TargetPath == f.SourcePath {
					seen[f.SourcePath] = true
				}
			}
			if len(seen) == len(generatorFiles) {
				matched++
			}
		}
		if matched != 1 {
			return zero, rootError("GENERATOR_EXPORT_MAPPING")
		}
	}
	for _, e := range index.Exports {
		selector := wire.Alias + "." + e.Domain + "." + e.Name
		result.Rules.Exports[selector] = ExportFact{ContractDigest: wire.ContractDigest, Version: e.Version}
		if err := appendRule("export", struct {
			Entry   ExportEntry
			Path    string
			Payload json.RawMessage
			Blocks  []blockexport.BlockExport
		}{e, payloadPath[e.ID], payloadRaw[e.ID], blockRecords[e.ID]}); err != nil {
			return zero, err
		}
	}
	sort.Slice(result.Rules.Rules, func(i, j int) bool { return result.Rules.Rules[i].ID < result.Rules.Rules[j].ID })
	sort.Slice(result.Ownership, func(i, j int) bool { return result.Ownership[i].RuleID < result.Ownership[j].RuleID })
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return result, nil
}
func (in rootInput) blob(name string) ([]byte, error) {
	if ValidatePortablePath(name) != nil {
		return nil, rootError("RESOURCE_PATH")
	}
	if _, ok := in.files[name]; !ok {
		return nil, rootError("RESOURCE_MISSING")
	}
	raw, ok := in.source.Blob(name)
	if !ok {
		return nil, rootError("RESOURCE_MISSING")
	}
	return raw, nil
}

// The existing gotemplate engine removes one .tmpl suffix in output paths.
func (in rootInput) outputBlob(root, target string) ([]byte, error) {
	plain, p := in.files[root+"/"+target]
	_, t := in.files[root+"/"+target+".tmpl"]
	if p && t {
		return nil, rootError("FILE_MAPPING")
	}
	if p {
		return in.blob(plain.Path)
	}
	if t {
		return in.blob(root + "/" + target + ".tmpl")
	}
	return nil, rootError("RESOURCE_MISSING")
}
func rootWirePin(p deps.PinnedSource) SourcePin {
	return SourcePin{Alias: p.Alias, ProviderID: p.ProviderID, Origin: p.Origin, TemplatePath: p.TemplatePath, RequestedRef: p.RequestedRef, CommitAlgorithm: p.CommitAlgorithm, Commit: p.Commit, TreeDigest: p.TreeDigest, ContentDigest: p.ContentDigest, ContractDigest: p.ContractDigest, EvidenceDigest: p.EvidenceDigest}
}
func rootEmpty(v any) bool {
	raw, _ := json.Marshal(v)
	var x any
	_ = json.Unmarshal(raw, &x)
	var empty func(any) bool
	empty = func(v any) bool {
		switch v := v.(type) {
		case nil:
			return true
		case string:
			return v == ""
		case bool:
			return !v
		case float64:
			return v == 0
		case []any:
			for _, x := range v {
				if !empty(x) {
					return false
				}
			}
			return true
		case map[string]any:
			for _, x := range v {
				if !empty(x) {
					return false
				}
			}
			return true
		}
		return false
	}
	return empty(x)
}
func rootTarget(s string) error {
	if s == "" || path.IsAbs(s) || strings.ContainsAny(s, "\x00\r\n\\") || len(s) > 4096 {
		return rootError("GENERATOR_TARGET")
	}
	if _, err := template.New("target").Parse(s); err != nil {
		return err
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." || part == "." || part == "" {
			return rootError("GENERATOR_TARGET")
		}
	}
	return nil
}
func rootSlotMatches(raw []byte, pointer, want string) bool {
	var v any
	if canonicaljson.DecodeStrict(raw, &v) != nil {
		return false
	}
	if !strings.HasPrefix(pointer, "/") {
		return false
	}
	for _, part := range strings.Split(pointer[1:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		v, ok = m[part]
		if !ok {
			return false
		}
	}
	got, ok := v.(string)
	return ok && got == want
}

// ProjectRootCatalog binds authored metadata only to a validated SourceNode
// matching the already accepted full pin. It does not authenticate a new node.
func ProjectRootCatalog(prepared RootRulePreparation, node deps.SourceNode) (Catalog, error) {
	if prepared.source == nil || len(prepared.Rules.Rules) == 0 || node.Key == "" {
		return Catalog{}, rootError("CATALOG_SOURCE")
	}
	accepted, ok := prepared.source.AcceptedPin()
	if !ok {
		return Catalog{}, rootError("CATALOG_SOURCE")
	}
	fresh, err := PrepareRootRules(context.Background(), prepared.source, rootWirePin(accepted))
	if err != nil {
		return Catalog{}, err
	}
	a0, _ := canonicaljson.Canonical(prepared.Index)
	b0, _ := canonicaljson.Canonical(fresh.Index)
	p0, _ := canonicaljson.Canonical(prepared.SourcePin)
	q0, _ := canonicaljson.Canonical(accepted)
	if !bytes.Equal(a0, b0) || !bytes.Equal(p0, q0) || prepared.ClosureDigest != fresh.ClosureDigest {
		return Catalog{}, rootError("CATALOG_SOURCE")
	}
	graph, err := deps.BuildSourceGraph([]deps.PinnedSource{accepted})
	if err != nil {
		return Catalog{}, err
	}
	if len(graph.Nodes) != 1 {
		return Catalog{}, errors.New("ROOT_RULE_CATALOG_SOURCE")
	}
	expected := graph.Nodes[0]
	a, _ := canonicaljson.Canonical(expected)
	b, _ := canonicaljson.Canonical(node)
	if !bytes.Equal(a, b) {
		return Catalog{}, rootError("CATALOG_SOURCE")
	}
	raw, err := canonicaljson.Canonical(prepared.Index)
	if err != nil {
		return Catalog{}, err
	}
	index, err := ParseSourceLocalExportIndex(raw)
	if err != nil {
		return Catalog{}, err
	}
	catalog := Catalog{APIVersion: CatalogAPIVersion, Provider: node.Identity.ProviderID, Source: node.Key, ContractDigest: node.Identity.ContractDigest, Exports: index.Exports}
	return catalog, catalog.Validate()
}

func rootRuleIdentity(closure json.RawMessage, kind string, record json.RawMessage) (string, string, error) {
	if kind != "file" && kind != "generator" && kind != "export" {
		return "", "", rootError("ID_KIND")
	}
	original, err := canonicaljson.Canonicalize(record)
	if err != nil {
		return "", "", err
	}
	id := "root." + kind + "." + strings.TrimPrefix(digestBytes(original), "sha256:")
	if !exportTokenRE.MatchString(id) {
		return "", "", rootError("ID_GRAMMAR")
	}
	data, err := canonicaljson.Canonical(struct {
		Domain   string
		Closure  json.RawMessage
		Kind     string
		Original json.RawMessage
	}{RootRuleDomain, closure, kind, original})
	if err != nil {
		return "", "", err
	}
	return id, digestBytes(append([]byte(RootRuleDomain+"\x00"), data...)), nil
}
