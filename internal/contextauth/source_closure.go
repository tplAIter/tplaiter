// Package contextauth retains authenticated source closures, never execution authority.
package contextauth

import (
	"context"
	"encoding/json"
	"path"
	"reflect"
	"sort"
	"sync"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextwire"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

var errContextSources = contextwire.ErrSources
var errContextSourceLimit = contextwire.ErrSourceLimit

type ContextSourceBindings = contextwire.ContextSourceBindings
type ContextCatalogBinding = contextwire.ContextCatalogBinding
type NativeContextContract = contextwire.NativeContextContract
type ContextDependency = contextwire.ContextDependency

const ContextSourceBindingsPath = contextwire.ContextSourceBindingsPath

func contextResourcePath(p string) bool { return contextwire.ResourcePath(p) }
func DecodeNativeContextContractV2(raw, manifest []byte) (NativeContextContract, error) {
	return contextwire.DecodeNativeContextContractV2(raw, manifest)
}
func DecodeContextSourceBindingsV2(raw []byte) (ContextSourceBindings, error) {
	return contextwire.DecodeContextSourceBindingsV2(raw)
}
func subjectKey(s trustverify.Subject) string {
	return s.Origin + "\x00" + s.TemplatePath + "\x00" + s.Commit
}

type contextSourceRecord struct {
	subject    trustverify.Subject
	evidence   trustverify.EvidenceRefs
	resolution *trustverify.VerifiedResolution
	binding    ContextSourceBindings
	contract   NativeContextContract
	pin        deps.PinnedSource
	data       exports.CatalogData
}

// VerifiedSourceClosure owns verified source preparation only. It has no wire
// decoder, caller-reader constructor, New conversion, permit or write method.
// Its lifetime is bounded by the actual installed Runtime, not by a trust flag.
type VerifiedSourceClosure struct {
	mu        sync.Mutex
	installed *trustload.Runtime
	stable    *trustverify.Runtime
	profile   bootstrap.ProfileBinding
	project   trustload.ProjectContext
	root      string
	records   map[string]contextSourceRecord
	graph     deps.SourceGraph
	catalogs  []exports.SourceCatalog
	closed    bool
	parent    *VerifiedSourceClosure
	self      *VerifiedSourceClosure
}

// AdmitSourceClosure consumes original admissions from one installed runtime.
// Eligibility and DAG edges come from retained authenticated source bytes;
// rechecking original evidence never synthesizes project locks or permissions.
func AdmitSourceClosure(ctx context.Context, r *trustload.Runtime, root *trustverify.VerifiedResolution, dependencies []*trustverify.VerifiedResolution) (*VerifiedSourceClosure, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || root == nil || len(dependencies) > contextwire.MaxContextSources-1 {
		return nil, errContextSources
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	var e error

	stable := r.TrustRuntime()
	if stable.Binding().ID == bootstrap.ProfileDevelopment {
		return nil, errContextSources
	}
	p := &VerifiedSourceClosure{installed: r, stable: stable, profile: stable.Binding(), project: r.ProjectContext(), records: map[string]contextSourceRecord{}, catalogs: []exports.SourceCatalog{}}
	p.self = p
	bySubject := map[string]string{}
	inputs := append([]*trustverify.VerifiedResolution{root}, dependencies...)
	for i, resolution := range inputs {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if resolution == nil || !resolution.ValidFor(stable, stable.Binding()) || resolution.Subject().RequestedRef != resolution.Subject().Commit {
			return nil, errContextSources
		}
		fresh, err := stable.VerifySubject(ctx, resolution.Subject(), resolution.Evidence())
		if err != nil {
			return nil, err
		}
		if fresh.Subject() != resolution.Subject() || fresh.Evidence() != resolution.Evidence() {
			return nil, errContextSources
		}

		snap, e := stable.VerifiedSnapshot(resolution)
		if e != nil {
			return nil, e
		}
		manifest, e := contextSnapshotBlob(snap, "template.manifest.yaml", 1<<20, true)
		if e != nil {
			return nil, e
		}
		contractRaw, e := contextSnapshotBlob(snap, "template.contract.json", 1<<20, true)
		if e != nil {
			return nil, e
		}
		var contract NativeContextContract
		if c, e2 := DecodeNativeContextContractV2(contractRaw, manifest); e2 == nil {
			contract = c
		} else {
			// Empty v1 leaf remains v1; neither decoder's guard is relaxed.
			old, e2 := contextwire.DecodeNativeContract(contractRaw, manifest)
			if e2 != nil || contextwire.ValidateManifest(manifest) != nil {
				return nil, errContextSources
			}
			contract = NativeContextContract{APIVersion: old.APIVersion, Kind: old.Kind, ManifestPath: old.ManifestPath, ManifestSHA256: old.ManifestSHA256, Dependencies: []ContextDependency{}}
		}
		bindingRaw, e := contextSnapshotBlob(snap, ContextSourceBindingsPath, 64<<10, true)
		if e != nil {
			return nil, e
		}
		binding, e := DecodeContextSourceBindingsV2(bindingRaw)
		if e != nil {
			return nil, e
		}
		if len(contract.Dependencies) != len(binding.Dependencies) {
			return nil, errContextSources
		}
		for j, d := range contract.Dependencies {
			if d.Alias != binding.Dependencies[j].Alias {
				return nil, errContextSources
			}
		}
		alias := binding.Source.Alias
		if _, ok := p.records[alias]; ok {
			return nil, errContextSources
		}
		s := resolution.Subject()
		key := subjectKey(s)
		if _, ok := bySubject[key]; ok {
			return nil, errContextSources
		}
		bySubject[key] = alias
		content, e := deps.SnapshotContentDigest(snap.Entries())
		if e != nil {
			return nil, e
		}
		algo := "sha1"
		if len(s.Commit) == 64 {
			algo = "sha256"
		}
		adjacency := []string{}
		for _, d := range contract.Dependencies {
			adjacency = append(adjacency, d.Alias)
		}
		pin := deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: alias, ProviderID: binding.Source.ProviderID, Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, CommitAlgorithm: algo, Commit: s.Commit, TreeDigest: s.TreeSHA256, ContentDigest: content, ContractDigest: s.ContractSHA256, EvidenceDigest: resolution.Evidence().StatementCAS, Parameters: binding.Source.Parameters, Dependencies: adjacency}
		reader, e := deps.NewSourceReader(stable)
		if e != nil {
			return nil, e
		}
		if _, e = reader.Read(ctx, resolution, pin); e != nil {
			return nil, e
		}
		p.records[alias] = contextSourceRecord{subject: resolution.Subject(), evidence: resolution.Evidence(), resolution: resolution, binding: binding, contract: contract, pin: pin}
		if i == 0 {
			p.root = alias
		}
	}
	// Match the source-specific contract and association before constructing even
	// the pure source graph. A correctly signed but undeclared source is ineligible.
	for alias, record := range p.records {
		for i, d := range record.contract.Dependencies {
			dependency, ok := p.records[d.Alias]
			if !ok || d.Alias == alias {
				return nil, errContextSources
			}
			pin := dependency.pin
			association := record.binding.Dependencies[i]
			if d.Origin != pin.Origin || d.TemplatePath != pin.TemplatePath || d.CommitAlgorithm != pin.CommitAlgorithm || d.Commit != pin.Commit || d.TreeDigest != pin.TreeDigest || d.ContractDigest != pin.ContractDigest || association.ProviderID != pin.ProviderID || !contextParametersEqual(association.Parameters, pin.Parameters) {
				return nil, errContextSources
			}
		}
	}
	reached := map[string]bool{}
	active := map[string]bool{}
	var visit func(string) error
	visit = func(alias string) error {
		if active[alias] {
			return errContextSources
		}
		if reached[alias] {
			return nil
		}
		active[alias] = true
		record, ok := p.records[alias]
		if !ok {
			return errContextSources
		}
		for _, d := range record.pin.Dependencies {
			if e := visit(d); e != nil {
				return e
			}
		}
		delete(active, alias)
		reached[alias] = true
		return nil
	}
	if e = visit(p.root); e != nil || len(reached) != len(p.records) {
		return nil, errContextSources
	}
	pins := p.pinsLocked()
	rootPin := p.records[p.root].pin
	others := []deps.PinnedSource{}
	for _, pin := range pins {
		if pin.Alias != p.root {
			others = append(others, pin)
		}
	}
	result, e := deps.BuildSourceGraphWithContext(deps.SourceGraphInput{Root: &rootPin, DependencyClosure: &deps.SourceDependencyClosure{Pins: others}})
	if e != nil {
		return nil, e
	}
	p.graph = result.Graph
	aggregate := 0
	for _, pin := range pins {
		record := p.records[pin.Alias]
		reader, e := deps.NewSourceReader(stable)
		if e != nil {
			return nil, e
		}
		source, e := reader.Read(ctx, record.resolution, pin)
		if e != nil {
			return nil, e
		}
		key := ""
		for _, node := range p.graph.Nodes {
			for _, prov := range node.Provenance {
				if prov.Alias == pin.Alias {
					key = node.Key
				}
			}
		}
		data, e := collectContextSourceData(ctx, source, record.binding.Source, key)
		if e != nil {
			return nil, e
		}
		aggregate += len(data.Entries) + len(data.Tool)
		for _, payload := range data.Payloads {
			aggregate += len(payload.Raw)
		}
		for _, blob := range data.Blobs {
			aggregate += len(blob.Content)
		}
		if aggregate > 16<<20 {
			return nil, errContextSourceLimit
		}
		record.data = data
		p.records[pin.Alias] = record
		c, e := exports.BuildSourceCatalog(exports.SourceCatalogInput{Pins: pins, Alias: pin.Alias, Data: data})
		if e != nil {
			return nil, e
		}
		if c.Sources.Digest != p.graph.Digest {
			return nil, errContextSources
		}
		p.catalogs = append(p.catalogs, c)
	}
	// Replay all sources after complete catalog consumption, before exposing data.
	if e = p.Recheck(ctx); e != nil {
		return nil, e
	}
	return p, nil
}
func contextParametersEqual(a, b []deps.Parameter) bool {
	x, e := canonicaljson.Canonical(a)
	if e != nil {
		return false
	}
	y, e := canonicaljson.Canonical(b)
	return e == nil && reflect.DeepEqual(x, y)
}
func contextSnapshotBlob(s *trustverify.SourceSnapshot, name string, limit int, metadata bool) ([]byte, error) {
	if s == nil || !contextResourcePath(name) {
		return nil, errContextSources
	}
	for _, entry := range s.Entries() {
		if entry.Path != name {
			continue
		}
		raw, ok := s.Blob(name)
		if !ok || entry.Kind != "file" || (entry.Mode != "100644" && entry.Mode != "100755") || (metadata && entry.Mode != "100644") || len(raw) > limit || evidencecas.Digest(raw) != entry.ContentSHA256 {
			return nil, errContextSources
		}
		return raw, nil
	}
	return nil, errContextSources
}
func collectContextSourceData(ctx context.Context, s *deps.VerifiedSource, b ContextCatalogBinding, sourceKey string) (exports.CatalogData, error) {
	out := exports.CatalogData{Payloads: []exports.SourcePayload{}, Blobs: []exports.MaterialBlob{}}
	read := func(name string, metadata bool) ([]byte, string, error) {
		if !contextResourcePath(name) {
			return nil, "", errContextSources
		}
		for _, entry := range s.Entries() {
			if entry.Path != name {
				continue
			}
			raw, ok := s.Blob(name)
			if !ok || entry.Kind != "file" || (entry.Mode != "100644" && entry.Mode != "100755") || (metadata && entry.Mode != "100644") || len(raw) > 1<<20 || evidencecas.Digest(raw) != entry.ContentSHA256 {
				return nil, "", errContextSources
			}
			return raw, entry.Mode, nil
		}
		return nil, "", errContextSources
	}
	var e error
	out.Entries, _, e = read(b.EntriesPath, true)
	if e != nil {
		return out, e
	}
	out.Tool, _, e = read(b.ToolPath, true)
	if e != nil {
		return out, e
	}
	var entries []exports.ExportEntry
	// Preserve raw record validation in the existing catalog parser and builder.
	wire, e := json.Marshal(struct {
		APIVersion string          `json:"apiVersion"`
		Provider   string          `json:"provider"`
		Source     string          `json:"source"`
		Contract   string          `json:"contractDigest"`
		Exports    json.RawMessage `json:"exports"`
	}{exports.CatalogAPIVersion, b.ProviderID, sourceKey, s.Subject().ContractSHA256, out.Entries})
	if e != nil {
		return out, e
	}
	parsed, e := exports.ParseCatalog(wire)
	if e != nil {
		return out, e
	}
	entries = parsed.Exports
	seen := map[string]bool{}
	total := len(out.Entries) + len(out.Tool)
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		raw, _, e := read(path.Join(b.PayloadDirectory, entry.ID+".json"), true)
		if e != nil {
			return out, e
		}
		payload, e := exports.ParseExportPayload(raw)
		if e != nil || len(payload.Slots) != 0 || len(payload.Blocks) != 0 {
			return out, errContextSources
		}
		out.Payloads = append(out.Payloads, exports.SourcePayload{ExportID: entry.ID, Raw: raw})
		total += len(raw)
		for _, file := range payload.Files {
			if seen[file.SourcePath] {
				continue
			}
			seen[file.SourcePath] = true
			raw, mode, e := read(file.SourcePath, false)
			if e != nil {
				return out, e
			}
			out.Blobs = append(out.Blobs, exports.MaterialBlob{Path: file.SourcePath, Mode: mode, Content: raw})
			total += len(raw)
		}
		if total > 16<<20 {
			return out, errContextSourceLimit
		}
	}
	return out, nil
}
func (p *VerifiedSourceClosure) pinsLocked() []deps.PinnedSource {
	out := []deps.PinnedSource{}
	for _, record := range p.records {
		out = append(out, record.pin)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}
func (p *VerifiedSourceClosure) checkLocked(ctx context.Context) error {
	if p.self != p {
		return errContextSources
	}
	if p.parent != nil {
		if e := p.parent.RecheckFor(ctx, p.installed); e != nil {
			return e
		}
	}
	if ctx == nil || p.closed || p.installed == nil || p.stable == nil || p.installed.TrustRuntime() != p.stable || !p.stable.Binding().Equal(p.profile) || p.installed.ProjectContext() != p.project || len(p.records) == 0 || p.root == "" {
		return errContextSources
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	reader, e := deps.NewSourceReader(p.stable)
	if e != nil {
		return e
	}
	for _, pin := range p.pinsLocked() {
		record := p.records[pin.Alias]
		if record.resolution == nil || !record.resolution.ValidFor(p.stable, p.profile) || record.resolution.Subject() != record.subject || record.resolution.Evidence() != record.evidence {
			return errContextSources
		}
		fresh, e := p.stable.VerifySubject(ctx, record.subject, record.evidence)
		if e != nil {
			return e
		}
		if fresh.Subject() != record.resolution.Subject() || fresh.Evidence() != record.resolution.Evidence() {
			return errContextSources
		}
		if _, e = reader.Read(ctx, fresh, pin); e != nil {
			return e
		}
	}
	return ctx.Err()
}
func (p *VerifiedSourceClosure) Recheck(ctx context.Context) error {
	if p == nil {
		return errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checkLocked(ctx)
}

// Close discards retained preparation without closing the caller's runtime.
func (p *VerifiedSourceClosure) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.parent = nil
	p.records = nil
	p.catalogs = nil
	p.graph = deps.SourceGraph{}
}
func contextCopy[T any](in T) (T, error) {
	var out T
	raw, e := json.Marshal(in)
	if e != nil {
		return out, e
	}
	e = json.Unmarshal(raw, &out)
	return out, e
}
func (p *VerifiedSourceClosure) Pins(ctx context.Context) ([]deps.PinnedSource, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	return contextCopy(p.pinsLocked())
}
func (p *VerifiedSourceClosure) SourceGraph(ctx context.Context) (deps.SourceGraph, error) {
	if p == nil {
		return deps.SourceGraph{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return deps.SourceGraph{}, e
	}
	return contextCopy(p.graph)
}
func (p *VerifiedSourceClosure) Catalogs(ctx context.Context) ([]exports.SourceCatalog, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	return contextCopy(p.catalogs)
}
func (p *VerifiedSourceClosure) CatalogData(ctx context.Context, alias string) (exports.CatalogData, error) {
	if p == nil {
		return exports.CatalogData{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return exports.CatalogData{}, e
	}
	record, ok := p.records[alias]
	if !ok {
		return exports.CatalogData{}, errContextSources
	}
	return contextCopy(record.data)
}

// Resolution returns only the original opaque same-runtime admission carrier.
func (p *VerifiedSourceClosure) Resolution(ctx context.Context, alias string) (*trustverify.VerifiedResolution, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	record, ok := p.records[alias]
	if !ok {
		return nil, errContextSources
	}
	return record.resolution, nil
}

// RecheckFor binds consumption to the identical installed runtime that admitted
// this carrier. It is a freshness check, never an operation permission.
func (p *VerifiedSourceClosure) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if p == nil {
		return errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r == nil || r != p.installed {
		return errContextSources
	}
	return p.checkLocked(ctx)
}

// RootPin identifies the authenticated root without caller alias projection.
func (p *VerifiedSourceClosure) RootPin(ctx context.Context) (deps.PinnedSource, error) {
	if p == nil {
		return deps.PinnedSource{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(ctx); err != nil {
		return deps.PinnedSource{}, err
	}
	return contextCopy(p.records[p.root].pin)
}

// Borrow retains a child lifetime under the same installed runtime. Closing the
// child does not close its owner; closing the owner invalidates every child.
func (p *VerifiedSourceClosure) Borrow(ctx context.Context, r *trustload.Runtime) (*VerifiedSourceClosure, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r == nil || r != p.installed {
		return nil, errContextSources
	}
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	child := &VerifiedSourceClosure{installed: p.installed, stable: p.stable, profile: p.profile, project: p.project, root: p.root, records: p.records, graph: p.graph, catalogs: p.catalogs, parent: p}
	child.self = child
	return child, nil
}

// RootResolution returns the original opaque root admission, never a JSON reconstruction.
func (p *VerifiedSourceClosure) RootResolution(ctx context.Context, r *trustload.Runtime) (*trustverify.VerifiedResolution, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r == nil || r != p.installed {
		return nil, errContextSources
	}
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	return p.records[p.root].resolution, nil
}

// OperationSubjects projects every complete authenticated subject. It grants no actions.
func (p *VerifiedSourceClosure) OperationSubjects(ctx context.Context, r *trustload.Runtime) ([]trustverify.Provider, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r == nil || r != p.installed {
		return nil, errContextSources
	}
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	out := []trustverify.Provider{}
	for _, pin := range p.pinsLocked() {
		s := p.records[pin.Alias].subject
		out = append(out, trustverify.Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Origin+"\x00"+a.TemplatePath+"\x00"+a.Commit < b.Origin+"\x00"+b.TemplatePath+"\x00"+b.Commit
	})
	return out, nil
}
