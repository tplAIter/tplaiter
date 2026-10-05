package contextcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"sync"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type RootSelectionRequest struct {
	Selections   []exports.Selection `json:"selections"`
	BindingsPath string              `json:"bindingsPath,omitempty"`
	MaxRecords   int                 `json:"maxRecords,omitempty"`
	MaxBytes     int                 `json:"maxBytes,omitempty"`
	Snapshot     string              `json:"snapshot,omitempty"`
}

// This carrier retains concrete installed authority. It has no wire decoder,
// authority Boolean, anonymous provider constructor or mutation capability.
type authenticatedSourceSnapshot struct {
	context                      context.Context
	runtime                      *trustload.Runtime
	resolution                   *trustverify.VerifiedResolution
	snapshot                     *trustverify.SourceSnapshot
	session                      *runtimeassembly.ReadSession
	rootDigest, dependencyDigest string
	knowledge                    []byte
	sourceID                     string
}

// RootSelection owns a held read lease until Close. The installed caller must
// Recheck immediately before emission, then close after emission finishes.
type RootSelection struct {
	mu       sync.Mutex
	admitted *authenticatedSourceSnapshot
	result   resultdto.ContextRootSelectionData
	stop     func() bool
}

func (s *RootSelection) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		s.stop()
		s.stop = nil
	}
	if s.admitted != nil {
		s.admitted.session.Close()
		s.admitted = nil
	}
	s.result = resultdto.ContextRootSelectionData{}
}

func (s *RootSelection) Result() resultdto.ContextRootSelectionData {
	if s == nil {
		return resultdto.ContextRootSelectionData{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.admitted == nil || s.admitted.context.Err() != nil {
		return resultdto.ContextRootSelectionData{}
	}
	raw, _ := json.Marshal(s.result)
	var out resultdto.ContextRootSelectionData
	_ = json.Unmarshal(raw, &out)
	return out
}

func (s *RootSelection) Recheck(ctx context.Context) error {
	if s == nil || ctx == nil {
		return fail(Invalid)
	}
	s.mu.Lock()
	if s.admitted == nil {
		s.mu.Unlock()
		return fail(Stale)
	}
	a := s.admitted
	err := ctx.Err()
	if err == nil {
		err = a.context.Err()
	}
	if err == nil {
		err = a.session.Recheck(ctx)
	}
	if err == nil {
		var root, dependency []byte
		root, err = readRootLock(a.runtime.ProjectContext().RootPath)
		if err == nil {
			dependency, err = readProjectLedger(a.runtime.ProjectContext().RootPath, "template.lock.json")
		}
		if err == nil && (evidencecas.Digest(root) != a.rootDigest || evidencecas.Digest(dependency) != a.dependencyDigest) {
			err = fail(Stale)
		}
	}
	if err == nil {
		_, err = knowledge.ObserveSource(ctx, a.runtime.TrustRuntime(), a.resolution, a.knowledge, a.sourceID)
	}
	s.mu.Unlock()
	if err != nil {
		s.Close()
	}
	return err
}

func BeginRootSelection(ctx context.Context, r *trustload.Runtime, req RootSelectionRequest) (*RootSelection, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, fail(Invalid)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.BindingsPath == "" {
		req.BindingsPath = DefaultRootBindingsPath
	}
	if req.MaxRecords == 0 {
		req.MaxRecords = 256
	}
	if req.MaxBytes == 0 {
		req.MaxBytes = 32768
	}
	if !rootPath(req.BindingsPath) || len(req.Selections) < 1 || len(req.Selections) > 16 || req.MaxRecords < 1 || req.MaxRecords > 256 || req.MaxBytes < 1 || req.MaxBytes > 32768 {
		return nil, fail(Invalid)
	}
	// Own and validate caller bindings before retaining any authority.
	owned := make([]exports.Selection, len(req.Selections))
	for i, v := range req.Selections {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		owned[i], err = exports.ParseSelection(raw)
		if err != nil {
			return nil, err
		}
	}
	req.Selections = owned
	session, err := runtimeassembly.OpenReadOnly(ctx, r, runtimeassembly.Options{})
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			session.Close()
		}
	}()
	a, err := admit(ctx, r, "")
	if err != nil {
		return nil, err
	}
	snap, err := r.TrustRuntime().VerifiedSnapshot(a.resolution)
	if err != nil {
		return nil, err
	}
	dependencyBytes, err := readProjectLedger(r.ProjectContext().RootPath, "template.lock.json")
	if err != nil {
		return nil, err
	}
	root, err := provenance.DecodeRootTemplateLock(a.rootBytes)
	if err != nil {
		return nil, err
	}
	dependency, err := provenance.DecodeTemplateLock(dependencyBytes)
	if err != nil {
		return nil, err
	}
	if err = provenance.ValidateLockPair(*root, *dependency); err != nil {
		return nil, err
	}
	if len(dependency.Dependencies) != 0 || root.Root.Subject() != a.resolution.Subject() || !root.TrustProfile.Equal(r.TrustRuntime().Binding()) {
		return nil, fail(Stale)
	}
	bindingRaw, _, err := rootBlob(snap, req.BindingsPath, 64<<10, true)
	if err != nil {
		return nil, err
	}
	b, err := decodeRootBindings(bindingRaw)
	if err != nil {
		return nil, err
	}
	pin := a.catalog.Sources[0].Pin
	pin.Alias, pin.ProviderID = b.Source.Alias, b.Source.ProviderID
	compiled, err := collectRootCatalog(ctx, snap, pin, b.Source)
	if err != nil {
		return nil, err
	}
	g, err := exports.ResolveSelections(req.Selections, compiled.Sources, []exports.Catalog{compiled.Catalog})
	if err != nil {
		return nil, err
	}
	files, err := rootImages(compiled, g)
	if err != nil {
		return nil, err
	}
	d, coreReq, err := rootKnowledge(snap, root.Root, root.Policy.PolicySHA256, pin, b, req.BindingsPath, compiled, g, files, req)
	if err != nil {
		return nil, err
	}
	knowledgeRaw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	if _, err = knowledge.Decode(knowledgeRaw); err != nil {
		return nil, err
	}
	catalogRaw, err := json.Marshal(compiled.Catalog)
	if err != nil {
		return nil, err
	}
	if _, err = knowledge.ProjectExportCatalog(d, d.Sources[0].ID, catalogRaw); err != nil {
		return nil, err
	}
	if _, err = knowledge.ObserveSource(ctx, r.TrustRuntime(), a.resolution, knowledgeRaw, d.Sources[0].ID); err != nil {
		return nil, err
	}
	idx, err := contextindex.New(knowledgeRaw, nil)
	if err != nil {
		return nil, err
	}
	bound := contextindex.Binding{SourceID: d.Sources[0].ID, Runtime: r.TrustRuntime(), Resolution: a.resolution}
	packet, err := idx.Retrieve(ctx, coreReq, []contextindex.Binding{bound})
	if err != nil {
		return nil, err
	}
	body := resultdto.RootContextBody{TrustProfile: r.TrustRuntime().Binding(), APIVersion: "tplaiter.dev/context-root-selection/v1", Qualification: "authenticated-installed-native-root", MaterializationScope: "task-context-preview", RootLockDigest: evidencecas.Digest(a.rootBytes), DependencyLockDigest: evidencecas.Digest(dependencyBytes), BindingsDigest: evidencecas.Digest(bindingRaw), SourceGraphDigest: compiled.Sources.Digest, CatalogDigest: evidencecas.Digest(catalogRaw), Selections: req.Selections, Graph: g, Packet: packet, Files: files}
	body.Snapshot, err = bootstrap.DomainDigest("tplaiter/context-root-snapshot/v1", struct {
		Project                                                    trustload.ProjectContext
		Profile                                                    bootstrap.ProfileBinding
		Root, Dependency, Binding, SourceGraph, Catalog, Selection string
	}{r.ProjectContext(), r.TrustRuntime().Binding(), body.RootLockDigest, body.DependencyLockDigest, body.BindingsDigest, body.SourceGraphDigest, body.CatalogDigest, g.Digest})
	if err != nil {
		return nil, err
	}
	if req.Snapshot != "" && req.Snapshot != body.Snapshot {
		return nil, fail(Stale)
	}
	out, err := deliverRootContext(ctx, idx, coreReq, bound, req, body)
	if err != nil {
		return nil, err
	}
	selection := &RootSelection{admitted: &authenticatedSourceSnapshot{context: ctx, runtime: r, resolution: a.resolution, snapshot: snap, session: session, rootDigest: body.RootLockDigest, dependencyDigest: body.DependencyLockDigest, knowledge: knowledgeRaw, sourceID: d.Sources[0].ID}, result: out}
	if err = selection.Recheck(ctx); err != nil {
		return nil, err
	}
	selection.mu.Lock()
	selection.stop = context.AfterFunc(ctx, selection.Close)
	selection.mu.Unlock()
	if err = ctx.Err(); err != nil {
		selection.Close()
		return nil, err
	}
	success = true
	return selection, nil
}

func collectRootCatalog(ctx context.Context, snap *trustverify.SourceSnapshot, pin deps.PinnedSource, b rootBinding) (exports.SourceCatalog, error) {
	empty := exports.SourceCatalog{}
	entries, _, err := rootBlob(snap, b.EntriesPath, 1<<20, true)
	if err != nil {
		return empty, err
	}
	tool, _, err := rootBlob(snap, b.ToolPath, 1<<20, true)
	if err != nil {
		return empty, err
	}
	graph, err := deps.BuildSourceGraph([]deps.PinnedSource{pin})
	if err != nil {
		return empty, err
	}
	wire, err := json.Marshal(struct {
		APIVersion     string          `json:"apiVersion"`
		Provider       string          `json:"provider"`
		Source         string          `json:"source"`
		ContractDigest string          `json:"contractDigest"`
		Exports        json.RawMessage `json:"exports"`
	}{exports.CatalogAPIVersion, pin.ProviderID, graph.Nodes[0].Key, pin.ContractDigest, entries})
	if err != nil {
		return empty, err
	}
	catalog, err := exports.ParseCatalog(wire)
	if err != nil {
		return empty, err
	}
	data := exports.CatalogData{Entries: entries, Tool: tool, Payloads: []exports.SourcePayload{}, Blobs: []exports.MaterialBlob{}}
	seen := map[string]bool{}
	total := len(entries) + len(tool)
	for _, entry := range catalog.Exports {
		if err = ctx.Err(); err != nil {
			return empty, err
		}
		raw, _, e := rootBlob(snap, path.Join(b.PayloadDirectory, entry.ID+".json"), 1<<20, true)
		if e != nil {
			return empty, e
		}
		payload, e := exports.ParseExportPayload(raw)
		if e != nil {
			return empty, e
		}
		// ROOT task context is a readonly complete-file projection. Managed edits
		// and JSON slots need their existing transaction consumer, not this route.
		if len(payload.Slots) != 0 || len(payload.Blocks) != 0 {
			return empty, fail(SourceUnavailable)
		}
		data.Payloads = append(data.Payloads, exports.SourcePayload{ExportID: entry.ID, Raw: raw})
		total += len(raw)
		for _, file := range payload.Files {
			if seen[file.SourcePath] {
				continue
			}
			seen[file.SourcePath] = true
			content, mode, e := rootBlob(snap, file.SourcePath, 1<<20, false)
			if e != nil {
				return empty, e
			}
			data.Blobs = append(data.Blobs, exports.MaterialBlob{Path: file.SourcePath, Mode: mode, Content: content})
			total += len(content)
		}
		if total > 16<<20 {
			return empty, fail(Budget)
		}
	}
	return exports.BuildSourceCatalog(exports.SourceCatalogInput{Pins: []deps.PinnedSource{pin}, Alias: pin.Alias, Data: data})
}

func rootImages(c exports.SourceCatalog, g exports.ExportGraph) ([]resultdto.RootContextFile, error) {
	in := exports.MaterializeInput{Sources: []exports.MaterialSource{}, TargetInventory: []exports.InventoryEntry{}, Current: []exports.FileState{}, Owned: []exports.OwnedPreimage{}, Operations: []exports.MaterialOperation{}, Managed: []exports.ManagedCandidate{}}
	files := []resultdto.RootContextFile{}
	for si, selected := range g.Selected {
		var raw []byte
		for _, p := range c.Payloads {
			if p.ExportID == selected.ID {
				raw = p.Raw
			}
		}
		payload, err := exports.ParseExportPayload(raw)
		if err != nil {
			return nil, err
		}
		identity, err := exports.SelectedExportIdentity(selected)
		if err != nil {
			return nil, err
		}
		blobs := []exports.MaterialBlob{}
		for _, f := range payload.Files {
			for _, blob := range c.Blobs {
				if blob.Path == f.SourcePath {
					blobs = append(blobs, blob)
				}
			}
		}
		in.Sources = append(in.Sources, exports.MaterialSource{Selected: selected, Payload: raw, Blobs: blobs})
		for fi, f := range payload.Files {
			in.Current = append(in.Current, exports.FileState{Path: f.TargetPath})
			in.Operations = append(in.Operations, exports.MaterialOperation{Kind: "add", Path: f.TargetPath, AfterOwner: exports.MaterialOwner{Provider: selected.Provider, RuleID: "context-preview", ExportID: selected.ID}, SourceIndex: si, EntryIndex: fi})
			files = append(files, resultdto.RootContextFile{SelectedIdentity: identity, ExportID: selected.ID, SourcePath: f.SourcePath, TargetPath: f.TargetPath, Mode: f.Mode, ContentSHA256: f.ContentSHA256})
		}
	}
	materialized, err := exports.Materialize(in)
	if err != nil {
		return nil, err
	}
	if len(materialized.Conflicts) != 0 || len(materialized.Images) != len(files) {
		return nil, fail(Stale)
	}
	for i := range files {
		for _, image := range materialized.Images {
			if image.Path == files[i].TargetPath {
				if image.After.Mode != files[i].Mode || image.After.ContentSHA256 != files[i].ContentSHA256 {
					return nil, fail(Stale)
				}
				files[i].Content = append([]byte(nil), image.After.Content...)
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].TargetPath < files[j].TargetPath })
	return files, nil
}

func rootKnowledge(snap *trustverify.SourceSnapshot, anchor provenance.RootSubject, policy string, pin deps.PinnedSource, b rootBindings, bindingPath string, c exports.SourceCatalog, g exports.ExportGraph, files []resultdto.RootContextFile, req RootSelectionRequest) (knowledge.Catalog, contextindex.Request, error) {
	d := knowledge.Catalog{APIVersion: knowledge.APIVersion, Kind: "KnowledgeCatalog", ID: "root:catalog:selection", Version: "1.0.0", Sources: []knowledge.Source{{ID: "root:source:installed", Pin: pin, Anchor: anchor}}, Items: []knowledge.Item{}, Edges: []knowledge.Edge{}}
	add := func(p, kind, identity string, entry *exports.ExportEntry) (string, error) {
		raw, mode, err := rootBlob(snap, p, 1<<20, false)
		if err != nil {
			return "", err
		}
		h := evidencecas.Digest([]byte(p + "\x00" + identity))
		id := "root:" + kind + ":r-" + h[7:39]
		version := "1.0.0"
		if entry != nil {
			version = entry.Version
		}
		it := knowledge.Item{ID: id, Kind: kind, Version: version, SourceID: d.Sources[0].ID, SourcePath: p, ContentSHA256: evidencecas.Digest(raw), Mode: mode, Ownership: knowledge.Ownership{OwnerID: "root:owner:declared", Version: "1.0.0", PolicySHA256: policy}, Executor: knowledge.Executor{ID: "root:executor:metadata-reader", Version: "1.0.0", InputContractSHA256: pin.ContractDigest, OutputContractSHA256: pin.ContractDigest}, UpdateTriggers: []string{"source", "content", "contract"}, Requires: []string{}, Produces: []string{}, Quality: []knowledge.Quality{}, Inputs: knowledge.InputContract{APIVersion: knowledge.InputsAPIVersion, ContextFloor: []string{}, Definitions: []knowledge.InputDefinition{}}, Export: entry}
		d.Items = append(d.Items, it)
		return id, nil
	}
	metadata := []string{"template.manifest.yaml", "template.contract.json", bindingPath, b.Source.EntriesPath, b.Source.ToolPath}
	for _, s := range g.Selected {
		metadata = append(metadata, path.Join(b.Source.PayloadDirectory, s.ID+".json"))
	}
	sort.Strings(metadata)
	seen := map[string]bool{}
	for _, p := range metadata {
		if seen[p] {
			continue
		}
		seen[p] = true
		if _, err := add(p, "resource", "metadata", nil); err != nil {
			return d, contextindex.Request{}, err
		}
	}
	keys := map[string][]string{}
	for _, f := range files {
		var entry exports.ExportEntry
		for _, e := range c.Catalog.Exports {
			if e.ID == f.ExportID {
				entry = e
			}
		}
		kind := entry.Domain
		if kind == "approach" {
			kind = "resource"
		}
		id, err := add(f.SourcePath, kind, f.SelectedIdentity, &entry)
		if err != nil {
			return d, contextindex.Request{}, err
		}
		key := c.Catalog.Source + "\x00" + c.Catalog.Provider + "\x00" + entry.Domain + "\x00" + entry.ID
		keys[key] = append(keys[key], id)
	}
	for _, e := range g.Edges {
		for _, from := range keys[e.Dependency] {
			for _, to := range keys[e.Consumer] {
				d.Edges = append(d.Edges, knowledge.Edge{From: from, To: to, Layer: "export", Relation: "depends-on", State: "declared"})
			}
		}
	}
	// Every observed record is mandatory. Existing C03 has a closed 32-ID input
	// floor; larger projections refuse rather than weakening it or paging it.
	if len(d.Items) > 32 {
		return d, contextindex.Request{}, fail(Budget)
	}
	required := make([]string, 0, len(d.Items))
	for _, it := range d.Items {
		required = append(required, it.ID)
	}
	sort.Strings(required)
	if len(required) == 0 {
		return d, contextindex.Request{}, fmt.Errorf("root context: empty projection")
	}
	return d, contextindex.Request{Query: contextindex.Query{ID: required[0], One: true}, Limit: 1, MaxRecords: req.MaxRecords, MaxBytes: req.MaxBytes, Required: required, IncludeExcerpts: true, MaxExcerptBytes: 2048}, nil
}
