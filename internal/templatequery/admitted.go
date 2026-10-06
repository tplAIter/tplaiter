package templatequery

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/trustload"
	d "github.com/tplAIter/tplaiter/pkg/templatediscovery"
)

// AdmittedObservation owns the original live closure through serialization.
// The result is descriptive context; it is not a permit or installability proof.
type AdmittedObservation struct {
	runtime   *trustload.Runtime
	sources   *contextsource.PreparedContextSources
	operation *contextsource.SourceOperation
	result    d.Result
	readCalls map[string][]d.ReadOnlyCall
}

func (o *AdmittedObservation) Result() d.Result {
	if o == nil {
		return d.Result{}
	}
	raw, _ := json.Marshal(o.result)
	var copy d.Result
	_ = json.Unmarshal(raw, &copy)
	return copy
}
func (o *AdmittedObservation) Recheck(ctx context.Context) error {
	if o == nil || o.sources == nil || o.operation == nil || o.runtime == nil || o.runtime.TrustRuntime() == nil {
		return ErrSource
	}
	if err := o.operation.Check(ctx, o.runtime); err != nil {
		return err
	}
	return o.operation.FinalRecheck(ctx, o.runtime)
}

// Fit derives presentation only from this owner's retained result and resolved
// read-call map; caller bytes never replace original catalog identities.
func (o *AdmittedObservation) Fit(ctx context.Context, maxBytes int) (d.Result, error) {
	if o == nil || o.operation == nil || o.runtime == nil {
		return d.Result{}, ErrSource
	}
	if err := o.operation.Check(ctx, o.runtime); err != nil {
		return d.Result{}, err
	}
	return fitAdmittedReadCalls(o.Result(), o.readCalls, maxBytes)
}
func (o *AdmittedObservation) Close() {
	if o != nil && o.sources != nil {
		o.sources.Close()
		o.sources = nil
		o.operation = nil
		o.runtime = nil
	}
}
func exportPin(e exports.ExportEntry) d.SourcePin {
	return d.SourcePin{Qualification: "owner-supplied", SourceID: e.ID, Revision: e.Version, ContentSHA256: e.ContentDigest}
}
func original(p d.SourcePin) d.OriginalPin {
	return d.OriginalPin{SourceID: p.SourceID, Revision: p.Revision, ContentSHA256: p.ContentSHA256}
}
func payload(c exports.SourceCatalog, e exports.ExportEntry) (exports.ExportPayload, error) {
	for _, p := range c.Payloads {
		if p.ExportID == e.ID && d.Digest(p.Raw) == e.ContentDigest {
			return exports.ParseExportPayload(p.Raw)
		}
	}
	return exports.ExportPayload{}, ErrSource
}
func catalogKind(c exports.SourceCatalog, e exports.ExportEntry) d.Kind {
	switch e.Domain {
	case "skill":
		return d.KindSkill
	case "approach":
		return d.KindRecipe
	case "block":
		p, err := payload(c, e)
		if err == nil && len(p.Blocks) > 0 {
			return d.KindBlock
		}
		return d.KindContext
	default:
		return d.KindUnknown
	}
}

// joinReference consumes only a built original catalog with its retained
// payload/body material. Declared descriptions never create an export record.
func joinReference(ref d.Reference, c exports.SourceCatalog, sourceAlias string, graph *deps.SourceGraph, all []exports.Catalog) (d.Reference, string, string) {
	ref.Availability = "unavailable"
	ref.Provenance = nil
	for _, e := range c.Catalog.Exports {
		matches := ref.ID == e.ID
		if ref.SourcePin.Qualification == "owner-supplied" {
			matches = matches && original(ref.SourcePin) == original(exportPin(e))
		}
		if !matches {
			continue
		}
		if _, err := payload(c, e); err != nil {
			return ref, "", ""
		}
		selector := sourceAlias + "." + e.Domain + "." + e.Name
		resolved, err := exports.ResolveSelections([]exports.Selection{{APIVersion: exports.SelectionAPIVersion, Selector: selector, Bindings: []exports.ScalarParameter{}}}, graph, all)
		if err != nil {
			return ref, "", ""
		}
		actualKind := catalogKind(c, e)
		// A prose-only block payload remains context. A declared skill must be an
		// actual skill-domain record; AGENTS text alone never supplies one.
		if ref.CandidateKind == d.KindUnknown {
			ref.CandidateKind = actualKind
		}
		if ref.CandidateKind == d.KindBlock && actualKind != d.KindBlock || ref.CandidateKind == d.KindSkill && actualKind != d.KindSkill {
			return ref, "", ""
		}
		ref.SourcePin = exportPin(e)
		ref.Availability = "admitted-record"
		ref.Provenance = &d.Provenance{CatalogSource: c.Catalog.Source, Provider: c.Catalog.Provider, ContractSHA256: c.Catalog.ContractDigest, ExportID: e.ID, Domain: e.Domain, ContentSHA256: e.ContentDigest}
		return ref, selector, resolved.Digest
	}
	return ref, "", ""
}

// Admit uses the ordinary installed runtime and full typed source admission.
// sourceTransport is only the followup locator for the same original input.
func Admit(ctx context.Context, r *trustload.Runtime, raw []byte, sourceTransport, projectKey string, q d.Query) (*AdmittedObservation, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, ErrSource
	}
	q, err := d.Normalize(q)
	if err != nil {
		return nil, err
	}
	sources, err := contextsource.PrepareContextSources(ctx, r, raw)
	if err != nil {
		return nil, err
	}
	operation, err := sources.BeginOperation(ctx, r)
	if err != nil {
		sources.Close()
		return nil, err
	}
	o := &AdmittedObservation{runtime: r, sources: sources, operation: operation}
	complete := false
	defer func() {
		if !complete {
			o.Close()
		}
	}()
	if err = operation.Check(ctx, r); err != nil {
		return nil, err
	}
	pins, err := operation.Pins()
	if err != nil {
		return nil, err
	}
	if err = operation.Check(ctx, r); err != nil {
		return nil, err
	}
	catalogs, err := operation.Catalogs()
	if err != nil {
		return nil, err
	}
	if err = operation.Check(ctx, r); err != nil {
		return nil, err
	}
	graph, err := operation.SourceGraph()
	if err != nil {
		return nil, err
	}
	sort.Slice(pins, func(i, j int) bool { return pins[i].Alias < pins[j].Alias })
	plain := []exports.Catalog{}
	for _, c := range catalogs {
		plain = append(plain, c.Catalog)
	}
	candidates := []d.Candidate{}
	calls := map[string][]d.ReadOnlyCall{}
	diagnostics := []d.Diagnostic{}
	if len(pins) > 4096 {
		return nil, d.ErrInput
	}
	for _, pin := range pins {
		if err = operation.Check(ctx, r); err != nil {
			return nil, err
		}
		resolution, err := operation.Resolution(pin.Alias)
		if err != nil {
			return nil, err
		}
		snapshot, err := r.TrustRuntime().VerifiedSnapshot(resolution)
		if err != nil {
			return nil, err
		}
		manifestRaw, ok := snapshot.Blob("template.manifest.yaml")
		if !ok {
			return nil, ErrSource
		}
		tpl, err := manifest.ParseTemplate(manifestRaw)
		if err != nil {
			return nil, err
		}
		nodeKey := ""
		for _, node := range graph.Nodes {
			for _, p := range node.Provenance {
				if p.Alias == pin.Alias {
					nodeKey = node.Key
				}
			}
		}
		var catalog *exports.SourceCatalog
		for i := range catalogs {
			if catalogs[i].Catalog.Source == nodeKey {
				if catalog != nil {
					return nil, ErrSource
				}
				catalog = &catalogs[i]
			}
		}
		if catalog == nil {
			return nil, ErrSource
		}
		rootPin := d.SourcePin{Qualification: "owner-supplied", SourceID: nodeKey, Revision: pin.Commit, ContentSHA256: pin.ContentDigest, Repo: pin.ProviderID, Path: pin.TemplatePath, Commit: pin.Commit, ManifestSHA256: d.Digest(manifestRaw)}
		localPin := rootPin
		localPin.Qualification = "local-observed"
		localPin.Repo = pin.Alias
		localPin.SourceID = ""
		localPin.Revision = ""
		localPin.ContentSHA256 = ""
		c, err := declared(tpl, localPin)
		if err != nil {
			diagnostics = append(diagnostics, d.Diagnostic{Code: "metadata_invalid", Field: "manifest"})
			continue
		}
		c.SourcePin = rootPin
		if metadataRaw, present := snapshot.Blob(d.MetadataLocator); present {
			m, err := d.DecodeMetadata(metadataRaw)
			if err != nil {
				diagnostics = append(diagnostics, d.Diagnostic{Code: "metadata_invalid", Field: "companion"})
				continue
			}
			matched := false
			for _, e := range catalog.Catalog.Exports {
				p := exportPin(e)
				if original(p) == m.CandidatePin {
					if matched {
						return nil, ErrMetadata
					}
					matched = true
					p.Repo = rootPin.Repo
					p.Path = rootPin.Path
					p.Commit = rootPin.Commit
					p.ManifestSHA256 = rootPin.ManifestSHA256
					c, err = d.CandidateFromMetadata(m, p)
					if err != nil {
						return nil, err
					}
				}
			}
			if !matched {
				diagnostics = append(diagnostics, d.Diagnostic{Code: "source_unavailable", Field: "companion-pin"})
				continue
			}
		} else {
			// Only actual typed original catalog records can supplement legacy
			// manifest references. This does not infer readiness or installation.
			existing := map[string]bool{}
			for _, ref := range append(append([]d.Reference{}, c.Blocks...), c.Skills...) {
				existing[ref.ID] = true
			}
			for _, e := range catalog.Catalog.Exports {
				if e.Domain != "block" && e.Domain != "skill" {
					continue
				}
				if !existing[e.ID] {
					ref := d.Reference{ID: e.ID, SourcePin: exportPin(e), CandidateKind: catalogKind(*catalog, e), Readiness: d.Unknown, DeclarationStatus: "metadata-declared", Availability: "unavailable"}
					if e.Domain == "skill" {
						c.Skills = append(c.Skills, ref)
					} else {
						c.Blocks = append(c.Blocks, ref)
					}
				}
				c.Labels["catalog-names"] = append(c.Labels["catalog-names"], e.Name)
			}
		}
		selectors := map[string]string{}
		digests := map[string]string{}
		join := func(refs []d.Reference) []d.Reference {
			out := []d.Reference{}
			for _, ref := range refs {
				joined, selector, digest := joinReference(ref, *catalog, pin.Alias, &graph, plain)
				out = append(out, joined)
				if selector != "" {
					selectors[ref.ID] = selector
					digests[ref.ID] = digest
				}
			}
			return out
		}
		c.Blocks = join(c.Blocks)
		c.Skills = join(c.Skills)
		c, err = d.Identify(c)
		if err != nil {
			diagnostics = append(diagnostics, d.Diagnostic{Code: "metadata_invalid", Field: "candidate"})
			continue
		}
		candidates = append(candidates, c)
		refs := append(append([]d.Reference{}, c.Blocks...), c.Skills...)
		for _, ref := range refs {
			selector := selectors[ref.ID]
			if selector == "" {
				continue
			}
			calls[c.ID+"\x00"+ref.ID] = []d.ReadOnlyCall{admittedReadCall(r.ProjectContext().RootPath, projectKey, sourceTransport, selector, digests[ref.ID])}
		}
	}
	result, err := d.Rank(q, candidates)
	if err != nil {
		return nil, err
	}
	result.Qualification = "descriptive-data-only"
	result.Budget.Considered = len(pins)

	for _, v := range diagnostics {
		if len(result.Diagnostics) < 32 {
			result.Diagnostics = append(result.Diagnostics, v)
		} else {
			result.Budget.Truncated = true
		}
	}
	result, err = fitAdmittedReadCalls(result, calls, q.MaxBytes)
	if err != nil {
		return nil, err
	}
	o.result = result
	o.readCalls = calls
	if err := o.Recheck(ctx); err != nil {
		return nil, err
	}
	complete = true
	return o, nil
}

// The owner constructs calls only from retained exact reference identities whose
// selectors were resolved against its original typed catalog/body graph.
func fitAdmittedReadCalls(result d.Result, calls map[string][]d.ReadOnlyCall, maxBytes int) (d.Result, error) {
	attach := func() {
		for i := range result.Suggestions {
			s := &result.Suggestions[i]
			s.NextToolCalls = []d.ReadOnlyCall{}
			for _, ref := range append(append([]d.Reference{}, s.Blocks...), s.Skills...) {
				if ref.Availability != "admitted-record" {
					continue
				}
				for _, call := range calls[s.ID+"\x00"+ref.ID] {
					if len(s.NextToolCalls) < 4 {
						raw, _ := json.Marshal(call)
						var copy d.ReadOnlyCall
						_ = json.Unmarshal(raw, &copy)
						s.NextToolCalls = append(s.NextToolCalls, copy)
					}
				}
			}
		}
	}
	for i := 0; i < 8; i++ {
		attach()
		hadJoinedCall := false
		for _, s := range result.Suggestions {
			if len(s.NextToolCalls) > 0 && len(s.Blocks)+len(s.Skills) > 0 {
				hadJoinedCall = true
			}
		}
		var err error
		result, err = d.Fit(result, maxBytes)
		if err != nil {
			return result, err
		}
		if hadJoinedCall && len(result.Suggestions) == 0 {
			return result, ErrOutputBudget
		}
		fitted, _ := json.Marshal(result)
		attach()
		rebuilt, _ := json.Marshal(result)
		if bytes.Equal(fitted, rebuilt) {
			return result, nil
		}
	}
	return result, ErrSource
}

func admittedReadCall(root, projectKey, sourceTransport, selector, expectedDigest string) d.ReadOnlyCall {
	return d.ReadOnlyCall{Tool: "graph_exports", Arguments: map[string]any{"dir": root, "projectContext": projectKey, "sourceInput": sourceTransport, "expectedDigest": expectedDigest, "selectors": []string{selector}, "limit": 1, "maxBytes": 4096, "representation": "page"}}
}
