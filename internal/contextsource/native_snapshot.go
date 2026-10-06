package contextsource

import (
	"context"
	"io/fs"
	"maps"
	"sort"
	"strings"
	"sync"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextauth"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// RecordedNativeSnapshotInput is calculation data. The lifecycle owner derives
// recorded values from authenticated marker or sealed migration beforeimages.
type RecordedNativeSnapshotInput struct {
	Render          renderref.Input
	RecordedValues  settings.Values
	RendererVersion string
}

// PreparedNativeSnapshot owns recorded rendering, not execution or publication.
// Closing either this carrier or its admitted sources invalidates its projections.
type PreparedNativeSnapshot struct {
	mu               sync.Mutex
	owner            *trustload.Runtime
	self             *PreparedNativeSnapshot
	sources          *PreparedContextSources
	formatterSources *contextauth.VerifiedSourceClosure
	root             provenance.RootTemplateLock
	dependencies     provenance.TemplateLock
	rendered         *renderref.Result
	manifest         []byte
	rootAlias        string
	contextDigest    string
}

// ProjectContextSourceLocks projects only locks from freshly admitted sources.
// Detached returned locks do not reconstruct the source carrier.
func ProjectContextSourceLocks(ctx context.Context, r *trustload.Runtime, sources *PreparedContextSources, renderer string) (provenance.RootTemplateLock, provenance.TemplateLock, error) {
	if ctx == nil || r == nil || sources == nil || !nativeNewRenderer.MatchString(renderer) {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, errContextSources
	}
	if err := sources.RecheckFor(ctx, r); err != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, err
	}
	pin, err := sources.RootPin(ctx)
	if err != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, err
	}
	// Read immutable original admissions under the source owner mutex after the
	// complete fresh closure check above. Public getters keep their own checks.
	sources.mu.Lock()
	if sources.installed != r || sources.closure == nil || len(sources.records) == 0 {
		sources.mu.Unlock()
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, errContextSources
	}
	records := map[string]*trustverify.VerifiedResolution{}
	for alias, record := range sources.records {
		if record.resolution == nil || record.resolution != record.original || !record.resolution.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
			sources.mu.Unlock()
			return provenance.RootTemplateLock{}, provenance.TemplateLock{}, errContextSources
		}
		records[alias] = record.resolution
	}
	sources.mu.Unlock()
	resolution, ok := records[pin.Alias]
	if !ok {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, errContextSources
	}
	subject, evidence := resolution.Subject(), resolution.Evidence()
	binding := r.TrustRuntime().Binding()
	root := provenance.RootTemplateLock{APIVersion: provenance.RootTemplateLockAPIVersion, Kind: provenance.RootTemplateLockKind, TrustProfile: binding, Policy: provenance.PolicyBinding{PolicySHA256: binding.PolicySHA256}, Root: provenance.RootSubjectFromTrust(subject, bootstrap.PublisherEvidence{StatementCAS: evidence.StatementCAS, SignatureCAS: evidence.SignatureCAS, KeyFingerprint: evidence.KeyFingerprint}, evidence.CheckpointCAS, evidence.InclusionProofCAS), Renderer: provenance.RendererIdentity{Name: "go-text-template", Version: renderer}}
	root.RootLockSHA256, err = provenance.ComputeRootLockSHA256(root)
	if err != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, err
	}
	dependencies := provenance.TemplateLock{APIVersion: provenance.TemplateLockAPIVersion, Kind: provenance.DependencyExportLockKind, TrustProfile: binding, RootLockSHA256: root.RootLockSHA256, Dependencies: []provenance.DependencySubject{}}
	for alias, resolution := range records {
		if alias == pin.Alias {
			continue
		}
		s, e := resolution.Subject(), resolution.Evidence()
		dependencies.Dependencies = append(dependencies.Dependencies, provenance.DependencySubject(provenance.RootSubjectFromTrust(s, bootstrap.PublisherEvidence{StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint}, e.CheckpointCAS, e.InclusionProofCAS)))
	}
	sort.Slice(dependencies.Dependencies, func(i, j int) bool {
		a, b := dependencies.Dependencies[i], dependencies.Dependencies[j]
		return a.Origin+"\x00"+a.TemplatePath+"\x00"+a.Commit < b.Origin+"\x00"+b.TemplatePath+"\x00"+b.Commit
	})
	dependencies.LockSHA256, err = provenance.ComputeTemplateLockSHA256(dependencies)
	if err != nil || provenance.ValidateLockPair(root, dependencies) != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, errContextSources
	}
	if err := sources.RecheckFor(ctx, r); err != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, err
	}
	return root, dependencies, nil
}

func PrepareRecordedNativeSnapshot(ctx context.Context, r *trustload.Runtime, sources *PreparedContextSources, in RecordedNativeSnapshotInput) (*PreparedNativeSnapshot, error) {
	if ctx == nil || r == nil || sources == nil || in.RecordedValues == nil || !nativeNewRenderer.MatchString(in.RendererVersion) {
		return nil, errContextSources
	}
	if err := sources.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	pin, err := sources.RootPin(ctx)
	if err != nil {
		return nil, err
	}
	resolution, err := sources.Resolution(ctx, pin.Alias)
	if err != nil {
		return nil, err
	}
	snapshot, err := r.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	raw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return nil, errContextSources
	}
	if _, err := DecodeNativeContextContractV2(snapshot.ContractBytes(), raw); err != nil {
		return nil, err
	}
	src, err := operationtrust.SnapshotFS(r.TrustRuntime(), resolution)
	if err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(src)
	if err != nil {
		return nil, err
	}
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || tpl.AIConfig.Path != "" || operationtrust.ValidateBoundProjectBuildContent(snapshot, tpl) != nil {
		return nil, errContextSources
	}
	in.Render.Values = renderref.Values(in.Render.Values).Clone()
	in.RecordedValues = renderref.Values(in.RecordedValues).Clone()
	result, err := renderref.RenderRecordedInScratch(ctx, src, in.Render, r.ScratchRoot(), in.RecordedValues)
	if err != nil {
		return nil, err
	}
	for name := range result.Files {
		if !fs.ValidPath(name) || name == "." || strings.Contains(name, "\\") || name == ".tplaiter" || strings.HasPrefix(name, ".tplaiter/") || name == ".tplater" || strings.HasPrefix(name, ".tplater/") {
			return nil, errContextSources
		}
	}
	root, dependencies, err := ProjectContextSourceLocks(ctx, r, sources, in.RendererVersion)
	if err != nil {
		return nil, err
	}
	graph, err := sources.SourceGraph(ctx)
	if err != nil {
		return nil, err
	}
	catalogs, err := sources.Catalogs(ctx)
	if err != nil {
		return nil, err
	}
	wires := []exports.Catalog{}
	for _, c := range catalogs {
		wires = append(wires, c.Catalog)
	}
	digest, err := bootstrap.DomainDigest("tplaiter.dev/native-recorded-context/v2", struct {
		Root           provenance.RootTemplateLock
		Dependencies   provenance.TemplateLock
		Render         renderref.Input
		RecordedValues settings.Values
		Values         settings.Values
		Graph          deps.SourceGraph
		Catalogs       []exports.Catalog
		Images         []nativeNewImage
	}{root, dependencies, in.Render, in.RecordedValues, result.Resolved.Values, graph, wires, nativeNewImages(result.Files)})
	if err != nil {
		return nil, err
	}
	p := &PreparedNativeSnapshot{owner: r, sources: sources, root: root, dependencies: dependencies, rendered: result, manifest: append([]byte(nil), raw...), rootAlias: pin.Alias, contextDigest: digest}
	p.self = p
	if err := p.RecheckFor(ctx, r); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

func (p *PreparedNativeSnapshot) check(ctx context.Context, r *trustload.Runtime) error {
	if p == nil || ctx == nil || r == nil || p.self != p || p.owner != r || p.sources == nil || p.rendered == nil {
		return errContextSources
	}
	return p.sources.RecheckFor(ctx, r)
}

func (p *PreparedNativeSnapshot) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if p == nil {
		return errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.check(ctx, r)
}

func (p *PreparedNativeSnapshot) RootLock(ctx context.Context, r *trustload.Runtime) (provenance.RootTemplateLock, error) {
	if p == nil {
		return provenance.RootTemplateLock{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return provenance.RootTemplateLock{}, err
	}
	return p.root, nil
}

func (p *PreparedNativeSnapshot) DependencyLock(ctx context.Context, r *trustload.Runtime) (provenance.TemplateLock, error) {
	if p == nil {
		return provenance.TemplateLock{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return provenance.TemplateLock{}, err
	}
	out := p.dependencies
	out.Dependencies = append([]provenance.DependencySubject{}, out.Dependencies...)
	return out, nil
}

func (p *PreparedNativeSnapshot) RootResolution(ctx context.Context, r *trustload.Runtime) (*trustverify.VerifiedResolution, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	return p.sources.Resolution(ctx, p.rootAlias)
}

func (p *PreparedNativeSnapshot) ContextDigest(ctx context.Context, r *trustload.Runtime) (string, error) {
	if p == nil {
		return "", errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return "", err
	}
	return p.contextDigest, nil
}

func (p *PreparedNativeSnapshot) Rendered(ctx context.Context, r *trustload.Runtime) (*renderref.Result, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	out := *p.rendered
	out.Files = map[string][]byte{}
	for name, data := range p.rendered.Files {
		out.Files[name] = append([]byte(nil), data...)
	}
	tpl, err := manifest.ParseTemplate(p.manifest)
	if err != nil {
		return nil, err
	}
	out.Template = tpl
	if out.Baseline != nil {
		baseline := *out.Baseline
		baseline.Files = maps.Clone(out.Baseline.Files)
		out.Baseline = &baseline
	}
	out.Resolved.Values = out.Resolved.Values.Clone()
	out.Resolved.ActiveValues = out.Resolved.ActiveValues.Clone()
	out.Resolved.Report.Implied = append([]settings.ImpliedValue(nil), out.Resolved.Report.Implied...)
	out.Resolved.Report.Warnings = append([]string(nil), out.Resolved.Report.Warnings...)
	return &out, nil
}

func (p *PreparedNativeSnapshot) FormatterSources(ctx context.Context, r *trustload.Runtime) (*contextauth.VerifiedSourceClosure, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	if p.formatterSources == nil {
		c, err := p.sources.borrowClosure(ctx, r)
		if err != nil {
			return nil, err
		}
		p.formatterSources = c
	}
	if err := p.formatterSources.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	return p.formatterSources, nil
}

func (p *PreparedNativeSnapshot) SourceGraph(ctx context.Context, r *trustload.Runtime) (deps.SourceGraph, error) {
	if p == nil {
		return deps.SourceGraph{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return deps.SourceGraph{}, err
	}
	return p.sources.SourceGraph(ctx)
}

func (p *PreparedNativeSnapshot) Manifest(ctx context.Context, r *trustload.Runtime) ([]byte, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	return append([]byte(nil), p.manifest...), nil
}

func (p *PreparedNativeSnapshot) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.formatterSources != nil {
		p.formatterSources.Close()
	}
	p.formatterSources = nil
	p.owner = nil
	p.self = nil
	p.sources = nil
	p.rendered = nil
	p.manifest = nil
	p.contextDigest = ""
	p.dependencies.Dependencies = nil
}

func recordedAnswersDigest(values settings.Values) (string, error) {
	raw, err := canonicaljson.Canonical(values)
	if err != nil {
		return "", err
	}
	return evidencecas.Digest(raw), nil
}

func (p *PreparedNativeSnapshot) nativeUpdateFacts(ctx context.Context, r *trustload.Runtime) ([]trustverify.Provider, settings.Values, error) {
	if p == nil {
		return nil, nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, nil, err
	}
	p.sources.mu.Lock()
	defer p.sources.mu.Unlock()
	if p.sources.installed != r || p.sources.closure == nil || len(p.sources.records) == 0 {
		return nil, nil, errContextSources
	}
	providers := []trustverify.Provider{}
	for _, record := range p.sources.records {
		resolution := record.resolution
		if resolution == nil || resolution != record.original || !resolution.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
			return nil, nil, errContextSources
		}
		subject := resolution.Subject()
		providers = append(providers, trustverify.Provider{Origin: subject.Origin, TemplatePath: subject.TemplatePath, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256})
	}
	sort.Slice(providers, func(i, j int) bool { return nativeProviderOrder(providers[i]) < nativeProviderOrder(providers[j]) })
	return providers, p.rendered.Resolved.Values.Clone(), nil
}
