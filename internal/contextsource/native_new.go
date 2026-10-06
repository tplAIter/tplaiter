package contextsource

import (
	"context"
	"io/fs"
	"maps"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/tplAIter/tplaiter/internal/blockmarkers"
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

var nativeNewRenderer = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)

type NativeNewInput struct {
	Render          renderref.Input
	RendererVersion string
}

// PreparedNativeNew retains calculation intent only. It is neither a creation
// permit nor serialized recovery material; resources and publication are separate.
type PreparedNativeNew struct {
	mu                       sync.Mutex
	owner                    *trustload.Runtime
	sources                  *PreparedContextSources
	formatterSources         *contextauth.VerifiedSourceClosure
	formatterOwner           *PreparedNativeNew
	root                     provenance.RootTemplateLock
	dependencies             provenance.TemplateLock
	rendered                 *renderref.Result
	manifest                 []byte
	rootAlias                string
	operation, contextDigest string
	operationBase            trustverify.OperationInputs
	managedFiles             []NativeManagedFile
}

// NativeManagedFile describes exact unformatted root-authored Go content.
// Marker provider labels identify content, never dependency authority.
type NativeManagedFile struct {
	Path        string
	Mode        string
	InputSHA256 string
	Markers     []blockmarkers.Marker
}

type nativeNewMode uint8

const (
	nativeActionFree nativeNewMode = iota
	nativeManaged
)

func PrepareNativeNew(ctx context.Context, r *trustload.Runtime, sources *PreparedContextSources, in NativeNewInput) (*PreparedNativeNew, error) {
	return prepareNativeNew(ctx, r, sources, in, nativeActionFree)
}

// PrepareManagedNativeNew calculates authenticated root render intent. It grants
// neither formatter execution nor project publication; those remain owner routes.
func PrepareManagedNativeNew(ctx context.Context, r *trustload.Runtime, sources *PreparedContextSources, in NativeNewInput) (*PreparedNativeNew, error) {
	return prepareNativeNew(ctx, r, sources, in, nativeManaged)
}

func prepareNativeNew(ctx context.Context, r *trustload.Runtime, sources *PreparedContextSources, in NativeNewInput, mode nativeNewMode) (*PreparedNativeNew, error) {
	if ctx == nil || r == nil || sources == nil || !nativeNewRenderer.MatchString(in.RendererVersion) {
		return nil, errContextSources
	}
	if err := sources.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	stable := r.TrustRuntime()
	project := r.ProjectContext()
	if stable == nil || r.ScratchRoot() == "" || project.ProjectID == "" || project.RootPath == "" {
		return nil, errContextSources
	}
	pin, err := sources.RootPin(ctx)
	if err != nil {
		return nil, err
	}
	resolution, err := sources.Resolution(ctx, pin.Alias)
	if err != nil {
		return nil, err
	}
	snapshot, err := operationtrust.SnapshotFS(stable, resolution)
	if err != nil {
		return nil, err
	}
	raw, err := fs.ReadFile(snapshot, "template.manifest.yaml")
	if err != nil {
		return nil, err
	}
	contract, err := fs.ReadFile(snapshot, "template.contract.json")
	if err != nil {
		return nil, err
	}
	if _, err = DecodeNativeContextContractV2(contract, raw); err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(snapshot)
	if err != nil {
		return nil, err
	}
	verifiedSnapshot, err := stable.VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || tpl.AIConfig.Path != "" || operationtrust.ValidateBoundProjectBuildContent(verifiedSnapshot, tpl) != nil {
		return nil, errContextSources
	}
	if err := validateNativeNewValues(tpl, in.Render.Values); err != nil {
		return nil, err
	}
	in.Render.Values = in.Render.Values.Clone()
	result, err := renderref.RenderInScratch(ctx, snapshot, in.Render, r.ScratchRoot())
	if err != nil {
		return nil, err
	}
	for name, data := range result.Files {
		if !fs.ValidPath(name) || name == "." || name == ".tplaiter" || strings.HasPrefix(name, ".tplaiter/") || name == ".tplater" || strings.HasPrefix(name, ".tplater/") || (mode == nativeActionFree && strings.Contains(string(data), "tplater:managed-")) {
			return nil, errContextSources
		}
	}
	var managedFiles []NativeManagedFile
	if mode == nativeManaged {
		managedFiles, err = nativeManagedInventory(ctx, result.Files)
		if err != nil {
			return nil, err
		}
	}
	binding := stable.Binding()
	subject, evidence := resolution.Subject(), resolution.Evidence()
	root := provenance.RootTemplateLock{APIVersion: provenance.RootTemplateLockAPIVersion, Kind: provenance.RootTemplateLockKind, TrustProfile: binding, Policy: provenance.PolicyBinding{PolicySHA256: binding.PolicySHA256}, Root: provenance.RootSubjectFromTrust(subject, bootstrap.PublisherEvidence{StatementCAS: evidence.StatementCAS, SignatureCAS: evidence.SignatureCAS, KeyFingerprint: evidence.KeyFingerprint}, evidence.CheckpointCAS, evidence.InclusionProofCAS), Renderer: provenance.RendererIdentity{Name: "go-text-template", Version: in.RendererVersion}}
	root.RootLockSHA256, err = provenance.ComputeRootLockSHA256(root)
	if err != nil {
		return nil, err
	}
	dependencies := provenance.TemplateLock{APIVersion: provenance.TemplateLockAPIVersion, Kind: provenance.DependencyExportLockKind, TrustProfile: binding, RootLockSHA256: root.RootLockSHA256, Dependencies: []provenance.DependencySubject{}}
	providers := []trustverify.Provider{}
	pins, err := sources.Pins(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pins {
		resolved, err := sources.Resolution(ctx, p.Alias)
		if err != nil {
			return nil, err
		}
		s, e := resolved.Subject(), resolved.Evidence()
		providers = append(providers, trustverify.Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256})
		if p.Alias != pin.Alias {
			dependencies.Dependencies = append(dependencies.Dependencies, provenance.DependencySubject(provenance.RootSubjectFromTrust(s, bootstrap.PublisherEvidence{StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint}, e.CheckpointCAS, e.InclusionProofCAS)))
		}
	}
	if mode == nativeManaged {
		unique := map[string]trustverify.Provider{}
		for _, provider := range providers {
			key := nativeProviderOrder(provider)
			if old, ok := unique[key]; ok && old != provider {
				return nil, errContextSources
			}
			unique[key] = provider
		}
		providers = providers[:0]
		for _, provider := range unique {
			providers = append(providers, provider)
		}
	}
	sort.Slice(providers, func(i, j int) bool { return nativeProviderOrder(providers[i]) < nativeProviderOrder(providers[j]) })
	sort.Slice(dependencies.Dependencies, func(i, j int) bool {
		a, b := dependencies.Dependencies[i], dependencies.Dependencies[j]
		return a.Origin+"\x00"+a.TemplatePath+"\x00"+a.Commit < b.Origin+"\x00"+b.TemplatePath+"\x00"+b.Commit
	})
	dependencies.LockSHA256, err = provenance.ComputeTemplateLockSHA256(dependencies)
	if err != nil || provenance.ValidateLockPair(root, dependencies) != nil {
		return nil, errContextSources
	}
	profileDigest, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, binding)
	if err != nil {
		return nil, err
	}
	values, err := canonicaljson.Canonical(result.Resolved.Values)
	if err != nil {
		return nil, err
	}
	operationBase := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: profileDigest, ProjectID: project.ProjectID, Scope: "new", PreimageSHA256: evidencecas.Digest(nil), AnswersSHA256: evidencecas.Digest(values), Subjects: providers, Actions: []trustverify.ActionMaterial{}}
	operation, err := trustverify.ComputeOperationInputsSHA256(operationBase)
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
	catalogWires := []exports.Catalog{}
	for _, c := range catalogs {
		catalogWires = append(catalogWires, c.Catalog)
	}
	// Complete render coordinates and source-associated catalogs are identity data,
	// independent of the operation digest and future complete publication inventory.
	contextDigest, err := bootstrap.DomainDigest("tplaiter.dev/native-new-context/v2", struct {
		Root         provenance.RootTemplateLock
		Dependencies provenance.TemplateLock
		Render       renderref.Input
		Graph        deps.SourceGraph
		Catalogs     []exports.Catalog
	}{root, dependencies, in.Render, graph, catalogWires})
	if err != nil {
		return nil, err
	}
	if mode == nativeManaged {
		contextDigest, err = bootstrap.DomainDigest("tplaiter.dev/native-managed-new-context/v2", struct {
			Root         provenance.RootTemplateLock
			Dependencies provenance.TemplateLock
			Render       renderref.Input
			Values       settings.Values
			Graph        deps.SourceGraph
			Catalogs     []exports.Catalog
			Images       []nativeNewImage
			Managed      []NativeManagedFile
		}{root, dependencies, in.Render, result.Resolved.Values, graph, catalogWires, nativeNewImages(result.Files), managedFiles})
		if err != nil {
			return nil, err
		}
	}
	if err = sources.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	prepared := &PreparedNativeNew{owner: r, sources: sources, root: root, dependencies: dependencies, rendered: result, manifest: append([]byte(nil), raw...), rootAlias: pin.Alias, operation: operation, contextDigest: contextDigest, operationBase: operationBase, managedFiles: managedFiles}
	if mode == nativeManaged {
		prepared.formatterOwner = prepared
	}
	return prepared, nil
}

type nativeNewImage struct {
	Path, Mode, ContentSHA256 string
}

func nativeNewImages(files map[string][]byte) []nativeNewImage {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	images := make([]nativeNewImage, 0, len(names))
	for _, name := range names {
		images = append(images, nativeNewImage{name, "100644", evidencecas.Digest(files[name])})
	}
	return images
}
func nativeManagedInventory(ctx context.Context, files map[string][]byte) ([]NativeManagedFile, error) {
	folded := map[string]bool{}
	for name := range files {
		if !fs.ValidPath(name) || name == "." || strings.Contains(name, "\\") {
			return nil, errContextSources
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := strings.ToLower(name)
		if folded[key] {
			return nil, errContextSources
		}
		folded[key] = true
		if key == ".tplaiter" || strings.HasPrefix(key, ".tplaiter/") || key == ".tplater" || strings.HasPrefix(key, ".tplater/") {
			return nil, errContextSources
		}
	}
	for key := range folded {
		for parent := path.Dir(key); parent != "."; parent = path.Dir(parent) {
			if folded[parent] {
				return nil, errContextSources
			}
		}
	}
	out := []NativeManagedFile{}
	mentions := 0
	for _, image := range nativeNewImages(files) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data := files[image.Path]
		if !strings.Contains(string(data), "tplater:managed-") {
			continue
		}
		mentions += strings.Count(string(data), "tplater:managed-")
		if !strings.HasSuffix(image.Path, ".go") || mentions > 8192 || len(out) >= 4096 {
			return nil, errContextSources
		}
		markers, err := blockmarkers.Validate(blockmarkers.LanguageGo, image.Path, data)
		if err != nil {
			return nil, err
		}
		if len(markers) == 0 {
			return nil, errContextSources
		}
		out = append(out, NativeManagedFile{image.Path, "100644", image.ContentSHA256, markers})
	}
	if len(out) == 0 {
		return nil, errContextSources
	}
	return out, nil
}

// OperationBase is calculation data with no actions. The formatter owner must
// bind its actual selected actions and tool subject to a separate operation.
func (p *PreparedNativeNew) OperationBase(ctx context.Context, r *trustload.Runtime) (trustverify.OperationInputs, error) {
	if p == nil {
		return trustverify.OperationInputs{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return trustverify.OperationInputs{}, err
	}
	out := p.operationBase
	out.Subjects = append([]trustverify.Provider{}, out.Subjects...)
	out.Actions = []trustverify.ActionMaterial{}
	if err := p.check(ctx, r); err != nil {
		return trustverify.OperationInputs{}, err
	}
	return out, nil
}
func (p *PreparedNativeNew) ManagedFiles(ctx context.Context, r *trustload.Runtime) ([]NativeManagedFile, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	if len(p.managedFiles) == 0 || p.formatterOwner != p {
		return nil, errContextSources
	}
	out := append([]NativeManagedFile{}, p.managedFiles...)
	for i := range out {
		out[i].Markers = append([]blockmarkers.Marker{}, out[i].Markers...)
	}
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	return out, nil
}
func (p *PreparedNativeNew) SourcePins(ctx context.Context, r *trustload.Runtime) ([]deps.PinnedSource, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	out, err := p.sources.Pins(ctx)
	if err != nil {
		return nil, err
	}
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	return out, nil
}
func (p *PreparedNativeNew) SourceGraph(ctx context.Context, r *trustload.Runtime) (deps.SourceGraph, error) {
	if p == nil {
		return deps.SourceGraph{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return deps.SourceGraph{}, err
	}
	out, err := p.sources.SourceGraph(ctx)
	if err != nil {
		return deps.SourceGraph{}, err
	}
	if err := p.check(ctx, r); err != nil {
		return deps.SourceGraph{}, err
	}
	return out, nil
}
func (p *PreparedNativeNew) Catalogs(ctx context.Context, r *trustload.Runtime) ([]exports.SourceCatalog, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	out, err := p.sources.Catalogs(ctx)
	if err != nil {
		return nil, err
	}
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	return out, nil
}

func nativeProviderOrder(p trustverify.Provider) string {
	return p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit
}
func (p *PreparedNativeNew) check(ctx context.Context, r *trustload.Runtime) error {
	if p == nil || ctx == nil || r == nil || p.owner != r || p.sources == nil || p.rendered == nil {
		return errContextSources
	}
	return p.sources.RecheckFor(ctx, r)
}
func (p *PreparedNativeNew) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if p == nil {
		return errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.check(ctx, r)
}
func (p *PreparedNativeNew) RootLock(ctx context.Context, r *trustload.Runtime) (provenance.RootTemplateLock, error) {
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
func (p *PreparedNativeNew) DependencyLock(ctx context.Context, r *trustload.Runtime) (provenance.TemplateLock, error) {
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
func (p *PreparedNativeNew) RootResolution(ctx context.Context, r *trustload.Runtime) (*trustverify.VerifiedResolution, error) {
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
func (p *PreparedNativeNew) OperationInputsSHA256(ctx context.Context, r *trustload.Runtime) (string, error) {
	if p == nil {
		return "", errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return "", err
	}
	return p.operation, nil
}
func (p *PreparedNativeNew) ContextDigest(ctx context.Context, r *trustload.Runtime) (string, error) {
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
func (p *PreparedNativeNew) Rendered(ctx context.Context, r *trustload.Runtime) (*renderref.Result, error) {
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
func (p *PreparedNativeNew) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.formatterSources != nil {
		p.formatterSources.Close()
	}
	p.formatterSources = nil
	p.formatterOwner = nil
	p.owner = nil
	p.sources = nil
	p.rendered = nil
	p.manifest = nil
	p.dependencies.Dependencies = nil
	p.operation = ""
	p.contextDigest = ""
	p.operationBase = trustverify.OperationInputs{}
	p.managedFiles = nil
}

// Validate the existing typed settings carrier using its declared groups and
// existing fresh CLI atom codec. Resolve remains the sole implication engine.
func validateNativeNewValues(tpl *manifest.Template, values settings.Values) error {
	if err := settings.ValidateFreshValues(tpl, values); err != nil {
		return err
	}
	groups := map[string]string{}
	var walk func([]manifest.SettingGroup)
	walk = func(list []manifest.SettingGroup) {
		for _, g := range list {
			groups[g.Group] = g.Type
			for _, o := range g.Options {
				walk(o.Settings)
			}
		}
	}
	walk(tpl.Settings)
	names := []string{}
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		kind, known := groups[name]
		if !known {
			return errContextSources
		}
		value := values[name]
		// Typed string answers are already canonical; the CLI codec trims its
		// command text, while answers files legitimately retain whitespace.
		if kind == manifest.TypeString {
			if _, ok := value.(string); !ok {
				return errContextSources
			}
			continue
		}
		text := ""
		switch v := value.(type) {
		case string:
			text = v
		case bool:
			text = strconv.FormatBool(v)
		case int:
			text = strconv.Itoa(v)
		case []string:
			text = strings.Join(v, ",")
		default:
			return errContextSources
		}
		// The empty select is an existing inactive/unselected zero, not an atom.
		if text == "" && kind == manifest.TypeSelect {
			if _, ok := value.(string); ok {
				continue
			}
		}
		_, parsed, err := settings.ParseSet(tpl, name+"="+text)
		if err != nil {
			return err
		}
		if list, ok := value.([]string); ok {
			typed, ok := parsed.([]string)
			if !ok || !slices.Equal(list, typed) {
				return errContextSources
			}
		} else if !reflect.DeepEqual(parsed, value) {
			return errContextSources
		}
	}
	return nil
}

// FormatterSources borrows the actual admitted source closure for a managed
// calculation. This is neither an execution permit nor publication authority.
func (p *PreparedNativeNew) FormatterSources(ctx context.Context, r *trustload.Runtime) (*contextauth.VerifiedSourceClosure, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.managedFiles) == 0 || p.formatterOwner != p {
		return nil, errContextSources
	}
	if e := p.check(ctx, r); e != nil {
		return nil, e
	}
	if p.formatterSources == nil {
		c, e := p.sources.borrowClosure(ctx, r)
		if e != nil {
			return nil, e
		}
		p.formatterSources = c
	}
	if e := p.formatterSources.RecheckFor(ctx, r); e != nil {
		return nil, e
	}
	return p.formatterSources, nil
}
