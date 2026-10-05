package operationtrust

import (
	"context"
	"errors"
	"io/fs"

	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// PrepareSnapshotInput is read-only recorded rendering input, never a New grant.
type (
	PrepareSnapshotInput struct {
		SourceInput     []byte
		Render          renderref.Input
		RendererVersion string
	}
	// PreparedSnapshot is an opaque read-only source/baseline calculation. It has no
	// decoder, New conversion, transaction or execution method.
	PreparedSnapshot struct {
		root       provenance.RootTemplateLock
		deps       provenance.TemplateLock
		rendered   *renderref.Result
		operation  string
		runtime    *trustverify.Runtime
		resolution *trustverify.VerifiedResolution
	}
)

func (p *PreparedSnapshot) RootLock() provenance.RootTemplateLock {
	if p == nil {
		return provenance.RootTemplateLock{}
	}
	return p.root
}

func (p *PreparedSnapshot) DependencyLock() provenance.TemplateLock {
	if p == nil {
		return provenance.TemplateLock{}
	}
	return p.deps
}

func (p *PreparedSnapshot) Rendered() *renderref.Result {
	if p == nil {
		return nil
	}
	out := cloneResult(p.rendered)
	if out != nil {
		out.Resolved.Values = p.rendered.Resolved.Values.Clone()
		out.Resolved.ActiveValues = p.rendered.Resolved.ActiveValues.Clone()
		out.Resolved.Report.Implied = append([]settings.ImpliedValue(nil), p.rendered.Resolved.Report.Implied...)
		out.Resolved.Report.Warnings = append([]string(nil), p.rendered.Resolved.Report.Warnings...)
	}
	return out
}

func PrepareSnapshot(ctx context.Context, runtime *trustload.Runtime, in PrepareSnapshotInput) (*PreparedSnapshot, error) {
	if ctx == nil || runtime == nil || !rendererToken.MatchString(in.RendererVersion) {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	stable := runtime.TrustRuntime()
	project := runtime.ProjectContext()
	if stable == nil || runtime.ScratchRoot() == "" || project.ProjectID == "" || project.RootPath == "" {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	selection, err := DecodeSourceSelection(in.SourceInput)
	if err != nil {
		return nil, err
	}
	resolution, err := stable.VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	src, err := SnapshotFS(stable, resolution)
	if err != nil {
		return nil, err
	}
	contract, err := fs.ReadFile(src, "template.contract.json")
	if err != nil {
		return nil, ErrSourceAdapterUnsupported
	}
	manifest, err := fs.ReadFile(src, "template.manifest.yaml")
	if err != nil {
		return nil, ErrSourceAdapterUnsupported
	}
	if _, err = requireNativeContract(contract, manifest); err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(src)
	if err != nil || unsupportedTemplateActions(tpl, "new") {
		return nil, ErrSourceAdapterUnsupported
	}
	result, err := renderref.RenderRecordedInScratch(ctx, src, in.Render, runtime.ScratchRoot(), in.Render.Values)
	if err != nil {
		return nil, err
	}
	root, deps, err := projectNativeLockPair(stable, resolution, in.RendererVersion)
	if err != nil {
		return nil, err
	}
	operation, err := emptyOperation(stable, resolution, project.ProjectID, "new", in.Render.Values)
	if err != nil {
		return nil, err
	}
	// Freshly re-verify proof locators and full binding before handing out even
	// an in-memory preview. The retained result is discarded on drift.
	fresh, err := stable.VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil || fresh.Subject() != resolution.Subject() || fresh.Evidence() != resolution.Evidence() || !fresh.ValidFor(stable, stable.Binding()) {
		return nil, errors.New("TRUST_APPROVAL_MISMATCH")
	}
	return &PreparedSnapshot{root: root, deps: deps, rendered: cloneResult(result), operation: operation, runtime: stable, resolution: resolution}, nil
}

// ValidFor rechecks source identity without granting a lifecycle capability.
func (p *PreparedSnapshot) ValidFor(runtime *trustverify.Runtime) bool {
	return p != nil && runtime != nil && p.runtime == runtime && p.resolution.ValidFor(runtime, runtime.Binding()) && provenance.ValidateLockPair(p.root, p.deps) == nil && p.root.TrustProfile.Equal(runtime.Binding()) && p.operation != ""
}
