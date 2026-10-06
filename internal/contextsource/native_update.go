package contextsource

import (
	"context"
	"sort"
	"sync"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type NativeUpdateInput struct {
	SourceRender, TargetRender                 renderref.Input
	SourceRecordedValues, TargetRecordedValues settings.Values
	RendererVersion, PreimageSHA256            string
}

// PreparedNativeUpdate retains two independently admitted recorded closures.
// OperationBase contains no actions and grants no mutation or execution.
type PreparedNativeUpdate struct {
	mu              sync.Mutex
	owner           *trustload.Runtime
	self            *PreparedNativeUpdate
	source, target  *PreparedNativeSnapshot
	operation       trustverify.OperationInputs
	operationDigest string
}

func PrepareNativeUpdate(ctx context.Context, r *trustload.Runtime, sourceSources, targetSources *PreparedContextSources, in NativeUpdateInput) (*PreparedNativeUpdate, error) {
	if ctx == nil || r == nil || sourceSources == nil || targetSources == nil || !contextDigestRE.MatchString(in.PreimageSHA256) {
		return nil, errContextSources
	}
	if sourceSources == targetSources {
		return nil, errContextSources
	}
	source, err := PrepareRecordedNativeSnapshot(ctx, r, sourceSources, RecordedNativeSnapshotInput{Render: in.SourceRender, RecordedValues: in.SourceRecordedValues, RendererVersion: in.RendererVersion})
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			source.Close()
		}
	}()
	target, err := PrepareRecordedNativeSnapshot(ctx, r, targetSources, RecordedNativeSnapshotInput{Render: in.TargetRender, RecordedValues: in.TargetRecordedValues, RendererVersion: in.RendererVersion})
	if err != nil {
		return nil, err
	}
	defer func() {
		if !complete {
			target.Close()
		}
	}()
	subjects := map[string]trustverify.Provider{}
	var targetValues settings.Values
	for _, snapshot := range []*PreparedNativeSnapshot{source, target} {
		providers, values, err := snapshot.nativeUpdateFacts(ctx, r)
		if err != nil {
			return nil, err
		}
		if snapshot == target {
			targetValues = values
		}
		for _, provider := range providers {
			key := nativeProviderOrder(provider)
			if old, ok := subjects[key]; ok && old != provider {
				return nil, errContextSources
			}
			subjects[key] = provider
		}
	}
	providers := []trustverify.Provider{}
	for _, provider := range subjects {
		providers = append(providers, provider)
	}
	sort.Slice(providers, func(i, j int) bool { return nativeProviderOrder(providers[i]) < nativeProviderOrder(providers[j]) })
	answers, err := recordedAnswersDigest(targetValues)
	if err != nil {
		return nil, err
	}
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	if err != nil {
		return nil, err
	}
	operation := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: binding, ProjectID: r.ProjectContext().ProjectID, Scope: "update", PreimageSHA256: in.PreimageSHA256, AnswersSHA256: answers, Subjects: providers, Actions: []trustverify.ActionMaterial{}}
	digest, err := trustverify.ComputeOperationInputsSHA256(operation)
	if err != nil {
		return nil, err
	}
	p := &PreparedNativeUpdate{owner: r, source: source, target: target, operation: operation, operationDigest: digest}
	p.self = p
	if err := p.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	complete = true
	return p, nil
}

func (p *PreparedNativeUpdate) check(ctx context.Context, r *trustload.Runtime) error {
	if p == nil || ctx == nil || r == nil || p.self != p || p.owner != r || p.source == nil || p.target == nil || p.operationDigest == "" {
		return errContextSources
	}
	if err := p.source.RecheckFor(ctx, r); err != nil {
		return err
	}
	return p.target.RecheckFor(ctx, r)
}

func (p *PreparedNativeUpdate) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if p == nil {
		return errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.check(ctx, r)
}

func (p *PreparedNativeUpdate) SourceSnapshot(ctx context.Context, r *trustload.Runtime) (*PreparedNativeSnapshot, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	return p.source, nil
}

func (p *PreparedNativeUpdate) TargetSnapshot(ctx context.Context, r *trustload.Runtime) (*PreparedNativeSnapshot, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	return p.target, nil
}

func (p *PreparedNativeUpdate) OperationBase(ctx context.Context, r *trustload.Runtime) (trustverify.OperationInputs, error) {
	if p == nil {
		return trustverify.OperationInputs{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return trustverify.OperationInputs{}, err
	}
	out := p.operation
	out.Subjects = append([]trustverify.Provider{}, out.Subjects...)
	out.Actions = []trustverify.ActionMaterial{}
	return out, nil
}

func (p *PreparedNativeUpdate) OperationInputsSHA256(ctx context.Context, r *trustload.Runtime) (string, error) {
	if p == nil {
		return "", errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, r); err != nil {
		return "", err
	}
	return p.operationDigest, nil
}

func (p *PreparedNativeUpdate) SourceRootLock(ctx context.Context, r *trustload.Runtime) (provenance.RootTemplateLock, error) {
	snapshot, err := p.SourceSnapshot(ctx, r)
	if err != nil {
		return provenance.RootTemplateLock{}, err
	}
	return snapshot.RootLock(ctx, r)
}

func (p *PreparedNativeUpdate) TargetRootLock(ctx context.Context, r *trustload.Runtime) (provenance.RootTemplateLock, error) {
	snapshot, err := p.TargetSnapshot(ctx, r)
	if err != nil {
		return provenance.RootTemplateLock{}, err
	}
	return snapshot.RootLock(ctx, r)
}

func (p *PreparedNativeUpdate) SourceDependencyLock(ctx context.Context, r *trustload.Runtime) (provenance.TemplateLock, error) {
	snapshot, err := p.SourceSnapshot(ctx, r)
	if err != nil {
		return provenance.TemplateLock{}, err
	}
	return snapshot.DependencyLock(ctx, r)
}

func (p *PreparedNativeUpdate) TargetDependencyLock(ctx context.Context, r *trustload.Runtime) (provenance.TemplateLock, error) {
	snapshot, err := p.TargetSnapshot(ctx, r)
	if err != nil {
		return provenance.TemplateLock{}, err
	}
	return snapshot.DependencyLock(ctx, r)
}

func (p *PreparedNativeUpdate) Rendered(ctx context.Context, r *trustload.Runtime) (*renderref.Result, error) {
	snapshot, err := p.TargetSnapshot(ctx, r)
	if err != nil {
		return nil, err
	}
	return snapshot.Rendered(ctx, r)
}

func (p *PreparedNativeUpdate) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.source != nil {
		p.source.Close()
	}
	if p.target != nil {
		p.target.Close()
	}
	p.owner = nil
	p.self = nil
	p.source = nil
	p.target = nil
	p.operation = trustverify.OperationInputs{}
	p.operationDigest = ""
}
