package trustload

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// RuntimeOptions are composition inputs supplied by the installed launcher.
// They intentionally contain no reader, path, bundle, or protected-backend
// override: all of those are derived from the authenticated RuntimeInstall.
type RuntimeOptions struct {
	Selection  LaunchSelection
	ProjectKey string
	Clock      bootstrap.Clock
}

// Runtime owns the concrete readers used by one stable trustverify Runtime.
// Callers must close it when command composition is finished.
type Runtime struct {
	installation LaunchSelection
	mu           sync.Mutex
	runtime      *trustverify.Runtime
	store        *Store
	evidence     *evidencecas.FSReader
	objects      *ObjectReader
	scratchRoot  string
	project      ProjectContext
	closed       bool
}

// OpenRuntime constructs the OSS stable runtime from fixed installed inputs.
// Organization construction is deliberately unavailable until the separately
// authenticated protected adapter exists; it never opens an OSS reader as a
// fallback.
func OpenRuntime(ctx context.Context, options RuntimeOptions) (*Runtime, error) {
	if ctx == nil || options.Clock == nil || !token(options.ProjectKey) {
		return nil, ErrAnchorMissing
	}
	loaded, err := Load(ctx, options.Selection)
	if err != nil {
		return nil, err
	}
	if loaded.Install.Profile == bootstrap.ProfileOrganization {
		return nil, ErrProtectedUnavailable
	}
	if loaded.Install.Profile != bootstrap.ProfileOSS || loaded.Install.OSS == nil {
		return nil, ErrConfigInvalid
	}
	project, ok := selectedProjectContext(loaded.Install, options.ProjectKey)
	if !ok {
		return nil, ErrProvenanceUnavailable
	}

	objects, err := NewObjectReader(loaded.Install.ObjectOrigins)
	if err != nil {
		return nil, err
	}
	evidence, err := evidencecas.NewFSReader(loaded.Install.EvidenceRoot)
	if err != nil {
		_ = objects.Close()
		return nil, ErrProvenanceUnavailable
	}
	store, err := OpenReadOnly(ctx, options.Selection)
	if err != nil {
		_ = evidence.Close()
		_ = objects.Close()
		return nil, err
	}
	closeOnFailure := func(cause error) (*Runtime, error) {
		_ = store.Close()
		_ = evidence.Close()
		_ = objects.Close()
		return nil, cause
	}

	readers := runtimeReaders{selection: options.Selection, projectKey: options.ProjectKey, store: store, localEvidence: evidence}
	stable, err := trustverify.NewRuntime(ctx, trustverify.StableOptions{
		Profile:  bootstrap.ProfileOSS,
		Project:  projectReader{readers},
		Policy:   policyReader{readers},
		External: store,
		Bundle:   bundleReader{readers},
		Evidence: readers,
		Objects:  objects,
		Clock:    options.Clock,
	})
	if err != nil {
		return closeOnFailure(err)
	}
	return &Runtime{installation: options.Selection, runtime: stable, store: store, evidence: evidence, objects: objects, scratchRoot: loaded.Install.ScratchRoot, project: project}, nil
}

// TrustRuntime returns the actual stable runtime, whose reader dependencies
// remain owned by this wrapper until Close.
func (r *Runtime) TrustRuntime() *trustverify.Runtime {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	return r.runtime
}

// ScratchRoot is the fixed scratch locator authenticated by the RuntimeInstall
// used to construct this runtime. It is a read-only locator, not a caller
// selectable path or a capability to create, render, or publish anything.
func (r *Runtime) ScratchRoot() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ""
	}
	return r.scratchRoot
}

// ProjectContext returns the selected context captured from the authenticated
// RuntimeInstall used at construction. It is a copied value, not a reader or
// caller-selected path capability.
func (r *Runtime) ProjectContext() ProjectContext {
	if r == nil {
		return ProjectContext{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ProjectContext{}
	}
	return r.project
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	store, evidence, objects := r.store, r.evidence, r.objects
	r.store, r.evidence, r.objects, r.runtime, r.scratchRoot, r.project = nil, nil, nil, nil, "", ProjectContext{}
	r.mu.Unlock()
	var result error
	if store != nil {
		result = errors.Join(result, store.Close())
	}
	if evidence != nil {
		result = errors.Join(result, evidence.Close())
	}
	if objects != nil {
		result = errors.Join(result, objects.Close())
	}
	return result
}

// runtimeReaders deliberately reload the fixed installation for project and
// policy reads. A runtime invocation therefore fails closed after any pin or
// semantic-document drift rather than retaining a stale authority projection.
type runtimeReaders struct {
	selection     LaunchSelection
	projectKey    string
	store         *Store
	localEvidence *evidencecas.FSReader
}

func (r runtimeReaders) Load(ctx context.Context) (trustverify.ProjectContext, error) {
	loaded, err := Load(ctx, r.selection)
	if err != nil {
		return trustverify.ProjectContext{}, err
	}
	project, ok := selectedProjectContext(loaded.Install, r.projectKey)
	if !ok {
		return trustverify.ProjectContext{}, ErrProvenanceUnavailable
	}
	return trustverify.ProjectContext{ProjectID: project.ProjectID, SubmitterPrincipalID: project.SubmitterPrincipalID, MinimumProfile: string(project.MinimumProfile), RootPath: project.RootPath}, nil
}

func selectedProjectContext(install RuntimeInstall, key string) (ProjectContext, bool) {
	for _, project := range install.ProjectContexts {
		if project.Key == key {
			return project, true
		}
	}
	return ProjectContext{}, false
}

func (r runtimeReaders) LoadPolicy(ctx context.Context) (trustverify.ExecutionPolicySnapshot, error) {
	loaded, err := Load(ctx, r.selection)
	if err != nil {
		return trustverify.ExecutionPolicySnapshot{}, err
	}
	policy, err := trustverify.DecodeExecutionPolicy(loaded.PolicyJSON)
	if err != nil {
		return trustverify.ExecutionPolicySnapshot{}, ErrProvenanceUnavailable
	}
	return trustverify.ExecutionPolicySnapshot{PolicyJSON: append([]byte(nil), loaded.PolicyJSON...), ExpectedPolicySHA256: policy.PolicySHA256}, nil
}

func (r runtimeReaders) BundleLoad(ctx context.Context) (bootstrap.Bundle, error) {
	stored, _, err := r.store.currentBundle(ctx)
	if err != nil {
		return bootstrap.Bundle{}, ErrProvenanceUnavailable
	}
	bundle, err := bundleFromStored(ctx, r.store, stored)
	if err != nil {
		return bootstrap.Bundle{}, ErrProvenanceUnavailable
	}
	return bundle, nil
}

func (r runtimeReaders) Read(ctx context.Context, ref string) ([]byte, error) {
	var local, committed []byte
	var localOK, committedOK bool
	if r.localEvidence != nil {
		if raw, err := r.localEvidence.Read(ctx, ref); err == nil {
			local, localOK = raw, true
		}
	}
	if r.store != nil {
		if raw, err := r.store.Read(ctx, ref); err == nil {
			committed, committedOK = raw, true
		}
	}
	if !localOK && !committedOK {
		return nil, ErrProvenanceUnavailable
	}
	if localOK && committedOK && !bytes.Equal(local, committed) {
		return nil, ErrProvenanceUnavailable
	}
	raw := committed
	if localOK {
		raw = local
	}
	if evidencecas.Digest(raw) != ref {
		return nil, ErrProvenanceUnavailable
	}
	return append([]byte(nil), raw...), nil
}

type (
	projectReader struct{ runtimeReaders }
	policyReader  struct{ runtimeReaders }
	bundleReader  struct{ runtimeReaders }
)

func (r projectReader) Load(ctx context.Context) (trustverify.ProjectContext, error) {
	return r.runtimeReaders.Load(ctx)
}

func (r policyReader) Load(ctx context.Context) (trustverify.ExecutionPolicySnapshot, error) {
	return r.LoadPolicy(ctx)
}

func (r bundleReader) Load(ctx context.Context) (bootstrap.Bundle, error) {
	return r.BundleLoad(ctx)
}
