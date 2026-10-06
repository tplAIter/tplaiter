package sourceadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// PrepareRecordedContextSources admits the complete recorded root/dependency
// pair afresh. Recorded locks are proof transport, never a source grant.
func PrepareRecordedContextSources(ctx context.Context, r *trustload.Runtime, rootRaw, dependencyRaw []byte) (*contextsource.PreparedContextSources, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || len(rootRaw) == 0 || len(rootRaw) > 1<<20 || len(dependencyRaw) == 0 || len(dependencyRaw) > 1<<20 {
		return nil, ErrMismatch
	}
	root, dependencies, input, err := recordedContextInput(rootRaw, dependencyRaw)
	if err != nil {
		return nil, err
	}
	if !root.TrustProfile.Equal(r.TrustRuntime().Binding()) {
		return nil, ErrMismatch
	}
	sources, err := contextsource.PrepareContextSources(ctx, r, input)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			sources.Close()
		}
	}()
	projectedRoot, projectedDependencies, err := contextsource.ProjectContextSourceLocks(ctx, r, sources, root.Renderer.Version)
	if err != nil {
		return nil, err
	}
	expected, err := canonicaljson.Canonical(dependencies)
	if err != nil {
		return nil, err
	}
	actual, err := canonicaljson.Canonical(projectedDependencies)
	if err != nil {
		return nil, err
	}
	if projectedRoot != *root || !bytes.Equal(actual, expected) {
		return nil, ErrMismatch
	}
	if err := sources.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	complete = true
	return sources, nil
}

// RegisteredSourceInput selects the source transport from the freshly
// verified signed root contract. Contract version, rather than optional
// binding files, owns the v1/v2 branch. A valid v1 root keeps the legacy
// selection path; a valid v2 root requires the complete recorded DAG and
// never falls back to a v1 selection when v2 decoding fails.
func RegisteredSourceInput(ctx context.Context, r *trustload.Runtime, rootRaw, dependencyRaw []byte) ([]byte, error) {
	root, dependencies, _, err := recordedContextInput(rootRaw, dependencyRaw)
	if err != nil || r == nil || r.TrustRuntime() == nil || !root.TrustProfile.Equal(r.TrustRuntime().Binding()) || !dependencies.TrustProfile.Equal(r.TrustRuntime().Binding()) {
		return nil, ErrMismatch
	}
	refs := trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: root.Root.StatementCAS, SignatureCAS: root.Root.SignatureCAS, KeyFingerprint: root.Root.KeyFingerprint, CheckpointCAS: root.Root.CheckpointCAS, InclusionProofCAS: root.Root.InclusionProofCAS}
	resolution, err := r.TrustRuntime().VerifySubject(ctx, root.Root.Subject(), refs)
	if err != nil {
		return nil, err
	}
	snapshot, err := r.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	manifest, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return nil, ErrMismatch
	}
	contract, ok := snapshot.Blob("template.contract.json")
	if !ok {
		return nil, ErrMismatch
	}
	if _, err := contextsource.DecodeNativeContextContractV2(contract, manifest); err == nil {
		return RecordedContextSourceInput(ctx, r, rootRaw, dependencyRaw)
	}
	if _, err := operationtrust.DecodeNativeContract(contract, manifest); err != nil {
		return nil, ErrMismatch
	}
	selection := operationtrust.SourceSelection{
		APIVersion:   operationtrust.SourceSelectionAPIVersion,
		Subject:      operationtrust.SelectionSubject{Origin: root.Root.Origin, TemplatePath: root.Root.TemplatePath, RequestedRef: root.Root.RequestedRef, Commit: root.Root.Commit, TreeSHA256: root.Root.TreeSHA256, ContractSHA256: root.Root.ContractSHA256},
		Evidence:     operationtrust.SelectionEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: root.Root.StatementCAS, SignatureCAS: root.Root.SignatureCAS, KeyFingerprint: root.Root.KeyFingerprint, CheckpointCAS: root.Root.CheckpointCAS, InclusionProofCAS: root.Root.InclusionProofCAS},
		Dependencies: []string{},
	}
	return json.Marshal(selection)
}

// RecordedContextSourceInput returns detached transport after actual admission.
// Every subsequent consumer must independently prepare it with its own Runtime.
func RecordedContextSourceInput(ctx context.Context, r *trustload.Runtime, rootRaw, dependencyRaw []byte) ([]byte, error) {
	sources, err := PrepareRecordedContextSources(ctx, r, rootRaw, dependencyRaw)
	if err != nil {
		return nil, err
	}
	defer sources.Close()
	_, _, input, err := recordedContextInput(rootRaw, dependencyRaw)
	return input, err
}

func recordedContextInput(rootRaw, dependencyRaw []byte) (*provenance.RootTemplateLock, *provenance.TemplateLock, []byte, error) {
	root, err := provenance.DecodeRootTemplateLock(rootRaw)
	if err != nil {
		return nil, nil, nil, err
	}
	dependencies, err := provenance.DecodeTemplateLock(dependencyRaw)
	if err != nil || provenance.ValidateLockPair(*root, *dependencies) != nil {
		return nil, nil, nil, ErrMismatch
	}
	proof := func(s provenance.RootSubject) contextsource.ContextSourceProof {
		return contextsource.ContextSourceProof{Subject: operationtrust.SelectionSubject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}, Evidence: operationtrust.SelectionEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: s.StatementCAS, SignatureCAS: s.SignatureCAS, KeyFingerprint: s.KeyFingerprint, CheckpointCAS: s.CheckpointCAS, InclusionProofCAS: s.InclusionProofCAS}}
	}
	selection := contextsource.ContextSourceSelection{APIVersion: contextsource.ContextSourceSelectionAPIVersion, Root: proof(root.Root), Sources: []contextsource.ContextSourceProof{}}
	for _, dependency := range dependencies.Dependencies {
		selection.Sources = append(selection.Sources, proof(provenance.RootSubject(dependency)))
	}
	sort.Slice(selection.Sources, func(i, j int) bool {
		a, b := selection.Sources[i].Subject, selection.Sources[j].Subject
		return a.Origin+"\x00"+a.TemplatePath+"\x00"+a.Commit < b.Origin+"\x00"+b.TemplatePath+"\x00"+b.Commit
	})
	input, err := canonicaljson.Canonical(selection)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := contextsource.DecodeSourceSelectionV2(input); err != nil {
		return nil, nil, nil, err
	}
	return root, dependencies, input, nil
}
