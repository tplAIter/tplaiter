package gen

import (
	"io/fs"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const nativeResourceLockPath = ".tplaiter/resources.lock.json"

// Wire mirrors resources.ResourceLockV2: resources currently imports gen, so
// the reader cannot import its enrollment owner without creating a cycle.
type nativeResourceArtifact struct {
	Path       string                 `json:"path"`
	SourcePath string                 `json:"sourcePath"`
	SHA256     string                 `json:"sha256"`
	Mode       uint32                 `json:"mode"`
	Source     provenance.RootSubject `json:"source"`
	Provider   trustverify.Provider   `json:"provider"`
}
type nativeResourceLock struct {
	Version        int                      `json:"version"`
	RootLockSHA256 string                   `json:"rootLockSHA256"`
	TrustProfile   bootstrap.ProfileBinding `json:"trustProfile"`
	Artifacts      []nativeResourceArtifact `json:"artifacts"`
}
type nativeResourceImages struct {
	Files map[string][]byte
	Lock  nativeResourceLock
}

func nativeResources(runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, root provenance.RootTemplateLock) (*nativeResourceImages, error) {
	if runtime == nil || resolution == nil || !resolution.ValidFor(runtime, runtime.Binding()) || root.Validate() != nil || !root.TrustProfile.Equal(runtime.Binding()) {
		return nil, ErrNativeOwnership
	}
	e := resolution.Evidence()
	source := provenance.RootSubjectFromTrust(resolution.Subject(), bootstrap.PublisherEvidence{StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint}, e.CheckpointCAS, e.InclusionProofCAS)
	if source != root.Root {
		return nil, ErrNativeOwnership
	}
	snapshot, err := runtime.VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	raw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return nil, ErrNativeOwnership
	}
	if _, err := operationtrust.DecodeNativeContract(snapshot.ContractBytes(), raw); err != nil {
		return nil, err
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil || tpl.Validate() != nil {
		return nil, ErrNativeOwnership
	}
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || len(tpl.Commands) != 0 || tpl.AIConfig.Path != "" {
		return nil, ErrExecutionUnavailable
	}
	refs := map[string]bool{}
	add := func(ref string) error {
		if !fs.ValidPath(ref) || ref == "." || strings.ContainsAny(ref, "\\\n\x00:") {
			return ErrNativeOwnership
		}
		refs[ref] = true
		return nil
	}
	for _, g := range tpl.Generators {
		if g.Snippet != "" {
			if err := add(g.Snippet); err != nil {
				return nil, err
			}
		}
		for _, t := range g.Targets {
			if err := add(t.Snippet); err != nil {
				return nil, err
			}
		}
		for _, a := range g.Anchors {
			if err := add(a.Insert); err != nil {
				return nil, err
			}
		}
	}
	if len(refs) > 256 {
		return nil, ErrNativeOwnership
	}
	paths := make([]string, 0, len(refs))
	for ref := range refs {
		paths = append(paths, ref)
	}
	sort.Strings(paths)
	out := &nativeResourceImages{Files: map[string][]byte{}, Lock: nativeResourceLock{Version: 2, RootLockSHA256: root.RootLockSHA256, TrustProfile: root.TrustProfile, Artifacts: []nativeResourceArtifact{}}}
	entries := map[string]trustverify.SourceEntry{}
	for _, entry := range snapshot.Entries() {
		entries[entry.Path] = entry
	}
	total := 0
	for _, ref := range paths {
		raw, ok := snapshot.Blob(ref)
		entry := entries[ref]
		if !ok || entry.Kind != "file" || entry.Mode != "100644" || entry.ContentSHA256 != evidencecas.Digest(raw) || len(raw) > 1<<20 {
			return nil, ErrNativeOwnership
		}
		total += len(raw)
		if total > 16<<20 {
			return nil, ErrNativeOwnership
		}
		name := GeneratorsRelPath + "/" + ref
		out.Files[name] = raw
		out.Lock.Artifacts = append(out.Lock.Artifacts, nativeResourceArtifact{Path: name, SourcePath: ref, SHA256: evidencecas.Digest(raw), Mode: 0o644, Source: source, Provider: trustverify.Provider{Origin: source.Origin, TemplatePath: source.TemplatePath, Commit: source.Commit, TreeSHA256: source.TreeSHA256, ContractSHA256: source.ContractSHA256}})
	}
	return out, nil
}
