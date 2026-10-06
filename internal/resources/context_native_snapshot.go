package resources

import (
	"context"
	"io/fs"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// PlanContextNativeSnapshotGeneratorImages consumes only an actual recorded snapshot.
// Dependency catalogs remain context; no execution or publication is authorized.
func PlanContextNativeSnapshotGeneratorImages(ctx context.Context, r *trustload.Runtime, prepared *contextsource.PreparedNativeSnapshot) (*ResourceImages, error) {
	if ctx == nil || r == nil || prepared == nil {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	if err := prepared.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	root, err := prepared.RootLock(ctx, r)
	if err != nil {
		return nil, err
	}
	resolution, err := prepared.RootResolution(ctx, r)
	if err != nil {
		return nil, err
	}
	stable := r.TrustRuntime()
	if stable == nil || !resolution.ValidFor(stable, stable.Binding()) {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	snapshot, err := stable.VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	src, err := retainSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	manifest, err := fs.ReadFile(src, "template.manifest.yaml")
	if err != nil || len(manifest) > maxNativeResourceBytes {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	contract, err := contextsource.DecodeNativeContextContractV2(snapshot.ContractBytes(), manifest)
	if err != nil {
		return nil, err
	}
	files, err := nativeGeneratorContent(snapshot, src, contract.ManifestPath)
	if err != nil {
		return nil, err
	}
	images := &ResourceImages{Files: files, Lock: ResourceLockV2{Version: 2, RootLockSHA256: root.RootLockSHA256, TrustProfile: root.TrustProfile, Artifacts: []ResourceArtifact{}}}
	paths := []string{}
	for name := range files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		images.Lock.Artifacts = append(images.Lock.Artifacts, ResourceArtifact{Path: name, SourcePath: strings.TrimPrefix(name, nativeGeneratorPrefix), SHA256: evidencecas.Digest(files[name]), Mode: 0o644, Source: root.Root, Provider: nativeProvider(root.Root)})
	}
	if err = images.Validate(root); err != nil {
		return nil, err
	}
	if err = prepared.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	return images, nil
}
