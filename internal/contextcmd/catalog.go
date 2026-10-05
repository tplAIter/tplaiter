// Package contextcmd binds C03 retrieval to installed project identity and
// genuinely signed immutable source snapshots. Caller JSON is never admitted.
package contextcmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type admitted struct {
	raw        []byte
	catalog    knowledge.Catalog
	resolution *trustverify.VerifiedResolution
	rootBytes  []byte
	origin     string
}

func admit(ctx context.Context, runtime *trustload.Runtime, catalogPath string) (admitted, error) {
	var out admitted
	raw, err := readRootLock(runtime.ProjectContext().RootPath)
	if err != nil {
		return out, err
	}
	lock, err := provenance.DecodeRootTemplateLock(raw)
	if err != nil {
		return out, err
	}
	dependencyBytes, err := readProjectLedger(runtime.ProjectContext().RootPath, "template.lock.json")
	if err != nil {
		return out, err
	}
	dependencies, err := provenance.DecodeTemplateLock(dependencyBytes)
	if err != nil {
		return out, err
	}
	if err = provenance.ValidateLockPair(*lock, *dependencies); err != nil {
		return out, err
	}
	if len(dependencies.Dependencies) != 0 {
		// Root-only consumer coverage must not invent a dependency-free closure
		// for an installed project whose external providers are not yet admitted.
		return out, fail(SourceUnavailable)
	}
	stable := runtime.TrustRuntime()
	if stable == nil || !lock.TrustProfile.Equal(stable.Binding()) {
		return out, fail(Stale)
	}
	s := lock.Root
	proof, err := stable.VerifySubject(ctx, s.Subject(), trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: s.StatementCAS, SignatureCAS: s.SignatureCAS, KeyFingerprint: s.KeyFingerprint, CheckpointCAS: s.CheckpointCAS, InclusionProofCAS: s.InclusionProofCAS})
	if err != nil {
		return out, err
	}
	snap, err := stable.VerifiedSnapshot(proof)
	if err != nil {
		return out, err
	}
	if catalogPath != "" {
		if !fs.ValidPath(catalogPath) || catalogPath == "." || len(catalogPath) > 256 || strings.ContainsAny(catalogPath, "\\\x00\r\n") {
			return out, fail(Invalid)
		}
		bytes, ok := snap.Blob(catalogPath)
		if !ok {
			return out, fail(Missing)
		}
		regular := false
		for _, e := range snap.Entries() {
			if e.Path == catalogPath {
				regular = e.Kind == "file" && e.Mode == "100644" && e.ContentSHA256 == evidencecas.Digest(bytes)
			}
		}
		if !regular {
			return out, fail(Stale)
		}
		out.catalog, err = knowledge.Decode(bytes)
		if err != nil {
			return out, err
		}
		// External providers are not guessed or bound to the root by label. Their
		// concrete C02 consumer enrollment is a separate, still pending contract.
		if len(out.catalog.Sources) != 1 || out.catalog.Sources[0].Anchor != s {
			return out, fail(SourceUnavailable)
		}
		out.raw = append([]byte(nil), bytes...)
		out.origin = "signed-embedded:" + catalogPath
	} else {
		out.catalog, err = nativeCatalog(snap, s, lock.Policy.PolicySHA256)
		if err != nil {
			return out, err
		}
		out.raw, err = json.Marshal(out.catalog)
		if err != nil {
			return out, err
		}
		out.origin = "signed-native-resource-metadata"
	}
	// Authenticate every item before exposing even metadata obtained from an
	// embedded catalog. Merely residing inside signed bytes does not bind anchors.
	if _, err = knowledge.ObserveSource(ctx, stable, proof, out.raw, out.catalog.Sources[0].ID); err != nil {
		return admitted{}, err
	}
	out.resolution, out.rootBytes = proof, raw
	return out, nil
}

func nativeCatalog(snap *trustverify.SourceSnapshot, s provenance.RootSubject, policy string) (knowledge.Catalog, error) {
	d := knowledge.Catalog{APIVersion: knowledge.APIVersion, Kind: "KnowledgeCatalog", ID: "installed:catalog:native", Version: "1.0.0", Sources: []knowledge.Source{}, Items: []knowledge.Item{}, Edges: []knowledge.Edge{}}
	algorithm := "sha1"
	if len(s.Commit) == 64 {
		algorithm = "sha256"
	}
	d.Sources = append(d.Sources, knowledge.Source{ID: "installed:source:root", Anchor: s, Pin: deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: "root", ProviderID: "installed", Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, CommitAlgorithm: algorithm, Commit: s.Commit, TreeDigest: s.TreeSHA256, ContentDigest: s.TreeSHA256, ContractDigest: s.ContractSHA256, EvidenceDigest: s.StatementCAS, Parameters: []deps.Parameter{}, Dependencies: []string{}}})
	raw, ok := snap.Blob("template.manifest.yaml")
	if !ok {
		return d, fail(Missing)
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		return d, err
	}
	if err = tpl.Validate(); err != nil {
		return d, err
	}
	// These are inert declared source resources, not fabricated ownership or
	// execution proofs. Generator snippets are read without running the generator.
	paths := map[string]bool{"template.manifest.yaml": true, "template.contract.json": true}
	for _, g := range tpl.Generators {
		if g.Snippet != "" {
			paths[g.Snippet] = true
		}
		for _, t := range g.Targets {
			paths[t.Snippet] = true
		}
		for _, a := range g.Anchors {
			paths[a.Insert] = true
		}
	}
	if len(paths) > 512 {
		return d, fail(Budget)
	}
	entries := map[string]trustverify.SourceEntry{}
	for _, e := range snap.Entries() {
		entries[e.Path] = e
	}
	ordered := make([]string, 0, len(paths))
	for p := range paths {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)
	for _, p := range ordered {
		e, ok := entries[p]
		if !ok {
			return d, fail(Missing)
		}
		if e.Kind != "file" || (e.Mode != "100644" && e.Mode != "100755") {
			return d, fail(Stale)
		}
		h := sha256.Sum256([]byte(p))
		id := "installed:resource:r-" + hex.EncodeToString(h[:])[:60]
		d.Items = append(d.Items, knowledge.Item{ID: id, Kind: "resource", Version: "1.0.0", SourceID: d.Sources[0].ID, SourcePath: p, ContentSHA256: e.ContentSHA256, Mode: e.Mode, Ownership: knowledge.Ownership{OwnerID: "installed:owner:declared", Version: "1.0.0", PolicySHA256: policy}, Executor: knowledge.Executor{ID: "installed:executor:metadata-reader", Version: "1.0.0", InputContractSHA256: s.ContractSHA256, OutputContractSHA256: s.ContractSHA256}, UpdateTriggers: []string{"source", "content", "contract"}, Requires: []string{}, Produces: []string{}, Quality: []knowledge.Quality{}, Inputs: knowledge.InputContract{APIVersion: knowledge.InputsAPIVersion, ContextFloor: []string{}, Definitions: []knowledge.InputDefinition{}}})
	}
	// Native resource interpretation requires its signed manifest and contract.
	// Their complete records/pins remain in the C03 floor even if a page only
	// selects a snippet. The manifest retains native parameter/default metadata;
	// this frontend does not reinterpret it as a workflow execution contract.
	var nativeFloor []string
	for _, item := range d.Items {
		if item.SourcePath == "template.manifest.yaml" || item.SourcePath == "template.contract.json" {
			nativeFloor = append(nativeFloor, item.ID)
		}
	}
	for n := range d.Items {
		if d.Items[n].SourcePath != "template.manifest.yaml" && d.Items[n].SourcePath != "template.contract.json" {
			d.Items[n].Inputs.ContextFloor = append([]string(nil), nativeFloor...)
		}
	}
	if err = knowledge.Validate(d); err != nil {
		return d, err
	}
	return d, nil
}

// Read only the installed root's sealed source locator through no-follow,
// bounded handles. The runtime authenticates the subject; this self-hash alone
// is never an authority grant. The read session rechecks committed state.
func readRootLock(root string) ([]byte, error) {
	return readProjectLedger(root, "root-template.lock.json")
}

func readProjectLedger(root, leaf string) ([]byte, error) {
	held, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer held.Close()
	st, err := held.Lstat(".tplaiter")
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fail(Stale)
	}
	rel := filepath.Join(".tplaiter", leaf)
	before, err := held.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fail(Stale)
	}
	f, err := held.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) {
		return nil, fail(Stale)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, fail(Budget)
	}
	after, err := held.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, fail(Stale)
	}
	return raw, nil
}
