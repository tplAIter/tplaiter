package ossinstall

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const contextSelectionDirectory = "config/context-source-selections"

var errContextEnrollment = errors.New("ossinstall: invalid context source enrollment closure")

type contextEnrollmentSource struct {
	subject  operationtrust.SelectionSubject
	contract contextsource.NativeContextContract
	binding  contextsource.ContextSourceBindings
	pin      deps.PinnedSource
	v2       bool
	inert    bool
}

// These records are derived from the package's immutable Git bytes. They are
// producer data, not admitted runtime resolutions or execution capabilities.
func contextEnrollmentSources(ctx context.Context, packages []SourcePackage) ([]contextEnrollmentSource, error) {
	records := make([]contextEnrollmentSource, len(packages))
	snapshots := make([]*trustverify.SourceSnapshot, len(packages))
	hasV2 := false
	for i, p := range packages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		statement, err := bootstrap.DecodePublisherStatement(p.Statement)
		if err != nil {
			return nil, err
		}
		reader := &packageObjects{origin: statement.Subject.Origin, objects: map[string]trustverify.GitObject{}, used: map[string]bool{}}
		for id, raw := range p.Objects {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			o, err := rawObject(id, raw)
			if err != nil {
				return nil, err
			}
			reader.objects[id] = o
		}
		snapshot, err := trustverify.VerifySource(ctx, reader, statementSubject(statement))
		if err != nil {
			return nil, err
		}
		if len(reader.used) != len(p.Objects) {
			return nil, errContextEnrollment
		}
		kind, err := validateSourceSnapshot(snapshot)
		if err != nil {
			return nil, err
		}
		if kind == sourceInertContent {
			// Keep generic authenticated selection/evidence, with no native binding.
			records[i] = contextEnrollmentSource{subject: operationtrust.SelectionSubject{Origin: statement.Subject.Origin, TemplatePath: statement.Subject.TemplatePath, RequestedRef: statement.Subject.Commit, Commit: statement.Subject.Commit, TreeSHA256: statement.Subject.TreeSHA256, ContractSHA256: statement.Subject.ContractSHA256}, inert: true}
			snapshots[i] = snapshot
			continue
		}
		manifest, ok := snapshot.Blob("template.manifest.yaml")
		if !ok {
			return nil, errContextEnrollment
		}
		c, err := contextsource.DecodeNativeContextContractV2(snapshot.ContractBytes(), manifest)
		v2 := err == nil
		if !v2 {
			old, err := operationtrust.DecodeNativeContract(snapshot.ContractBytes(), manifest)
			if err != nil {
				return nil, err
			}
			c = contextsource.NativeContextContract{APIVersion: old.APIVersion, Kind: old.Kind, ManifestPath: old.ManifestPath, ManifestSHA256: old.ManifestSHA256, Dependencies: []contextsource.ContextDependency{}}
		}
		subject := operationtrust.SelectionSubject{Origin: statement.Subject.Origin, TemplatePath: statement.Subject.TemplatePath, RequestedRef: statement.Subject.Commit, Commit: statement.Subject.Commit, TreeSHA256: statement.Subject.TreeSHA256, ContractSHA256: statement.Subject.ContractSHA256}
		r := contextEnrollmentSource{subject: subject, contract: c, v2: v2}
		records[i] = r
		snapshots[i] = snapshot
		hasV2 = hasV2 || v2
	}
	// Ordinary v1 enrollment never consumes the separate v2 binding path.
	if !hasV2 {
		return records, nil
	}
	for i, snapshot := range snapshots {
		r := records[i]
		if r.inert {
			continue
		}
		c, subject, v2, p := r.contract, r.subject, r.v2, packages[i]
		raw, present := snapshot.Blob(contextsource.ContextSourceBindingsPath)
		if !present {
			if v2 {
				return nil, errContextEnrollment
			}
			records[i] = r
			continue
		}
		binding, err := contextsource.DecodeContextSourceBindingsV2(raw)
		r.binding = binding
		if err != nil {
			return nil, err
		}
		if len(c.Dependencies) != len(r.binding.Dependencies) {
			return nil, errContextEnrollment
		}
		content, err := deps.SnapshotContentDigest(snapshot.Entries())
		if err != nil {
			return nil, err
		}
		algorithm := "sha1"
		if len(subject.Commit) == 64 {
			algorithm = "sha256"
		}
		adjacency := []string{}
		for j, d := range c.Dependencies {
			if d.Alias != r.binding.Dependencies[j].Alias {
				return nil, errContextEnrollment
			}
			adjacency = append(adjacency, d.Alias)
		}
		r.pin = deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: r.binding.Source.Alias, ProviderID: r.binding.Source.ProviderID, Origin: subject.Origin, TemplatePath: subject.TemplatePath, RequestedRef: subject.RequestedRef, CommitAlgorithm: algorithm, Commit: subject.Commit, TreeDigest: subject.TreeSHA256, ContentDigest: content, ContractDigest: subject.ContractSHA256, EvidenceDigest: evidencecas.Digest(p.Statement), Parameters: r.binding.Source.Parameters, Dependencies: adjacency}
		records[i] = r
	}
	return records, nil
}

func contextSelectionName(s operationtrust.SelectionSubject) (string, error) {
	digest, err := bootstrap.DomainDigest(contextsource.ContextSourceSelectionAPIVersion, s)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(digest, "sha256:") + ".json", nil
}

// Complete closure is determined by signed source declarations. Input proofs
// carry evidence locators only and cannot supply a different graph or binding.
func contextEnrollmentDocuments(ctx context.Context, records []contextEnrollmentSource, selections []operationtrust.SourceSelection) ([]operationtrust.SourceSelection, map[string][]byte, error) {
	if len(records) != len(selections) {
		return nil, nil, errContextEnrollment
	}
	legacy := []operationtrust.SourceSelection{}
	documents := map[string][]byte{}
	byAlias := map[string]int{}
	hasV2 := false
	for i, r := range records {
		if r.subject != selections[i].Subject {
			return nil, nil, errContextEnrollment
		}
		if !r.v2 {
			legacy = append(legacy, selections[i])
		} else {
			hasV2 = true
		}
		if r.pin.Alias != "" {
			if _, ok := byAlias[r.pin.Alias]; ok {
				return nil, nil, errContextEnrollment
			}
			byAlias[r.pin.Alias] = i
		}
	}
	if !hasV2 {
		return legacy, documents, nil
	}
	for root, r := range records {
		if !r.v2 {
			continue
		}
		reached := map[int]bool{}
		active := map[int]bool{}
		var visit func(int) error
		visit = func(i int) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if active[i] {
				return errContextEnrollment
			}
			if reached[i] {
				return nil
			}
			active[i] = true
			current := records[i]
			if current.pin.Alias == "" {
				return errContextEnrollment
			}
			for j, d := range current.contract.Dependencies {
				k, ok := byAlias[d.Alias]
				if !ok {
					return errContextEnrollment
				}
				target := records[k].pin
				association := current.binding.Dependencies[j]
				a, err := contextEnrollmentParameters(association.Parameters)
				if err != nil {
					return err
				}
				b, err := contextEnrollmentParameters(target.Parameters)
				if err != nil {
					return err
				}
				if d.Origin != target.Origin || d.TemplatePath != target.TemplatePath || d.CommitAlgorithm != target.CommitAlgorithm || d.Commit != target.Commit || d.TreeDigest != target.TreeDigest || d.ContractDigest != target.ContractDigest || association.ProviderID != target.ProviderID || !bytes.Equal(a, b) {
					return errContextEnrollment
				}
				if err := visit(k); err != nil {
					return err
				}
			}
			delete(active, i)
			reached[i] = true
			return nil
		}
		if err := visit(root); err != nil {
			return nil, nil, err
		}
		order := []int{}
		for i := range reached {
			if i != root {
				order = append(order, i)
			}
		}
		sort.Slice(order, func(i, j int) bool { return records[order[i]].pin.Alias < records[order[j]].pin.Alias })
		pins := []deps.PinnedSource{}
		input := contextsource.ContextSourceSelection{APIVersion: contextsource.ContextSourceSelectionAPIVersion, Root: contextsource.ContextSourceProof{Subject: selections[root].Subject, Evidence: selections[root].Evidence}, Sources: []contextsource.ContextSourceProof{}}
		for _, i := range order {
			pins = append(pins, records[i].pin)
			input.Sources = append(input.Sources, contextsource.ContextSourceProof{Subject: selections[i].Subject, Evidence: selections[i].Evidence})
		}
		if _, err := deps.BuildSourceGraphWithContext(deps.SourceGraphInput{Root: &r.pin, DependencyClosure: &deps.SourceDependencyClosure{Pins: pins}}); err != nil {
			return nil, nil, err
		}
		raw, err := marshal(input)
		if err != nil {
			return nil, nil, err
		}
		if _, err = contextsource.DecodeSourceSelectionV2(raw); err != nil {
			return nil, nil, err
		}
		name, err := contextSelectionName(r.subject)
		if err != nil {
			return nil, nil, err
		}
		documents[name] = raw
	}
	return legacy, documents, nil
}

func contextEnrollmentParameters(p []deps.Parameter) ([]byte, error) {
	raw, err := marshal(p)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(raw)
}

func (g *generator) publishContextSelections() error {
	records, err := contextEnrollmentSources(g.context(), g.sources)
	if err != nil {
		return err
	}
	legacy, documents, err := contextEnrollmentDocuments(g.context(), records, g.selections)
	if err != nil {
		return err
	}
	raw, err := marshal(legacy)
	if err != nil {
		return err
	}
	if _, err = g.writeDocument(filepath.Join(g.root, "config", "source-selections.json"), raw); err != nil {
		return err
	}
	if len(documents) > 0 {
		if err := os.Mkdir(g.path(filepath.Join(g.root, contextSelectionDirectory)), 0700); err != nil {
			return err
		}
	}
	names := []string{}
	for name := range documents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := g.context().Err(); err != nil {
			return err
		}
		if _, err = g.writeDocument(filepath.Join(g.root, contextSelectionDirectory, name), documents[name]); err != nil {
			return err
		}
	}
	return nil
}

// Reuse verifies generated transport bytes against retained source packages and
// receipt-bound evidence. It does not enroll authority or mutate prior output.
func verifyContextSelectionReuse(ctx context.Context, result Result, packages []SourcePackage) error {
	records, err := contextEnrollmentSources(ctx, packages)
	if err != nil {
		return err
	}
	required := map[string]int{}
	for i, r := range records {
		if r.v2 {
			name, err := contextSelectionName(r.subject)
			if err != nil {
				return err
			}
			required[name] = i
		}
	}
	if len(required) == 0 {
		return nil
	}
	install := loadedInstallWithContext(ctx, result)
	if install == nil {
		return ErrInstallRootConflict
	}
	bundleRaw, err := readConfined(result.Root, strings.TrimPrefix(install.OSS.InitialBundlePath, result.Root+string(filepath.Separator)))
	if err != nil {
		return err
	}
	bundle, err := trustload.DecodeStoredBundle(bundleRaw)
	if err != nil {
		return err
	}
	reader, err := evidencecas.NewFSReader(install.EvidenceRoot)
	if err != nil {
		return err
	}
	defer reader.Close()
	checkpointRaw, err := reader.Read(ctx, bundle.Transparency.CheckpointCAS)
	if err != nil {
		return err
	}
	checkpoint, err := bootstrap.DecodeCheckpoint(checkpointRaw)
	if err != nil {
		return err
	}
	proofs := map[operationtrust.SelectionSubject]operationtrust.SelectionEvidence{}
	accept := func(p contextsource.ContextSourceProof) error {
		if previous, ok := proofs[p.Subject]; ok && previous != p.Evidence {
			return ErrInstallRootConflict
		}
		if p.Evidence.CheckpointCAS != bundle.Transparency.CheckpointCAS {
			return ErrInstallRootConflict
		}
		raw, err := reader.Read(ctx, p.Evidence.InclusionProofCAS)
		if err != nil {
			return err
		}
		inclusion, err := bootstrap.DecodeInclusionProof(raw)
		if err != nil || inclusion.TreeSize != checkpoint.TreeSize {
			return ErrInstallRootConflict
		}
		decode := func(s string) (bootstrap.MerkleHash, error) {
			var h bootstrap.MerkleHash
			b, err := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
			if err != nil || len(b) != len(h) {
				return h, ErrInstallRootConflict
			}
			copy(h[:], b)
			return h, nil
		}
		root, err := decode(checkpoint.RootHash)
		if err != nil {
			return err
		}
		hashes := []bootstrap.MerkleHash{}
		for _, s := range inclusion.Hashes {
			h, err := decode(s)
			if err != nil {
				return err
			}
			hashes = append(hashes, h)
		}
		if err := bootstrap.VerifyInclusion([]byte(p.Evidence.StatementCAS), inclusion.LeafIndex, inclusion.TreeSize, root, hashes); err != nil {
			return err
		}
		proofs[p.Subject] = p.Evidence
		return nil
	}
	dir := filepath.Join(result.Root, contextSelectionDirectory)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInstallRootConflict
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != len(required) {
		return ErrInstallRootConflict
	}
	actual := map[string][]byte{}
	for _, f := range files {
		if _, ok := required[f.Name()]; !ok || !f.Type().IsRegular() {
			return ErrInstallRootConflict
		}
		raw, err := readConfined(result.Root, filepath.Join(contextSelectionDirectory, f.Name()))
		if err != nil {
			return err
		}
		input, err := contextsource.DecodeSourceSelectionV2(raw)
		if err != nil {
			return err
		}
		if err = accept(input.Root); err != nil {
			return err
		}
		for _, p := range input.Sources {
			if err = accept(p); err != nil {
				return err
			}
		}
		actual[f.Name()] = raw
	}
	legacyRaw, err := readConfined(result.Root, "config/source-selections.json")
	if err != nil {
		return err
	}
	var old []operationtrust.SourceSelection
	if err = canonicaljson.DecodeStrict(legacyRaw, &old); err != nil {
		return err
	}
	for _, s := range old {
		if err = accept(contextsource.ContextSourceProof{Subject: s.Subject, Evidence: s.Evidence}); err != nil {
			return err
		}
	}
	selections := make([]operationtrust.SourceSelection, len(records))
	for i, r := range records {
		proof, ok := proofs[r.subject]
		if !ok {
			return ErrInstallRootConflict
		}
		p := packages[i]
		if proof.Format != bootstrap.PublisherStatementAPIVersion || proof.StatementCAS != evidencecas.Digest(p.Statement) || proof.SignatureCAS != evidencecas.Digest([]byte(p.Signature)) || proof.KeyFingerprint != p.KeyFingerprint {
			return ErrInstallRootConflict
		}
		selections[i] = operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: r.subject, Evidence: proof, Dependencies: []string{}}
	}
	if len(proofs) != len(records) {
		return ErrInstallRootConflict
	}
	legacy, expected, err := contextEnrollmentDocuments(ctx, records, selections)
	if err != nil {
		return err
	}
	// Source package order is immaterial to the enrollment contract. Preserve the
	// installation's original legacy order while comparing complete records.
	if len(old) != len(legacy) {
		return ErrInstallRootConflict
	}
	legacySeen := map[operationtrust.SelectionSubject]bool{}
	for _, s := range old {
		if legacySeen[s.Subject] {
			return ErrInstallRootConflict
		}
		legacySeen[s.Subject] = true
		found := false
		for _, e := range legacy {
			a, _ := marshal(s)
			b, _ := marshal(e)
			if bytes.Equal(a, b) {
				found = true
				break
			}
		}
		if !found {
			return ErrInstallRootConflict
		}
	}
	for name, raw := range expected {
		if !bytes.Equal(raw, actual[name]) {
			return ErrInstallRootConflict
		}
	}
	return ctx.Err()
}
