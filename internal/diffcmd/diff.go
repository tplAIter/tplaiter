// Package diffcmd projects authenticated current-project drift without mutation.
package diffcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/adoption"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/managed"
	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const (
	StateCode = "TPL-E-DIFF-STATE-001"
	BlockCode = "TPL-E-DIFF-BLOCK-001"
	StaleCode = "TPL-E-DIFF-STALE-001"
)

// Options contains locators and the existing secret classifier, never authority.
type Options struct {
	Home, RendererVersion string
	SecretProvider        stateledger.SecretDigestProvider
}
type Change struct {
	Path         string `json:"path"`
	BlockID      string `json:"blockId,omitempty"`
	Provider     string `json:"provider,omitempty"`
	Action       string `json:"action"`
	BeforeSHA256 string `json:"beforeSHA256,omitempty"`
	AfterSHA256  string `json:"afterSHA256,omitempty"`
}
type Report struct {
	Excluded                    []resultdto.DiffExclusion
	Changes                     []Change
	FilesChecked, BlocksChecked int
	CurrentRef                  string
}

func failure(code string, cause error) error {
	return resultdto.NewError(code, resultdto.ExitOperational, cause)
}

// Run holds real read coordination through signed reconstruction and final
// reobservation. Reports confer no writer, execution or recovery authority.
func Run(ctx context.Context, r *trustload.Runtime, opts Options) (Report, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || opts.RendererVersion == "" {
		return Report{}, failure(StateCode, stateledger.ErrProjectIdentity)
	}
	if err := ctx.Err(); err != nil {
		return Report{}, failure(projectverify.CancelledCode, err)
	}
	// The accepted verifier maps authentication, missing evidence and journal errors.
	if _, _, err := projectverify.VerifyObserved(ctx, r.ProjectContext().RootPath, r.TrustRuntime(), projectverify.Options{Runtime: r, HomeRoot: opts.Home, CAS: r, SecretProvider: opts.SecretProvider}); err != nil {
		return Report{}, err
	}
	session, err := runtimeassembly.OpenReadOnly(ctx, r, runtimeassembly.Options{Home: opts.Home, SecretProvider: opts.SecretProvider})
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	defer session.Close()
	reader, err := projectverify.OpenObservation(ctx, r.ProjectContext().RootPath)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	defer func() { _ = reader.Close() }()
	snapshot := session.Observation().Snapshot
	read := func(p string) ([]byte, error) { return reader.ReadVerified(ctx, snapshot, p) }
	raw, err := read(".tplaiter/root-template.lock.json")
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	root, err := provenance.DecodeRootTemplateLock(raw)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	raw, err = read(".tplaiter/template.lock.json")
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	deps, err := provenance.DecodeTemplateLock(raw)
	if err != nil || provenance.ValidateLockPair(*root, *deps) != nil || !root.TrustProfile.Equal(r.TrustRuntime().Binding()) {
		return Report{}, failure(StateCode, err)
	}
	s := root.Root
	selected := operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: operationtrust.SelectionSubject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}, Evidence: operationtrust.SelectionEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: s.StatementCAS, SignatureCAS: s.SignatureCAS, KeyFingerprint: s.KeyFingerprint, CheckpointCAS: s.CheckpointCAS, InclusionProofCAS: s.InclusionProofCAS}, Dependencies: []string{}}
	input, err := json.Marshal(selected)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	resolution, err := r.TrustRuntime().VerifySubject(ctx, selected.TrustSubject(), selected.EvidenceRefs())
	if err != nil {
		return Report{}, resultdto.NewError(projectverify.TrustCode, resultdto.ExitTrust, err)
	}
	src, err := operationtrust.SnapshotFS(r.TrustRuntime(), resolution)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	tpl, err := renderref.LoadTemplate(src)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	verifiedSource, err := r.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	manifestRaw, ok := verifiedSource.Blob("template.manifest.yaml")
	if !ok {
		return Report{}, failure(StateCode, stateledger.ErrUnsafe)
	}
	_, contextErr := contextsource.DecodeNativeContextContractV2(verifiedSource.ContractBytes(), manifestRaw)
	nativeV2 := contextErr == nil
	if nativeV2 {
		if len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || tpl.AIConfig.Path != "" || operationtrust.ValidateBoundProjectBuildContent(verifiedSource, tpl) != nil {
			return Report{}, operationtrust.ErrSourceAdapterUnsupported
		}
	} else {
		if len(tpl.Commands) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || tpl.AIConfig.Path != "" {
			return Report{}, operationtrust.ErrSourceAdapterUnsupported
		}
	}
	raw, err = read(".tplaiter/project.yaml")
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	var marker stateledger.ProjectV2
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err = dec.Decode(&marker); err != nil {
		return Report{}, failure(StateCode, err)
	}
	if err = dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Report{}, failure(StateCode, err)
	}
	if marker.ID != r.ProjectContext().ProjectID || marker.Template.ResolvedCommit != s.Commit || marker.Template.RequestedRef != s.RequestedRef {
		return Report{}, failure(StateCode, stateledger.ErrProjectIdentity)
	}
	policy, err := adoptionpolicy.Parse(marker.Ownership)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	if policy != nil {
		if _, err = adoption.Read(ctx, r, opts.Home, policy); err != nil {
			return Report{}, failure(StateCode, err)
		}
	}
	text := func(k string) string { v, _ := marker.Project[k].(string); return v }
	port, ok := marker.Runtime["port"].(int)
	if !ok || port < 0 || port > 65535 {
		return Report{}, failure(StateCode, stateledger.ErrUnsafe)
	}
	ledger, err := read(migrations.LedgerRelPath)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	if err := validateMigrationHistory(tpl, ledger); err != nil {
		return Report{}, err
	}
	values := map[string]any{}
	for k, v := range marker.Answers {
		values[k] = v.Value
	}
	var expected *renderref.Result
	var contextSnapshot *contextsource.PreparedNativeSnapshot
	if nativeV2 {
		rootRaw, err := canonicaljson.Canonical(root)
		if err != nil {
			return Report{}, failure(StateCode, err)
		}
		depsRaw, err := canonicaljson.Canonical(deps)
		if err != nil {
			return Report{}, failure(StateCode, err)
		}
		sources, err := sourceadapter.PrepareRecordedContextSources(ctx, r, rootRaw, depsRaw)
		if err != nil {
			return Report{}, failure(StateCode, err)
		}
		defer sources.Close()
		contextSnapshot, err = contextsource.PrepareRecordedNativeSnapshot(ctx, r, sources, contextsource.RecordedNativeSnapshotInput{Render: renderref.Input{Repo: marker.Template.Repo, Values: renderref.Values(values), Project: manifest.ProjectInfo{Name: text("name"), Slug: text("slug"), Module: text("module"), System: text("system"), Domain: text("domain")}, Runtime: manifest.ProjectRuntime{Port: port}}, RecordedValues: renderref.Values(values), RendererVersion: opts.RendererVersion})
		if err != nil {
			return Report{}, failure(StateCode, err)
		}
		defer contextSnapshot.Close()
		expected, err = contextSnapshot.Rendered(ctx, r)
		if err != nil {
			return Report{}, failure(StateCode, err)
		}
		if expected.Template.Metadata.Name != marker.Template.Name {
			return Report{}, failure(StateCode, stateledger.ErrUnsafe)
		}
	} else {
		prepared, err := operationtrust.PrepareSnapshot(ctx, r, operationtrust.PrepareSnapshotInput{SourceInput: input, RendererVersion: opts.RendererVersion, Render: renderref.Input{Repo: marker.Template.Repo, Values: renderref.Values(values), Project: manifest.ProjectInfo{Name: text("name"), Slug: text("slug"), Module: text("module"), System: text("system"), Domain: text("domain")}, Runtime: manifest.ProjectRuntime{Port: port}}})
		if err != nil {
			return Report{}, failure(StateCode, err)
		}
		if !prepared.ValidFor(r.TrustRuntime()) || prepared.RootLock() != *root || prepared.Rendered().Template.Metadata.Name != marker.Template.Name {
			return Report{}, failure(StateCode, stateledger.ErrUnsafe)
		}
		expected = prepared.Rendered()

	}
	blockRaw, err := read(".tplaiter/managed-blocks.json")
	if err != nil {
		return Report{}, failure(BlockCode, err)
	}
	recordedBlocks, err := managedblocks.ParseBaseline(blockRaw)
	if err != nil {
		return Report{}, failure(BlockCode, err)
	}
	lineage, err := reader.ReadState(ctx, managed.LineagePath)
	if err != nil {
		return Report{}, failure(BlockCode, err)
	}
	hasManaged := lineage.Exists || len(recordedBlocks.Files) > 0
	var authenticatedBlocks *managedblocks.Baseline
	for _, data := range expected.Files {
		if bytes.Contains(data, []byte("tplater:managed-")) {
			hasManaged = true
			break
		}
	}
	if hasManaged {
		projection, err := managed.Read(ctx, r, opts.Home, opts.RendererVersion)
		if err != nil {
			return Report{}, failure(BlockCode, err)
		}
		blocks := projection.Blocks()
		authenticatedBlocks = &blocks
		expected, err = projection.RenderedFor(expected)
		if err != nil {
			return Report{}, failure(BlockCode, err)
		}
	}
	raw, err = read(engine.BaselineRelPath)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	var baseline engine.Baseline
	if canonicaljson.DecodeStrict(raw, &baseline) != nil || !reflect.DeepEqual(&baseline, expected.Baseline) {
		return Report{}, failure(StateCode, errors.New("baseline does not equal signed reconstruction"))
	}
	raw, err = read(".tplaiter/managed-blocks.json")
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	managed, err := managedblocks.ParseBaseline(raw)
	if err != nil {
		return Report{}, failure(BlockCode, err)
	}
	built, err := signedBlocks(expected.Files, s)
	if err != nil {
		return Report{}, failure(BlockCode, err)
	}
	if authenticatedBlocks != nil {
		built = authenticatedBlocks.Clone()
	}
	if !reflect.DeepEqual(managed, built) {
		return Report{}, failure(BlockCode, errors.New("managed baseline does not equal signed reconstruction"))
	}
	var images *resources.ResourceImages
	if contextSnapshot != nil {
		images, err = resources.PlanContextNativeSnapshotGeneratorImages(ctx, r, contextSnapshot)
	} else {
		images, err = resources.PlanNativeGeneratorImages(r.TrustRuntime(), resolution, *root)
	}
	if err != nil {
		return Report{}, err
	}
	files := expected.Files
	for p, b := range images.Files {
		if _, exists := files[p]; exists {
			return Report{}, failure(StateCode, stateledger.ErrUnsafe)
		}
		files[p] = b
	}
	if len(files) > 4096 {
		return Report{}, failure(StateCode, stateledger.ErrUnsafe)
	}
	raw, err = read(ownership.InventoryRelPath)
	if err != nil {
		return Report{}, failure(StateCode, err)
	}
	if err = adoptionpolicy.ValidateInventory(raw, files, policy); err != nil {
		return Report{}, failure(StateCode, err)
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		if !fs.ValidPath(p) || p == "." || len(p) > 1024 || strings.ContainsAny(p, "\\:#") || strings.HasPrefix(p, ".globals/") {
			return Report{}, failure(StateCode, stateledger.ErrUnsafe)
		}
		paths = append(paths, p)
	}
	for _, p := range policy.Paths() {
		if _, ok := files[p]; !ok {
			paths = append(paths, p)
		}
	}
	if len(paths) > 4096 {
		return Report{}, failure(StateCode, stateledger.ErrUnsafe)
	}
	sort.Strings(paths)
	report := Report{Changes: []Change{}, CurrentRef: s.Commit}
	observed := map[string]ownership.State{}
	var total int
	for _, p := range paths {
		actual, e := reader.ReadState(ctx, p)
		if e != nil {
			return Report{}, failure(StateCode, e)
		}
		if actual.Exists && actual.Kind != ownership.KindFile {
			return Report{}, failure(StateCode, stateledger.ErrUnsafe)
		}
		total += len(actual.Data)
		if total > 64<<20 {
			return Report{}, failure(StateCode, stateledger.ErrUnsafe)
		}
		observed[p] = actual
		if policy.Contains(p) {
			x := exclusionObservation(p, files, policy, s, actual)
			report.Excluded = append(report.Excluded, x)
			if _, ok := files[p]; !ok {
				if x.Drift {
					action := "modify"
					if !actual.Exists {
						action = "delete"
					}
					report.Changes = append(report.Changes, Change{Path: p, Action: action, BeforeSHA256: x.ExpectedSHA256, AfterSHA256: x.CurrentSHA256})
				}
				report.FilesChecked++
				continue
			}
		}
		var bound *managedblocks.FileBaseline
		if authenticatedBlocks != nil {
			if baseline, exists := authenticatedBlocks.Files[p]; exists {
				bound = &baseline
			}
		}
		changes, blocks, e := compareBound(p, files[p], actual, bound)
		if e != nil {
			return Report{}, failure(BlockCode, e)
		}
		if report.BlocksChecked+blocks > 4096 || len(report.Changes)+len(changes) > 4096 {
			return Report{}, failure(StateCode, stateledger.ErrUnsafe)
		}
		report.Changes = append(report.Changes, changes...)
		report.FilesChecked++
		report.BlocksChecked += blocks
	}
	// Advisory locks exclude cooperating writers; exact re-reads also catch foreign edits.
	for _, p := range paths {
		fresh, e := reader.ReadState(ctx, p)
		if e != nil || !reflect.DeepEqual(observed[p], fresh) {
			return Report{}, failure(StaleCode, e)
		}
	}
	if err = session.Recheck(ctx); err != nil {
		return Report{}, failure(StaleCode, err)
	}
	if err = ctx.Err(); err != nil {
		return Report{}, failure(projectverify.CancelledCode, err)
	}
	if policy != nil {
		if _, err = adoption.Read(ctx, r, opts.Home, policy); err != nil {
			return Report{}, failure(StaleCode, err)
		}
	}
	return report, nil
}

func signedBlocks(files map[string][]byte, source provenance.RootSubject) (managedblocks.Baseline, error) {
	selected := map[string][]byte{}
	providers := map[string]bool{}
	markers := 0
	for p, b := range files {
		if !bytes.Contains(b, []byte("tplater:managed-")) {
			continue
		}
		markers += bytes.Count(b, []byte("tplater:managed-"))
		if markers > 8192 {
			return managedblocks.Baseline{}, stateledger.ErrUnsafe
		}
		d, e := managedblocks.Parse(p, b)
		if e != nil {
			return managedblocks.Baseline{}, e
		}
		selected[p] = b
		for _, region := range d.Regions {
			providers[region.Provider] = true
		}
	}
	refs := []managedblocks.ProviderSource{}
	for p := range providers {
		refs = append(refs, managedblocks.ProviderSource{Provider: p, Source: source})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Provider < refs[j].Provider })
	return managedblocks.BuildBaseline(selected, refs, nil)
}

func compare(path string, expected []byte, actual ownership.State) ([]Change, int, error) {
	return compareBound(path, expected, actual, nil)
}

// bound is populated only after Run reconstructs the committed publication and
// matches the entire recorded ledger. It permits inspection of retained blocks,
// never a new topology or any execution/publication authority.
func compareBound(path string, expected []byte, actual ownership.State, bound *managedblocks.FileBaseline) ([]Change, int, error) {
	changes := []Change{}
	managed := bytes.Contains(expected, []byte("tplater:managed-")) || bound != nil && len(bound.Blocks) > 0
	if !managed {
		if bytes.Contains(actual.Data, []byte("tplater:managed-")) {
			return nil, 0, errors.New("unsigned managed topology")
		}
		if !actual.Exists || !bytes.Equal(expected, actual.Data) || actual.Mode.Perm() != 0o644 {
			action := "modify"
			after := evidencecas.Digest(actual.Data)
			if !actual.Exists {
				action = "delete"
				after = ""
			}
			changes = append(changes, Change{Path: path, Action: action, BeforeSHA256: evidencecas.Digest(expected), AfterSHA256: after})
		}
		return changes, 0, nil
	}
	if bytes.Count(expected, []byte("tplater:managed-")) > 8192 || bytes.Count(actual.Data, []byte("tplater:managed-")) > 8192 {
		return nil, 0, stateledger.ErrUnsafe
	}
	base, err := managedblocks.Parse(path, expected)
	if err != nil {
		return nil, 0, err
	}
	current, err := managedblocks.Parse(path, actual.Data)
	if err != nil {
		return nil, 0, err
	}
	retained := map[string]managedblocks.BlockBaseline{}
	if bound != nil {
		for id, block := range bound.Blocks {
			if _, exists := base.ByID[id]; !exists && block.State == managedblocks.StateUpstreamDeletedLocalRetained && block.Tombstone != nil && block.Tombstone.Side == managedblocks.TombstoneUpstream {
				retained[id] = block
			}
		}
	}
	for id, r := range current.ByID {
		b, exists := base.ByID[id]
		if exists && r.Provider == b.Provider {
			continue
		}
		if block, permitted := retained[id]; !exists && permitted && r.Provider == block.Provider {
			continue
		}
		return nil, 0, errors.New("unbound managed block")
	}
	retainedIDs := make([]string, 0, len(retained))
	for id := range retained {
		retainedIDs = append(retainedIDs, id)
	}
	sort.Strings(retainedIDs)
	for _, id := range retainedIDs {
		block := retained[id]
		region, exists := current.ByID[id]
		action, after := "delete", ""
		if exists {
			action, after = "modify", evidencecas.Digest(region.Body)
			if after == block.BodySHA256 && region.Ordinal == block.Anchor.Ordinal {
				continue
			}
		}
		changes = append(changes, Change{Path: path, BlockID: id, Provider: block.Provider, Action: action, BeforeSHA256: block.BodySHA256, AfterSHA256: after})
	}
	for _, b := range base.Regions {
		c, exists := current.ByID[b.ID]
		action := "modify"
		after := ""
		if !exists {
			action = "delete"
		} else {
			after = evidencecas.Digest(c.Bytes())
			if bytes.Equal(b.Bytes(), c.Bytes()) && b.Ordinal == c.Ordinal {
				continue
			}
		}
		changes = append(changes, Change{Path: path, BlockID: b.ID, Provider: b.Provider, Action: action, BeforeSHA256: evidencecas.Digest(b.Bytes()), AfterSHA256: after})
	}
	// Encode the ordered gaps separately: concatenation loses their positions
	// relative to unchanged blocks and can hide block movement.
	beforeSkeleton, err := json.Marshal(base.Gaps)
	if err != nil {
		return nil, 0, err
	}
	afterSkeleton, err := json.Marshal(current.Gaps)
	if err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(beforeSkeleton, afterSkeleton) || (actual.Exists && actual.Mode.Perm() != 0o644) {
		changes = append(changes, Change{Path: path, Action: "skeleton", BeforeSHA256: evidencecas.Digest(beforeSkeleton), AfterSHA256: evidencecas.Digest(afterSkeleton)})
	}
	return changes, len(base.Regions) + len(retained), nil
}

func exclusionObservation(p string, files map[string][]byte, policy *adoptionpolicy.Policy, source provenance.RootSubject, actual ownership.State) resultdto.DiffExclusion {
	x := resultdto.DiffExclusion{Path: p, Policy: "user-owned", Present: actual.Exists, ReferenceCommit: source.Commit, ReferenceScope: "current-signed-source", ExpectedSHA256: evidencecas.Digest(files[p]), Mode: uint32(actual.Mode)}
	if actual.Exists {
		x.CurrentSHA256 = evidencecas.Digest(actual.Data)
	}
	if _, ok := files[p]; !ok {
		x.ReferenceScope = "adoption-origin"
		x.ReferenceCommit = policy.Origin.SourceCommit
		for _, origin := range policy.Origin.Exclusions {
			if origin.Path == p {
				x.ExpectedSHA256 = origin.SourceSHA256
			}
		}
	}
	x.Drift = !actual.Exists || x.CurrentSHA256 != x.ExpectedSHA256 || actual.Mode != 0o644
	return x
}

// validateMigrationHistory verifies the freshly signed current manifest's
// retained declarations; a ledger checksum alone is not reader authority.
func validateMigrationHistory(tpl *manifest.Template, raw []byte) error {
	if err := migrations.ValidateAppliedHistory(tpl.Migrations, tpl.Metadata.Version, raw); err != nil {
		return failure(StateCode, err)
	}
	return nil
}
