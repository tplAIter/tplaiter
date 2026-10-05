// Package updateplan computes bounded native update afterimages from real
// signed source capabilities. Reports are observations, never authority.
package updateplan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

var (
	ErrInvalid          = errors.New("native update: invalid runtime or plan")
	ErrUnsafe           = errors.New("native update: unsafe or unsupported project image")
	ErrStale            = errors.New("native update: preimage or authority changed")
	ErrConflict         = errors.New("native update: conflicting owned changes")
	ErrApplyUnsupported = errors.New("native update: existing-project transaction seam unavailable")
)

const APIVersion = "tplaiter.dev/native-update-plan/v1"

// Backend has one concrete authenticated runtime. The composition root supplies the actual renderer version. Historical
// renderers are not emulated. It accepts no caller trust
// flags, project-root overrides, execution runners or decoded plan grants.
type Backend struct {
	runtime         *trustload.Runtime
	home            string
	rendererVersion string
}

func New(runtime *trustload.Runtime, home, rendererVersion string) (*Backend, error) {
	if runtime == nil || runtime.TrustRuntime() == nil || runtime.ProjectContext().RootPath == "" || home == "" || rendererVersion == "" {
		return nil, ErrInvalid
	}
	return &Backend{runtime: runtime, home: home, rendererVersion: rendererVersion}, nil
}

// Input is untrusted source transport. Rendering coordinates and answers are
// derived from the verified current marker, not caller-supplied parameters.
type Input struct{ SourceInput, TargetInput []byte }

type Change struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Reason    string `json:"reason"`
	Conflict  bool   `json:"conflict"`
	Before    *Image `json:"before"`
	After     *Image `json:"after"`
	Content   []byte `json:"content,omitempty"`
}

type Report struct {
	// Publishable describes image consistency only; it grants no write authority.
	Publishable           bool                        `json:"publishable"`
	APIVersion            string                      `json:"apiVersion"`
	ProjectID             string                      `json:"projectID"`
	Root                  string                      `json:"root"`
	PreimageSHA256        string                      `json:"preimageSHA256"`
	OperationInputsSHA256 string                      `json:"operationInputsSHA256"`
	Source                provenance.RootTemplateLock `json:"source"`
	Target                provenance.RootTemplateLock `json:"target"`
	Preimages             []Image                     `json:"preimages"`
	Changes               []Change                    `json:"changes"`
	Registry              RegistryImage               `json:"registry"`
}

// Plan retains private preparation and root identity. Marshal returns only a
// detached fingerprinted report; no decoder turns report bytes into a Plan.
type Plan struct {
	homeIdentity     os.FileInfo
	registryIdentity os.FileInfo
	owner            *Backend
	input            Input
	report           Report
	digest           string
	observed         *observation
	prepared         *operationtrust.PreparedUpdate
}

func (p *Plan) Fingerprint() string {
	if p == nil {
		return ""
	}
	return p.digest
}

func (p *Plan) Marshal() ([]byte, error) {
	if p == nil {
		return nil, ErrInvalid
	}
	return canonicaljson.Canonical(p.report)
}

// Prepare writes no project, registry, lock or journal. The existing trusted
// renderer allocates and removes bounded runtime-owned scratch directories.
func (b *Backend) Prepare(ctx context.Context, in Input) (*Plan, error) {
	if ctx == nil || b == nil || b.runtime == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(in.SourceInput) == 0 || len(in.SourceInput) > 1<<20 || len(in.TargetInput) == 0 || len(in.TargetInput) > 1<<20 {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	in = Input{SourceInput: bytes.Clone(in.SourceInput), TargetInput: bytes.Clone(in.TargetInput)}
	stable := b.runtime.TrustRuntime()
	if stable == nil {
		return nil, ErrInvalid
	}
	root := b.runtime.ProjectContext().RootPath
	if _, err := stateledger.VerifyStable(ctx, root, stable, stateledger.StableVerifyOptions{}); err != nil {
		return nil, err
	}
	observed, err := observe(ctx, root)
	if err != nil {
		return nil, err
	}
	registryObserved, err := readRegistry(ctx, b.home)
	if err != nil {
		return nil, err
	}
	p, err := b.reconstruct(ctx, in, observed, registryObserved)
	if err != nil {
		return nil, err
	}
	fresh, err := observe(ctx, root)
	if err != nil {
		return nil, err
	}
	if !equalObservation(observed, fresh) {
		return nil, ErrStale
	}
	if _, err := stateledger.VerifyStable(ctx, root, stable, stateledger.StableVerifyOptions{}); err != nil {
		return nil, err
	}
	freshRegistry, err := readRegistry(ctx, b.home)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(freshRegistry.raw, p.report.Registry.BeforeContent) || freshRegistry.mode != p.report.Registry.Before.Mode || !os.SameFile(registryObserved.identity, freshRegistry.identity) || !os.SameFile(registryObserved.fileIdentity, freshRegistry.fileIdentity) {
		return nil, ErrStale
	}
	return p, nil
}

// reconstruct verifies both signed selections against exact supplied preimages.
// Live admission first verifies stable state; cold admission requires the engine's
// authenticated immutable receipt and phase classification, never caller trust.
func (b *Backend) reconstruct(ctx context.Context, in Input, observed *observation, registryObserved *registryObservation) (*Plan, error) {
	stable := b.runtime.TrustRuntime()
	root := b.runtime.ProjectContext().RootPath
	var marker stateledger.ProjectV2
	if err := decodeMarker(observed.files[".tplaiter/project.yaml"], &marker); err != nil {
		return nil, err
	}
	if err := stable.CheckProjectIdentity(ctx, root, marker.ID); err != nil {
		return nil, err
	}
	if len(marker.Ownership) != 0 {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	current, err := provenance.DecodeRootTemplateLock(observed.files[".tplaiter/root-template.lock.json"])
	if err != nil {
		return nil, err
	}
	deps, err := provenance.DecodeTemplateLock(observed.files[".tplaiter/template.lock.json"])
	if err != nil {
		return nil, err
	}
	if err := provenance.ValidateLockPair(*current, *deps); err != nil {
		return nil, err
	}
	if current.Renderer.Version != b.rendererVersion {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	if marker.Template.ResolvedCommit != current.Root.Commit || marker.Template.RequestedRef != current.Root.RequestedRef {
		return nil, ErrUnsafe
	}
	render, err := markerRender(marker)
	if err != nil {
		return nil, err
	}
	preimage, err := bootstrap.DomainDigest(APIVersion+"/preimage", observed.images)
	if err != nil {
		return nil, err
	}
	prepared, err := operationtrust.PrepareUpdate(ctx, b.runtime, operationtrust.PrepareUpdateInput{SourceInput: in.SourceInput, TargetInput: in.TargetInput, Render: render, RendererVersion: b.rendererVersion, PreimageSHA256: preimage})
	if err != nil {
		return nil, err
	}
	if !prepared.ValidFor(stable) || prepared.SourceRootLock() != *current {
		return nil, ErrUnsafe
	}
	// Render the independently verified source as the actual three-way base.
	base, err := operationtrust.PrepareNew(ctx, b.runtime, operationtrust.PrepareNewInput{SourceInput: in.SourceInput, Render: render, RendererVersion: b.rendererVersion})
	if err != nil {
		return nil, err
	}
	if base.Rendered().Template.Metadata.Name != marker.Template.Name {
		return nil, ErrUnsafe
	}
	sourceManifest, err := b.verifiedManifest(ctx, in.SourceInput)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sourceManifest, observed.files[manifest.SnapshotRelPath]) {
		return nil, ErrUnsafe
	}
	sourceImages, err := b.sourceImages(ctx, in.SourceInput, base.RootLock())
	if err != nil {
		return nil, err
	}
	targetImages, err := b.sourceImages(ctx, in.TargetInput, prepared.TargetRootLock())
	if err != nil {
		return nil, err
	}
	beforeFiles, afterFiles := base.Rendered().Files, prepared.Rendered().Files
	if err := appendResources(beforeFiles, sourceImages); err != nil {
		return nil, err
	}
	if err := appendResources(afterFiles, targetImages); err != nil {
		return nil, err
	}
	if err := validateOwned(observed, beforeFiles, base.Rendered(), sourceImages); err != nil {
		return nil, err
	}
	changes, err := computeChanges(observed, beforeFiles, afterFiles)
	if err != nil {
		return nil, err
	}
	metadata, err := targetMetadata(marker, prepared, targetImages)
	if err != nil {
		return nil, err
	}
	if current.RootLockSHA256 == prepared.TargetRootLock().RootLockSHA256 {
		// Preserve exact valid existing metadata encoding for a genuine no-op.
		for p := range metadata {
			metadata[p] = observed.files[p]
		}
	}
	manifestRaw, err := b.verifiedManifest(ctx, in.TargetInput)
	if err != nil {
		return nil, err
	}
	if current.RootLockSHA256 != prepared.TargetRootLock().RootLockSHA256 {
		metadata[manifest.SnapshotRelPath] = manifestRaw
	}
	for path, raw := range metadata {
		changes = append(changes, decision(observed, path, raw, true, "metadata", false))
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	registry, registryObserved, err := planRegistryObserved(registryObserved, b.home, marker, prepared, observed.files[engine.BaselineRelPath], root)
	if err != nil {
		return nil, err
	}
	publishable := resourceChangesValid(changes, targetImages, prepared.TargetRootLock())
	for _, change := range changes {
		if change.Conflict {
			publishable = false
		}
	}
	report := Report{Publishable: publishable, Registry: registry, APIVersion: APIVersion, ProjectID: marker.ID, Root: root, PreimageSHA256: preimage, OperationInputsSHA256: prepared.OperationInputsSHA256(), Source: prepared.SourceRootLock(), Target: prepared.TargetRootLock(), Preimages: observed.images, Changes: changes}
	digest, err := bootstrap.DomainDigest(APIVersion, report)
	if err != nil {
		return nil, err
	}
	return &Plan{homeIdentity: registryObserved.identity, registryIdentity: registryObserved.fileIdentity, owner: b, input: Input{SourceInput: bytes.Clone(in.SourceInput), TargetInput: bytes.Clone(in.TargetInput)}, report: report, digest: digest, observed: observed, prepared: prepared}, nil
}

// Recheck rebuilds the plan with fresh authority and actual project bytes.
// A matching report hash alone is insufficient: runtime and root identities
// must still match the private in-memory preparation.
func (b *Backend) Recheck(ctx context.Context, p *Plan, expected string) error {
	_, err := b.recheckPlan(ctx, p, expected)
	return err
}

// Return the freshly authenticated preparation, never material from a detached
// report or an old preparation that merely has a matching stored digest.
func (b *Backend) recheckPlan(ctx context.Context, p *Plan, expected string) (*Plan, error) {
	if ctx == nil || b == nil || b.runtime == nil || p == nil || p.prepared == nil || p.owner != b || expected == "" || p.digest != expected || !p.prepared.ValidFor(b.runtime.TrustRuntime()) {
		return nil, ErrInvalid
	}
	digest, err := bootstrap.DomainDigest(APIVersion, p.report)
	if err != nil || digest != expected {
		return nil, ErrInvalid
	}
	current, err := b.Prepare(ctx, p.input)
	if err != nil {
		return nil, err
	}
	if current.digest != expected || !equalObservation(p.observed, current.observed) || !os.SameFile(p.homeIdentity, current.homeIdentity) || !os.SameFile(p.registryIdentity, current.registryIdentity) {
		return nil, ErrStale
	}
	return current, nil
}

// Apply validates exact transaction images but remains a typed refusal until
// the separate existing-tree primitive admits signed update intent, deletions,
// registry publication and cold recovery. No creation transaction is reused.
func (b *Backend) Apply(ctx context.Context, p *Plan, expected string) error {
	if _, err := b.prepareMutation(ctx, p, expected); err != nil {
		return err
	}
	return ErrApplyUnsupported
}

func decodeMarker(raw []byte, out *stateledger.ProjectV2) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrUnsafe
	}
	return nil
}

func markerRender(m stateledger.ProjectV2) (renderref.Input, error) {
	text := func(key string) string { v, _ := m.Project[key].(string); return v }
	port, ok := m.Runtime["port"].(int)
	if !ok || port < 0 || port > 65535 {
		return renderref.Input{}, ErrUnsafe
	}
	values := map[string]any{}
	for k, v := range m.Answers {
		values[k] = v.Value
	}
	return renderref.Input{Repo: m.Template.Repo, Values: renderref.Values(values), Project: manifest.ProjectInfo{Name: text("name"), Slug: text("slug"), Module: text("module"), System: text("system"), Domain: text("domain")}, Runtime: manifest.ProjectRuntime{Port: port}}, nil
}

func (b *Backend) sourceImages(ctx context.Context, raw []byte, lock provenance.RootTemplateLock) (*resources.ResourceImages, error) {
	selection, err := operationtrust.DecodeSourceSelection(raw)
	if err != nil {
		return nil, err
	}
	stable := b.runtime.TrustRuntime()
	resolution, err := stable.VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	return resources.PlanNativeGeneratorImages(stable, resolution, lock)
}

func (b *Backend) verifiedManifest(ctx context.Context, raw []byte) ([]byte, error) {
	selection, err := operationtrust.DecodeSourceSelection(raw)
	if err != nil {
		return nil, err
	}
	stable := b.runtime.TrustRuntime()
	resolution, err := stable.VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	snapshot, err := operationtrust.SnapshotFS(stable, resolution)
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(snapshot, "template.manifest.yaml")
}

func appendResources(files map[string][]byte, images *resources.ResourceImages) error {
	for p, data := range files {
		if !safePath(p) || p == ".tplaiter" || strings.HasPrefix(p, ".tplaiter/") || p == ".tplater" || strings.HasPrefix(p, ".tplater/") || bytes.Contains(data, []byte("tplater:managed-")) {
			return ErrUnsafe
		}
	}
	for p, data := range images.Files {
		if _, ok := files[p]; ok {
			return ErrUnsafe
		}
		files[p] = bytes.Clone(data)
	}
	return nil
}

func validateOwned(observed *observation, base map[string][]byte, result *renderref.Result, images *resources.ResourceImages) error {
	for _, image := range observed.images {
		if image.Path == updateControlPath && image.Kind == "file" && image.Mode == 0o600 && len(observed.files[image.Path]) == 0 {
			info := observed.identities[image.Path]
			if info == nil || updateSingleLink(info) {
				// Cold semantic images have no live FileInfo. The receipt owner
				// separately verifies actual held control identity/link count.
				continue
			}
		}
		if strings.HasPrefix(image.Path, ".tplaiter/") && image.Kind == "file" && image.Mode != 0o644 {
			return ErrUnsafe
		}
	}
	var inventory ownership.Inventory
	if err := canonicaljson.DecodeStrict(observed.files[ownership.InventoryRelPath], &inventory); err != nil {
		return err
	}
	if inventory.Version != 1 || len(inventory.Skipped) != 0 || len(inventory.Tombstones) != 0 || len(inventory.Artifacts) != len(base) {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	seen := map[string]bool{}
	for _, a := range inventory.Artifacts {
		raw, ok := base[a.Path]
		if !ok || seen[a.Path] || a.Mode != 0o644 || (a.Kind != "" && a.Kind != ownership.KindFile) || a.Target != "" || a.SHA256 != strings.TrimPrefix(evidencecas.Digest(raw), "sha256:") {
			return ErrUnsafe
		}
		seen[a.Path] = true
	}
	expected, err := canonicaljson.Canonical(result.Baseline)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, observed.files[engine.BaselineRelPath]) {
		return ErrUnsafe
	}
	expected, err = canonicaljson.Canonical(images.Lock)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, observed.files[resources.NativeResourceLockPath]) {
		return ErrUnsafe
	}
	// Active generation, managed blocks, migrations and AI ownership require
	// dedicated consumers. Never silently ignore their durable state.
	empty := map[string]any{
		".tplaiter/ai-managed.json": struct {
			Version int      `json:"version"`
			Files   []string `json:"files"`
		}{1, []string{}},
		".tplaiter/generator-targets.lock.json": struct {
			Version int   `json:"version"`
			Targets []any `json:"targets"`
		}{1, []any{}},
		".tplaiter/managed-blocks.json": struct {
			Schema int            `json:"schema"`
			Files  map[string]any `json:"files"`
		}{1, map[string]any{}},
		".tplaiter/migrations.json": struct {
			Version int   `json:"version"`
			Applied []any `json:"applied"`
		}{1, []any{}},
	}
	for p, v := range empty {
		raw, err := canonicaljson.Canonical(v)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, observed.files[p]) {
			return operationtrust.ErrSourceAdapterUnsupported
		}
	}
	return nil
}

func targetMetadata(marker stateledger.ProjectV2, p *operationtrust.PreparedUpdate, images *resources.ResourceImages) (map[string][]byte, error) {
	result := p.Rendered()
	inv := ownership.Inventory{Version: 1, Artifacts: []ownership.Artifact{}}
	for path, raw := range result.Files {
		a, err := ownership.ArtifactFor(path, raw, 0o644, "")
		if err != nil {
			return nil, err
		}
		inv.Artifacts = append(inv.Artifacts, a)
	}
	for _, a := range images.Lock.Artifacts {
		inv.Artifacts = append(inv.Artifacts, ownership.Artifact{Path: a.Path, Mode: a.Mode, SHA256: strings.TrimPrefix(a.SHA256, "sha256:")})
	}
	sort.Slice(inv.Artifacts, func(i, j int) bool { return inv.Artifacts[i].Path < inv.Artifacts[j].Path })
	for k, v := range result.Resolved.Values {
		previous, ok := marker.Answers[k]
		if !ok {
			previous = stateledger.Answer{Source: "default"}
		}
		previous.Value = v
		marker.Answers[k] = previous
	}
	root := p.TargetRootLock()
	marker.Template.RequestedRef = root.Root.RequestedRef
	marker.Template.ResolvedCommit = root.Root.Commit
	marker.Template.Name = result.Template.Metadata.Name
	values := map[string]any{
		".tplaiter/root-template.lock.json": root, ".tplaiter/template.lock.json": p.TargetDependencyLock(),
		engine.BaselineRelPath: result.Baseline, ownership.InventoryRelPath: inv, resources.NativeResourceLockPath: images.Lock,
	}
	out := map[string][]byte{}
	for path, v := range values {
		raw, err := canonicaljson.Canonical(v)
		if err != nil {
			return nil, err
		}
		out[path] = raw
	}
	raw, err := yaml.Marshal(marker)
	if err != nil {
		return nil, err
	}
	out[".tplaiter/project.yaml"] = raw
	out[manifest.SnapshotRelPath] = nil
	return out, nil
}

func decision(observed *observation, path string, raw []byte, exists bool, reason string, conflict bool) Change {
	change := Change{Path: path, Operation: "keep", Reason: reason, Conflict: conflict}
	for _, image := range observed.images {
		if image.Path == path {
			copyImage := image
			change.Before = &copyImage
			break
		}
	}
	if exists {
		change.After = &Image{Path: path, Kind: "file", Mode: 0o644, SHA256: evidencecas.Digest(raw)}
		change.Content = bytes.Clone(raw)
	}
	if change.Before == nil && change.After == nil {
		return change
	}
	if change.Before != nil && change.After != nil && *change.Before == *change.After {
		return change
	}
	if exists {
		change.Operation = "write"
	} else {
		change.Operation = "delete"
	}
	return change
}

func computeChanges(observed *observation, base, target map[string][]byte) ([]Change, error) {
	if err := validateOutput(base); err != nil {
		return nil, err
	}
	if err := validateOutput(target); err != nil {
		return nil, err
	}
	if err := validateObservedNamespace(observed, target); err != nil {
		return nil, err
	}
	paths := map[string]bool{}
	for p := range base {
		paths[p] = true
	}
	for p := range target {
		paths[p] = true
	}
	changes := make([]Change, 0, len(paths))
	for p := range paths {
		for _, image := range observed.images {
			if image.Path == p && image.Kind != "file" {
				return nil, ErrUnsafe
			}
		}
		old, owned := base[p]
		next, wanted := target[p]
		if strings.HasPrefix(p, ".tplaiter/generators/") {
			changes = append(changes, exactResourceDecision(observed, p, old, owned, next, wanted))
			continue
		}
		work, present := observed.files[p]
		if !owned && present {
			c := decision(observed, p, work, true, "foreign preserved", true)
			c.After = c.Before
			c.Operation = "keep"
			changes = append(changes, c)
			continue
		}
		if owned && !present {
			changes = append(changes, decision(observed, p, nil, false, "user deletion preserved", false))
			continue
		}
		mode := uint32(0o644)
		for _, image := range observed.images {
			if image.Path == p {
				mode = image.Mode
			}
		}
		modified := present && (!bytes.Equal(work, old) || mode != 0o644)
		if owned && modified && (!wanted || bytes.Equal(old, next)) {
			c := decision(observed, p, work, true, "local changes preserved", false)
			c.After = c.Before
			c.Operation = "keep"
			changes = append(changes, c)
			continue
		}
		if owned && modified {
			merged, conflict := merge(old, work, next)
			c := decision(observed, p, merged, true, "three-way merge", conflict)
			if mode != 0o644 {
				c.Conflict = true
				c.Reason = "permission change preserved"
				c.Content = bytes.Clone(work)
				c.After = c.Before
				c.Operation = "keep"
			}
			changes = append(changes, c)
			continue
		}
		changes = append(changes, decision(observed, p, next, wanted, "upstream", false))
	}
	return changes, nil
}

// Conservative bounded merge accepts independent same-length line edits.
// General overlapping/binary edits remain observable conflicts and preserve ours.
func merge(base, ours, theirs []byte) ([]byte, bool) {
	if bytes.Equal(ours, theirs) {
		return bytes.Clone(ours), false
	}
	if bytes.Count(base, []byte("\n")) > 2047 || bytes.Count(ours, []byte("\n")) > 2047 || bytes.Count(theirs, []byte("\n")) > 2047 || bytes.Contains(base, []byte{0}) || bytes.Contains(ours, []byte{0}) || bytes.Contains(theirs, []byte{0}) {
		return bytes.Clone(ours), true
	}
	b, o, t := strings.Split(string(base), "\n"), strings.Split(string(ours), "\n"), strings.Split(string(theirs), "\n")
	if len(b) != len(o) || len(b) != len(t) || len(b) > 2048 {
		return bytes.Clone(ours), true
	}
	result := append([]string(nil), b...)
	for i := range b {
		switch {
		case o[i] == t[i]:
			result[i] = o[i]
		case o[i] == b[i]:
			result[i] = t[i]
		case t[i] == b[i]:
			result[i] = o[i]
		default:
			return bytes.Clone(ours), true
		}
	}
	return []byte(strings.Join(result, "\n")), false
}

// validateOutput bounds the prepared image and refuses file/directory and
// case-folded collisions before producing publication material.
func validateOutput(files map[string][]byte) error {
	if len(files) > maxFiles {
		return ErrUnsafe
	}
	var total int64
	for p, raw := range files {
		if !safePath(p) {
			return ErrUnsafe
		}
		total += int64(len(raw))
		if total > maxBytes {
			return ErrUnsafe
		}
	}
	_, err := outputNamespace(files)
	return err
}

// namespaceNode retains spelling and type, including implicit parent directories.
type namespaceNode struct{ path, kind string }

func addNamespace(nodes map[string]namespaceNode, p, kind string) error {
	key := strings.ToLower(p)
	if previous, ok := nodes[key]; ok && (previous.path != p || previous.kind != kind) {
		return ErrUnsafe
	}
	nodes[key] = namespaceNode{path: p, kind: kind}
	for parent := path.Dir(p); parent != "."; parent = path.Dir(parent) {
		key = strings.ToLower(parent)
		if previous, ok := nodes[key]; ok && (previous.path != parent || previous.kind != "directory") {
			return ErrUnsafe
		}
		nodes[key] = namespaceNode{path: parent, kind: "directory"}
	}
	return nil
}

func outputNamespace(files map[string][]byte) (map[string]namespaceNode, error) {
	nodes := map[string]namespaceNode{}
	for p := range files {
		if err := addNamespace(nodes, p, "file"); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func validateObservedNamespace(observed *observation, target map[string][]byte) error {
	desired, err := outputNamespace(target)
	if err != nil {
		return err
	}
	current := map[string]namespaceNode{}
	for _, image := range observed.images {
		if image.Path == "." {
			continue
		}
		if image.Kind != "file" && image.Kind != "directory" {
			return ErrUnsafe
		}
		if err := addNamespace(current, image.Path, image.Kind); err != nil {
			return err
		}
	}
	for key, node := range desired {
		if existing, ok := current[key]; ok && (node.path != existing.path || node.kind != existing.kind) {
			return ErrUnsafe
		}
	}
	return nil
}

// Resource bytes are exact verified images, never an ordinary three-way merge.
// Local edits/deletions are preserved as conflicts unless they already equal
// the requested signed image with its exact mode and established ownership.
func exactResourceDecision(observed *observation, p string, old []byte, owned bool, next []byte, wanted bool) Change {
	c := decision(observed, p, next, wanted, "exact verified resource image", false)
	work, present := observed.files[p]
	var mode uint32
	if c.Before != nil {
		mode = c.Before.Mode
	}
	modified := present && (!bytes.Equal(work, old) || mode != 0o644)
	conflict := (!owned && present) || (wanted && !present && owned) || (owned && modified && (!wanted || !bytes.Equal(work, next) || mode != 0o644))
	if conflict {
		c = decision(observed, p, work, present, "local resource image preserved", true)
		c.After = c.Before
		c.Operation = "keep"
	}
	return c
}

// Validate the actual proposed managed resource set and planned lock together.
// A report with an unresolvable local resource image cannot be publishable.
func resourceChangesValid(changes []Change, target *resources.ResourceImages, root provenance.RootTemplateLock) bool {
	images := &resources.ResourceImages{Files: map[string][]byte{}}
	var foundLock bool
	for _, c := range changes {
		if c.Path == resources.NativeResourceLockPath {
			lock, err := resources.DecodeResourceLockV2(c.Content)
			if err != nil || c.After == nil || c.After.Mode != 0o644 {
				return false
			}
			images.Lock = *lock
			foundLock = true
			continue
		}
		if !strings.HasPrefix(c.Path, ".tplaiter/generators/") {
			continue
		}
		if c.After == nil {
			continue
		}
		if c.After.Kind != "file" || c.After.Mode != 0o644 || c.After.SHA256 != evidencecas.Digest(c.Content) {
			return false
		}
		images.Files[c.Path] = c.Content
	}
	if !foundLock || images.Validate(root) != nil {
		return false
	}
	// In addition to typed lock validation, compare the verified desired set.
	if len(images.Files) != len(target.Files) {
		return false
	}
	for p, raw := range target.Files {
		if !bytes.Equal(raw, images.Files[p]) {
			return false
		}
	}
	return true
}
