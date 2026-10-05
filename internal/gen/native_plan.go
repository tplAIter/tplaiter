package gen

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/stateledger/ledgerpath"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

var (
	ErrNativeIdentityUnavailable = errors.New("TRUST_NATIVE_PROJECT_IDENTITY_UNAVAILABLE")
	ErrNativeOwnership           = errors.New("TRUST_NATIVE_OWNERSHIP_UNCERTAIN")
)

// NativeOperation transports user input only; it confers no source authority.
type NativeOperation struct {
	Kind, Name string
	Provided   map[string]string
}

type nativeImage struct {
	data []byte
	mode fs.FileMode
	dir  bool
	info fs.FileInfo
}

// NativePlan keeps authenticated inputs and exact before/after images private.
// A zero value cannot authorize writes. No manifest or snippet reader is supplied
// by the caller. Planning performs no writes, probes or command execution.
type NativePlan struct {
	runtime              *trustload.Runtime
	root, home, markerID string
	before, after        map[string]nativeImage
	result               BatchResult
	operationNames       []string
	operations           []NativeOperation
	owned                map[string]ownership.Artifact
}

// Result returns detached reporting data, never the writer's private images.
func (p *NativePlan) Result() BatchResult {
	if p == nil {
		return BatchResult{}
	}
	r := p.result
	r.CreatedFiles = append([]string(nil), r.CreatedFiles...)
	r.EditedFiles = append([]string(nil), r.EditedFiles...)
	r.Results = append([]Result(nil), r.Results...)
	for i := range r.Results {
		r.Results[i].CreatedFiles = append([]string(nil), r.Results[i].CreatedFiles...)
		r.Results[i].EditedFiles = append([]string(nil), r.Results[i].EditedFiles...)
	}
	return r
}

// NativeAction is deliberately a finite refusal surface until fixed approved
// action adapters exist. Raw Runner/Exec and manifest shell strings never enter.
type NativeAction string

const (
	NativeFormat NativeAction = "formatter"
	NativeBuild  NativeAction = "build"
	NativeHook   NativeAction = "hook"
)

func (p *NativePlan) ExecuteAction(_ context.Context, _ NativeAction) error {
	return ErrExecutionUnavailable
}

// PlanNative authenticates the installed identity, complete stable ledger and
// signed native resource closure before rendering any operation. A fresh identity
// API must be present on the concrete stable runtime; caller adapters are refused.
func PlanNative(ctx context.Context, runtime *trustload.Runtime, home string, operations []NativeOperation) (*NativePlan, error) {
	operations = cloneNativeOperations(operations)
	if ctx == nil || runtime == nil || runtime.TrustRuntime() == nil {
		return nil, ErrNativeIdentityUnavailable
	}
	root := runtime.ProjectContext().RootPath
	before, err := nativeCapture(root, false)
	if err != nil {
		return nil, err
	}
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(before[".tplaiter/project.yaml"].data, &marker); err != nil {
		return nil, err
	}
	if err := nativeIdentity(ctx, runtime, root, marker.ID); err != nil {
		return nil, err
	}
	if _, err := stateledger.VerifyStable(ctx, root, runtime.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		return nil, err
	}
	p, err := buildNativeFromImages(ctx, runtime, home, before, operations)
	if err != nil {
		return nil, err
	}
	fresh, err := nativeCapture(root, false)
	if err != nil || !nativeEqual(before, fresh) {
		return nil, ErrNativeOwnership
	}
	return p, nil
}

func buildNativeFromImages(ctx context.Context, runtime *trustload.Runtime, home string, before map[string]nativeImage, operations []NativeOperation) (*NativePlan, error) {
	root := runtime.ProjectContext().RootPath
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(before[".tplaiter/project.yaml"].data, &marker); err != nil {
		return nil, err
	}
	if err := nativeIdentity(ctx, runtime, root, marker.ID); err != nil {
		return nil, err
	}
	// Policy-bearing projects require an authenticated, policy-aware generator.
	// This common boundary also protects reconstruction of cold material.
	var inventory ownership.Inventory
	if err := canonicaljson.DecodeStrict(before[ownership.InventoryRelPath].data, &inventory); err != nil || inventory.Version != 1 {
		return nil, ErrNativeOwnership
	}
	if len(marker.Ownership) != 0 || len(inventory.Skipped) != 0 || len(inventory.Tombstones) != 0 {
		return nil, ErrNativeOwnership
	}
	// The runtime verifies the root's actual evidence, rather than accepting a
	// caller-provided resolution or trusting the resource lock's self-hash.
	lock, err := provenance.DecodeRootTemplateLock(before[".tplaiter/root-template.lock.json"].data)
	if err != nil {
		return nil, err
	}
	s := lock.Root
	resolution, err := runtime.TrustRuntime().VerifySubject(ctx, trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}, trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: s.StatementCAS, SignatureCAS: s.SignatureCAS, KeyFingerprint: s.KeyFingerprint, CheckpointCAS: s.CheckpointCAS, InclusionProofCAS: s.InclusionProofCAS})
	if err != nil {
		return nil, err
	}
	images, err := nativeResources(runtime.TrustRuntime(), resolution, *lock)
	if err != nil {
		return nil, err
	}
	expectedLock, err := canonicaljson.Canonical(images.Lock)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(expectedLock, before[nativeResourceLockPath].data) {
		return nil, ErrNativeOwnership
	}
	owned := map[string]ownership.Artifact{}
	for _, a := range inventory.Artifacts {
		if _, duplicate := owned[a.Path]; duplicate {
			return nil, ErrNativeOwnership
		}
		owned[a.Path] = a
	}
	for name, raw := range images.Files {
		observed, ok := before[name]
		a, own := owned[name]
		if !ok || !own || observed.dir || observed.mode != 0o644 || !bytes.Equal(observed.data, raw) || a.SHA256 != strings.TrimPrefix(evidencecas.Digest(raw), "sha256:") || a.Mode != 0o644 || a.Kind != "" || a.Target != "" {
			return nil, ErrNativeOwnership
		}
	}
	for name := range before {
		if strings.HasPrefix(name, GeneratorsRelPath+"/") && !before[name].dir {
			if _, ok := images.Files[name]; !ok {
				return nil, ErrNativeOwnership
			}
		}
	}
	snapshot, err := runtime.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	raw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return nil, ErrNativeOwnership
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		return nil, err
	}
	values := settings.Values{}
	for k, a := range marker.Answers {
		values[k] = a.Value
	}
	resolved, err := settings.ResolveRecorded(tpl, values, values)
	if err != nil {
		return nil, err
	}
	projectRaw, err := yaml.Marshal(marker.Project)
	if err != nil {
		return nil, err
	}
	var project manifest.ProjectInfo
	if err := yaml.Unmarshal(projectRaw, &project); err != nil {
		return nil, err
	}
	p := &NativePlan{runtime: runtime, root: root, home: home, markerID: marker.ID, before: before, after: nativeClone(before), owned: owned, operations: operations}
	if err := p.render(tpl, resolved.Values, project, images.Files, operations); err != nil {
		return nil, err
	}
	if err := p.recordOwnership(inventory); err != nil {
		return nil, err
	}
	return p, nil
}

func nativeIdentity(ctx context.Context, runtime *trustload.Runtime, root, id string) error {
	if ctx == nil || runtime == nil || runtime.TrustRuntime() == nil {
		return ErrNativeIdentityUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	checker, ok := any(runtime.TrustRuntime()).(interface {
		CheckProjectIdentity(context.Context, string, string) error
	})
	if !ok {
		return ErrNativeIdentityUnavailable
	}
	return checker.CheckProjectIdentity(ctx, root, id)
}

func nativeCapture(root string, pending bool) (map[string]nativeImage, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrNativeOwnership
	}
	// Refuse every symlink component, even an otherwise contained alias.
	for current := root; current != filepath.Dir(current); current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrNativeOwnership
		}
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := map[string]nativeImage{}
	total := 0
	err = fs.WalkDir(r.FS(), ".", func(name string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		if pending && name == ".tplaiter/"+ledgerpath.NewPendingMarker {
			return nil
		}
		info, err := r.Lstat(name)
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || len(out) >= 10000 || info.Size() > 16<<20 {
			return ErrNativeOwnership
		}
		image := nativeImage{mode: info.Mode().Perm(), dir: info.IsDir(), info: info}
		if !image.dir {
			if !nativeSingleLink(info) {
				return ErrNativeOwnership
			}
			image.data, err = r.ReadFile(name)
			if err != nil {
				return err
			}
			total += len(image.data)
			if total > 64<<20 {
				return ErrNativeOwnership
			}
		}
		after, err := r.Lstat(name)
		if err != nil || !os.SameFile(info, after) {
			return ErrNativeOwnership
		}
		out[name] = image
		return nil
	})
	return out, err
}

func nativeClone(in map[string]nativeImage) map[string]nativeImage {
	out := map[string]nativeImage{}
	for k, v := range in {
		v.data = bytes.Clone(v.data)
		out[k] = v
	}
	return out
}

func nativeEqual(a, b map[string]nativeImage) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || v.dir != w.dir || v.mode != w.mode || !bytes.Equal(v.data, w.data) || (v.info != nil && w.info != nil && !os.SameFile(v.info, w.info)) {
			return false
		}
	}
	return true
}

func nativePath(name string) error {
	if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\\\x00\n\r:") {
		return ErrNativeOwnership
	}
	for _, part := range strings.Split(name, "/") {
		if strings.EqualFold(part, ".git") || strings.EqualFold(part, ".tplaiter") || strings.EqualFold(part, ".tplater") {
			return ErrNativeOwnership
		}
	}
	return nil
}

func nativeRender(name string, raw []byte, data Context) ([]byte, error) {
	t, err := template.New(name).Funcs(engine.FuncMap(data.Settings)).Parse(string(raw))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err = t.Execute(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (p *NativePlan) render(tpl *manifest.Template, values settings.Values, project manifest.ProjectInfo, snippets map[string][]byte, ops []NativeOperation) error {
	if len(ops) == 0 {
		return errors.New("gen batch: at least one operation is required")
	}
	reserved := map[string]struct{}{}
	edited := map[string]bool{}
	for _, op := range ops {
		g, err := Lookup(tpl, op.Kind)
		if err != nil {
			return err
		}
		available, err := evalGate(g.When, values)
		if err != nil {
			return err
		}
		if !available {
			return fmt.Errorf("gen %s is unavailable with current settings", op.Kind)
		}
		declared := map[string]bool{}
		for _, param := range g.Params {
			declared[param.Name] = true
		}
		for k := range op.Provided {
			if !declared[k] {
				return fmt.Errorf("gen: unknown parameter %q", k)
			}
		}
		params, fields, err := ResolveParams(g, op.Provided)
		if err != nil {
			return err
		}
		c, err := newContext(op.Name, values, project)
		if err != nil {
			return err
		}
		c.Params, c.Fields = params, fields
		specs, err := resolveTargets(g, values)
		if err != nil {
			return err
		}
		if len(specs) == 0 {
			return errors.New("gen: no available targets")
		}
		for _, spec := range specs {
			if spec.Numbered == manifest.NumberedGoose {
				rel, err := renderTargetPath(spec.Target, c)
				if err != nil {
					return err
				}
				if err := nativePath(rel); err != nil {
					return err
				}
				highestSequence := 0
				for name := range p.after {
					if path.Dir(name) == path.Dir(rel) {
						if m := migSeqRe.FindStringSubmatch(path.Base(name)); m != nil {
							n, e := strconv.Atoi(m[1])
							if e == nil && n > highestSequence {
								highestSequence = n
							}
						}
					}
				}
				c.MigrationSeq = fmt.Sprintf("%05d", highestSequence+1)
				break
			}
		}
		result := Result{Kind: op.Kind}
		for _, spec := range specs {
			rel, err := renderTargetPath(spec.Target, c)
			if err != nil {
				return err
			}
			if err := nativePath(rel); err != nil {
				return err
			}
			if _, exists := p.after[rel]; exists {
				return fmt.Errorf("%w: gen: %s already exists (already generated)", ErrNativeOwnership, rel)
			}
			if _, exists := reserved[rel]; exists {
				return fmt.Errorf("gen: duplicate target %s", rel)
			}
			raw, ok := snippets[GeneratorsRelPath+"/"+spec.Snippet]
			if !ok {
				return ErrNativeOwnership
			}
			content, err := nativeRender(spec.Snippet, raw, c)
			if err != nil {
				return err
			}
			if err := p.add(rel, content, 0o644); err != nil {
				return err
			}
			reserved[rel] = struct{}{}
			result.CreatedFiles = append(result.CreatedFiles, rel)
			p.result.CreatedFiles = append(p.result.CreatedFiles, rel)
		}
		c.Marker = fmt.Sprintf("// gen:%s:%s", op.Kind, c.Name.Snake)
		seen := map[string]bool{}
		for _, a := range g.Anchors {
			if err := nativePath(a.File); err != nil {
				return err
			}
			image, ok := p.after[a.File]
			original := p.before[a.File]
			owner, owned := p.owned[a.File]
			if !owned || (owner.Kind != "" && owner.Kind != ownership.KindFile) || owner.Target != "" || owner.Mode != uint32(original.mode) || owner.SHA256 != strings.TrimPrefix(evidencecas.Digest(original.data), "sha256:") {
				return ErrNativeOwnership
			}
			_, existedBefore := p.before[a.File]
			if !ok || !existedBefore || image.dir {
				return ErrNativeOwnership
			}
			if strings.Contains(string(image.data), c.Marker) {
				return fmt.Errorf("gen: marker already present in %s", a.File)
			}
			raw, ok := snippets[GeneratorsRelPath+"/"+a.Insert]
			if !ok {
				return ErrNativeOwnership
			}
			block, err := nativeRender(a.Insert, raw, c)
			if err != nil {
				return err
			}
			updated, err := insertBeforeAnchor(string(image.data), a.Anchor, string(block))
			if err != nil {
				return err
			}
			image.data = []byte(updated)
			p.after[a.File] = image
			edited[a.File] = true
			if !seen[a.File] {
				result.EditedFiles = append(result.EditedFiles, a.File)
				seen[a.File] = true
			}
		}
		p.result.Results = append(p.result.Results, result)
		p.operationNames = append(p.operationNames, op.Name)
	}
	for name := range edited {
		p.result.EditedFiles = append(p.result.EditedFiles, name)
	}
	sort.Strings(p.result.EditedFiles)
	return nil
}

func (p *NativePlan) add(name string, raw []byte, mode fs.FileMode) error {
	for node := name; node != "."; node = path.Dir(node) {
		for existing := range p.after {
			if strings.EqualFold(existing, node) && existing != node {
				return ErrNativeOwnership
			}
		}
	}
	for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
		if old, ok := p.after[parent]; ok && !old.dir {
			return ErrNativeOwnership
		}
		if _, ok := p.after[parent]; !ok {
			p.after[parent] = nativeImage{mode: 0o755, dir: true}
		}
	}
	p.after[name] = nativeImage{data: bytes.Clone(raw), mode: mode}
	return nil
}

// nativeTargetRecord is the proposed inert v1 generator inventory record.
// These records never authorize source selection, writes or execution.
type nativeTargetRecord struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}
type nativeTargetLock struct {
	Version int                  `json:"version"`
	Targets []nativeTargetRecord `json:"targets"`
}

func (p *NativePlan) recordOwnership(inv ownership.Inventory) error {
	var targets nativeTargetLock
	if canonicaljson.DecodeStrict(p.before[".tplaiter/generator-targets.lock.json"].data, &targets) != nil || targets.Version != 1 || targets.Targets == nil {
		return ErrNativeOwnership
	}
	seen := map[string]bool{}
	for _, record := range targets.Targets {
		image, ok := p.before[record.Path]
		if !ok || image.dir || seen[record.Path] || nativePath(record.Path) != nil || record.Kind == "" || record.Name == "" || record.SHA256 != evidencecas.Digest(image.data) || record.Mode != uint32(image.mode) {
			return ErrNativeOwnership
		}
		seen[record.Path] = true
	}
	for i, result := range p.result.Results {
		for _, name := range result.CreatedFiles {
			if seen[name] {
				return ErrNativeOwnership
			}
			image := p.after[name]
			targets.Targets = append(targets.Targets, nativeTargetRecord{Path: name, Kind: result.Kind, Name: p.operationNames[i], SHA256: evidencecas.Digest(image.data), Mode: uint32(image.mode)})
			seen[name] = true
		}
	}
	sort.Slice(targets.Targets, func(i, j int) bool { return targets.Targets[i].Path < targets.Targets[j].Path })
	targetRaw, err := canonicaljson.Canonical(targets)
	if err != nil {
		return err
	}
	old := p.after[".tplaiter/generator-targets.lock.json"]
	old.data = targetRaw
	p.after[".tplaiter/generator-targets.lock.json"] = old
	byPath := map[string]ownership.Artifact{}
	for _, a := range inv.Artifacts {
		byPath[a.Path] = a
	}
	changed := append(append([]string{}, p.result.CreatedFiles...), p.result.EditedFiles...)
	for _, name := range changed {
		image := p.after[name]
		a, err := ownership.ArtifactFor(name, image.data, image.mode, "")
		if err != nil {
			return err
		}
		byPath[name] = a
	}
	inv.Artifacts = nil
	for _, a := range byPath {
		inv.Artifacts = append(inv.Artifacts, a)
	}
	sort.Slice(inv.Artifacts, func(i, j int) bool { return inv.Artifacts[i].Path < inv.Artifacts[j].Path })
	raw, err := canonicaljson.Canonical(inv)
	if err != nil {
		return err
	}
	old = p.after[ownership.InventoryRelPath]
	old.data = raw
	p.after[ownership.InventoryRelPath] = old
	return nil
}

func cloneNativeOperations(in []NativeOperation) []NativeOperation {
	out := make([]NativeOperation, len(in))
	for i, op := range in {
		out[i] = op
		out[i].Provided = map[string]string{}
		for k, v := range op.Provided {
			out[i].Provided[k] = v
		}
	}
	return out
}
