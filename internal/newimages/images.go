package newimages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"gopkg.in/yaml.v3"
)

var ErrUnsafe = errors.New("native new image: unsafe projection")

// Context is pure image construction data. It cannot admit a source, execute
// formatting or publish files. Managed publication independently rebuilds it.
type Context struct {
	ID          string
	Source      *sourceadapter.Source
	Info        manifest.ProjectInfo
	Port        int
	Result      *renderref.Result
	Prepared    *operationtrust.PreparedNew
	Resources   *resources.ResourceImages
	Sources     map[string]survey.Source
	Interactive bool
}

func Build(c Context) (map[string][]byte, error) {
	if c.Source == nil || c.Prepared == nil || c.Resources == nil || c.Result == nil {
		return nil, ErrUnsafe
	}
	return build(c.ID, c.Source, c.Info, c.Port, c.Result, c.Prepared.RootLock(), c.Prepared.DependencyLock(), c.Resources, c.Sources, c.Interactive)
}

func build(id string, src *sourceadapter.Source, info manifest.ProjectInfo, port int, result *renderref.Result, rootLock provenance.RootTemplateLock, dependencyLock provenance.TemplateLock, resourceImages *resources.ResourceImages, sources map[string]survey.Source, interactive bool) (files map[string][]byte, err error) {
	if result == nil || result.Template == nil {
		return nil, ErrUnsafe
	}
	if _, err := settings.Resolve(result.Template, result.Resolved.Values); err != nil {
		return nil, err
	}
	files = make(map[string][]byte, len(result.Files)+12)
	write := func(path string, raw []byte) error {
		if _, exists := files[path]; exists {
			return ErrUnsafe
		}
		files[path] = append([]byte(nil), raw...)
		return nil
	}
	inv := ownership.Inventory{Version: 1, Artifacts: []ownership.Artifact{}}
	paths := make([]string, 0, len(result.Files))
	for path := range result.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		data := result.Files[path]
		if err := write(path, data); err != nil {
			return nil, err
		}
		artifact, err := ownership.ArtifactFor(path, data, 0o644, "")
		if err != nil {
			return nil, err
		}
		inv.Artifacts = append(inv.Artifacts, artifact)
	}
	if err := resourceImages.Validate(rootLock); err != nil {
		return nil, err
	}
	for _, a := range resourceImages.Lock.Artifacts {
		if err := write(a.Path, resourceImages.Files[a.Path]); err != nil {
			return nil, err
		}
		// Ownership is deliberately only path/hash/mode; provenance lives in the lock.
		inv.Artifacts = append(inv.Artifacts, ownership.Artifact{Path: a.Path, SHA256: strings.TrimPrefix(a.SHA256, "sha256:"), Mode: a.Mode})
	}
	sort.Slice(inv.Artifacts, func(i, j int) bool { return inv.Artifacts[i].Path < inv.Artifacts[j].Path })
	if err := provenance.ValidateLockPair(rootLock, dependencyLock); err != nil {
		return nil, err
	}
	for name, lock := range map[string]any{stateledger.RootLockFile: rootLock, stateledger.DependencyLockFile: dependencyLock} {
		raw, err := canonicaljson.Canonical(lock)
		if err != nil {
			return nil, err
		}
		if err := write(".tplaiter/"+name, raw); err != nil {
			return nil, err
		}
	}
	answers := map[string]stateledger.Answer{}
	for k, v := range result.Resolved.Values {
		source := "default"
		if interactive || (sources[k] != "" && sources[k] != survey.SourceDefault) {
			source = "user"
		}
		answers[k] = stateledger.Answer{Value: v, Source: source}
	}
	marker := stateledger.ProjectV2{APIVersion: stateledger.ProjectV2APIVersion, Kind: "Project", ID: id, Template: stateledger.TemplateIdentity{Repo: src.Alias, Name: src.Name, RequestedRef: rootLock.Root.RequestedRef, ResolvedCommit: rootLock.Root.Commit}, Project: map[string]any{"name": info.Name, "slug": info.Slug, "module": info.Module, "system": info.System, "domain": info.Domain}, Answers: answers, Runtime: map[string]any{"port": port}, State: stateledger.StandardPointers()}
	images := map[string]any{
		engine.BaselineRelPath:           result.Baseline,
		ownership.InventoryRelPath:       inv,
		resources.NativeResourceLockPath: resourceImages.Lock,
		".tplaiter/ai-managed.json": struct {
			Version int      `json:"version"`
			Files   []string `json:"files"`
		}{1, []string{}},
		".tplaiter/generator-targets.lock.json": struct {
			Version int   `json:"version"`
			Targets []any `json:"targets"`
		}{1, []any{}},
		".tplaiter/managed-blocks.json": managedblocks.Baseline{Schema: managedblocks.SchemaVersion, Files: map[string]managedblocks.FileBaseline{}},
		".tplaiter/migrations.json":     migrations.Ledger{Version: 1, Applied: []migrations.LedgerEntry{}},
	}
	for path, image := range images {
		raw, err := canonicaljson.Canonical(image)
		if err != nil {
			return nil, err
		}
		if err := write(path, raw); err != nil {
			return nil, err
		}
	}
	raw, err := yaml.Marshal(marker)
	if err != nil {
		return nil, err
	}
	if err := write(".tplaiter/project.yaml", raw); err != nil {
		return nil, err
	}
	raw, err = fs.ReadFile(src.Snapshot, "template.manifest.yaml")
	if err != nil {
		return nil, err
	}
	if err := write(manifest.SnapshotRelPath, raw); err != nil {
		return nil, err
	}
	return files, nil
}

// BuildManaged is pure construction data. The publication owner must supply
// exactly the outputs obtained from verified formatter pairs and independently
// rebuild these complete images before admitting either warm or cold writes.
func BuildManaged(c Context, formatted map[string][]byte) (map[string][]byte, error) {
	if c.Prepared == nil {
		return nil, ErrUnsafe
	}
	return buildManaged(c, c.Prepared.RootLock(), c.Prepared.DependencyLock(), formatted)
}

// BuildContextManaged consumes only the same runtime's genuine native-v2 intent.
// It calculates images; it grants neither execution nor publication authority.
func BuildContextManaged(ctx context.Context, r *trustload.Runtime, intent *contextsource.PreparedNativeNew, c Context, formatted map[string][]byte) (map[string][]byte, error) {
	if intent == nil || c.Prepared != nil {
		return nil, ErrUnsafe
	}
	result, err := intent.Rendered(ctx, r)
	if err != nil {
		return nil, err
	}
	root, err := intent.RootLock(ctx, r)
	if err != nil {
		return nil, err
	}
	dependencies, err := intent.DependencyLock(ctx, r)
	if err != nil {
		return nil, err
	}
	c.Result = result
	images, err := buildManaged(c, root, dependencies, formatted)
	if err != nil {
		return nil, err
	}
	if err = intent.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	return images, nil
}

func buildManaged(c Context, root provenance.RootTemplateLock, dependencies provenance.TemplateLock, formatted map[string][]byte) (map[string][]byte, error) {
	if c.Source == nil || c.Resources == nil || c.Result == nil || c.Result.Baseline == nil || len(formatted) == 0 {
		return nil, ErrUnsafe
	}
	result := *c.Result
	result.Files = make(map[string][]byte, len(c.Result.Files))
	baseline := *c.Result.Baseline
	baseline.Files = make(map[string]string, len(c.Result.Baseline.Files))
	for path, digest := range c.Result.Baseline.Files {
		baseline.Files[path] = digest
	}
	selected := map[string]bool{}
	for path, raw := range c.Result.Files {
		data := raw
		if bytes.Contains(raw, []byte("tplater:managed-")) {
			output, exists := formatted[path]
			if !exists {
				return nil, ErrUnsafe
			}
			data = output
			selected[path] = true
			sum := sha256.Sum256(output)
			baseline.Files[path] = hex.EncodeToString(sum[:])
		}
		result.Files[path] = append([]byte(nil), data...)
	}
	if len(selected) != len(formatted) {
		return nil, ErrUnsafe
	}
	for path := range formatted {
		if !selected[path] {
			return nil, ErrUnsafe
		}
	}
	result.Baseline = &baseline
	c.Result = &result
	files, err := build(c.ID, c.Source, c.Info, c.Port, c.Result, root, dependencies, c.Resources, c.Sources, c.Interactive)
	if err != nil {
		return nil, err
	}
	managed, err := managedblocks.SignedRootBaseline(result.Files, root.Root)
	if err != nil || len(managed.Files) == 0 {
		return nil, ErrUnsafe
	}
	raw, err := canonicaljson.Canonical(managed)
	if err != nil {
		return nil, err
	}
	files[".tplaiter/managed-blocks.json"] = raw
	return files, nil
}
