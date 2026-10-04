package newcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/survey"
)

// runLive is the bounded native, action-free lifecycle. It never calls the
// legacy checkout, runner, hook or environment helpers in newcmd.go.
func runLive(ctx context.Context, opts Options, d Deps, fault newtransaction.FaultInjector) (err error) {
	if ctx == nil || d.Runtime == nil || d.Runtime.TrustRuntime() == nil {
		return errors.New("TRUST_RUNTIME_INVALID")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	project := d.Runtime.ProjectContext()
	slug, err := Slugify(opts.ProjectName)
	if err != nil {
		return err
	}
	target := opts.Dir
	if target == "" {
		target = "./" + slug
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return err
	}
	// Project-root authority comes exclusively from the installed context.
	if (!opts.DryRun && target != project.RootPath) || project.ProjectID == "" {
		return errors.New("TRUST_PROJECT_CONTEXT_MISMATCH")
	}
	if !opts.DryRun {
		if err := vacantLive(target); err != nil {
			return err
		}
	}
	src, err := sourceadapter.Resolve(ctx, d.Runtime, d.Home, opts.Ref, d.SourceInput)
	if err != nil {
		return err
	}
	tpl, err := loadTemplateFromFS(src.Snapshot)
	if err != nil {
		return err
	}
	// Resource and execution consumers are separate slices. Refuse rather than
	// silently omit declared work or hand it to an ambient runner.
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || len(tpl.Commands) != 0 || tpl.AIConfig.Path != "" || (opts.EnvSetup != nil && *opts.EnvSetup) {
		return fmt.Errorf("%w: live new supports native action-free templates only", operationtrust.ErrSourceAdapterUnsupported)
	}
	constraint := tpl.Requires.Tplaiter
	if constraint == "" {
		constraint = tpl.Requires.Tplater
	}
	if tpl.Requires.Tplaiter != "" && tpl.Requires.Tplater != "" && tpl.Requires.Tplaiter != tpl.Requires.Tplater {
		return errors.New("newcmd: conflicting version requirements")
	}
	if err := checkTplaterVersion(constraint, opts.CLIVersion); err != nil {
		return err
	}
	r := &run{opts: opts, d: d}
	preset, sources, err := r.buildPreset(tpl)
	if err != nil {
		return err
	}
	out := d.Out
	if out == nil {
		out = io.Discard
	}
	if opts.Interactive && !opts.Defaults && d.Prompter == nil {
		return errors.New("newcmd: interactive prompter is required")
	}
	answers, err := survey.AskFlow(tpl, preset, survey.FlowOptions{Defaults: opts.Defaults, Interactive: opts.Interactive, PresetSources: sources}, d.Prompter, out, d.Palette)
	if err != nil {
		return err
	}
	info := manifest.ProjectInfo{Name: opts.ProjectName, Slug: slug, Module: r.moduleOrDefault(slug), System: opts.System, Domain: opts.Domain}
	port := opts.Port
	if port == 0 {
		port = defaultPort
	}
	prepared, err := Prepare(ctx, d.Runtime, operationtrust.PrepareNewInput{SourceInput: src.Input, Render: renderref.Input{Values: answers.Values, Project: info, Runtime: manifest.ProjectRuntime{Port: port}, Repo: src.Alias}, RendererVersion: opts.CLIVersion})
	if err != nil {
		return err
	}
	if !prepared.ValidFor(d.Runtime.TrustRuntime()) {
		return errors.New("TRUST_RUNTIME_INVALID")
	}
	selection, err := operationtrust.DecodeSourceSelection(src.Input)
	if err != nil {
		return err
	}
	resolution, err := d.Runtime.TrustRuntime().VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil {
		return err
	}
	resourceImages, err := resources.PlanNativeGeneratorImages(d.Runtime.TrustRuntime(), resolution, prepared.RootLock())
	if err != nil {
		return err
	}
	result := prepared.Rendered()
	// The managed-block consumer is not restored in this slice.
	for path, data := range result.Files {
		if !fs.ValidPath(path) || path == "." || path == ".tplaiter" || strings.HasPrefix(path, ".tplaiter/") || path == ".tplater" || strings.HasPrefix(path, ".tplater/") {
			return newtransaction.ErrUnsafe
		}
		if strings.Contains(string(data), "tplater:managed-") {
			return operationtrust.ErrSourceAdapterUnsupported
		}
	}
	if opts.DryRun {
		return nil
	}
	if d.Home == "" {
		return errors.New("newcmd: registry home is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Begin needs an existing, empty directory. Mkdir (not MkdirAll) refuses a
	// competing creator; the transaction captures the empty before image.
	if err := vacantLive(target); err != nil {
		return err
	}
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(target, 0o755); err != nil {
			return err
		}
	}
	images, err := liveTreeImages(project.ProjectID, src, info, port, result, prepared, resourceImages, sources, opts.Interactive && !opts.Defaults)
	if err != nil {
		return err
	}
	tx, err := newtransaction.BeginSealedWithFault(d.Home, target, images, fault)
	if err != nil {
		return err
	}
	defer tx.Release()
	commitAttempted := false
	defer func() {
		if err != nil && !commitAttempted && !errors.Is(err, newtransaction.ErrInjectedCrash) {
			err = errors.Join(err, tx.Abort())
		}
	}()
	// Begin captures its before image while holding the transaction lock. A
	// concurrent writer between the vacancy check and staging must not become
	// part of the newly generated project; abort preserves that writer's image.
	if tx.Journal().TargetBeforeTreeSHA != evidencecas.Digest(nil) {
		return newtransaction.ErrUnsafe
	}
	if err := writeLiveTree(tx.Workspace(), images); err != nil {
		// A failed exclusive write may have encountered a foreign path. Keep
		// partial writes and the journal; never infer ownership from filenames.
		commitAttempted = true
		return fmt.Errorf("newcmd: transaction %s requires recovery: %w", tx.ID(), errors.Join(err, newtransaction.ErrOwnershipUncertain))
	}
	if err := tx.SealOutputs(); err != nil {
		commitAttempted = true
		return fmt.Errorf("newcmd: transaction %s requires recovery: %w", tx.ID(), err)
	}
	plan, err := liveRegistryPlan(d.Home, target, project.ProjectID, src, result, d.Now)
	if err != nil {
		return err
	}
	if err := tx.PrepareRegistry(plan); err != nil {
		return err
	}
	// Re-resolve the selector and re-authenticate evidence immediately before
	// publication. A moved ref, changed policy or revoked publisher fails closed.
	if _, err := sourceadapter.Resolve(ctx, d.Runtime, d.Home, opts.Ref, src.Input); err != nil {
		return err
	}
	if err := d.Runtime.TrustRuntime().CheckBinding(prepared.RootLock().TrustProfile); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	commitAttempted = true
	if err := tx.Commit(plan); err != nil {
		return fmt.Errorf("newcmd: transaction %s requires recovery: %w", tx.ID(), err)
	}
	if err := tx.Finalize(); err != nil {
		return fmt.Errorf("newcmd: transaction %s requires recovery: %w", tx.ID(), err)
	}
	_, err = fmt.Fprintf(out, "Project %s created in %s\n", slug, target)
	return err
}

func vacantLive(target string) error {
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return newtransaction.ErrUnsafe
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("newcmd: target is not empty; use update")
	}
	return nil
}

func liveTreeImages(id string, src *sourceadapter.Source, info manifest.ProjectInfo, port int, result *renderref.Result, prepared *operationtrust.PreparedNew, resourceImages *resources.ResourceImages, sources map[string]survey.Source, interactive bool) (files map[string][]byte, err error) {
	files = make(map[string][]byte, len(result.Files)+12)
	write := func(path string, raw []byte) error {
		if _, exists := files[path]; exists {
			return newtransaction.ErrUnsafe
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
	rootLock, dependencyLock := prepared.RootLock(), prepared.DependencyLock()
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
	marker := stateledger.ProjectV2{APIVersion: stateledger.ProjectV2APIVersion, Kind: "Project", ID: id, Template: stateledger.TemplateIdentity{Repo: src.Alias, Name: src.Name, RequestedRef: prepared.RootLock().Root.RequestedRef, ResolvedCommit: prepared.RootLock().Root.Commit}, Project: map[string]any{"name": info.Name, "slug": info.Slug, "module": info.Module, "system": info.System, "domain": info.Domain}, Answers: answers, Runtime: map[string]any{"port": port}, State: stateledger.StandardPointers()}
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
	raw, err = fs.ReadFile(src.Snapshot, templateManifestFileName)
	if err != nil {
		return nil, err
	}
	if err := write(manifest.SnapshotRelPath, raw); err != nil {
		return nil, err
	}
	return files, nil
}

func liveRegistryPlan(home, target, id string, src *sourceadapter.Source, result *renderref.Result, now func() time.Time) (plan newtransaction.RegistryPlan, err error) {
	plan.Home = home
	err = state.WithLock(home, func() error {
		raw, exists, _, err := state.ReadProjectsRaw(home)
		if err != nil {
			return err
		}
		projects := state.DefaultProjects()
		if exists {
			projects, err = state.DecodeProjectsRaw(raw)
			if err != nil {
				return err
			}
			plan.Before = raw
		}
		for _, p := range projects.Items {
			if p.ID == id || p.Path == target {
				return errors.New("newcmd: project is already registered")
			}
		}
		stamp := time.Now().UTC()
		if now != nil {
			stamp = now()
		}
		baseline, err := canonicaljson.Canonical(result.Baseline)
		if err != nil {
			return err
		}
		projects.Upsert(state.ProjectRef{ID: id, Path: target, Template: state.TemplateSelection{Repo: src.Alias, Name: src.Name, Version: src.Version}, CreatedAt: stamp, LastSeenAt: stamp, BaselineSHA: strings.TrimPrefix(evidencecas.Digest(baseline), "sha256:")})
		plan.After, err = state.MarshalProjects(projects)
		return err
	})
	return plan, err
}

// Write only bytes already sealed in the expected inventory, including both
// validated canonical lock files. No ledger replacement can overwrite a
// concurrent file in this initially empty project.
func writeLiveTree(root string, images map[string][]byte) error {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	// Begin owns this state directory. Keep its 0700 mode and never chmod
	// either it or the caller's project root as part of output creation.
	stateDir, err := dir.Lstat(".tplaiter")
	if err != nil || !stateDir.IsDir() || stateDir.Mode().Perm() != 0o700 {
		return newtransaction.ErrOwnershipUncertain
	}
	rootFile, err := dir.Open(".")
	if err != nil {
		return err
	}
	rootInfo, statErr := rootFile.Stat()
	if err := errors.Join(statErr, rootFile.Close()); err != nil {
		return err
	}
	observedDirs := map[string]os.FileInfo{".": rootInfo, ".tplaiter": stateDir}
	paths := make([]string, 0, len(images))
	for name := range images {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		if err := mkdirLiveParents(dir, filepath.Dir(name), observedDirs); err != nil {
			return err
		}
		file, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(images[name])
		// O_EXCL gave us this inode, not merely its mutable pathname. Apply
		// the sealed mode through the retained FD regardless of user umask.
		if err := errors.Join(writeErr, chmodSyncLive(file, 0o644), file.Close()); err != nil {
			return err
		}
	}
	return nil
}

func chmodSyncLive(file *os.File, mode os.FileMode) error {
	if err := file.Chmod(mode); err != nil {
		return err
	}
	return file.Sync()
}

// A successful mkdir does not identify the inode at its pathname afterwards.
// Create with the exact mode in an isolated child and never chmod directories.
// Later observations validate mode/identity; they do not prove mkdir ownership.
func mkdirLiveParents(root *os.Root, parent string, observed map[string]os.FileInfo) error {
	return mkdirLiveParentsWith(root, parent, observed, mkdirLiveDirectory)
}

type liveDirectoryCreator func(*os.Root, string, os.FileInfo) error

func mkdirLiveParentsWith(root *os.Root, parent string, observed map[string]os.FileInfo, create liveDirectoryCreator) error {
	if parent == "." {
		return nil
	}
	if err := mkdirLiveParentsWith(root, filepath.Dir(parent), observed, create); err != nil {
		return err
	}
	if prior, ok := observed[parent]; ok {
		now, err := root.Lstat(parent)
		if err != nil || !now.IsDir() || !os.SameFile(prior, now) {
			return newtransaction.ErrOwnershipUncertain
		}
		return nil
	}
	if err := create(root, parent, observed[filepath.Dir(parent)]); err != nil {
		return errors.Join(newtransaction.ErrOwnershipUncertain, err)
	}
	// A replacement before this first observation cannot become a chmod
	// target: there is no directory chmod anywhere in the creation path.
	now, err := root.Lstat(parent)
	if err != nil || !now.IsDir() || now.Mode().Perm() != 0o755 {
		return newtransaction.ErrOwnershipUncertain
	}
	observed[parent] = now
	return nil
}
