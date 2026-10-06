package newcmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/newimages"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/trustverify"
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
	if opts.FormatStage && (opts.Prepare || opts.DryRun || opts.Interactive && !opts.Defaults) {
		return ErrManagedControls
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
	// A version header chooses only the matching closed admission route. A failed
	// v2 decoder is never retried through the legacy source adapter.
	var header struct {
		APIVersion string `json:"apiVersion"`
	}
	if len(d.SourceInput) <= 1<<20 && json.Unmarshal(d.SourceInput, &header) == nil && header.APIVersion == contextsource.ContextSourceSelectionAPIVersion {
		return runContextManagedLive(ctx, opts, d, slug)
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
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || operationtrust.ValidateProjectBuildSource(ctx, d.Runtime.TrustRuntime(), src.Input, tpl) != nil || tpl.AIConfig.Path != "" || (opts.EnvSetup != nil && *opts.EnvSetup) {
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
	managed := false
	for path, data := range result.Files {
		if !fs.ValidPath(path) || path == "." || path == ".tplaiter" || strings.HasPrefix(path, ".tplaiter/") || path == ".tplater" || strings.HasPrefix(path, ".tplater/") {
			return newtransaction.ErrUnsafe
		}
		if strings.Contains(string(data), "tplater:managed-") {
			managed = true
		}
	}
	if managed {
		return runManagedLive(ctx, opts, d, src, info, port, answers.Values, sources)
	}
	if opts.FormatStage || len(d.ToolSourceInput) != 0 || len(d.FormatApprovals) != 0 {
		return ErrManagedControls
	}
	if opts.DryRun || opts.Prepare {
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

func liveTreeImages(id string, src *sourceadapter.Source, info manifest.ProjectInfo, port int, result *renderref.Result, prepared *operationtrust.PreparedNew, resourceImages *resources.ResourceImages, sources map[string]survey.Source, interactive bool) (map[string][]byte, error) {
	files, err := newimages.Build(newimages.Context{ID: id, Source: src, Info: info, Port: port, Result: result, Prepared: prepared, Resources: resourceImages, Sources: sources, Interactive: interactive})
	if errors.Is(err, newimages.ErrUnsafe) {
		return nil, newtransaction.ErrUnsafe
	}
	return files, err
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

var ErrManagedControls = errors.New("MANAGED_FORMAT_CONTROLS_INVALID")

// ManagedPreparation is detached reporting data. It cannot authorize execution
// or publication, and no transport approval paths enter its semantic frame.
type ManagedPreparation struct {
	APIVersion string                           `json:"apiVersion"`
	Requests   []trustverify.ExecutionRequest   `json:"requests"`
	References map[string]formatproof.Reference `json:"references"`
}

func runManagedLive(ctx context.Context, opts Options, d Deps, src *sourceadapter.Source, info manifest.ProjectInfo, port int, values settings.Values, origins map[string]survey.Source) (err error) {
	return runManagedLiveVersion(ctx, opts, d, src, info, port, values, origins, "tplaiter.dev/managed-new-clean-input/v1")
}

func runManagedLiveVersion(ctx context.Context, opts Options, d Deps, src *sourceadapter.Source, info manifest.ProjectInfo, port int, values settings.Values, origins map[string]survey.Source, version string) (err error) {
	if len(d.ToolSourceInput) == 0 || d.Home == "" {
		return ErrManagedControls
	}
	canonicalOrigins := map[string]survey.Source{}
	for key := range values {
		canonicalOrigins[key] = survey.SourceDefault
		if origin, ok := origins[key]; ok {
			canonicalOrigins[key] = origin
		}
	}
	input := formatproof.NewCleanInput{APIVersion: version, Home: d.Home, Ref: opts.Ref, SourceInput: src.Input, ToolSource: d.ToolSourceInput, Render: renderref.Input{Values: values, Project: info, Runtime: manifest.ProjectRuntime{Port: port}, Repo: src.Alias}, RendererVersion: opts.CLIVersion, Origins: canonicalOrigins, Interactive: opts.Interactive && !opts.Defaults}
	prepared, err := formatproof.PrepareNewClean(ctx, d.Runtime, input)
	if err != nil {
		return err
	}
	requests, err := prepared.RequiredRequests(ctx)
	if err != nil {
		return err
	}
	report := ManagedPreparation{APIVersion: "tplaiter.dev/managed-new-preparation/v1", Requests: requests, References: prepared.References()}
	if d.PreparedOut != nil {
		raw, err := canonicaljson.Canonical(report)
		if err != nil {
			return err
		}
		if _, err := d.PreparedOut.Write(raw); err != nil {
			return err
		}
	}
	if opts.Prepare || opts.DryRun {
		if len(d.FormatApprovals) != 0 {
			return ErrManagedControls
		}
		return nil
	}
	if opts.FormatStage {
		_, err := formatproof.StageNewClean(ctx, prepared, d.FormatApprovals)
		return err
	}
	if len(d.FormatApprovals) != 0 {
		return ErrManagedControls
	}
	clean, err := formatproof.OpenNewClean(ctx, prepared, prepared.References())
	if err != nil {
		return err
	}
	publication, err := formatproof.BuildNewPublication(ctx, prepared, clean)
	if err != nil {
		return err
	}
	target := d.Runtime.ProjectContext().RootPath
	if err := vacantLive(target); err != nil {
		return err
	}
	if _, err := os.Lstat(target); errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(target, 0o755); err != nil {
			return err
		}
	}
	tx, projection, err := newtransaction.BeginManagedPublication(ctx, d.Runtime, publication)
	if err != nil {
		return err
	}
	defer tx.Release()
	publishing := false
	defer func() {
		if err != nil && !publishing {
			err = errors.Join(err, tx.Abort())
		}
	}()
	if tx.Journal().TargetBeforeTreeSHA != evidencecas.Digest(nil) {
		return newtransaction.ErrUnsafe
	}
	if err := writeLiveTree(tx.Workspace(), projection.Images); err != nil {
		publishing = true
		return fmt.Errorf("newcmd: transaction %s requires recovery: %w", tx.ID(), errors.Join(err, newtransaction.ErrOwnershipUncertain))
	}
	if err := tx.SealOutputs(); err != nil {
		publishing = true
		return err
	}
	plan := newtransaction.RegistryPlan{Home: projection.Home, Before: projection.RegistryBefore, After: projection.RegistryAfter}
	if err := tx.PrepareRegistry(plan); err != nil {
		return err
	}
	publishing = true
	if err := tx.Commit(plan); err != nil {
		return fmt.Errorf("newcmd: transaction %s requires recovery: %w", tx.ID(), err)
	}
	if err := tx.Finalize(); err != nil {
		return fmt.Errorf("newcmd: transaction %s requires recovery: %w", tx.ID(), err)
	}
	if d.Out != nil {
		_, err = fmt.Fprintf(d.Out, "Project %s created in %s\n", info.Slug, target)
	}
	return err
}

// runContextManagedLive uses the published opaque DAG carrier and the same
// publication owner. It has no ambient checkout, hook or runner fallback.
func runContextManagedLive(ctx context.Context, opts Options, d Deps, slug string) error {
	src, err := sourceadapter.ResolveContextSources(ctx, d.Runtime, d.Home, opts.Ref, d.SourceInput)
	if err != nil {
		return err
	}
	defer src.Close()
	root, err := src.Root(ctx, d.Runtime)
	if err != nil {
		return err
	}
	tpl, err := loadTemplateFromFS(root.Snapshot)
	if err != nil {
		return err
	}
	if opts.EnvSetup != nil && *opts.EnvSetup {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	constraint := tpl.Requires.Tplaiter
	if constraint == "" {
		constraint = tpl.Requires.Tplater
	}
	if tpl.Requires.Tplaiter != "" && tpl.Requires.Tplater != "" && tpl.Requires.Tplaiter != tpl.Requires.Tplater {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	if err := checkTplaterVersion(constraint, opts.CLIVersion); err != nil {
		return err
	}
	owner := &run{opts: opts, d: d}
	preset, origins, err := owner.buildPreset(tpl)
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
	answers, err := survey.AskFlow(tpl, preset, survey.FlowOptions{Defaults: opts.Defaults, Interactive: opts.Interactive, PresetSources: origins}, d.Prompter, out, d.Palette)
	if err != nil {
		return err
	}
	info := manifest.ProjectInfo{Name: opts.ProjectName, Slug: slug, Module: owner.moduleOrDefault(slug), System: opts.System, Domain: opts.Domain}
	port := opts.Port
	if port == 0 {
		port = defaultPort
	}
	if err := src.RecheckFor(ctx, d.Runtime); err != nil {
		return err
	}
	return runManagedLiveVersion(ctx, opts, d, root, info, port, answers.Values, origins, "tplaiter.dev/managed-new-clean-input/v2")
}
