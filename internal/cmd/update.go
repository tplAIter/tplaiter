package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"github.com/tplAIter/tplaiter/internal/update"
)

// updateRunner — runner for `tplater update` post-update hooks. A package
// variable following newRunner/runRunner for substitution in tests.
var updateRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newUpdateCmd)
}

// newUpdateCmd creates `tplater update`: a 3-way update of the project to a new
// template version with a five-category report and conflict markers.
func newUpdateCmd() *cobra.Command {
	var (
		to             string
		all            bool
		dryRun         bool
		check          bool
		sourceInput    string
		projectContext string
	)

	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunTrustOwned),

		Use:   "update",
		Short: "Update project to new template version (3-way merge)",
		Long: "Updates the generated project to target template version using the 3-way merge model " +
			"(base is a clean render of the pinned version, target is a render of the new version; " +
			"user edits are determined by .tplaiter/baseline.json). Non-overlapping edits merge automatically; " +
			"overlapping edits produce conflict markers " +
			"(<<<<<<< / ======= / >>>>>>>) and exit code 2.\n\n" +
			"Without --to, uses the latest stable tag from repository cache (`tplater repo update` " +
			"fetches new tags). --dry-run computes the plan without writing; --check scans the tree " +
			"for remaining conflict markers (exit code 1); --all processes all registry projects.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case check:
				setResultOperation(cmd, resultdto.OperationUpdateCheck)
			case dryRun:
				setResultOperation(cmd, resultdto.OperationUpdatePlan)
			default:
				setResultOperation(cmd, resultdto.OperationUpdateApply)
			}
			if all {
				return update.ErrLifecycleUnavailable
			}
			if check {
				return checkLocalConflicts(cmd)
			}
			runtime, err := composeRuntimeForProject(cmd.Context(), projectContext)
			if err != nil {
				return err
			}
			defer runtime.Close()
			if !dryRun {
				return update.ErrLifecycleUnavailable
			}
			if sourceInput == "" {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			target, err := readUntrustedDocument(cmd.Context(), sourceInput)
			if err != nil {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			targetSelection, err := operationtrust.DecodeSourceSelection(target)
			if err != nil || (to != "" && targetSelection.Subject.Commit != to) {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			source, err := registeredSourceInput(cmd.Context(), runtime)
			if err != nil {
				return err
			}
			preimage, err := registeredProjectPreimage(cmd.Context(), runtime.ProjectContext().RootPath)
			if err != nil {
				return err
			}
			prepared, err := update.Prepare(cmd.Context(), runtime, operationtrust.PrepareUpdateInput{SourceInput: source, TargetInput: target, Render: renderref.Input{}, RendererVersion: resolveVersion(), PreimageSHA256: preimage})
			if err != nil {
				return err
			}
			if !prepared.ValidFor(runtime.TrustRuntime()) {
				return errors.New("TRUST_RUNTIME_INVALID")
			}
			if jsonMode(cmd) {
				return emitData(cmd, resultdto.OperationUpdatePlan, trustProject(runtime.ProjectContext()),
					resultdto.UpdateData{DryRun: true, To: to, ConflictMarkers: []string{}})
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "dry-run prepared")
			return nil
		},
	}

	f := c.Flags()
	f.StringVar(&to, "to", "", "target template version (by default — latest stable tag)")
	f.BoolVar(&all, "all", false, "update all registry projects with status ok")
	f.BoolVar(&dryRun, "dry-run", false, "show plan without modifying files")
	f.BoolVar(&check, "check", false, "check tree for conflict markers (exit code 1 if found)")
	f.StringVar(&projectContext, "project-context", "", "key of an authenticated installed project context (default: registration key)")
	f.StringVar(&sourceInput, "source-input", "", "sealed JSON of target source selection")
	return withResult(c, resultdto.OperationUpdateApply)
}

// trustProject identifies the project of a trust runtime for a result
// envelope: the project id and root pinned by the runtime configuration, or
// the project marker at that root when the configuration names no id.
func trustProject(pc trustload.ProjectContext) *resultdto.Project {
	if pc.ProjectID != "" && pc.RootPath != "" {
		return &resultdto.Project{ID: pc.ProjectID, Root: pc.RootPath}
	}
	return projectAt(pc.RootPath)
}

// registeredSourceInput reads the existing project pair at its fixed metadata
// paths. The pair is only an assertion until it passes its strict decoders,
// pair validation, exact active profile comparison, and the fresh verification
// performed by operationtrust.PrepareUpdate.
func registeredSourceInput(ctx context.Context, runtime interface {
	ProjectContext() trustload.ProjectContext
	TrustRuntime() *trustverify.Runtime
},
) ([]byte, error) {
	if ctx == nil || runtime == nil || runtime.TrustRuntime() == nil {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	project := runtime.ProjectContext()
	rootRaw, err := readRegisteredLock(ctx, project.RootPath, "root-template.lock.json")
	if err != nil {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	depsRaw, err := readRegisteredLock(ctx, project.RootPath, "template.lock.json")
	if err != nil {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	root, err := provenance.DecodeRootTemplateLock(rootRaw)
	if err != nil {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	deps, err := provenance.DecodeTemplateLock(depsRaw)
	if err != nil || provenance.ValidateLockPair(*root, *deps) != nil || !root.TrustProfile.Equal(runtime.TrustRuntime().Binding()) || !deps.TrustProfile.Equal(runtime.TrustRuntime().Binding()) {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	s := root.Root
	selection := operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: operationtrust.SelectionSubject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}, Evidence: operationtrust.SelectionEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: s.StatementCAS, SignatureCAS: s.SignatureCAS, KeyFingerprint: s.KeyFingerprint, CheckpointCAS: s.CheckpointCAS, InclusionProofCAS: s.InclusionProofCAS}, Dependencies: []string{}}
	raw, err := json.Marshal(selection)
	if err != nil {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	return raw, nil
}

// registeredProjectPreimage is a bounded, local-only snapshot digest used by
// preparation. It never follows symlinks or leaves the registered root.
func registeredProjectPreimage(ctx context.Context, root string) (string, error) {
	if ctx == nil || root == "" || !filepath.IsAbs(root) {
		return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	var paths []string
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return errors.New("scan")
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || !fs.ValidPath(filepath.ToSlash(rel)) || entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("scan")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || len(paths) >= 4096 {
			return errors.New("scan")
		}
		info, err := entry.Info()
		if err != nil || info.Size() < 0 || total+info.Size() > 64<<20 {
			return errors.New("scan")
		}
		total += info.Size()
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	sort.Strings(paths)
	h := sha256.New()
	remaining := int64(64 << 20)
	for _, rel := range paths {
		if _, err := h.Write([]byte(rel)); err != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		if _, err := h.Write([]byte{0}); err != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		data, err := readRegisteredPreimageFile(ctx, root, rel, remaining)
		if err != nil || int64(len(data)) > remaining || ctx.Err() != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		remaining -= int64(len(data))
		if _, err := h.Write(data); err != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		if _, err := h.Write([]byte{0}); err != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func checkLocalConflicts(cmd *cobra.Command) error {
	// --check is intentionally local and bounded; it does not load a manager,
	// source ref, registry, or publisher. The project root is the current dir.
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	found, err := update.ScanConflicts(root, nil)
	if err != nil {
		return err
	}
	markersErr := errors.New("conflict markers found")
	if jsonMode(cmd) {
		env := newResult(resultdto.OperationUpdateCheck)
		env.Project = projectAt(root)
		env.Summary.Conflicts = len(found)
		if err := env.SetData(resultdto.UpdateData{ConflictMarkers: nonNil(found)}); err != nil {
			return err
		}
		if len(found) == 0 {
			return emitResult(cmd, env, resultdto.ExitSuccess, nil)
		}
		// Markers left in the tree are a finding (exit 1), not a failure.
		env.Status = resultdto.StatusConflicted
		for _, path := range found {
			env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "TPL-E-CONFLICT-MARKER", Severity: "error", Message: "conflict markers remain in the file", Path: path, Details: map[string]any{}})
		}
		return emitResult(cmd, env, resultdto.ExitFinding, markersErr)
	}
	for _, path := range found {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), path)
	}
	if len(found) != 0 {
		return &ExitError{Code: 1, Err: markersErr}
	}
	return nil
}
