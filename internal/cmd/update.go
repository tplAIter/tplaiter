package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// updateRunner — runner for `tplaiter update` post-update hooks. A package
// variable following newRunner/runRunner for substitution in tests.
var updateRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newUpdateCmd)
}

// newUpdateCmd composes the authenticated, action-free native update lifecycle.
func newUpdateCmd() *cobra.Command {
	var controls nativeUpdateControls
	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunTrustOwned),
		Use:         "update", Short: "Update an authenticated native project (3-way merge)",
		Long: "Updates the installed project context from its signed current source to the exact target in --source-input. " +
			"--to, when supplied, must equal that pinned commit. --dir must match the installed root. " +
			"--dry-run prepares a read-only plan; --check with source input checks that plan, otherwise it scans conflict markers. " +
			"Conflicting plans preserve the project and registry. Actions, hooks, tools, environment and --all are unavailable.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runNativeUpdate(cmd, controls) },
	}
	f := c.Flags()
	f.StringVar(&controls.to, "to", "", "exact target commit from the signed source selection")
	f.BoolVar(&controls.all, "all", false, "update all registry projects (currently unavailable)")
	f.BoolVar(&controls.dryRun, "dry-run", false, "show authenticated plan without modifying files")
	f.BoolVar(&controls.check, "check", false, "check target plan, or remaining conflict markers when no source input is given")
	f.StringVar(&controls.key, "project-context", "", "key of an authenticated installed project context")
	f.StringVar(&controls.dir, "dir", "", "locator; must match the installed project root")
	f.StringVar(&controls.sourceInput, "source-input", "", "JSON pinned target source selection and publisher evidence locators")
	c.AddCommand(newNativeUpdateAbortCmd(), newNativeUpdateContinueCmd())
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

func checkNativeConflicts(cmd *cobra.Command, root string, project *resultdto.Project) error {
	found, err := scanNativeConflictMarkers(cmd.Context(), root)
	if err != nil {
		return err
	}
	markersErr := errors.New("conflict markers found")
	if jsonMode(cmd) {
		env := newResult(resultdto.OperationUpdateCheck)
		env.Project = project
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
