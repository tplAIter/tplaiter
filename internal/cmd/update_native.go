package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/update"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

type nativeUpdateControls struct {
	key, dir, to, sourceInput string
	all, dryRun, check        bool
}

func runNativeUpdate(cmd *cobra.Command, c nativeUpdateControls) error {
	op := resultdto.OperationUpdateApply
	if c.check {
		op = resultdto.OperationUpdateCheck
	} else if c.dryRun {
		op = resultdto.OperationUpdatePlan
	}
	setResultOperation(cmd, op)
	if c.all {
		return update.ErrLifecycleUnavailable
	}
	// Reuse the installed-context/no-follow root binding used by native Gen.
	r, err := nativeGenRuntime(cmd, nativeGenControls{key: c.key, dir: c.dir})
	if err != nil {
		return err
	}
	defer r.Close()
	if c.check && c.sourceInput == "" {
		if c.to != "" || c.dryRun {
			return &usageError{err: errors.New("update: target checks require --source-input")}
		}
		if _, err := stateledger.VerifyStable(cmd.Context(), r.ProjectContext().RootPath, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
			return err
		}
		return checkNativeConflicts(cmd, r.ProjectContext().RootPath, trustProject(r.ProjectContext()))
	}
	if c.sourceInput == "" {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	target, err := readUntrustedDocument(cmd.Context(), c.sourceInput)
	if err != nil {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	// This is the same closed, operator-enrolled input as new. Selection is
	// untrusted transport; Backend.Prepare freshly verifies both signed closures
	// using installed object/evidence roots, never ambient Git or local manifests.
	selected, err := operationtrust.DecodeSourceSelection(target)
	if err != nil {
		return err
	}
	if c.to != "" && c.to != selected.Subject.Commit {
		return resultdto.NewError("TRUST_SOURCE_SELECTION_MISMATCH", resultdto.ExitTrust, nil)
	}
	if err := nativeUpdateTargetPolicy(cmd.Context(), r, *selected); err != nil {
		return err
	}
	source, err := registeredSourceInput(cmd.Context(), r)
	if err != nil {
		return err
	}
	home, err := readonlyHome()
	if err != nil {
		return err
	}
	backend, err := updateplan.New(r, home, resolveVersion())
	if err != nil {
		return err
	}
	plan, err := backend.Prepare(cmd.Context(), updateplan.Input{SourceInput: source, TargetInput: target})
	if err != nil {
		return err
	}
	raw, err := plan.Marshal()
	if err != nil {
		return err
	}
	var report updateplan.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}
	env := newResult(op)
	env.Project = trustProject(r.ProjectContext())
	env.PlanSHA256, env.CurrentRef, env.TargetRef = plan.Fingerprint(), report.Source.Root.Commit, report.Target.Root.Commit
	for _, change := range report.Changes {
		if change.Operation != "keep" {
			env.Changes = append(env.Changes, resultdto.Change{Path: change.Path, Action: change.Operation})
		}
		if change.Conflict {
			env.Summary.Conflicts++
			env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "TPL-E-NATIVE-UPDATE-CONFLICT", Severity: "error", Path: change.Path, Message: change.Reason, Details: map[string]any{}})
		}
	}
	// Registry is outside the project namespace: report its sealed transition
	// as a diagnostic, never pretend that its home-relative path is a project file.
	if report.Registry.Before.SHA256 != report.Registry.After.SHA256 {
		env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "TPL-I-NATIVE-UPDATE-REGISTRY", Severity: "info", Message: "project registry transition", Details: map[string]any{"beforeSHA256": report.Registry.Before.SHA256, "afterSHA256": report.Registry.After.SHA256}})
	}
	if err := env.SetData(resultdto.UpdateData{DryRun: c.dryRun || c.check, To: env.TargetRef, ConflictMarkers: []string{}}); err != nil {
		return err
	}
	if !report.Publishable {
		env.Status = resultdto.StatusConflicted
		code := resultdto.ExitConflict
		if c.check {
			code = resultdto.ExitFinding
		}
		return emitNativeUpdate(cmd, env, code, updateplan.ErrConflict)
	}
	if len(env.Changes) != 0 {
		env.Status = resultdto.StatusChanges
	}
	if c.check || c.dryRun {
		return emitNativeUpdate(cmd, env, resultdto.ExitSuccess, nil)
	}
	// Only the opaque, freshly prepared plan admits a concrete transaction.
	// Begin reconstructs after actual lease acquisition and Seal rechecks the
	// authenticated native receipt guard. Reporting bytes never grant a writer.
	tx, err := projecttransaction.BeginUpdate(cmd.Context(), plan, plan.Fingerprint())
	if tx != nil {
		defer tx.Release()
	}
	if err != nil {
		return nativeUpdateTransactionError(err)
	}
	id := tx.ID()
	env.TransactionID = &id
	if err := tx.Commit(cmd.Context()); err != nil {
		rollbackErr := tx.Rollback(context.WithoutCancel(cmd.Context()))
		return nativeUpdateTransactionError(errors.Join(err, rollbackErr))
	}
	return emitNativeUpdate(cmd, env, resultdto.ExitSuccess, nil)
}

func nativeUpdateTransactionError(err error) error {
	return resultdto.NewError("TPL-E-NATIVE-UPDATE-TRANSACTION", resultdto.ExitTransaction, err)
}

func emitNativeUpdate(cmd *cobra.Command, env resultdto.Result, code resultdto.ExitCode, cause error) error {
	env.Summary.FilesChanged = len(env.Changes)
	if jsonMode(cmd) {
		return emitResult(cmd, env, code, cause)
	}
	for _, c := range env.Changes {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", c.Action, c.Path)
	}
	for _, d := range env.Diagnostics {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", d.Code, d.Message)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s -> %s (%s)\n", env.CurrentRef, env.TargetRef, env.Operation)
	if code != resultdto.ExitSuccess {
		return &resultExitError{code: code, err: cause}
	}
	return nil
}

// Only a freshly verified sealed source closure is used to inspect configured
// actions. Current native Update cannot execute or implicitly skip them.
func nativeUpdateTargetPolicy(ctx context.Context, r *trustload.Runtime, selected operationtrust.SourceSelection) error {
	resolution, err := r.TrustRuntime().VerifySubject(ctx, selected.TrustSubject(), selected.EvidenceRefs())
	if err != nil {
		return err
	}
	snapshot, err := operationtrust.SnapshotFS(r.TrustRuntime(), resolution)
	if err != nil {
		return err
	}
	tpl, err := renderref.LoadTemplate(snapshot)
	if err != nil {
		return err
	}
	if len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || len(tpl.Commands) != 0 || len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || tpl.AIConfig.Path != "" {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	return nil
}

// Conflict scanning uses the authenticated root and the existing bounded,
// no-follow rooted reader. Symlinks/devices and excessive trees are refusals.
func scanNativeConflictMarkers(ctx context.Context, root string) ([]string, error) {
	found := []string{}
	count := 0
	remaining := int64(64 << 20)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == root {
			return nil
		}
		count++
		if count > 4096 {
			return updateplan.ErrUnsafe
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || !fs.ValidPath(filepath.ToSlash(rel)) || entry.Type()&os.ModeSymlink != 0 {
			return updateplan.ErrUnsafe
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".tplaiter", "docs":
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return updateplan.ErrUnsafe
		}
		data, err := readRegisteredPreimageFile(ctx, root, filepath.ToSlash(rel), remaining)
		if err != nil || int64(len(data)) > remaining {
			return updateplan.ErrUnsafe
		}
		remaining -= int64(len(data))
		first, _, _ := bytes.Cut(data, []byte("\n"))
		if bytes.IndexByte(first, 0) >= 0 {
			return nil
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if strings.HasPrefix(line, "<<<<<<< ") {
				found = append(found, filepath.ToSlash(rel))
				break
			}
		}
		return nil
	})
	sort.Strings(found)
	return found, err
}

// Cold abort obtains authority only from a freshly authenticated kind-bound
// receipt and retained real leases. No generic new/v1 recovery is involved.
func newNativeUpdateAbortCmd() *cobra.Command {
	var key, dir string
	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunTrustOwned),
		Use:         "abort <transaction-id>", Short: "Abort an authenticated native Update transaction",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := nativeGenRuntime(cmd, nativeGenControls{key: key, dir: dir})
			if err != nil {
				return err
			}
			defer r.Close()
			home, err := readonlyHome()
			if err != nil {
				return err
			}
			tx, err := projecttransaction.OpenUpdate(cmd.Context(), r, home, args[0], resolveVersion())
			if err != nil {
				return nativeUpdateTransactionError(err)
			}
			defer tx.Release()
			if err := tx.Rollback(cmd.Context()); err != nil {
				return nativeUpdateTransactionError(err)
			}
			env := newResult(resultdto.OperationUpdateAbort)
			env.Project = trustProject(r.ProjectContext())
			id := tx.ID()
			env.TransactionID = &id
			if jsonMode(cmd) {
				return emitResult(cmd, env, resultdto.ExitSuccess, nil)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "aborted native Update %s\n", id)
			return err
		},
	}
	c.Flags().StringVar(&key, "project-context", "", "key of an authenticated installed project context")
	c.Flags().StringVar(&dir, "dir", "", "locator; must match the installed project root")
	return withResult(c, resultdto.OperationUpdateAbort)
}

// Cold Continue authenticates the native kind-bound receipt and commits under
// retained leases. Preparing prefixes resume only with authenticated staging
// ownership; ambiguous or malformed receipts remain transaction failures.
func newNativeUpdateContinueCmd() *cobra.Command {
	var key, dir string
	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunTrustOwned),
		Use:         "continue <transaction-id>", Short: "Continue an authenticated native Update transaction",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := nativeGenRuntime(cmd, nativeGenControls{key: key, dir: dir})
			if err != nil {
				return err
			}
			defer r.Close()
			home, err := readonlyHome()
			if err != nil {
				return err
			}
			tx, err := projecttransaction.OpenUpdate(cmd.Context(), r, home, args[0], resolveVersion())
			if err != nil {
				return nativeUpdateTransactionError(err)
			}
			defer tx.Release()
			if err := tx.Commit(cmd.Context()); err != nil {
				// Commit owns conditional restoration and publication uncertainty.
				// A continuation failure does not authorize a separate Abort.
				return nativeUpdateTransactionError(err)
			}
			env := newResult(resultdto.OperationUpdateContinue)
			env.Project = trustProject(r.ProjectContext())
			id := tx.ID()
			env.TransactionID = &id
			if jsonMode(cmd) {
				return emitResult(cmd, env, resultdto.ExitSuccess, nil)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "continued native Update %s\n", id)
			return err
		},
	}
	c.Flags().StringVar(&key, "project-context", "", "key of an authenticated installed project context")
	c.Flags().StringVar(&dir, "dir", "", "locator; must match the installed project root")
	return withResult(c, resultdto.OperationUpdateContinue)
}
