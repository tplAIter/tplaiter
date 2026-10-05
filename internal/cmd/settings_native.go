package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/settingscmd"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

type nativeSettingsControls struct {
	key, dir, value string
	dryRun, yes     bool
}

func addNativeSettingsFlags(cmd *cobra.Command, c *nativeSettingsControls, mutable bool) {
	cmd.Flags().StringVar(&c.key, "project-context", "", "key of an authenticated installed project context")
	cmd.Flags().StringVar(&c.dir, "dir", "", "locator; must match the installed project root")
	if mutable {
		cmd.Flags().BoolVar(&c.dryRun, "dry-run", false, "show signed plan without publication")
		cmd.Flags().BoolVar(&c.yes, "yes", false, "apply without interactive confirmation")
	}
}

func nativeSettingsInput(err error) error {
	return resultdto.NewError("TPL-E-SETTINGS-INPUT", resultdto.ExitUsage, err)
}

func nativeSettingsReadError(err error) error {
	for _, kind := range []error{stateledger.ErrUnsafe, stateledger.ErrFutureVersion, stateledger.ErrDowngrade, stateledger.ErrPolicyOrigin, stateledger.ErrDigest, stateledger.ErrEvidence, stateledger.ErrProjectIdentity, stateledger.ErrLegacyLock, updateplan.ErrUnsafe} {
		if errors.Is(err, kind) {
			return resultdto.NewError("TRUST_NATIVE_SETTINGS_STATE_INVALID", resultdto.ExitTrust, err)
		}
	}
	return err
}

func runNativeSettings(cmd *cobra.Command, c nativeSettingsControls, args []string, op resultdto.Operation) error {
	if op == resultdto.OperationSettingsReanswer && len(args) == 0 && cmd.Flags().Changed("value") {
		return nativeSettingsInput(errors.New("settings edit --value requires a group"))
	}
	r, err := nativeGenRuntime(cmd, nativeGenControls{key: c.key, dir: c.dir})
	if err != nil {
		return err
	}
	defer r.Close()
	home, err := readonlyHome()
	if err != nil {
		return err
	}
	backend, err := settingscmd.NewNative(r, home, resolveVersion())
	if err != nil {
		return err
	}
	view, err := backend.Read(cmd.Context())
	if err != nil {
		return nativeSettingsReadError(err)
	}
	d := settingscmd.Deps{Out: humanOut(cmd), Err: cmd.ErrOrStderr(), Palette: ui.Default(), Prompter: survey.HuhPrompter{In: cmd.InOrStdin(), Out: humanOut(cmd)}, Interactive: term.IsTerminal(int(os.Stdin.Fd())) && !jsonMode(cmd)}
	if op == resultdto.OperationSettingsShow || op == resultdto.OperationSettingsReanswer && len(args) == 0 {
		env := newResult(op)
		env.Project = trustProject(r.ProjectContext())
		if err := env.SetData(resultdto.SettingsShowData{Template: resultdto.TemplateRef{Repo: view.Selection.Repo, Name: view.Selection.Name, Version: view.Selection.ResolvedCommit}, Settings: map[string]any(view.Values)}); err != nil {
			return err
		}
		if jsonMode(cmd) {
			return emitResult(cmd, env, resultdto.ExitSuccess, nil)
		}
		settingscmd.PrintNativeView(d, view)
		return nil
	}
	pairs := args
	if op == resultdto.OperationSettingsReanswer {
		if cmd.Flags().Changed("value") {
			pairs = []string{args[0] + "=" + c.value}
		} else {
			if !d.Interactive {
				return nativeSettingsInput(errors.New("settings edit requires --value or an interactive terminal"))
			}
			pairs, err = settingscmd.Reanswer(view, args[0], d)
			if err != nil {
				return nativeSettingsInput(err)
			}
		}
	}
	plan, err := backend.Prepare(cmd.Context(), pairs)
	if err != nil {
		if errors.Is(err, updateplan.ErrSettingsInput) {
			return nativeSettingsInput(err)
		}
		return nativeSettingsReadError(err)
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
	env.PlanSHA256 = plan.Fingerprint()
	env.CurrentRef = report.Source.Root.Commit
	env.TargetRef = report.Target.Root.Commit
	for _, change := range report.Changes {
		if change.Operation != "keep" {
			env.Changes = append(env.Changes, resultdto.Change{Path: change.Path, Action: change.Operation})
		}
		if change.Warning != "" {
			env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "TPL-W-NATIVE-SETTINGS-LOCAL-EDITS", Severity: "warning", Path: change.Path, Message: change.Warning, Details: map[string]any{}})
		}
		if change.Conflict {
			env.Summary.Conflicts++
			env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "TPL-E-NATIVE-SETTINGS-CONFLICT", Severity: "error", Path: change.Path, Message: change.Reason, Details: map[string]any{}})
		}
	}
	if err := env.SetData(resultdto.SettingsSetData{DryRun: c.dryRun}); err != nil {
		return err
	}
	if !report.Publishable {
		env.Status = resultdto.StatusConflicted
		return emitNativeSettings(cmd, env, resultdto.ExitConflict, updateplan.ErrConflict)
	}
	if len(env.Changes) > 0 {
		env.Status = resultdto.StatusChanges
	}
	if c.dryRun {
		if env.Summary.Conflicts > 0 {
			env.Status = resultdto.StatusConflicted
			return emitNativeSettings(cmd, env, resultdto.ExitConflict, updateplan.ErrConflict)
		}
		return emitNativeSettings(cmd, env, resultdto.ExitSuccess, nil)
	}
	if d.Interactive && !c.yes && op == resultdto.OperationSettingsSet {
		approved, err := d.Prompter.Confirm("Apply authenticated settings plan?")
		if err != nil {
			return err
		}
		if !approved {
			return nativeSettingsInput(errors.New("settings change cancelled"))
		}
	}
	tx, err := projecttransaction.BeginSettings(cmd.Context(), plan, plan.Fingerprint())
	if tx != nil {
		defer tx.Release()
	}
	if err != nil {
		return nativeUpdateTransactionError(err)
	}
	if err := tx.Commit(cmd.Context()); err != nil {
		return nativeUpdateTransactionError(err)
	}
	id := tx.ID()
	env.TransactionID = &id
	if env.Summary.Conflicts > 0 {
		env.Status = resultdto.StatusConflicted
		return emitNativeSettings(cmd, env, resultdto.ExitCode(2), updateplan.ErrConflict)
	}
	return emitNativeSettings(cmd, env, resultdto.ExitSuccess, nil)
}

func emitNativeSettings(cmd *cobra.Command, env resultdto.Result, code resultdto.ExitCode, cause error) error {
	env.Summary.FilesChanged = len(env.Changes)
	if jsonMode(cmd) {
		return emitResult(cmd, env, code, cause)
	}
	for _, diagnostic := range env.Diagnostics {
		if diagnostic.Severity == "warning" {
			if _, err := fmt.Fprintln(cmd.ErrOrStderr(), diagnostic.Message); err != nil {
				return err
			}
		}
	}
	for _, change := range env.Changes {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", change.Action, change.Path); err != nil {
			return err
		}
	}
	if code != resultdto.ExitSuccess {
		return &resultExitError{code: code, err: cause}
	}
	_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", env.Operation, env.Status)
	return err
}
