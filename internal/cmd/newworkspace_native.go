package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/workspace"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

type nativeWorkspaceControls struct {
	key, serviceKey, dir, source, module, answers string
	sets                                          []string
	port                                          int
	defaults, dryRun, envSetup                    bool
}

func workspaceInputError(err error) error {
	return resultdto.NewError("TPL-E-NATIVE-WORKSPACE-INPUT", resultdto.ExitUsage, err)
}

func workspaceTransactionError(err error) error {
	return resultdto.NewError("TPL-E-NATIVE-WORKSPACE-TRANSACTION", resultdto.ExitTransaction, err)
}

func nativeWorkspaceFlags(cmd *cobra.Command, c *nativeWorkspaceControls) {
	f := cmd.Flags()
	f.StringVar(&c.key, "project-context", "", "authenticated installed workspace context")
	f.StringVar(&c.serviceKey, "service-context", "", "authenticated installed context for services/<slug>")
	f.StringVar(&c.dir, "dir", "", "exact installed workspace root locator")
}

func newNativeWorkspaceAddServiceCmd() *cobra.Command {
	var c nativeWorkspaceControls
	cmd := &cobra.Command{Annotations: prerunAnnotations(prerunTrustOwned), Use: "add-service <name>", Short: "Add a signed native Go service to an authenticated workspace", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return runNativeWorkspace(cmd, c, args[0]) }}
	nativeWorkspaceFlags(cmd, &c)
	f := cmd.Flags()
	f.StringVar(&c.source, "source-input", "", "closed signed service source selection")
	f.StringVar(&c.module, "module", "", "service module; default <workspace module>/services/<slug>")
	f.StringArrayVar(&c.sets, "set", nil, "service setting group=value")
	f.StringVar(&c.answers, "answers", "", "answers files are unavailable in this bounded native operation")
	f.BoolVar(&c.defaults, "defaults", false, "use default service settings")
	f.BoolVar(&c.dryRun, "dry-run", false, "authenticate and report without writes")
	f.BoolVar(&c.envSetup, "env-setup", false, "request environment execution (unavailable)")
	f.Bool("no-env-setup", false, "native workspace never executes environment actions")
	f.Bool("no-hooks", false, "native workspace refuses declared hooks")
	f.Bool("no-deps-check", false, "native workspace refuses declared tools")
	f.Bool("yes", false, "non-interactive native operation")
	f.IntVar(&c.port, "port", 0, "service port (default 8080)")
	return withResult(cmd, resultdto.OperationWorkspaceAddService)
}

func runNativeWorkspace(cmd *cobra.Command, c nativeWorkspaceControls, name string) error {
	if c.serviceKey == "" || c.source == "" || c.answers != "" || c.envSetup {
		return workspaceInputError(errors.New("service-context and source-input are required; answers/env execution are unsupported"))
	}
	wr, err := nativeGenRuntime(cmd, nativeGenControls{key: c.key, dir: c.dir})
	if err != nil {
		return err
	}
	defer wr.Close()
	sr, err := composeRuntimeForProject(cmd.Context(), c.serviceKey)
	if err != nil {
		return err
	}
	defer sr.Close()
	source, err := readUntrustedDocument(cmd.Context(), c.source)
	if err != nil {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	current, err := registeredSourceInput(cmd.Context(), wr)
	if err != nil {
		return err
	}
	home, err := readonlyHome()
	if err != nil {
		return err
	}
	plan, err := workspace.Prepare(cmd.Context(), wr, sr, home, resolveVersion(), workspace.Input{Name: name, Module: c.module, Port: c.port, Sets: c.sets, Defaults: c.defaults, WorkspaceSource: current, ServiceSource: source})
	if err != nil {
		if errors.Is(err, workspace.ErrInput) {
			return workspaceInputError(err)
		}
		return err
	}
	report := plan.Report()
	env := newResult(resultdto.OperationWorkspaceAddService)
	env.Project = trustProject(wr.ProjectContext())
	env.PlanSHA256 = plan.Fingerprint()
	env.Status = resultdto.StatusChanges
	for _, p := range report.Paths {
		env.Changes = append(env.Changes, resultdto.Change{Path: p, Action: "write"})
	}
	env.Summary.FilesChanged = len(env.Changes)
	if err := env.SetData(resultdto.WorkspaceAddServiceData{Service: report.Service, Module: report.Module, Dir: "services/" + report.Service}); err != nil {
		return err
	}
	if !c.dryRun {
		tx, err := workspace.Begin(cmd.Context(), plan, plan.Fingerprint())
		if tx != nil {
			defer tx.Release()
		}
		if err != nil {
			return workspaceTransactionError(err)
		}
		if err := tx.Commit(cmd.Context()); err != nil {
			return workspaceTransactionError(err)
		}
		id := tx.ID()
		env.TransactionID = &id
	}
	if jsonMode(cmd) {
		return emitResult(cmd, env, resultdto.ExitSuccess, nil)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s: services/%s (%s)\n", env.Operation, report.Service, map[bool]string{true: "dry-run", false: "committed"}[c.dryRun])
	return err
}

// Both recovery commands retain the workspace result schema. The authenticated
// transaction kind and supplied ID determine the operation, never caller bytes.
func newNativeWorkspaceRecoveryCmd(abort bool) *cobra.Command {
	var c nativeWorkspaceControls
	verb := "continue"
	if abort {
		verb = "abort"
	}
	cmd := &cobra.Command{Annotations: prerunAnnotations(prerunTrustOwned), Use: verb + " <transaction-id>", Short: verb + " an authenticated native workspace transaction", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if c.serviceKey == "" {
			return workspaceInputError(errors.New("service-context is required"))
		}
		wr, err := nativeGenRuntime(cmd, nativeGenControls{key: c.key, dir: c.dir})
		if err != nil {
			return err
		}
		defer wr.Close()
		sr, err := composeRuntimeForProject(cmd.Context(), c.serviceKey)
		if err != nil {
			return err
		}
		defer sr.Close()
		home, err := readonlyHome()
		if err != nil {
			return err
		}
		tx, err := workspace.Open(cmd.Context(), wr, sr, home, args[0], resolveVersion())
		if err != nil {
			return workspaceTransactionError(err)
		}
		defer tx.Release()
		if abort {
			err = tx.Abort(cmd.Context())
		} else {
			err = tx.Commit(cmd.Context())
		}
		if err != nil {
			return workspaceTransactionError(err)
		}
		env := newResult(resultdto.OperationWorkspaceAddService)
		env.Project = trustProject(wr.ProjectContext())
		id := tx.ID()
		env.TransactionID = &id
		report, err := tx.Report()
		if err != nil {
			return err
		}
		if err := env.SetData(resultdto.WorkspaceAddServiceData{Service: report.Service, Module: report.Module, Dir: "services/" + report.Service}); err != nil {
			return err
		}
		env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "TPL-I-NATIVE-WORKSPACE-RECOVERY", Severity: "info", Message: verb, Details: map[string]any{}})
		if jsonMode(cmd) {
			return emitResult(cmd, env, resultdto.ExitSuccess, nil)
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s native workspace %s\n", verb, id)
		return err
	}}
	nativeWorkspaceFlags(cmd, &c)
	return withResult(cmd, resultdto.OperationWorkspaceAddService)
}
