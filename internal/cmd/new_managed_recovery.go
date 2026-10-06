package cmd

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// Recovery enters only the typed source/formatter owner; generic New recovery
// can never be a fallback for missing or stripped managed admission.
func newManagedRecoveryCmd(operation string) *cobra.Command {
	var key string
	c := &cobra.Command{Use: operation + " <transaction-id>", Short: operation + " a source-bound managed New transaction", Args: cobra.ExactArgs(1), Annotations: prerunAnnotations(prerunTrustOwned), RunE: func(c *cobra.Command, args []string) error {
		runtime, err := composeRuntimeForProject(c.Context(), key)
		if err != nil {
			return err
		}
		defer runtime.Close()
		home, err := readonlyHome()
		if err != nil {
			return err
		}
		switch operation {
		case "continue":
			err = newtransaction.ContinueManaged(c.Context(), runtime, home, args[0])
		case "abort":
			err = newtransaction.AbortManaged(c.Context(), runtime, home, args[0])
		default:
			return errors.New("MANAGED_NEW_RECOVERY_INVALID")
		}
		if err != nil {
			return err
		}
		if !jsonMode(c) {
			return nil
		}
		op := resultdto.OperationNewContinue
		if operation == "abort" {
			op = resultdto.OperationNewAbort
		}
		env := newResult(op)
		env.Project = trustProject(runtime.ProjectContext())
		env.TransactionID = &args[0]

		env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "TPL-I-MANAGED-NEW-RECOVERY", Severity: "info", Message: operation, Details: map[string]any{"phase": operation}})
		return emitResult(c, env, resultdto.ExitSuccess, nil)
	}}
	c.Flags().StringVar(&key, "project-context", "", "authenticated installed project context key")
	op := resultdto.OperationNewContinue
	if operation == "abort" {
		op = resultdto.OperationNewAbort
	}
	return withResult(c, op)
}
