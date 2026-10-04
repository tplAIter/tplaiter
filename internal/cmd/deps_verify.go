package cmd

import (
	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func init() { registerDepsSubcommand(newDepsVerifyCmd) }
func newDepsVerifyCmd() *cobra.Command {
	return newReadonlyProjectCommand("verify", "Verify the canonical dependency lock pair offline", resultdto.OperationDepsVerify, runDepsVerify)
}

func runDepsVerify(cmd *cobra.Command, runtime *trustload.Runtime, root string) error {
	if err := projectverify.VerifyDependencies(cmd.Context(), root, runtime.TrustRuntime(), runtime); err != nil {
		return err
	}
	return readonlyResult(cmd, resultdto.OperationDepsVerify, runtime, resultdto.DepsVerifyData{Offline: true, Verified: true}, resultdto.ExitSuccess)
}
