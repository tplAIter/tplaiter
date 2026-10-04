package cmd

import (
	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/projectcheck"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func init() { registerCommand(newCheckCmd) }
func newCheckCmd() *cobra.Command {
	return newReadonlyProjectCommand("check", "Check verified project ownership and drift offline", resultdto.OperationProjectCheck, runCheck)
}

func runCheck(cmd *cobra.Command, runtime *trustload.Runtime, root string) error {
	home, err := readonlyHome()
	if err != nil {
		return err
	}
	report, err := projectcheck.Run(cmd.Context(), projectcheck.Options{ProjectRoot: root, HomeRoot: home, Authority: runtime.TrustRuntime(), CAS: runtime, SecretProvider: readonlyHomeClassifier{}})
	if err != nil {
		return err
	}
	exit := resultdto.ExitSuccess
	if report.Status != "pass" {
		exit = resultdto.ExitFinding
	}
	data := resultdto.ProjectCheckData{Offline: true, APIVersion: report.APIVersion, Status: report.Status, Managed: resultdto.ManagedCheckData{State: report.Managed.State, Modified: nonNil(report.Managed.Modified), Missing: nonNil(report.Managed.Missing), Invalid: nonNil(report.Managed.Invalid)}, Findings: nonNil(report.Findings), Verify: verifyData(report.Verify)}
	return readonlyResult(cmd, resultdto.OperationProjectCheck, runtime, data, exit)
}
