package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/diffcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func init() { registerCommand(newDiffCmd) }
func newDiffCmd() *cobra.Command {
	var exitCode bool
	c := newReadonlyProjectCommand("diff", "Compare current files and independent managed blocks with the signed baseline", resultdto.OperationProjectDiff, func(cmd *cobra.Command, r *trustload.Runtime, _ string) error {
		home, err := readonlyHome()
		if err != nil {
			return err
		}
		report, err := diffcmd.Run(cmd.Context(), r, diffcmd.Options{Home: home, RendererVersion: resolveVersion(), SecretProvider: readonlyHomeClassifier{}})
		if err != nil {
			return err
		}
		env := newResult(resultdto.OperationProjectDiff)
		env.Project = trustProject(r.ProjectContext())
		env.CurrentRef = report.CurrentRef
		for _, ch := range report.Changes {
			env.Changes = append(env.Changes, resultdto.Change{Path: ch.Path, BlockID: ch.BlockID, Provider: ch.Provider, Action: ch.Action})
			if ch.BlockID != "" {
				env.Summary.BlocksChanged++
			} else {
				env.Summary.FilesChanged++
			}
		}
		if len(env.Changes) > 0 {
			env.Status = resultdto.StatusChanges
		}
		if err = env.SetData(resultdto.ProjectDiffData{Offline: true, FilesChecked: report.FilesChecked, BlocksChecked: report.BlocksChecked}); err != nil {
			return err
		}
		code := resultdto.ExitSuccess
		if exitCode && len(env.Changes) > 0 {
			code = resultdto.ExitFinding
		}
		if jsonMode(cmd) {
			return emitResult(cmd, env, code, nil)
		}
		for _, ch := range env.Changes {
			id := ch.Path
			if ch.BlockID != "" {
				id += "#" + ch.BlockID
			}
			if _, err = fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", ch.Action, id); err != nil {
				return err
			}
		}
		if code != resultdto.ExitSuccess {
			return &resultExitError{code: code, err: errResultReported}
		}
		return nil
	})
	c.Flags().BoolVar(&exitCode, "exit-code", false, "return exit 1 when drift is found; errors keep their typed exit")
	return c
}
