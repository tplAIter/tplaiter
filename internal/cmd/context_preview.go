package cmd

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func newContextPreviewCmd(action string) *cobra.Command {
	var req contextcmd.LocalPreviewRequest
	var key, dir, raw string
	c := &cobra.Command{Use: action, Short: "Read explicitly untrusted observed local provider data", Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunReadonly)}
	c.Flags().StringVar(&key, "project-context", "", "exact installed project-context key")
	c.Flags().StringVar(&dir, "dir", "", "locator matching the installed root")
	c.Flags().StringVar(&raw, "request", "", "closed installed registration/selectors/bounds JSON; no endpoints")
	c.Flags().StringVar(&req.RegistrationID, "registration", "", "exact installed local registration ID")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if raw != "" {
			if cmd.Flags().Changed("registration") || len(raw) > 16384 || canonicaljson.DecodeStrict([]byte(raw), &req) != nil {
				return resultdto.NewError(contextcmd.Invalid, resultdto.ExitUsage, nil)
			}
		}
		if err := contextcmd.NormalizeLocalPreview(action, &req); err != nil {
			return resultdto.NewError(contextcmd.Invalid, resultdto.ExitUsage, err)
		}
		runtime, err := nativeGenRuntime(cmd, nativeGenControls{key: key, dir: dir})
		if err != nil {
			return err
		}
		defer runtime.Close()
		data, err := contextcmd.RunLocalPreview(cmd.Context(), runtime, action, req)
		if err != nil {
			exit := resultdto.ExitUnavailable
			var invalid *contextcmd.Error
			if errors.As(err, &invalid) && invalid.Code == contextcmd.Invalid {
				exit = resultdto.ExitUsage
			}
			return resultdto.NewError(contextcmd.Code(err), exit, err)
		}
		env := newResult(resultdto.OperationContextQuery)
		env.Project = trustProject(runtime.ProjectContext())
		if err = env.SetData(data); err != nil {
			return err
		}
		encoded, err := resultdto.MarshalCanonical(env)
		if err != nil {
			return err
		}
		if len(encoded)+1 > req.MaxBytes {
			return resultdto.NewError(contextcmd.Budget, resultdto.ExitUnavailable, nil)
		}
		// Emit the same measured result envelope in text/JSON modes. Do not reduce
		// the mandatory floor to squeeze it under the caller's ceiling.
		return emitResult(cmd, env, resultdto.ExitSuccess, nil)
	}
	return withResult(c, resultdto.OperationContextQuery)
}
