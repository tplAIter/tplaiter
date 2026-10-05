package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/update"
)

func init() { registerCommand(newSettingsCmd) }

func newSettingsCmd() *cobra.Command {
	c := &cobra.Command{Use: "settings", Short: "Show and change authenticated native project settings", Annotations: prerunAnnotations(prerunTrustOwned)}
	c.AddCommand(newSettingsListCmd(), newSettingsSetCmd(), newSettingsEditCmd())
	return c
}

func newSettingsListCmd() *cobra.Command {
	var controls nativeSettingsControls
	c := &cobra.Command{Use: "list", Aliases: []string{"show"}, Short: "Show authenticated current settings", Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunTrustOwned), RunE: func(cmd *cobra.Command, _ []string) error {
		return runNativeSettings(cmd, controls, nil, resultdto.OperationSettingsShow)
	}}
	addNativeSettingsFlags(c, &controls, false)
	return withResult(c, resultdto.OperationSettingsShow)
}

func newSettingsSetCmd() *cobra.Command {
	var controls nativeSettingsControls
	c := &cobra.Command{Use: "set group=value [group2=value2 ...]", Short: "Change settings through a signed same-version native plan", Args: cobra.MinimumNArgs(1), Annotations: prerunAnnotations(prerunTrustOwned), RunE: func(cmd *cobra.Command, args []string) error {
		return runNativeSettings(cmd, controls, args, resultdto.OperationSettingsSet)
	}}
	addNativeSettingsFlags(c, &controls, true)
	return withResult(c, resultdto.OperationSettingsSet)
}

func newSettingsEditCmd() *cobra.Command {
	var controls nativeSettingsControls
	c := &cobra.Command{Use: "edit [group]", Short: "Reanswer an authenticated settings group", Args: cobra.MaximumNArgs(1), Annotations: prerunAnnotations(prerunTrustOwned), RunE: func(cmd *cobra.Command, args []string) error {
		return runNativeSettings(cmd, controls, args, resultdto.OperationSettingsReanswer)
	}}
	addNativeSettingsFlags(c, &controls, true)
	c.Flags().StringVar(&controls.value, "value", "", "explicit answer for the selected group (non-interactive edit)")
	return withResult(c, resultdto.OperationSettingsReanswer)
}

// mapExit retains compatibility for callers classifying historical error values;
// native settings never call the legacy mutable settings workflow.
func mapExit(err error) error {
	var ece *update.ExitCodeError
	if errors.As(err, &ece) {
		return &resultExitError{code: updateExit(ece.Code), err: ece.Err}
	}
	return err
}
