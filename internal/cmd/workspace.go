package cmd

import "github.com/spf13/cobra"

func init() { registerCommand(newWorkspaceCmd) }

func newWorkspaceCmd() *cobra.Command {
	c := &cobra.Command{Use: "workspace", Short: "Operations on a signed Go workspace"}
	c.AddCommand(newWorkspaceAddServiceCmd(), newNativeWorkspaceRecoveryCmd(false), newNativeWorkspaceRecoveryCmd(true))
	return c
}

// newWorkspaceAddServiceCmd admits signed native service creation and registration.
func newWorkspaceAddServiceCmd() *cobra.Command { return newNativeWorkspaceAddServiceCmd() }
