package cmd

import "github.com/spf13/cobra"

// The `deps` command group is the shared parent for template dependency
// subcommands. It deliberately has no subcommands of its own yet: later work
// packages add them in their own files (for example `deps verify` and
// `deps install`) by calling registerDepsSubcommand from that file's init(),
// and annotate each subcommand with its pre-run class (see prerun_class.go).

func init() {
	registerCommand(newDepsCmd)
}

// depsSubcommands lists subcommand constructors for the deps group.
var depsSubcommands []func() *cobra.Command

// registerDepsSubcommand adds a subcommand to the deps group. It records the
// constructor for per-invocation roots and attaches the subcommand to rootCmd's
// deps group; package init order between files therefore does not matter.
func registerDepsSubcommand(factory func() *cobra.Command) { //nolint:unused // extension point for the deps subcommands (U08, U09)
	depsSubcommands = append(depsSubcommands, factory)
	for _, c := range rootCmd.Commands() {
		if c.Name() == "deps" {
			c.AddCommand(factory())
		}
	}
}

func newDepsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "deps",
		Short: "Inspect and manage template dependencies",
		Args:  cobra.NoArgs,
	}
	for _, factory := range depsSubcommands {
		c.AddCommand(factory())
	}
	return c
}
