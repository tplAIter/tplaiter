package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// firstRunSkip — top-level commands that must not print the first-run greeting:
// the user is asking for help/version, so stay silent about ~/.tplaiter even on
// the first invocation on the machine.
var firstRunSkip = map[string]bool{
	"help":       true,
	"version":    true,
	"completion": true,
}

// firstRunPreRun — PersistentPreRunE for the root command. If the tplaiter home
// directory did not exist and the invoked command is not in firstRunSkip, it
// creates its skeleton ([state.EnsureHome]) and prints a short greeting to
// stderr. An EnsureHome error stops execution: without ~/.tplaiter only
// help/version work; other commands need it.
func firstRunPreRun(cmd *cobra.Command, _ []string) error {
	if firstRunSkip[topLevelCommand(cmd).Name()] {
		return nil
	}

	_, created, err := state.EnsureHome()
	if err != nil {
		return fmt.Errorf("cmd: first-run: %w", err)
	}
	if created {
		printWelcome(cmd)
	}
	return nil
}

// topLevelCommand returns the top-level subcommand (a direct child of rootCmd)
// on the path to cmd — for example, "completion" for `tplaiter completion
// bash`, or "version" for `tplaiter version`. It is used instead of cmd.Name()
// because first-run must stay silent for ANY command inside "completion", not
// only for the completion command itself.
func topLevelCommand(cmd *cobra.Command) *cobra.Command {
	c := cmd
	for c.HasParent() && c.Parent().HasParent() {
		c = c.Parent()
	}
	return c
}

// printWelcome prints the first-run greeting: how to add a template repository
// and where to find documentation (exactly three lines).
func printWelcome(cmd *cobra.Command) {
	p := ui.Default()
	out := cmd.ErrOrStderr()
	fmt.Fprintln(out, p.Muted("tplaiter: created directory ~/.tplaiter — this is the first run on this machine."))
	fmt.Fprintln(out, p.Muted("Add template repository:  tplaiter repo add <alias> <url>"))
	fmt.Fprintln(out, p.Muted("Documentation: README.md and docs/ in tplaiter repository."))
}
