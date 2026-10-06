// Command tplaiter is a template repository manager and MCP server for
// AI-assisted project scaffolding (see README.md and docs/).
package main

import (
	"os"

	"github.com/tplAIter/tplaiter/internal/cmd"
)

// main delegates to cmd.Main, which owns the exit-code registry
// (docs/exit-codes.md) and the --json failure envelope.
func main() {
	if handled, code := cmd.TryActionBootstrap(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(cmd.Main())
}
