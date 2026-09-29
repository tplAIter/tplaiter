// Command tplaiter is a template repository manager and MCP server for
// AI-assisted project scaffolding (see README.md and docs/).
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/tplAIter/tplaiter/internal/cmd"
	"github.com/tplAIter/tplaiter/internal/ui"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, ui.ErrorPrefix(ui.Default()), err)
		var exit *cmd.ExitError
		if errors.As(err, &exit) && exit.Code != 0 {
			os.Exit(exit.Code)
		}
		os.Exit(1)
	}
}
