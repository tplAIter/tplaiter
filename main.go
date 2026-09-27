// Command tplater is a Helm-like template repository manager (see project documentation).
//
// At this stage only the skeleton is implemented: the Cobra root, `tplater version`,
// and utility packages (execx, ui). Product commands (repo, template, new,
// update, stats, run, ...) are added by subsequent related components according
// to the project documentation.
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
