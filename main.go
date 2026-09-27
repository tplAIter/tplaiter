// Command tplater — helm-подобный менеджер репозиториев шаблонов (см. документацию проекта).
//
// На этапе  реализован только скелет: cobra root + `tplater version` и
// служебные пакеты (execx, ui). Продуктовые команды (repo, template, new,
// update, stats, run, ...) добавляются последующими связанными компонентами согласно
// документацию проекта
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
