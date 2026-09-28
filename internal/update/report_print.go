package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// printSingle prints one project's update result (normal mode).
func printSingle(d Deps, opts Options, res *Result) {
	if opts.Check {
		if len(res.Conflicts) > 0 {
			fmt.Fprintln(d.Out, d.Palette.Warn("обнаружены маркеры конфликта:"))
			for _, c := range res.Conflicts {
				fmt.Fprintf(d.Out, "  %s\n", c)
			}
			return
		}
		fmt.Fprintln(d.Out, "маркеров конфликта не найдено")
		return
	}

	if res.NoOp {
		fmt.Fprintf(d.Out, "проект уже на версии %s — обновлять нечего\n", res.NewVersion)
		return
	}

	verb := "обновление"
	if res.DryRun {
		verb = "план обновления (--dry-run, изменения не записаны)"
	}
	fmt.Fprintf(d.Out, "%s %s → %s\n\n", verb, res.OldVersion, res.NewVersion)
	if res.Report != nil {
		res.Report.Render(d.Out, d.Palette, opts.Verbose)
	}
	if len(res.Conflicts) > 0 && !res.DryRun {
		fmt.Fprintln(d.Out, d.Palette.Warn("\nобновление завершилось с конфликтами — разрешите маркеры и закоммитьте изменения"))
	}
}

// exitFor computes the single-project exit code: 1 for --check markers, 2 for
// conflicts left by update, otherwise nil.
func exitFor(res *Result, opts Options) error {
	if opts.Check {
		if len(res.Conflicts) > 0 {
			return &ExitCodeError{Code: 1, Err: fmt.Errorf("update: найдены маркеры конфликта в %d файле(ах)", len(res.Conflicts))}
		}
		return nil
	}
	if len(res.Conflicts) > 0 {
		return &ExitCodeError{Code: 2, Err: fmt.Errorf("update: %d конфликт(ов) требуют ручного разрешения", len(res.Conflicts))}
	}
	return nil
}

// runAll updates all registry projects with status ok sequentially; one project
// error does not stop the others. It prints a summary and returns a nonzero exit
// code if any project has conflicts.
func runAll(ctx context.Context, d Deps, opts Options) error {
	projects, err := state.LoadProjects(d.Home)
	if err != nil {
		return err
	}
	if len(projects.Items) == 0 {
		fmt.Fprintln(d.Out, "реестр проектов пуст — нечего обновлять")
		return nil
	}

	table := ui.NewTable("PROJECT", "VERSION", "STATUS", "CONFLICTS")
	anyConflict := false

	for _, item := range projects.Items {
		name := filepath.Base(item.Path)
		if !dirExists(item.Path) {
			table.AddRow(name, item.Template.Version, d.Palette.Muted("missing — пропуск"), "")
			continue
		}
		proj, lerr := manifest.LoadProject(filepath.Join(item.Path, project.MarkerRelPath))
		if lerr != nil {
			table.AddRow(name, item.Template.Version, d.Palette.Error("ошибка маркера"), "")
			warnf(d, "%s: %v", item.Path, lerr)
			continue
		}
		res, uerr := updateOne(ctx, d, opts, item.Path, proj)
		if uerr != nil {
			table.AddRow(name, item.Template.Version, d.Palette.Error("ошибка"), "")
			warnf(d, "%s: %v", item.Path, uerr)
			continue
		}
		if len(res.Conflicts) > 0 {
			anyConflict = true
		}
		status, conf := summaryCells(d, opts, res)
		table.AddRow(name, versionCell(res), status, conf)
	}

	fmt.Fprintln(d.Out, table.RenderStyled(d.Palette))
	if anyConflict {
		code := 2
		if opts.Check {
			code = 1
		}
		return &ExitCodeError{Code: code, Err: errors.New("update --all: часть проектов завершилась с конфликтами")}
	}
	return nil
}

// summaryCells returns STATUS and CONFLICTS cells for the --all summary row.
func summaryCells(d Deps, opts Options, res *Result) (status, conflicts string) {
	switch {
	case opts.Check:
		if len(res.Conflicts) > 0 {
			return d.Palette.Warn("маркеры"), strconv.Itoa(len(res.Conflicts))
		}
		return d.Palette.Success("чисто"), "0"
	case res.NoOp:
		return d.Palette.Muted("актуально"), "0"
	case len(res.Conflicts) > 0:
		return d.Palette.Warn("конфликты"), strconv.Itoa(len(res.Conflicts))
	case opts.DryRun:
		return "план", "0"
	default:
		return d.Palette.Success("обновлено"), "0"
	}
}

// versionCell formats the VERSION summary column as "old -> new" on update,
// otherwise the current version.
func versionCell(res *Result) string {
	if res.NoOp || res.NewVersion == res.OldVersion {
		return res.OldVersion
	}
	return res.OldVersion + " → " + res.NewVersion
}

// dirExists reports whether a path exists and is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
