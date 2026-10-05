package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/projectsync"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

func init() {
	registerCommand(newProjectsCmd)
}

// projectSyncSkip — top-level commands for which project registry sync is
// meaningless: help/version/completion for the same reasons as
// [firstRunSkip]/[suggestSkip] (see firstrun.go, selfupgrade.go), plus init-shell
// (a thin completion alias).
var projectSyncSkip = map[string]bool{
	"help":       true,
	"version":    true,
	"completion": true,
	"init-shell": true,
}

// projectSyncPreRun — third (and last) element of the root command's
// PersistentPreRunE chain (see [rootPreRun] in root.go, §1): when the working
// directory is inside a tplaiter project, it reconciles its entry in
// ~/.tplaiter/projects.yaml with actual state; [projectsync.SyncCurrent] does
// the work.
//
// Unlike firstRunPreRun, an error does not stop the invoking command: the
// registry is a navigation convenience, not the source of truth. On failure
// (unavailable home, busy lock, or corrupt .tplaiter/project.yaml), diagnostics
// are printed only with --verbose; normal runs stay silent.
func projectSyncPreRun(cmd *cobra.Command, _ []string) {
	if projectSyncSkip[topLevelCommand(cmd).Name()] {
		return
	}

	home, err := state.Home()
	if err != nil {
		logProjectSyncErr(cmd, err)
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		logProjectSyncErr(cmd, err)
		return
	}
	if err := projectsync.SyncCurrent(home, cwd, time.Now()); err != nil {
		logProjectSyncErr(cmd, err)
	}
}

func logProjectSyncErr(cmd *cobra.Command, err error) {
	if !verbose {
		return
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "tplaiter: project registry synchronization: %v\n", err)
}

// newProjectsCmd creates `tplaiter projects`: viewing and pruning the local
// ~/.tplaiter/projects.yaml registry.
func newProjectsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "projects",
		Short: "Registry of projects generated from templates on this machine",
		Long: "Registry ~/.tplaiter/projects.yaml — a navigation convenience, not the source of truth " +
			"(the source of truth is .tplaiter/ within each project). The registry is " +
			"automatically updated by each tplaiter command run inside a project: directory " +
			"relocation is tracked by stable id from .tplaiter/project.yaml, a project without " +
			"an entry (cloned by a colleague) is registered on first discovery, and " +
			"baselineSHA divergence (project updated on another machine) is updated on discovery.",
	}
	c.AddCommand(newProjectsListCmd(), newProjectsPruneCmd())
	return c
}

func newProjectsListCmd() *cobra.Command {
	return withResult(&cobra.Command{
		Use:   "list",
		Short: "List registry projects (PATH/TEMPLATE/LAST SEEN/STATUS)",
		Long: "STATUS column:\n" +
			"  ok      — directory at PATH exists and .tplaiter/project.yaml in it can be read.\n" +
			"  missing — directory deleted or project marker missing; entry cleaned by\n" +
			"            `tplaiter projects prune` command.\n\n" +
			"There is no separate \"relocated\" status: directory relocation (same project id, " +
			"different path) is detected and fixed automatically on first tplaiter run " +
			"in the new path — registry synchronization is built into " +
			"PersistentPreRunE of each command (see root.go), so list always shows " +
			"the current PATH, never stale paths.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := state.Home()
			if err != nil {
				return err
			}
			projects, err := state.LoadProjects(home)
			if err != nil {
				return err
			}

			if jsonMode(cmd) {
				data := resultdto.ProjectsListData{Projects: []resultdto.ProjectEntry{}}
				for _, ref := range projects.Items {
					status := "ok"
					if !projectRefExists(ref) {
						status = "missing"
					}
					data.Projects = append(data.Projects, resultdto.ProjectEntry{
						ID: ref.ID, Path: ref.Path, Template: formatTemplateSelection(ref.Template),
						LastSeenAt: rfc3339(ref.LastSeenAt), Status: status,
					})
				}
				return emitData(cmd, resultdto.OperationProjectsList, nil, data)
			}

			pal := ui.Default()
			t := ui.NewTable("PATH", "TEMPLATE", "LAST SEEN", "STATUS")
			for _, ref := range projects.Items {
				t.AddRow(ref.Path, formatTemplateSelection(ref.Template), dashTime(ref.LastSeenAt), statusCellProjects(pal, ref))
			}
			fmt.Fprintln(cmd.OutOrStdout(), t.RenderStyled(pal))
			return nil
		},
	}, resultdto.OperationProjectsList)
}

func newProjectsPruneCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "prune",
		Short: "Remove entries with missing status from the registry",
		Long: "Removes entries where the directory at PATH does not exist or " +
			".tplaiter/project.yaml in it is missing (same criterion as STATUS=missing in `projects list`). " +
			"Before deletion, prints the list of candidate entries; without --yes prompts " +
			"for confirmation interactively (huh), in non-interactive mode requires --yes explicitly.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := state.Home()
			if err != nil {
				return err
			}
			return state.WithLock(home, func() error {
				projects, err := state.LoadProjects(home)
				if err != nil {
					return err
				}

				stale := missingRefs(projects.Items)
				if len(stale) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "no entries with missing status — registry is clean.")
					return nil
				}

				out := cmd.OutOrStdout()
				fmt.Fprintln(out, "will be removed from registry (STATUS=missing):")
				for _, ref := range stale {
					fmt.Fprintf(out, "  %s  (%s)\n", ref.Path, formatTemplateSelection(ref.Template))
				}

				if !yes {
					confirmed, err := confirmPrune(cmd, len(stale))
					if err != nil {
						return err
					}
					if !confirmed {
						fmt.Fprintln(out, "cancelled, registry unchanged.")
						return nil
					}
				}

				removed := projects.Prune(func(path string) bool {
					_, statErr := os.Stat(filepath.Join(path, project.MarkerRelPath))
					return statErr == nil
				})
				if err := state.SaveProjects(home, projects); err != nil {
					return err
				}
				fmt.Fprintf(out, "removed entries: %d\n", len(removed))
				return nil
			})
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return c
}

// confirmPrune asks for confirmation before deleting n entries: interactively
// through huh when stdin is a terminal; otherwise it requires explicit --yes
// instead of assuming consent (registry deletion cannot be undone).
func confirmPrune(cmd *cobra.Command, n int) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, errors.New("cmd: projects prune: non-interactive mode — confirm with --yes flag")
	}
	var ok bool
	form := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title(fmt.Sprintf("Delete %d %s from the registry?", n, pluralEntries(n))).
			Affirmative("Yes").Negative("No").Value(&ok),
	))
	form = form.WithInput(cmd.InOrStdin()).WithOutput(cmd.OutOrStdout())
	if err := form.Run(); err != nil {
		return false, err
	}
	return ok, nil
}

// missingRefs returns the subset of items with missing status, the same
// criterion [state.Projects.Prune] uses for actual deletion.
func missingRefs(items []state.ProjectRef) []state.ProjectRef {
	var out []state.ProjectRef
	for _, ref := range items {
		if !projectRefExists(ref) {
			out = append(out, ref)
		}
	}
	return out
}

// projectRefExists checks STATUS=ok for one registry entry: ref.Path exists and
// its .tplaiter/project.yaml can be read. A single os.Stat of the marker covers
// both missing cases (the whole directory or only the marker was removed); see
// the `projects list` command's Long text.
func projectRefExists(ref state.ProjectRef) bool {
	_, err := os.Stat(filepath.Join(ref.Path, project.MarkerRelPath))
	return err == nil
}

func statusCellProjects(pal ui.Palette, ref state.ProjectRef) string {
	if projectRefExists(ref) {
		return ui.StatusIcon(pal, ui.StatusOK) + " ok"
	}
	return ui.StatusIcon(pal, ui.StatusWarn) + " missing"
}

func formatTemplateSelection(t state.TemplateSelection) string {
	return fmt.Sprintf("%s/%s@%s", t.Repo, t.Name, t.Version)
}

// pluralEntries returns the English noun form for n registry entries.
func pluralEntries(n int) string {
	if n == 1 {
		return "entry"
	}
	return "entries"
}
