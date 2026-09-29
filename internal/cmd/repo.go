package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// repoRunner — runner for git/glab/gh repository-management commands. A package
// variable that tests replace with execx.RecordingRunner (following auth.go).
var repoRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newRepoCmd)
}

func newRepoCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "repo",
		Short: "Manage template repositories",
		Long: "Add, update, and delete git repositories for templates (helm model). " +
			"See documentation.",
	}
	c.AddCommand(
		newRepoAddCmd(),
		newRepoListCmd(),
		newRepoRemoveCmd(),
		newRepoUpdateCmd(),
	)
	return c
}

// newManager builds repo.Manager for the command: home directory, token store,
// and UI over cobra streams. The caller closes authStore (returned for
// defer Close).
func newManager(cmd *cobra.Command) (*repo.Manager, *auth.Store, error) {
	home, _, err := state.EnsureHome()
	if err != nil {
		return nil, nil, err
	}
	st, err := auth.Open(cmd.Context())
	if err != nil {
		return nil, nil, err
	}

	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	u := repo.UI{
		In:          cmd.InOrStdin(),
		Out:         humanOut(cmd),
		Err:         cmd.ErrOrStderr(),
		Palette:     ui.Default(),
		Interactive: interactive,
	}
	if interactive {
		u.ReadSecret = func(prompt string) (string, error) {
			fmt.Fprint(cmd.ErrOrStderr(), prompt)
			b, rerr := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(cmd.ErrOrStderr())
			return string(b), rerr
		}
	}
	return repo.New(home, repoRunner, st, u), st, nil
}

func newRepoAddCmd() *cobra.Command {
	var (
		branch     string
		tokenStdin bool
	)
	c := &cobra.Command{
		Use:   "add <alias> <url>",
		Short: "Add a template repository",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			if err := mgr.Add(cmd.Context(), repo.AddOptions{
				Alias:      args[0],
				URL:        args[1],
				Branch:     branch,
				TokenStdin: tokenStdin,
			}); err != nil {
				return err
			}
			if !jsonMode(cmd) {
				return nil
			}
			return emitRepoInfos(cmd, mgr, resultdto.OperationRepoAdd, args[0])
		},
	}
	f := c.Flags()
	f.StringVar(&branch, "branch", "", "default branch")
	f.BoolVar(&tokenStdin, "token-stdin", false, "read token from stdin (non-interactive auth)")
	return withResult(c, resultdto.OperationRepoAdd)
}

// emitRepoInfos prints the repositories (all, or only alias) as the data of
// op.
func emitRepoInfos(cmd *cobra.Command, mgr *repo.Manager, op resultdto.Operation, alias string) error {
	infos, err := mgr.List()
	if err != nil {
		return err
	}
	data := resultdto.RepoListData{Repositories: []resultdto.RepoInfo{}}
	for _, in := range infos {
		if alias != "" && in.Ref.Alias != alias {
			continue
		}
		data.Repositories = append(data.Repositories, resultdto.RepoInfo{
			Alias: in.Ref.Alias, URL: in.Ref.URL, Type: string(in.Ref.Type),
			Templates: in.Templates, UpdatedAt: rfc3339(in.UpdatedAt),
		})
	}
	return emitData(cmd, op, nil, data)
}

func newRepoListCmd() *cobra.Command {
	return withResult(&cobra.Command{
		Use:   "list",
		Short: "List repositories (ALIAS/URL/TYPE/TEMPLATES/UPDATED)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			if jsonMode(cmd) {
				return emitRepoInfos(cmd, mgr, resultdto.OperationRepoList, "")
			}

			infos, err := mgr.List()
			if err != nil {
				return err
			}
			t := ui.NewTable("ALIAS", "URL", "TYPE", "TEMPLATES", "UPDATED")
			for _, in := range infos {
				t.AddRow(
					in.Ref.Alias,
					in.Ref.URL,
					string(in.Ref.Type),
					strconv.Itoa(in.Templates),
					dashTime(in.UpdatedAt),
				)
			}
			fmt.Fprintln(cmd.OutOrStdout(), t.RenderStyled(ui.Default()))
			return nil
		},
	}, resultdto.OperationRepoList)
}

func newRepoRemoveCmd() *cobra.Command {
	return withResult(&cobra.Command{
		Use:   "remove <alias>",
		Short: "Delete a repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			if err := mgr.Remove(args[0]); err != nil {
				return err
			}
			if !jsonMode(cmd) {
				return nil
			}
			return emitData(cmd, resultdto.OperationRepoRemove, nil, resultdto.RepoRemoveData{Alias: args[0]})
		},
	}, resultdto.OperationRepoRemove)
}

func newRepoUpdateCmd() *cobra.Command {
	return withResult(&cobra.Command{
		// Preserved from the former name-based switch, which matched every command
		// named "update": the root hooks do not run for `repo update`. Revisit when
		// the live lifecycle returns (U07).
		Annotations: prerunAnnotations(prerunTrustOwned),

		Use:   "update [alias]",
		Short: "git fetch + reindex all repositories or one",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			var alias string
			if len(args) == 1 {
				alias = args[0]
			}
			if err := mgr.Update(cmd.Context(), alias); err != nil {
				return err
			}
			if !jsonMode(cmd) {
				return nil
			}
			return emitRepoInfos(cmd, mgr, resultdto.OperationRepoUpdate, alias)
		},
	}, resultdto.OperationRepoUpdate)
}
