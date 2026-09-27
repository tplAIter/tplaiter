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
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// repoRunner — Runner для git/glab/gh команд управления репозиториями. Пакетная
// переменная для подмены на execx.RecordingRunner в тестах (стиль auth.go).
var repoRunner execx.Runner = execx.Exec{}

func init() {
	rootCmd.AddCommand(newRepoCmd())
}

func newRepoCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "repo",
		Short: "Управление репозиториями шаблонов",
		Long: "Добавляет, обновляет и удаляет git-репозитории шаблонов (helm-модель). " +
			"См. документацию.",
	}
	c.AddCommand(
		newRepoAddCmd(),
		newRepoListCmd(),
		newRepoRemoveCmd(),
		newRepoUpdateCmd(),
	)
	return c
}

// newManager собирает repo.Manager для команды: домашний каталог, стор токенов,
// UI поверх потоков cobra. authStore закрывается вызывающим (возвращается для
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
		Out:         cmd.OutOrStdout(),
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
		Short: "Добавить репозиторий шаблонов",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			return mgr.Add(cmd.Context(), repo.AddOptions{
				Alias:      args[0],
				URL:        args[1],
				Branch:     branch,
				TokenStdin: tokenStdin,
			})
		},
	}
	f := c.Flags()
	f.StringVar(&branch, "branch", "", "ветка по умолчанию")
	f.BoolVar(&tokenStdin, "token-stdin", false, "прочитать токен из stdin (неинтерактивный auth)")
	return c
}

func newRepoListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Список репозиториев (ALIAS/URL/TYPE/TEMPLATES/UPDATED)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

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
	}
}

func newRepoRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <alias>",
		Short: "Удалить репозиторий",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			return mgr.Remove(args[0])
		},
	}
}

func newRepoUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update [alias]",
		Short: "git fetch + переиндексация всех репозиториев или одного",
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
			return mgr.Update(cmd.Context(), alias)
		},
	}
}
