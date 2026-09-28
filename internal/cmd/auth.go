package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// authRunner — runner for external tools (glab/gh) used by auth commands. It is
// a package variable so tests can substitute execx.RecordingRunner for a real
// invocation.
var authRunner execx.Runner = execx.Exec{}

// dateLayout — format of the --expires flag.
const dateLayout = "2006-01-02"

func init() {
	rootCmd.AddCommand(newAuthCmd())
}

func newAuthCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "auth",
		Short: "Управление токенами доступа к репозиториям шаблонов",
		Long: "Хранит токены в ~/.tplaiter/tplater.db (права 0600) и подставляет их в " +
			"git-операции через собственный credential helper. См. документацию",
	}
	c.AddCommand(
		newAuthListCmd(),
		newAuthAddCmd(),
		newAuthRemoveCmd(),
		newAuthGitCredentialCmd(),
		newAuthImportCmd("import-glab", "glab", "gitlab", "gitlab.com"),
		newAuthImportCmd("import-gh", "gh", "github", "github.com"),
	)
	return c
}

func newAuthListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Показать сохранённые токены (маскированные)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := auth.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			creds, err := st.MaskedList()
			if err != nil {
				return err
			}

			t := ui.NewTable("ID", "HOST", "REPO", "TOOL", "TOKEN", "USERNAME", "LAST USED", "EXPIRES")
			for _, c := range creds {
				t.AddRow(
					strconv.FormatInt(c.ID, 10),
					c.Host,
					dash(c.Repo),
					c.Tool,
					c.Token,
					dash(c.Username),
					dashTime(c.LastUsedAt),
					dashTime(c.ExpiresAt),
				)
			}
			fmt.Fprintln(cmd.OutOrStdout(), t.RenderStyled(ui.Default()))
			return nil
		},
	}
}

func newAuthAddCmd() *cobra.Command {
	var (
		repo, tool, username, scopes, note, expires string
		tokenStdin                                  bool
	)
	c := &cobra.Command{
		Use:   "add <host>",
		Short: "Добавить/обновить токен для хоста (и опционально репозитория)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var expiresAt time.Time
			if expires != "" {
				parsed, err := time.Parse(dateLayout, expires)
				if err != nil {
					return fmt.Errorf("auth: некорректная дата --expires %q (ожидается YYYY-MM-DD): %w", expires, err)
				}
				expiresAt = parsed
			}

			token, err := readToken(cmd, tokenStdin)
			if err != nil {
				return err
			}
			if token == "" {
				return errors.New("auth: пустой токен")
			}

			st, err := auth.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			id, err := st.Put(auth.Credential{
				Host:      args[0],
				Repo:      repo,
				Tool:      tool,
				Token:     token,
				Username:  username,
				Scopes:    scopes,
				Note:      note,
				ExpiresAt: expiresAt,
			})
			if err != nil {
				return err
			}
			// NEVER print the token — report only that it was saved.
			fmt.Fprintf(cmd.OutOrStdout(), "Токен сохранён: id=%d host=%s\n", id, args[0])
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&repo, "repo", "", "репозиторий (пусто = токен уровня хоста)")
	f.StringVar(&tool, "tool", "git", "инструмент: gitlab|github|git|other")
	f.StringVar(&username, "username", "", "имя пользователя")
	f.StringVar(&scopes, "scopes", "", "scopes токена (справочно)")
	f.StringVar(&note, "note", "", "заметка")
	f.StringVar(&expires, "expires", "", "срок действия YYYY-MM-DD")
	f.BoolVar(&tokenStdin, "token-stdin", false, "прочитать токен из stdin (для пайпа)")
	return c
}

func newAuthRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <id>",
		Short: "Удалить токен по id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("auth: некорректный id %q: %w", args[0], err)
			}
			st, err := auth.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			if err := st.Delete(id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Токен удалён: id=%d\n", id)
			return nil
		},
	}
}

func newAuthGitCredentialCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "git-credential <get|store|erase>",
		Short:  "git credential helper (внутренняя команда)",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := auth.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			return auth.RunGitCredential(
				st, args[0],
				cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(),
				time.Now(),
			)
		},
	}
}

// newAuthImportCmd builds `auth import-<tool>`: it obtains a token through
// `<bin> auth token [--hostname h]` (mocked in tests through authRunner) and
// saves it in the store under the specified tool.
func newAuthImportCmd(use, bin, toolName, defaultHost string) *cobra.Command {
	var hostname string
	c := &cobra.Command{
		Use:   use + " [--hostname <h>]",
		Short: fmt.Sprintf("Импортировать токен из %s в хранилище tplater", bin),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := authRunner.LookPath(bin); err != nil {
				return fmt.Errorf("auth: %s не найден в PATH — установите его и повторите (%s auth login)", bin, bin)
			}

			runArgs := []string{"auth", "token"}
			if hostname != "" {
				runArgs = append(runArgs, "--hostname", hostname)
			}
			res, err := authRunner.Run(cmd.Context(), bin, runArgs, execx.Options{})
			if err != nil {
				return fmt.Errorf("auth: %s auth token: %w", bin, err)
			}
			token := strings.TrimSpace(res.Stdout)
			if token == "" {
				return fmt.Errorf("auth: %s вернул пустой токен (выполните `%s auth login`)", bin, bin)
			}

			host := hostname
			if host == "" {
				host = defaultHost
			}

			st, err := auth.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			id, err := st.Put(auth.Credential{
				Host:  host,
				Tool:  toolName,
				Token: token,
				Note:  "импортирован из " + bin,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Импортирован токен %s: id=%d host=%s\n", toolName, id, host)
			return nil
		},
	}
	c.Flags().StringVar(&hostname, "hostname", "", "хост (по умолчанию "+defaultHost+")")
	return c
}

// readToken obtains a token from stdin (--token-stdin, for a pipe) or through
// hidden interactive input using golang.org/x/term (already in go.mod; we do
// not pull in huh/charm for one input line). If stdin is not a terminal and
// --token-stdin is not set, it asks the user to use --token-stdin.
func readToken(cmd *cobra.Command, fromStdin bool) (string, error) {
	if fromStdin {
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return "", fmt.Errorf("auth: чтение токена из stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("auth: stdin не терминал — передайте токен через --token-stdin")
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Токен: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", fmt.Errorf("auth: чтение токена: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// dash returns "-" for an empty string (for table output).
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// dashTime formats a time as YYYY-MM-DD or "-" for the zero value.
func dashTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(dateLayout)
}
