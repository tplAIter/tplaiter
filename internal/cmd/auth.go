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
	registerCommand(newAuthCmd)
}

func newAuthCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "auth",
		Short: "Manage access tokens for template repositories",
		Long: "Stores tokens in ~/.tplaiter/tplater.db (mode 0600) and supplies them to " +
			"git operations via a built-in credential helper. See documentation",
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
		Short: "Show saved tokens (masked)",
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
		Short: "Add/update token for host (and optionally repository)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var expiresAt time.Time
			if expires != "" {
				parsed, err := time.Parse(dateLayout, expires)
				if err != nil {
					return fmt.Errorf("auth: invalid date --expires %q (expected YYYY-MM-DD): %w", expires, err)
				}
				expiresAt = parsed
			}

			token, err := readToken(cmd, tokenStdin)
			if err != nil {
				return err
			}
			if token == "" {
				return errors.New("auth: empty token")
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
			fmt.Fprintf(cmd.OutOrStdout(), "Token saved: id=%d host=%s\n", id, args[0])
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&repo, "repo", "", "repository (empty = host-level token)")
	f.StringVar(&tool, "tool", "git", "tool: gitlab|github|git|other")
	f.StringVar(&username, "username", "", "username")
	f.StringVar(&scopes, "scopes", "", "token scopes (for reference)")
	f.StringVar(&note, "note", "", "note")
	f.StringVar(&expires, "expires", "", "expiration date YYYY-MM-DD")
	f.BoolVar(&tokenStdin, "token-stdin", false, "read token from stdin (for piping)")
	return c
}

func newAuthRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <id>",
		Short: "Delete token by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("auth: invalid id %q: %w", args[0], err)
			}
			st, err := auth.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			if err := st.Delete(id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Token deleted: id=%d\n", id)
			return nil
		},
	}
}

func newAuthGitCredentialCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "git-credential <get|store|erase>",
		Short:  "git credential helper (internal command)",
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
		Short: fmt.Sprintf("Import token from %s into tplaiter store", bin),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := authRunner.LookPath(bin); err != nil {
				return fmt.Errorf("auth: %s not found in PATH — install it and retry (%s auth login)", bin, bin)
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
				return fmt.Errorf("auth: %s returned empty token (run `%s auth login`)", bin, bin)
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
				Note:  "imported from " + bin,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Imported %s token: id=%d host=%s\n", toolName, id, host)
			return nil
		},
	}
	c.Flags().StringVar(&hostname, "hostname", "", "host (default "+defaultHost+")")
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
			return "", fmt.Errorf("auth: reading token from stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("auth: stdin is not a terminal — pass token via --token-stdin")
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Token: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", fmt.Errorf("auth: reading token: %w", err)
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
