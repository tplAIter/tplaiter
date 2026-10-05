package auth

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// RunGitCredential implements the git credential helper protocol (see
// `git help credential`) for get/store/erase operations. Attributes are read
// from stdin (key=value lines until the first blank line or EOF), and the response is written to out.
//
// tplaiter store policy:
//   - get — look up a token by host (+path with credential.useHttpPath), output
//     username/password. If no token is found, output NOTHING and exit 0 (the
//     normal git protocol: the helper silently declines, and git tries the next
//     helper or an interactive prompt). This is not a process error.
//   - store — git reports credentials after successful authentication. We only
//     record use (TouchLastUsed) of an existing entry and NEVER create tokens
//     automatically: store population is only through explicit `tplaiter auth
//     add` / `import-*` (otherwise credentials entered in a git prompt without
//     tplaiter's knowledge would be stored in the database).
//   - erase — logged no-op: tokens are removed only through `tplaiter auth
//     remove`, so an authentication failure cannot silently lose a token.
//
// now is passed as an argument (to make TouchLastUsed testable). logw receives
// diagnostics (usually stderr); the token is never written there.
func RunGitCredential(s *Store, op string, in io.Reader, out, logw io.Writer, now time.Time) error {
	attrs, err := parseCredentialInput(in)
	if err != nil {
		return fmt.Errorf("auth: git-credential: reading input: %w", err)
	}
	host := attrs["host"]
	repo := normalizeRepoPath(attrs["path"])

	switch op {
	case "get":
		cred, found, err := s.findForHost(host, repo)
		if err != nil {
			return err
		}
		if !found {
			// Silent exit 0 — git will try other sources.
			return nil
		}
		fmt.Fprintf(out, "username=%s\n", credentialUsername(cred))
		fmt.Fprintf(out, "password=%s\n", cred.Token)
		return nil

	case "store":
		cred, found, err := s.findForHost(host, repo)
		if err != nil {
			return err
		}
		if !found {
			fmt.Fprintln(logw, "tplaiter auth: store — no saved token for this host, "+
				"not creating automatically (use `tplaiter auth add`)")
			return nil
		}
		return s.TouchLastUsed(cred.ID, now)

	case "erase":
		fmt.Fprintln(logw, "tplaiter auth: erase — no-op (tokens are removed only through `tplaiter auth remove`)")
		return nil

	default:
		return fmt.Errorf("auth: git-credential: unknown operation %q", op)
	}
}

// credentialUsername returns the username for git. If it is not set in the
// store, use a meaningful tool-specific default: for GitLab/GitHub PAT access,
// username is effectively ignored, but git requires it or prompts again.
func credentialUsername(c Credential) string {
	if c.Username != "" {
		return c.Username
	}
	switch c.Tool {
	case "gitlab":
		return "oauth2"
	case "github":
		return "x-access-token"
	default:
		return "git"
	}
}

// parseCredentialInput parses git credential input: key=value lines up to the
// first blank line (or EOF).
func parseCredentialInput(r io.Reader) (map[string]string, error) {
	attrs := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		attrs[key] = val
	}
	return attrs, sc.Err()
}

// normalizeRepoPath normalizes the git path (the path attribute with
// useHttpPath) to the form used by Credential.Repo: without leading/trailing
// slashes and without the ".git" suffix.
func normalizeRepoPath(p string) string {
	p = strings.Trim(p, "/")
	p = strings.TrimSuffix(p, ".git")
	return p
}

// HelperEnv returns environment variables (GIT_CONFIG_COUNT/KEY/VALUE format)
// that enable tplaiter as a git credential helper for ONE git command only —
// equivalent to `git -c credential.helper="!tplaiter auth git-credential"`,
// without modifying the global git config. Values are put in execx.Options.Env
// before running git (clone/fetch/push).
//
// The first (empty) credential.helper resets helpers from user config, and the
// second installs ours. For http(s) URLs, also enable credential.useHttpPath so
// git passes the path and we can select a repository-level token; for SSH the
// helper is not used and the path flag is unnecessary.
func HelperEnv(repoURL string) []string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "tplaiter"
	}
	helper := "!" + exe + " auth git-credential"

	env := []string{
		"GIT_CONFIG_KEY_0=credential.helper",
		"GIT_CONFIG_VALUE_0=",
		"GIT_CONFIG_KEY_1=credential.helper",
		"GIT_CONFIG_VALUE_1=" + helper,
	}
	count := 2
	if isHTTPURL(repoURL) {
		env = append(env,
			"GIT_CONFIG_KEY_2=credential.useHttpPath",
			"GIT_CONFIG_VALUE_2=true")
		count = 3
	}
	return append([]string{"GIT_CONFIG_COUNT=" + strconv.Itoa(count)}, env...)
}

func isHTTPURL(url string) bool {
	return strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://")
}
