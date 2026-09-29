package repo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/state"
)

// toolForKind maps a repository kind to the auth tool (the tool column in the
// store). The git-credential protocol does not need the tool—findForHost ignores
// it—but it is needed for display and choosing glab/gh.
func toolForKind(kind state.RepoKind) string {
	switch kind {
	case state.RepoKindGitLab:
		return "gitlab"
	case state.RepoKindGitHub:
		return "github"
	default:
		return "git"
	}
}

// resolveGitAuth prepares the environment for git operations during repo add.
//
// Non-http(s) URLs (ssh, file://) need no credential helper and return nil.
// For http(s), an existing host token immediately returns helper-env
// (auth.HelperEnv). Otherwise the auth flow is: tokenStdin reads and stores a
// token; non-interactive mode skips credentials; interactive mode offers (t)
// token input, (g) import from glab/gh, or (s) skip.
func (m *Manager) resolveGitAuth(ctx context.Context, repoURL string, kind state.RepoKind, tokenStdin bool) ([]string, error) {
	if !isHTTPURL(repoURL) {
		return nil, nil
	}
	host, repoPath := parseGitURL(repoURL)
	tool := toolForKind(kind)

	if m.authStore != nil {
		if _, found, err := m.authStore.Get(host, repoPath, tool); err != nil {
			return nil, err
		} else if found {
			return auth.HelperEnv(repoURL), nil
		}
	}

	if tokenStdin {
		return m.storeTokenFromReader(host, tool, repoURL)
	}
	if !m.ui.Interactive {
		m.warnf("token for %s not found, continuing without authentication (for a private repository add token: `tplater auth add %s`)\n", host, host)
		return nil, nil
	}
	return m.interactiveAuth(ctx, repoURL, host, kind, tool)
}

// resolveGitAuthQuiet handles auth for repo update without prompts: it uses a
// stored token when available, otherwise runs without credentials (a private
// repository fetch fails with a clear git error; the user can run `auth add`).
func (m *Manager) resolveGitAuthQuiet(repoURL string, kind state.RepoKind) ([]string, error) {
	if !isHTTPURL(repoURL) || m.authStore == nil {
		return nil, nil
	}
	host, repoPath := parseGitURL(repoURL)
	if _, found, err := m.authStore.Get(host, repoPath, toolForKind(kind)); err != nil {
		return nil, err
	} else if found {
		return auth.HelperEnv(repoURL), nil
	}
	return nil, nil
}

// interactiveAuth runs the authentication method selection dialog. Full
// interactive behavior (huh/hidden input) is implemented here with text prompts
// and reading from ui.In (using ui.ReadSecret for tokens when configured).
func (m *Manager) interactiveAuth(ctx context.Context, repoURL, host string, kind state.RepoKind, tool string) ([]string, error) {
	if m.authStore == nil {
		m.warnf("token store unavailable — continuing without authentication\n")
		return nil, nil
	}
	bin, importable := importBinFor(kind)

	m.printf("Token for %s not found. Choose authentication method:\n", host)
	m.printf("  [t] enter token manually\n")
	if importable {
		m.printf("  [g] log in and import token through %s\n", bin)
	}
	m.printf("  [s] skip (without authentication)\n")
	m.printf("Choice [t/%ss]: ", pick(importable, "g/", ""))

	choice, err := m.readLine()
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "t", "":
		return m.storeTokenInteractive(host, tool, repoURL)
	case "g":
		if !importable {
			m.warnf("import through glab/gh unavailable for this host — enter token manually\n")
			return m.storeTokenInteractive(host, tool, repoURL)
		}
		return m.importAndStore(ctx, bin, tool, host, repoURL)
	case "s":
		m.warnf("continuing without authentication\n")
		return nil, nil
	default:
		return nil, fmt.Errorf("repo: unknown choice %q", choice)
	}
}

// importBinFor returns the token-import binary for a repository kind.
func importBinFor(kind state.RepoKind) (bin string, ok bool) {
	switch kind {
	case state.RepoKindGitLab:
		return "glab", true
	case state.RepoKindGitHub:
		return "gh", true
	default:
		return "", false
	}
}

// importAndStore imports a token through glab/gh (auth.ImportFromTool) and
// returns helper-env on success. A missing binary or login produces a clear
// instructional error from auth.ImportFromTool.
func (m *Manager) importAndStore(ctx context.Context, bin, tool, host, repoURL string) ([]string, error) {
	m.printf("Trying to import token through `%s auth token`…\n", bin)
	if _, err := auth.ImportFromTool(ctx, m.authStore, m.runner, bin, tool, host); err != nil {
		return nil, err
	}
	m.printf("Token imported from %s and saved for %s\n", bin, host)
	return auth.HelperEnv(repoURL), nil
}

// storeTokenInteractive prompts for a token (hidden when ReadSecret is set) and
// stores it for the host.
func (m *Manager) storeTokenInteractive(host, tool, repoURL string) ([]string, error) {
	hint := tokenHint(tool)
	if hint != "" {
		m.printf("%s\n", hint)
	}
	var (
		token string
		err   error
	)
	if m.ui.ReadSecret != nil {
		token, err = m.ui.ReadSecret("Token: ")
	} else {
		m.printf("Token: ")
		token, err = m.readLine()
	}
	if err != nil {
		return nil, err
	}
	return m.putToken(host, tool, repoURL, strings.TrimSpace(token))
}

// storeTokenFromReader reads the complete token from ui.In (--token-stdin mode).
func (m *Manager) storeTokenFromReader(host, tool, repoURL string) ([]string, error) {
	if m.ui.In == nil {
		return nil, errors.New("repo: --token-stdin set, but stdin not connected")
	}
	data, err := io.ReadAll(m.in)
	if err != nil {
		return nil, fmt.Errorf("repo: reading token from stdin: %w", err)
	}
	return m.putToken(host, tool, repoURL, strings.TrimSpace(string(data)))
}

func (m *Manager) putToken(host, tool, repoURL, token string) ([]string, error) {
	if token == "" {
		return nil, errors.New("repo: empty token")
	}
	if _, err := m.authStore.Put(auth.Credential{
		Host:  host,
		Tool:  tool,
		Token: token,
		Note:  "added by `repo add`",
	}); err != nil {
		return nil, err
	}
	m.printf("Token saved for %s\n", host)
	return auth.HelperEnv(repoURL), nil
}

// readLine reads one line from ui.In without the trailing newline.
func (m *Manager) readLine() (string, error) {
	if m.in == nil {
		return "", errors.New("repo: input unavailable (stdin not connected)")
	}
	line, err := m.in.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("repo: reading input: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// tokenHint explains where to issue a token and which scopes are needed.
func tokenHint(tool string) string {
	switch tool {
	case "gitlab":
		return "Issue a Personal Access Token in GitLab (Settings → Access Tokens), scope: read_repository."
	case "github":
		return "Issue a Personal Access Token in GitHub (Settings → Developer settings → Tokens), scope: repo (read)."
	default:
		return ""
	}
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
