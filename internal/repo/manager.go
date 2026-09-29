// Package repo manages template repositories (Helm model): adding, removing,
// and updating git repositories; scanning and indexing manifests; authenticating
// git operations through the token store; and resolving `<repo>/<name>@<version>`.
//
// All git calls go through [execx.Runner], so integration tests use real git in
// t.TempDir (without network, through file:// repositories), while auth paths
// use glab/gh mocks over [execx.RecordingRunner].
package repo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// aliasRe is the allowed repository alias format: a lowercase letter followed
// by lowercase letters, digits, or hyphens.
var aliasRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// UI contains manager input/output streams and the message palette. In is used
// for interactive answers (auth method selection and token input); Interactive
// says whether questions may be asked (usually whether stdin is a TTY). When
// set, ReadSecret reads a token without echo (the CLI uses term); tests leave it
// nil and read the token as a line from In.
type UI struct {
	In          io.Reader
	Out         io.Writer
	Err         io.Writer
	Palette     ui.Palette
	Interactive bool
	ReadSecret  func(prompt string) (string, error)
}

// Manager encapsulates operations on the template repository registry.
type Manager struct {
	home      string
	runner    execx.Runner
	authStore *auth.Store
	ui        UI
	in        *bufio.Reader

	// now supplies index.GeneratedAt and is overridden in tests.
	now func() time.Time
}

// New creates a manager. home is the tplater home directory (see state.Home).
// authStore may be nil, making the auth flow unavailable for https URLs; git
// then runs without a credential helper, suitable for public/file:// repositories.
func New(home string, runner execx.Runner, authStore *auth.Store, u UI) *Manager {
	var r *bufio.Reader
	if u.In != nil {
		r = bufio.NewReader(u.In)
	}
	return &Manager{
		home:      home,
		runner:    runner,
		authStore: authStore,
		ui:        u,
		in:        r,
		now:       time.Now,
	}
}

// AddOptions contains repo add parameters.
type AddOptions struct {
	Alias  string
	URL    string
	Branch string
	// TokenStdin reads a token from stdin (non-interactive auth) instead of prompting.
	TokenStdin bool
}

// Info is a repo list output row: registry entry plus index aggregates.
type Info struct {
	Ref       state.RepoRef
	Templates int
	UpdatedAt time.Time
}

// reposDir returns the clone cache directory (~/.tplaiter/repos).
func (m *Manager) reposDir() string { return filepath.Join(m.home, "repos") }

// cloneDir returns the clone path for repository alias.
func (m *Manager) cloneDir(alias string) string { return filepath.Join(m.reposDir(), alias) }

// Add adds a repository: validates the alias, detects kind from host, performs
// auth for https, clones with the blob:none filter, scans and indexes manifests,
// then atomically writes config.yaml and index.yaml under an interprocess lock.
func (m *Manager) Add(ctx context.Context, opts AddOptions) error {
	if err := validateAlias(opts.Alias); err != nil {
		return err
	}
	if opts.URL == "" {
		return errors.New("repo: empty URL")
	}

	cfg, err := state.LoadConfig(m.home)
	if err != nil {
		return err
	}
	if _, ok := findRepo(cfg.Repos, opts.Alias); ok {
		return fmt.Errorf("repo: alias %q already in use", opts.Alias)
	}

	host, _ := parseGitURL(opts.URL)
	kind := detectKind(host)

	authEnv, err := m.resolveGitAuth(ctx, opts.URL, kind, opts.TokenStdin)
	if err != nil {
		return err
	}

	dest := m.cloneDir(opts.Alias)
	// Remove a possible leftover from an interrupted attempt with the same alias.
	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(m.reposDir(), 0o700); err != nil {
		return fmt.Errorf("repo: creating cache directory: %w", err)
	}

	cloneArgs := []string{"clone", "--filter=blob:none"}
	if opts.Branch != "" {
		cloneArgs = append(cloneArgs, "--branch", opts.Branch)
	}
	cloneArgs = append(cloneArgs, opts.URL, dest)

	sp := ui.NewSpinner(m.ui.Err, m.ui.Palette)
	sp.Start("Cloning %s → %s", opts.URL, dest)
	_, cloneErr := m.git(ctx, "", cloneArgs, authEnv)
	sp.Stop()
	if cloneErr != nil {
		_ = os.RemoveAll(dest)
		return fmt.Errorf("repo: cloning %s: %w", opts.URL, cloneErr)
	}

	branch := opts.Branch
	if branch == "" {
		branch = m.currentBranch(ctx, dest)
	}

	// strict=true: a broken manifest during add is fatal (the repository is not
	// registered). See scanRepo for the difference from update.
	entries, err := m.scanRepo(ctx, dest, branch, true)
	if err != nil {
		_ = os.RemoveAll(dest)
		return err
	}

	ref := state.RepoRef{Alias: opts.Alias, URL: opts.URL, Branch: opts.Branch, Type: kind}
	if err := state.WithLock(m.home, func() error {
		cfg, err := state.LoadConfig(m.home)
		if err != nil {
			return err
		}
		if _, ok := findRepo(cfg.Repos, opts.Alias); ok {
			return fmt.Errorf("repo: alias %q already in use", opts.Alias)
		}
		cfg.Repos = append(cfg.Repos, ref)
		if err := state.SaveConfig(m.home, cfg); err != nil {
			return err
		}
		return m.writeIndexEntry(opts.Alias, entries)
	}); err != nil {
		_ = os.RemoveAll(dest)
		return err
	}

	m.printf("Repository %s (%s) added, templates: %d\n", opts.Alias, kind, len(entries))
	return nil
}

// Remove removes a repository from config and index and deletes its clone.
func (m *Manager) Remove(alias string) error {
	if err := state.WithLock(m.home, func() error {
		cfg, err := state.LoadConfig(m.home)
		if err != nil {
			return err
		}
		if _, ok := findRepo(cfg.Repos, alias); !ok {
			return fmt.Errorf("repo: repository %q not found", alias)
		}
		cfg.Repos = removeRepo(cfg.Repos, alias)
		if err := state.SaveConfig(m.home, cfg); err != nil {
			return err
		}

		idx, err := m.loadIndex()
		if err != nil {
			return err
		}
		delete(idx.Repos, alias)
		idx.GeneratedAt = m.now()
		return state.SaveIndex(m.home, idx)
	}); err != nil {
		return err
	}

	if err := os.RemoveAll(m.cloneDir(alias)); err != nil {
		return fmt.Errorf("repo: deleting clone %q: %w", alias, err)
	}
	m.printf("Repository %s removed\n", alias)
	return nil
}

// Update runs git fetch --tags --force (the cache is disposable, so a moved
// origin tag must not block an update) and reindexes all repositories (empty
// alias) or one repository. Unlike Add, a broken template manifest during
// update is a warning and skips that template; see scanRepo.
func (m *Manager) Update(ctx context.Context, alias string) error {
	cfg, err := state.LoadConfig(m.home)
	if err != nil {
		return err
	}

	var targets []state.RepoRef
	if alias == "" {
		targets = cfg.Repos
	} else {
		ref, ok := findRepo(cfg.Repos, alias)
		if !ok {
			return fmt.Errorf("repo: repository %q not found", alias)
		}
		targets = []state.RepoRef{ref}
	}
	if len(targets) == 0 {
		m.printf("No repositories added\n")
		return nil
	}

	for _, ref := range targets {
		dest := m.cloneDir(ref.Alias)
		if _, statErr := os.Stat(dest); statErr != nil {
			m.warnf("repository %q: clone missing (%s) — skipping; run `tplater repo remove/add`\n", ref.Alias, dest)
			continue
		}
		authEnv, aerr := m.resolveGitAuthQuiet(ref.URL, ref.Type)
		if aerr != nil {
			return aerr
		}
		sp := ui.NewSpinner(m.ui.Err, m.ui.Palette)
		sp.Start("Updating %s", ref.Alias)
		_, fetchErr := m.git(ctx, dest, []string{"fetch", "--tags", "--force", "--prune", "origin"}, authEnv)
		sp.Stop()
		if fetchErr != nil {
			return fmt.Errorf("repo: fetch %q: %w", ref.Alias, fetchErr)
		}

		branch := ref.Branch
		if branch == "" {
			branch = m.currentBranch(ctx, dest)
		}

		// fetch above updates only the remote-tracking ref origin/<branch>;
		// without explicit checkout+reset, the cache clone stays at the old commit
		// and index.yaml is rebuilt from old content. Sync the working tree to the
		// updated origin/<branch> so update actually pulls changes (skip detached
		// HEAD, which is not our normal disposable-cache scenario).
		if branch != "HEAD" {
			if _, err := m.git(ctx, dest, []string{"checkout", branch}, authEnv); err != nil {
				return fmt.Errorf("repo: checkout %q@%s: %w", ref.Alias, branch, err)
			}
			if _, err := m.git(ctx, dest, []string{"reset", "--hard", "origin/" + branch}, authEnv); err != nil {
				return fmt.Errorf("repo: reset %q@%s: %w", ref.Alias, branch, err)
			}
		} else {
			m.warnf("repository %q: detached HEAD in cache — skipping working tree fast-forward, reindexing only\n", ref.Alias)
		}

		entries, err := m.scanRepo(ctx, dest, branch, false)
		if err != nil {
			return err
		}
		if err := state.WithLock(m.home, func() error {
			return m.writeIndexEntry(ref.Alias, entries)
		}); err != nil {
			return err
		}
		m.printf("  %s: templates %d\n", ref.Alias, len(entries))
	}
	return nil
}

// List returns registry entries enriched with the template count from the index
// and the clone's last update time (mtime of repos/<alias>).
func (m *Manager) List() ([]Info, error) {
	cfg, err := state.LoadConfig(m.home)
	if err != nil {
		return nil, err
	}
	idx, err := m.loadIndex()
	if err != nil {
		return nil, err
	}

	out := make([]Info, 0, len(cfg.Repos))
	for _, ref := range cfg.Repos {
		info := Info{Ref: ref, Templates: len(idx.Repos[ref.Alias])}
		if st, statErr := os.Stat(m.cloneDir(ref.Alias)); statErr == nil {
			info.UpdatedAt = st.ModTime()
		}
		out = append(out, info)
	}
	return out, nil
}

// Templates returns the aggregated template index for all added repositories
// (alias -> its templates), in the same form as index.yaml. It is the source
// for `template list`; the command filters by repo/name/labels, while this
// method only reads the cache with the same tolerance for corrupt index.yaml as
// [Manager.List]/[Manager.ResolveRef] (see [Manager.loadIndex]).
func (m *Manager) Templates() (map[string][]state.TemplateEntry, error) {
	idx, err := m.loadIndex()
	if err != nil {
		return nil, err
	}
	return idx.Repos, nil
}

// writeIndexEntry replaces one repository's templates in index.yaml. Call only
// under state.WithLock.
func (m *Manager) writeIndexEntry(alias string, entries []state.TemplateEntry) error {
	idx, err := m.loadIndex()
	if err != nil {
		return err
	}
	if idx.Repos == nil {
		idx.Repos = map[string][]state.TemplateEntry{}
	}
	idx.Repos[alias] = entries
	idx.GeneratedAt = m.now()
	return state.SaveIndex(m.home, idx)
}

// loadIndex reads the index, treating ErrIndexCorrupted as an empty cache (the
// index is rebuildable); a corrupt file must not break the command.
func (m *Manager) loadIndex() (state.Index, error) {
	idx, err := state.LoadIndex(m.home)
	if err != nil {
		if isIndexCorrupted(err) {
			m.warnf("index.yaml corrupted — rebuilding cache\n")
			return state.NewIndex(m.now()), nil
		}
		return state.Index{}, err
	}
	return idx, nil
}

// git runs git in dir (empty means the current directory) with extraEnv,
// usually the credential helper from auth.HelperEnv.
func (m *Manager) git(ctx context.Context, dir string, args, extraEnv []string) (execx.Result, error) {
	return m.runner.Run(ctx, "git", args, execx.Options{Dir: dir, Env: extraEnv})
}

// CloneDir returns the cache clone path for repository alias
// (~/.tplaiter/repos/<alias>). It is exported for internal/contribute
// (`tplater upgrade`), which creates a branch in the cache clone and returns it
// to the original ref after push; the private [Manager.cloneDir] serves the rest.
func (m *Manager) CloneDir(alias string) string { return m.cloneDir(alias) }

// RunGit runs an arbitrary git command in dir with extraEnv (usually the
// credential helper from [auth.HelperEnv] for push). It is a thin exported
// wrapper around private [Manager.git] for internal/contribute (`tplater upgrade`),
// which needs to branch, commit, push, and format-patch through the same runner.
func (m *Manager) RunGit(ctx context.Context, dir string, args, extraEnv []string) (execx.Result, error) {
	return m.git(ctx, dir, args, extraEnv)
}

// currentBranch returns the clone's current branch name, or "HEAD" on error.
func (m *Manager) currentBranch(ctx context.Context, dir string) string {
	res, err := m.git(ctx, dir, []string{"rev-parse", "--abbrev-ref", "HEAD"}, nil)
	if err != nil {
		return "HEAD"
	}
	b := strings.TrimSpace(res.Stdout)
	if b == "" || b == "HEAD" {
		return "HEAD"
	}
	return b
}

func (m *Manager) printf(format string, a ...any) {
	if m.ui.Out != nil {
		fmt.Fprintf(m.ui.Out, format, a...)
	}
}

func (m *Manager) warnf(format string, a ...any) {
	if m.ui.Err == nil {
		return
	}
	fmt.Fprint(m.ui.Err, m.ui.Palette.Warn("warning: "))
	fmt.Fprintf(m.ui.Err, format, a...)
}

// validateAlias checks the alias format (^[a-z][a-z0-9-]*$).
func validateAlias(alias string) error {
	if alias == "" {
		return errors.New("repo: empty alias")
	}
	if !aliasRe.MatchString(alias) {
		return fmt.Errorf("repo: invalid alias %q (expected ^[a-z][a-z0-9-]*$)", alias)
	}
	return nil
}

func findRepo(repos []state.RepoRef, alias string) (state.RepoRef, bool) {
	for _, r := range repos {
		if r.Alias == alias {
			return r, true
		}
	}
	return state.RepoRef{}, false
}

func removeRepo(repos []state.RepoRef, alias string) []state.RepoRef {
	out := repos[:0:0]
	for _, r := range repos {
		if r.Alias != alias {
			out = append(out, r)
		}
	}
	return out
}

// detectKind determines hosting from host: gitlab.* and scm.* mean gitlab;
// github.* means github; otherwise it is ordinary git.
func detectKind(host string) state.RepoKind {
	h := strings.ToLower(host)
	switch {
	case strings.HasPrefix(h, "gitlab.") || strings.HasPrefix(h, "scm."):
		return state.RepoKindGitLab
	case strings.HasPrefix(h, "github."):
		return state.RepoKindGitHub
	default:
		return state.RepoKindGit
	}
}

// parseGitURL extracts host and a normalized repository path from git URLs:
// http(s)://host/path, ssh://[user@]host[:port]/path, and scp-like
// [user@]host:path. The path has no leading/trailing "/" or ".git" suffix.
// For file:// URLs host is empty (kind becomes git and auth is unnecessary).
func parseGitURL(raw string) (host, repoPath string) {
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			return u.Hostname(), normalizeRepoPath(u.Path)
		}
		return "", normalizeRepoPath(raw)
	}
	// Scp-like form: [user@]host:path, with a colon before the first "/".
	if i := strings.Index(raw, ":"); i > 0 {
		if slash := strings.Index(raw, "/"); slash == -1 || slash > i {
			hostPart := raw[:i]
			if at := strings.LastIndex(hostPart, "@"); at >= 0 {
				hostPart = hostPart[at+1:]
			}
			return hostPart, normalizeRepoPath(raw[i+1:])
		}
	}
	return "", normalizeRepoPath(raw)
}

// normalizeRepoPath converts a path to Credential.Repo storage form: no leading
// or trailing "/" and no ".git" suffix.
func normalizeRepoPath(p string) string {
	p = strings.Trim(p, "/")
	p = strings.TrimSuffix(p, ".git")
	return p
}

// isHTTPURL reports whether a URL needs http(s) authentication; ssh/file:// URLs
// do not use the credential helper.
func isHTTPURL(raw string) bool {
	return strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://")
}

func isIndexCorrupted(err error) bool {
	return errors.Is(err, state.ErrIndexCorrupted)
}
