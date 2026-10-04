// Package sourceadapter binds repository selectors to runtime-verified sources.
// Registry data and Git refs select identity; neither supplies render bytes or trust.
package sourceadapter

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

var (
	ErrMismatch = errors.New("TRUST_SOURCE_SELECTION_MISMATCH")
	aliasToken  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// Source retains only verified snapshot bytes and a copied, pinned selection.
type Source struct {
	Input                []byte
	Snapshot             fs.FS
	Alias, Name, Version string
}

// Resolve accepts an exact commit or an indexed repository reference. Git is
// used only to resolve already-local refs: no checkout, lazy fetch or network.
// Signed evidence remains mandatory for both forms.
func Resolve(ctx context.Context, runtime *trustload.Runtime, home, ref string, raw []byte) (*Source, error) {
	if ctx == nil || runtime == nil || runtime.TrustRuntime() == nil {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	selection, err := operationtrust.DecodeSourceSelection(raw)
	if err != nil {
		return nil, err
	}
	alias, name, version := "pinned", "", selection.Subject.Commit
	if ref != selection.Subject.Commit {
		mgr := repo.New(home, nil, nil, repo.UI{})
		resolved, err := mgr.ResolveRef(ref)
		if err != nil {
			return nil, err
		}
		if !aliasToken.MatchString(resolved.RepoAlias) {
			return nil, ErrMismatch
		}
		cfg, err := state.LoadConfig(home)
		if err != nil {
			return nil, err
		}
		origin := ""
		for _, r := range cfg.Repos {
			if r.Alias == resolved.RepoAlias {
				if origin != "" {
					return nil, ErrMismatch
				}
				origin = r.URL
			}
		}
		path := resolved.Entry.Path
		if path == "" {
			path = "."
		}
		if origin == "" || origin != selection.Subject.Origin || path != selection.Subject.TemplatePath {
			return nil, ErrMismatch
		}
		clone := filepath.Join(home, "repos", resolved.RepoAlias)
		commit, err := localCommit(ctx, clone, resolved.GitRef)
		if err != nil || commit != selection.Subject.Commit {
			return nil, ErrMismatch
		}
		alias, name, version = resolved.RepoAlias, resolved.Entry.Name, resolved.Version
	}
	stable := runtime.TrustRuntime()
	resolution, err := stable.VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	snapshot, err := operationtrust.SnapshotFS(stable, resolution)
	if err != nil {
		return nil, err
	}
	contract, err := fs.ReadFile(snapshot, "template.contract.json")
	if err != nil {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	manifest, err := fs.ReadFile(snapshot, "template.manifest.yaml")
	if err != nil {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	if _, err := operationtrust.DecodeNativeContract(contract, manifest); err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(snapshot)
	if err != nil {
		return nil, err
	}
	if name != "" && name != tpl.Metadata.Name {
		return nil, ErrMismatch
	}
	return &Source{Input: append([]byte(nil), raw...), Snapshot: snapshot, Alias: alias, Name: tpl.Metadata.Name, Version: version}, nil
}

func localCommit(ctx context.Context, clone, ref string) (string, error) {
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "\x00\r\n") {
		return "", ErrMismatch
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return "", err
	}
	resolve := func(candidate string) (string, error) {
		cmd := exec.CommandContext(ctx, git, "--no-optional-locks", "-C", clone, "rev-parse", "--verify", "--end-of-options", candidate+"^{commit}")
		// No inherited Git config, credentials, alternate objects, replacement refs,
		// proxy, helpers or partial-clone lazy fetch can affect identity resolution.
		cmd.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1"}
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	if id, err := resolve("refs/remotes/origin/" + ref); err == nil {
		return id, nil
	}
	return resolve(ref)
}
