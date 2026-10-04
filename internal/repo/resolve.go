package repo

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/state"
)

// Resolved is the result of resolving a template reference.
type Resolved struct {
	RepoAlias string
	Entry     state.TemplateEntry
	// GitRef is the git reference suitable for checkout (a `vX.Y.Z`/`name/vX.Y.Z`
	// tag or a branch/HEAD for @latest).
	GitRef string
	// Version is the selected human-readable version (`v1.2.0` or `latest`).
	Version string
}

// ResolveRef parses `<repo>/<name>[@<version>]` or the short
// `<name>[@<version>]` and selects a specific version:
//   - `repo/` may be omitted when the name is unique among all repositories; otherwise
//     — an error with the list of candidates;
//   - `@<vX.Y.Z>` — a specific stable tag (it must exist);
//   - `@latest` — HEAD of the tracked branch;
//   - without `@` — the highest stable tag; if there are no tags, the branch
//     HEAD with a warning.
func (m *Manager) ResolveRef(ref string) (Resolved, error) {
	idx, err := m.loadIndex()
	if err != nil {
		return Resolved{}, err
	}

	coord, version := splitVersion(ref)
	repoPart, namePart := splitRepoName(coord)
	if namePart == "" {
		return Resolved{}, fmt.Errorf("repo: empty template name in reference %q", ref)
	}

	alias, entry, err := m.findTemplate(idx, repoPart, namePart)
	if err != nil {
		return Resolved{}, err
	}

	gitRef, chosen, err := selectVersion(entry, version)
	if err != nil {
		return Resolved{}, err
	}
	if version == "" && len(entry.Tags) == 0 {
		m.warnf("template %s/%s has no stable tags — using %s (@latest)\n", alias, namePart, entry.Ref)
	}
	return Resolved{RepoAlias: alias, Entry: entry, GitRef: gitRef, Version: chosen}, nil
}

// findTemplate finds (alias, entry) from an optional repoPart and name.
func (m *Manager) findTemplate(idx state.Index, repoPart, name string) (string, state.TemplateEntry, error) {
	if repoPart != "" {
		entries, ok := idx.Repos[repoPart]
		if !ok {
			return "", state.TemplateEntry{}, fmt.Errorf("repo: repository %q not found in index", repoPart)
		}
		for _, e := range entries {
			if e.Name == name {
				return repoPart, e, nil
			}
		}
		return "", state.TemplateEntry{}, fmt.Errorf("repo: template %q not found in repository %q", name, repoPart)
	}

	// Short form: search all repositories and require uniqueness.
	type hit struct {
		alias string
		entry state.TemplateEntry
	}
	var hits []hit
	for _, alias := range sortedKeys(idx.Repos) {
		for _, e := range idx.Repos[alias] {
			if e.Name == name {
				hits = append(hits, hit{alias, e})
			}
		}
	}
	switch len(hits) {
	case 0:
		return "", state.TemplateEntry{}, fmt.Errorf("repo: template %q not found in any repository", name)
	case 1:
		return hits[0].alias, hits[0].entry, nil
	default:
		var cands []string
		for _, h := range hits {
			cands = append(cands, h.alias+"/"+name)
		}
		return "", state.TemplateEntry{}, fmt.Errorf(
			"repo: name %q is ambiguous — specify repository (%s)", name, strings.Join(cands, ", "),
		)
	}
}

// selectVersion chooses the git ref and human-readable version for entry.
func selectVersion(entry state.TemplateEntry, version string) (gitRef, chosen string, err error) {
	switch version {
	case "":
		if len(entry.Tags) > 0 {
			return entry.Tags[0], tagVersionSuffix(entry.Tags[0], entry.Name), nil
		}
		return entry.Ref, "latest", nil
	case "latest":
		return entry.Ref, "latest", nil
	default:
		for _, tag := range entry.Tags {
			if tagVersionSuffix(tag, entry.Name) == version {
				return tag, version, nil
			}
		}
		if len(entry.Tags) == 0 {
			return "", "", fmt.Errorf("repo: template %q has no stable tags (requested version %q)", entry.Name, version)
		}
		return "", "", fmt.Errorf("repo: version %q not found for template %q (available: %s)",
			version, entry.Name, strings.Join(versionSuffixes(entry), ", "))
	}
}

// Checkout materializes the template tree at the requested ref in a separate
// git worktree and returns an fs.FS rooted at the template directory, a cleanup
// function, and an error.
//
// A worktree is used instead of `git archive`: worktree add --detach atomically
// creates a working copy of the requested ref, applies .gitattributes, and—for
// --filter=blob:none clones—lazily fetches exactly the blobs needed for that ref.
// (An archive would need the same objects but would produce a tar file requiring
// a separate extraction step.) Cleanup with `git worktree remove --force`
// returns git to a consistent state, with RemoveAll as a safeguard if the
// directory has already been detached.
func (m *Manager) Checkout(ctx context.Context, alias, gitRef, templatePath string) (fs.FS, func() error, error) {
	clone := m.cloneDir(alias)
	if _, err := os.Stat(clone); err != nil {
		return nil, nil, fmt.Errorf("repo: clone %q missing: %w", alias, err)
	}

	wt, err := os.MkdirTemp("", "tplater-checkout-"+alias+"-")
	if err != nil {
		return nil, nil, fmt.Errorf("repo: temporary directory for checkout: %w", err)
	}

	// After `repo update`, branches live at origin/<ref> (fetch in a non-bare
	// clone does not move the local branch), so current @latest uses the origin ref.
	checkoutRef := gitRef
	if _, err := m.git(ctx, clone, []string{"rev-parse", "--verify", "--quiet", "origin/" + gitRef}, nil); err == nil {
		checkoutRef = "origin/" + gitRef
	}

	if _, err := m.git(ctx, clone, []string{"worktree", "add", "--detach", wt, checkoutRef}, nil); err != nil {
		_ = os.RemoveAll(wt)
		return nil, nil, fmt.Errorf("repo: checkout %s@%s: %w", alias, gitRef, err)
	}

	root, err := confinedTemplateRoot(wt, templatePath)
	if err != nil {
		_, _ = m.git(ctx, clone, []string{"worktree", "remove", "--force", wt}, nil)
		_ = os.RemoveAll(wt)
		return nil, nil, err
	}

	cleanup := func() error {
		closeErr := root.Close()
		// worktree remove detaches and deletes the working directory; RemoveAll is
		// a safeguard if git left it behind, for example because of a dirty tree.
		_, rmErr := m.git(ctx, clone, []string{"worktree", "remove", "--force", wt}, nil)
		if err := os.RemoveAll(wt); err != nil && rmErr == nil {
			return err
		}
		if rmErr != nil {
			return rmErr
		}
		return closeErr
	}

	return root.FS(), cleanup, nil
}

// confinedTemplateRoot resolves the indexed template directory in the newly
// checked-out ref. The index is built from one ref, but callers may request
// another tag or branch; that ref can replace a directory with a symlink.
func confinedTemplateRoot(worktree, templatePath string) (*os.Root, error) {
	if templatePath == "" {
		templatePath = "."
	}
	clean, err := manifest.CleanTemplatePath(templatePath)
	if err != nil {
		return nil, err
	}
	checkout, err := os.OpenRoot(worktree)
	if err != nil {
		return nil, fmt.Errorf("repo: open checkout root: %w", err)
	}
	defer checkout.Close()
	root, err := checkout.OpenRoot(filepath.FromSlash(clean))
	if err != nil {
		return nil, fmt.Errorf("repo: template path %q escapes checkout root or is unavailable: %w", templatePath, err)
	}
	return root, nil
}

// splitVersion splits a reference into coordinates and version at the last '@'.
func splitVersion(ref string) (coord, version string) {
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

// splitRepoName splits `repo/name`; without '/', it contains only the name.
func splitRepoName(coord string) (repo, name string) {
	if i := strings.Index(coord, "/"); i >= 0 {
		return coord[:i], coord[i+1:]
	}
	return "", coord
}

func versionSuffixes(entry state.TemplateEntry) []string {
	out := make([]string, 0, len(entry.Tags))
	for _, t := range entry.Tags {
		out = append(out, tagVersionSuffix(t, entry.Name))
	}
	return out
}

func sortedKeys(m map[string][]state.TemplateEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
