package repo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/state"
)

// templateManifestName / repoManifestName are manifest names at the clone root.
const (
	templateManifestName = "template.manifest.yaml"
	repoManifestName     = "repo.manifest.yaml"
)

// MaxDiscoveryDepth is the maximum number of directory levels below a
// discovery root that are searched for template manifests. The template-base
// shape (bootstrap/template-repository/templates/service) needs four; the
// bound keeps discovery predictable on large repositories. Manifests deeper
// than this are not indexed.
const MaxDiscoveryDepth = 8

// scanRepo builds the template index of the clone in dir.
//
// Discovery (see [DiscoverTemplatePaths]):
//   - repo.manifest.yaml at the root is authoritative: its templates[].path
//     entries are the discovery roots (an empty list means the repository
//     root). Each root is searched recursively;
//   - without a repository manifest the repository root is the only root, so
//     a root template.manifest.yaml and nested templates (the provider shape,
//     for example templates/service) are indexed together.
//
// Tag namespace: a template at the repository root of a repository without
// repo.manifest.yaml keeps the legacy single-template tags ("v1.2.3"); every
// other template uses namespaced tags ("<name>/v1.2.3").
//
// strict controls handling of a broken or invalid template manifest:
//   - strict=true (repo add): every such error is fatal; add must report the
//     path and reason and must not register the repository;
//   - strict=false (repo update): a broken template is a warning and only that
//     template is skipped; an existing repository must not break because one
//     remote template was edited.
//
// Path confinement failures and duplicate identities are always fatal: they
// make the catalog unsafe or <repo>/<name> ambiguous.
func (m *Manager) scanRepo(ctx context.Context, dir, branch string, strict bool) ([]state.TemplateEntry, error) {
	ref := branch
	if ref == "" {
		ref = "HEAD"
	}

	found, err := discover(dir)
	if err != nil {
		return nil, err
	}
	if len(found.paths) == 0 {
		return nil, fmt.Errorf("repo: no %s found below the declared template roots", templateManifestName)
	}

	allTags := m.listTags(ctx, dir)

	entries := make([]state.TemplateEntry, 0, len(found.paths))
	for _, rel := range found.paths {
		manifestPath := filepath.Join(found.root, filepath.FromSlash(rel), templateManifestName)
		multi := found.declared || rel != "."
		entry, err := buildEntry(manifestPath, rel, ref, allTags, multi)
		if err != nil {
			if strict {
				return nil, err
			}
			m.warnf("%s — skipping template: %v\n", rel, err)
			continue
		}
		entries = append(entries, entry)
	}
	if err := rejectDuplicateTemplateNames(entries); err != nil {
		return nil, err
	}
	// Deterministic index order: name, then path.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name == entries[j].Name {
			return entries[i].Path < entries[j].Path
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// discovery is the result of template discovery in one repository.
type discovery struct {
	// root is the repository root after symlink resolution.
	root string
	// paths are canonical slash-separated template directories relative to
	// root, sorted; "." is the repository root.
	paths []string
	// declared reports whether repo.manifest.yaml declared the roots.
	declared bool
}

// DiscoverTemplatePaths returns the sorted, canonical (slash-separated,
// repository-relative) directories below dir that contain a
// template.manifest.yaml. It is shared by repository indexing, lint-template
// and init-template, so a provider cannot publish a nested template that its
// own lint silently skips.
//
// It enforces path confinement: declared roots and manifest symlinks must
// resolve inside dir (after resolving symlinks of dir itself); violations are
// reported as [*manifest.RepositoryError] with a CodeRepo* code. It performs
// discovery only; manifest parsing, validation, duplicate-name detection and
// tag selection remain the callers' responsibility.
func DiscoverTemplatePaths(dir string) ([]string, error) {
	found, err := discover(dir)
	if err != nil {
		return nil, err
	}
	return found.paths, nil
}

func discover(dir string) (discovery, error) {
	root, err := resolveRepoRoot(dir)
	if err != nil {
		return discovery{}, err
	}
	roots, declared, err := templateRoots(root)
	if err != nil {
		return discovery{}, err
	}
	seen := make(map[string]struct{})
	for _, r := range roots {
		if err := walkTemplateRoot(root, r.resolved, seen); err != nil {
			return discovery{}, err
		}
		if r.declared != "" && !rootHasTemplate(seen, r.resolved) {
			return discovery{}, fmt.Errorf("repo: %s: %w", repoManifestName,
				manifest.NewRepositoryError(manifest.CodeRepoPathInvalid, r.declared,
					"declared template root contains no "+templateManifestName))
		}
	}
	paths := make([]string, 0, len(seen))
	for rel := range seen {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	return discovery{root: root, paths: paths, declared: declared}, nil
}

// rootHasTemplate reports whether a template was already discovered below the
// resolved root rel (possible when declared roots overlap).
func rootHasTemplate(seen map[string]struct{}, rel string) bool {
	for p := range seen {
		if rel == "." || p == rel || strings.HasPrefix(p, rel+"/") {
			return true
		}
	}
	return false
}

// resolveRepoRoot returns the absolute, symlink-resolved repository root.
// Every confinement check compares against this path, so a clone reached
// through a symlinked parent (for example /var → /private/var on macOS) is
// handled correctly.
func resolveRepoRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("repo: resolving repository root %q: %w", dir, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("repo: resolving repository root %q: %w", dir, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("repo: repository root %q: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("repo: repository root %q is not a directory", dir)
	}
	return resolved, nil
}

// templateRoot is one discovery root: declared is the templates[].path value
// as written (empty for the implicit repository root); resolved is the
// canonical slash-separated path relative to the resolved repository root.
type templateRoot struct {
	declared string
	resolved string
}

// templateRoots returns the discovery roots of the repository at root. A
// repository manifest is authoritative when present; otherwise the repository
// root is the implicit single root.
func templateRoots(root string) ([]templateRoot, bool, error) {
	repoPath := filepath.Join(root, repoManifestName)
	info, err := os.Lstat(repoPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return []templateRoot{{resolved: "."}}, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("repo: checking %s: %w", repoManifestName, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		if _, err := confinedTarget(root, repoPath); err != nil {
			return nil, false, fmt.Errorf("repo: %w", err)
		}
	}
	r, err := manifest.LoadRepository(repoPath)
	if err != nil {
		return nil, false, fmt.Errorf("repo: %s: %w", repoManifestName, err)
	}
	if len(r.Templates) == 0 {
		return []templateRoot{{resolved: "."}}, true, nil
	}
	roots, err := explicitTemplateRoots(root, r.Templates)
	if err != nil {
		return nil, false, fmt.Errorf("repo: %s: %w", repoManifestName, err)
	}
	return roots, true, nil
}

// explicitTemplateRoots validates and resolves templates[].path entries.
// Entries that resolve to the same directory (literally or through a
// symlink) are rejected with CodeRepoDupPath. The result is sorted by the
// resolved path.
func explicitTemplateRoots(root string, refs []manifest.TemplateRef) ([]templateRoot, error) {
	byResolved := make(map[string]string, len(refs))
	out := make([]templateRoot, 0, len(refs))
	for _, ref := range refs {
		clean, err := manifest.CleanTemplatePath(ref.Path)
		if err != nil {
			return nil, err
		}
		if part, ignored := ignoredComponent(clean); ignored {
			return nil, manifest.NewRepositoryError(manifest.CodeRepoPathInvalid, ref.Path,
				fmt.Sprintf("points into excluded directory %q", part))
		}
		resolved, err := resolveDeclaredRoot(root, ref.Path, clean)
		if err != nil {
			return nil, err
		}
		if prior, dup := byResolved[resolved]; dup {
			return nil, manifest.NewRepositoryError(manifest.CodeRepoDupPath, ref.Path,
				fmt.Sprintf("resolves to the same directory %q as %q", resolved, prior))
		}
		byResolved[resolved] = ref.Path
		out = append(out, templateRoot{declared: ref.Path, resolved: resolved})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].resolved < out[j].resolved })
	return out, nil
}

// resolveDeclaredRoot resolves a cleaned declared root with EvalSymlinks and
// requires the result to be a directory inside root. A symlink that stays
// inside the repository is allowed; the canonical (resolved) path is
// returned so that the index never stores a symlinked template path.
func resolveDeclaredRoot(root, declared, clean string) (string, error) {
	joined := filepath.Join(root, filepath.FromSlash(clean))
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", manifest.NewRepositoryError(manifest.CodeRepoPathInvalid, declared, "template root does not exist")
		}
		return "", fmt.Errorf("repo: resolving template root %q: %w", declared, err)
	}
	rel, ok := within(root, resolved)
	if !ok {
		return "", manifest.NewRepositoryError(manifest.CodeRepoPathEscape, declared,
			"template root resolves outside the repository")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("repo: template root %q: %w", declared, err)
	}
	if !info.IsDir() {
		return "", manifest.NewRepositoryError(manifest.CodeRepoPathInvalid, declared, "template root is not a directory")
	}
	if part, ignored := ignoredComponent(rel); ignored {
		return "", manifest.NewRepositoryError(manifest.CodeRepoPathInvalid, declared,
			fmt.Sprintf("resolves into excluded directory %q", part))
	}
	return rel, nil
}

// walkTemplateRoot recursively collects template directories below rel.
// filepath.WalkDir does not follow directory symlinks, so discovery never
// leaves the tree through a symlinked directory. A symlinked
// template.manifest.yaml is accepted only if its target is a regular file
// inside the repository; an escaping manifest symlink is a CodeRepoPathEscape
// error. Excluded directories are pruned before descending, and directories
// deeper than MaxDiscoveryDepth below the root are not searched.
func walkTemplateRoot(root, rel string, seen map[string]struct{}) error {
	absRoot := filepath.Join(root, filepath.FromSlash(rel))
	err := filepath.WalkDir(absRoot, func(p string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if p == absRoot {
				return nil
			}
			if ignoredTemplateDirectory(entry.Name()) || depthBelow(absRoot, p) > MaxDiscoveryDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != templateManifestName {
			return nil
		}
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			target, err := confinedTarget(root, p)
			if err != nil {
				return err
			}
			info, err := os.Stat(target)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
		case !entry.Type().IsRegular():
			return nil
		}
		dirRel, ok := within(root, filepath.Dir(p))
		if !ok {
			// Unreachable: WalkDir stays below absRoot, which is inside root.
			return manifest.NewRepositoryError(manifest.CodeRepoPathEscape, filepath.ToSlash(p), "template directory outside the repository")
		}
		seen[dirRel] = struct{}{}
		return nil
	})
	if err != nil {
		var typed *manifest.RepositoryError
		if errors.As(err, &typed) {
			return fmt.Errorf("repo: %w", err)
		}
		return fmt.Errorf("repo: scanning template root %q: %w", rel, err)
	}
	return nil
}

// confinedTarget resolves the symlink at p and requires the target to be
// inside root. It returns the resolved absolute target.
func confinedTarget(root, p string) (string, error) {
	relLink, _ := within(root, p)
	target, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", manifest.NewRepositoryError(manifest.CodeRepoPathInvalid, relLink,
			fmt.Sprintf("unresolvable symlink: %v", err))
	}
	if _, ok := within(root, target); !ok {
		return "", manifest.NewRepositoryError(manifest.CodeRepoPathEscape, relLink,
			"symlink resolves outside the repository")
	}
	return target, nil
}

// within reports whether the absolute path p is root or below it, and returns
// p relative to root in canonical slash form ("." for root itself).
func within(root, p string) (string, bool) {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return normalizeTemplatePath(rel), true
}

// depthBelow returns how many directory levels p is below base.
func depthBelow(base, p string) int {
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(rel), "/") + 1
}

// ignoredTemplateDirectory reports whether discovery skips a directory: hidden
// directories (including .git), and dependency or build trees.
func ignoredTemplateDirectory(name string) bool {
	switch name {
	case "vendor", "node_modules", "cache", "target":
		return true
	}
	return strings.HasPrefix(name, ".") && name != "." && name != ".."
}

// ignoredComponent returns the first excluded component of a canonical
// relative path.
func ignoredComponent(rel string) (string, bool) {
	if rel == "." {
		return "", false
	}
	for _, part := range strings.Split(rel, "/") {
		if ignoredTemplateDirectory(part) {
			return part, true
		}
	}
	return "", false
}

// rejectDuplicateTemplateNames fails with CodeRepoDupName when two entries
// share metadata.name. Entries are inspected in path order, so the reported
// pair is deterministic.
func rejectDuplicateTemplateNames(entries []state.TemplateEntry) error {
	sorted := make([]state.TemplateEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	byName := make(map[string]string, len(sorted))
	for _, entry := range sorted {
		if prior, dup := byName[entry.Name]; dup {
			return fmt.Errorf("repo: %w", manifest.NewRepositoryError(manifest.CodeRepoDupName, entry.Path,
				fmt.Sprintf("template name %q is declared by both %q and %q", entry.Name, prior, entry.Path)))
		}
		byName[entry.Name] = entry.Path
	}
	return nil
}

// buildEntry loads and validates a template manifest and builds an index entry.
func buildEntry(manifestPath, rel, ref string, allTags []string, multi bool) (state.TemplateEntry, error) {
	tmpl, err := manifest.LoadTemplate(manifestPath)
	if err != nil {
		return state.TemplateEntry{}, fmt.Errorf("repo: %s: %w", manifestPath, err)
	}
	if err := tmpl.Validate(); err != nil {
		return state.TemplateEntry{}, fmt.Errorf("repo: %s is invalid: %w", manifestPath, err)
	}

	name := tmpl.Metadata.Name
	entry := state.TemplateEntry{
		Name:        name,
		Version:     tmpl.Metadata.Version,
		Description: tmpl.Metadata.Description,
		LabelsFlat:  flattenLabels(tmpl.Metadata.Labels),
		Path:        normalizeTemplatePath(rel),
		Ref:         ref,
		Tags:        stableTagsFor(allTags, name, multi),
	}
	return entry, nil
}

// listTags returns all clone tags (`git tag -l`); an error or empty output means
// there are no tags, which is normal for a repository without releases.
func (m *Manager) listTags(ctx context.Context, dir string) []string {
	res, err := m.git(ctx, dir, []string{"tag", "-l"}, nil)
	if err != nil {
		return nil
	}
	var tags []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

// flattenLabels copies manifest labels into the index form (LabelsFlat).
func flattenLabels(labels map[string][]string) map[string][]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string][]string, len(labels))
	for k, v := range labels {
		vs := make([]string, len(v))
		copy(vs, v)
		out[k] = vs
	}
	return out
}

// normalizeTemplatePath converts a relative template path to its canonical index
// form: repository root is ".", otherwise the path uses slash separators.
func normalizeTemplatePath(rel string) string {
	if rel == "." || rel == "" {
		return "."
	}
	return filepath.ToSlash(rel)
}
