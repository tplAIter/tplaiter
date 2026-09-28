package repo

import (
	"context"
	"fmt"
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

// scanRepo determines the repository type in clone dir and builds its template index.
//
// Detection order (§3):
//  1. template.manifest.yaml at the root → single (one template, path ".");
//  2. repo.manifest.yaml at the root → multi (paths from templates[]; if
//     templates[] is absent, auto-scan);
//  3. neither → auto-scan */template.manifest.yaml and */*/template.manifest.yaml.
//
// strict controls handling of a broken or invalid manifest:
//   - strict=true (repo add): every such error is fatal; add must report the
//     path and reason and must not register the repository;
//   - strict=false (repo update): a broken template is a warning and only that
//     template is skipped; an existing repository must not break because one
//     remote template was edited.
func (m *Manager) scanRepo(ctx context.Context, dir, branch string, strict bool) ([]state.TemplateEntry, error) {
	ref := branch
	if ref == "" {
		ref = "HEAD"
	}

	singlePath := filepath.Join(dir, templateManifestName)
	repoPath := filepath.Join(dir, repoManifestName)

	var (
		relPaths []string // Relative template directories.
		multi    bool
	)

	switch {
	case fileExists(singlePath):
		relPaths = []string{"."}
		multi = false
	case fileExists(repoPath):
		multi = true
		r, err := manifest.LoadRepository(repoPath)
		if err != nil {
			return nil, fmt.Errorf("repo: %s: %w", repoManifestName, err)
		}
		if len(r.Templates) > 0 {
			for _, tr := range r.Templates {
				p := strings.TrimSpace(tr.Path)
				if p == "" {
					return nil, fmt.Errorf("repo: %s: пустой templates[].path", repoManifestName)
				}
				rel := filepath.Clean(p)
				manifestPath := filepath.Join(dir, rel, templateManifestName)
				if !fileExists(manifestPath) {
					return nil, fmt.Errorf("repo: %s: шаблон %q не содержит %s", repoManifestName, p, templateManifestName)
				}
				relPaths = append(relPaths, rel)
			}
		} else {
			relPaths = autoScan(dir)
		}
	default:
		multi = true // Auto-scanned subdirectories are treated as multi (namespaced tags).
		relPaths = autoScan(dir)
		if len(relPaths) == 0 {
			return nil, fmt.Errorf("repo: не найдено ни %s в корне, ни */%s (глубина 2)", templateManifestName, templateManifestName)
		}
	}

	allTags := m.listTags(ctx, dir)

	entries := make([]state.TemplateEntry, 0, len(relPaths))
	for _, rel := range relPaths {
		manifestPath := filepath.Join(dir, rel, templateManifestName)
		entry, err := buildEntry(manifestPath, rel, ref, allTags, multi)
		if err != nil {
			if strict {
				return nil, err
			}
			m.warnf("%s — пропускаю шаблон: %v\n", rel, err)
			continue
		}
		entries = append(entries, entry)
	}
	// Deterministic index order.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// buildEntry loads and validates a template manifest and builds an index entry.
func buildEntry(manifestPath, rel, ref string, allTags []string, multi bool) (state.TemplateEntry, error) {
	tmpl, err := manifest.LoadTemplate(manifestPath)
	if err != nil {
		return state.TemplateEntry{}, fmt.Errorf("repo: %s: %w", manifestPath, err)
	}
	if err := tmpl.Validate(); err != nil {
		return state.TemplateEntry{}, fmt.Errorf("repo: %s невалиден: %w", manifestPath, err)
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

// autoScan searches for template.manifest.yaml at depths 1 and 2 (*/…, */*/…).
func autoScan(dir string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(rel string) {
		if !seen[rel] {
			seen[rel] = true
			out = append(out, rel)
		}
	}

	// Depth 1: */template.manifest.yaml.
	lvl1, _ := os.ReadDir(dir)
	for _, e1 := range lvl1 {
		if !e1.IsDir() || strings.HasPrefix(e1.Name(), ".") {
			continue
		}
		if fileExists(filepath.Join(dir, e1.Name(), templateManifestName)) {
			add(e1.Name())
			continue
		}
		// Depth 2: */*/template.manifest.yaml.
		lvl2, _ := os.ReadDir(filepath.Join(dir, e1.Name()))
		for _, e2 := range lvl2 {
			if !e2.IsDir() || strings.HasPrefix(e2.Name(), ".") {
				continue
			}
			if fileExists(filepath.Join(dir, e1.Name(), e2.Name(), templateManifestName)) {
				add(filepath.Join(e1.Name(), e2.Name()))
			}
		}
	}
	sort.Strings(out)
	return out
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
