// Package resources copies from a template checkout into a project's .tplaiter/
// the resources needed offline after checkout removal: environment directories
// (Ansible playbooks), generator snippets, and ai-config. Only manifest-declared
// resources are copied; undeclared environment/generators/aiConfig directories
// are not created.
//
// The logic is extracted from internal/newcmd into a shared package so
// `tplater update` can reuse it without duplication: updating the version copies
// the same resources from the new checkout. newcmd retains the thin
// copyResources → [Copy] wrapper.
package resources

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/aiconfig"
	"github.com/tplAIter/tplaiter/internal/envsetup"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// Copy transfers declared environment, generator, and ai-config resources from
// template checkout src into the project's .tplaiter/ target.
//
// Path contracts (symmetric across the three consumers):
//   - environment/generators: files preserve their relative path from the
//     template root under the RelPath directory, so Playbook.File/
//     Generator.Snippet join with TemplateDir/GeneratorsDir without renormalizing
//     (see envsetup.EnvironmentRelPath, gen.GeneratorsRelPath);
//   - ai-config: contents of aiConfig.path go DIRECTLY into .tplaiter/ai-config
//     (aiconfig.Load expects config.json at that directory's root).
func Copy(src fs.FS, target string, tpl *manifest.Template) error {
	if err := copyEnvironment(src, target, tpl); err != nil {
		return err
	}
	if err := copyGenerators(src, target, tpl); err != nil {
		return err
	}
	return copyAIConfig(src, target, tpl)
}

// copyEnvironment copies directories referenced by environment.playbooks[].file
// into .tplaiter/environment, preserving structure.
func copyEnvironment(src fs.FS, target string, tpl *manifest.Template) error {
	if len(tpl.Environment.Playbooks) == 0 {
		return nil
	}
	roots := make([]string, 0, len(tpl.Environment.Playbooks))
	for _, pb := range tpl.Environment.Playbooks {
		if pb.File != "" {
			roots = append(roots, pb.File)
		}
	}
	dst := filepath.Join(target, envsetup.EnvironmentRelPath)
	return copyRootsPreserving(src, roots, dst, "environment.playbooks[].file")
}

// copyGenerators copies snippet directories (Generator.Snippet and Anchor.Insert)
// into .tplaiter/generators, preserving structure.
func copyGenerators(src fs.FS, target string, tpl *manifest.Template) error {
	if len(tpl.Generators) == 0 {
		return nil
	}
	var roots []string
	for i := range tpl.Generators {
		g := &tpl.Generators[i]
		if g.Snippet != "" {
			roots = append(roots, g.Snippet)
		}
		for _, t := range g.Targets { // multifile form
			if t.Snippet != "" {
				roots = append(roots, t.Snippet)
			}
		}
		for _, a := range g.Anchors {
			if a.Insert != "" {
				roots = append(roots, a.Insert)
			}
		}
	}
	dst := filepath.Join(target, gen.GeneratorsRelPath)
	return copyRootsPreserving(src, roots, dst, "generators[].snippet/anchors[].insert")
}

// copyAIConfig copies aiConfig.path contents into .tplaiter/ai-config.
func copyAIConfig(src fs.FS, target string, tpl *manifest.Template) error {
	aiPath := strings.Trim(strings.TrimSpace(tpl.AIConfig.Path), "/")
	if aiPath == "" {
		return nil
	}
	dst := filepath.Join(target, aiconfig.AIConfigRelPath)
	if err := copyFSTree(src, aiPath, dst, true); err != nil {
		return fmt.Errorf("resources: копирование aiConfig.path %q: %w", tpl.AIConfig.Path, err)
	}
	return nil
}

// copyRootsPreserving copies top-level directories (or files) containing refs
// under dst, preserving structure relative to the template root. Deduplicating
// top segments avoids copying one directory repeatedly for multiple playbooks/generators.
func copyRootsPreserving(src fs.FS, refs []string, dst, what string) error {
	seen := make(map[string]bool)
	for _, ref := range refs {
		root := topSegment(ref)
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		if err := copyFSTree(src, root, dst, false); err != nil {
			return fmt.Errorf("resources: копирование ресурса %s (%q): %w", what, root, err)
		}
	}
	return nil
}

// topSegment returns the first slash-separated path segment (resource top-level
// directory), or the path itself when there are no segments. Empty/"."/".." → "".
func topSegment(p string) string {
	p = path.Clean(strings.TrimSpace(p))
	if p == "." || p == ".." || p == "" || strings.HasPrefix(p, "..") {
		return ""
	}
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}

// copyFSTree copies the src subtree rooted at srcRel into dst. flatten=false
// retains srcRel in the target path (dst/<srcRel>/...); flatten=true removes the
// srcRel prefix (directory contents go directly into dst). The checkout-worktree
// .git directory is not copied.
func copyFSTree(src fs.FS, srcRel, dst string, flatten bool) error {
	srcRel = path.Clean(srcRel)
	return fs.WalkDir(src, srcRel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		rel := p
		if flatten {
			rel = strings.TrimPrefix(p, srcRel)
			rel = strings.TrimPrefix(rel, "/")
		}
		if rel == "" { // subtree root when flattening
			if d.IsDir() {
				return nil
			}
		}
		outPath := filepath.Join(dst, filepath.FromSlash(rel))

		if d.IsDir() {
			return os.MkdirAll(outPath, 0o755)
		}
		data, rerr := fs.ReadFile(src, p)
		if rerr != nil {
			return fmt.Errorf("чтение %s: %w", p, rerr)
		}
		if mkErr := os.MkdirAll(filepath.Dir(outPath), 0o755); mkErr != nil {
			return mkErr
		}
		mode := os.FileMode(0o644)
		if info, ierr := d.Info(); ierr == nil {
			mode = info.Mode().Perm()
		}
		if werr := os.WriteFile(outPath, data, mode); werr != nil {
			return fmt.Errorf("запись %s: %w", outPath, werr)
		}
		return nil
	})
}
