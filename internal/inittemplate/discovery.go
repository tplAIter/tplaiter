package inittemplate

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
)

// checkEnclosingProvider rejects init-template when the target directory lies
// inside an existing template repository (a provider with a root
// template.manifest.yaml or repo.manifest.yaml) that already discovers a
// template with the same metadata.name: registering that provider would then
// fail with TPL-E-REPO-DUP-NAME. The enclosing repository is the nearest
// ancestor that holds a manifest, bounded by the nearest .git directory. A
// provider whose own discovery fails is not our concern here: it is reported
// by lint-template, so it only produces a warning.
func checkEnclosingProvider(opts InitOptions, repoDir string) error {
	provider, ok := enclosingProvider(repoDir)
	if !ok {
		return nil
	}
	paths, err := repo.DiscoverTemplatePaths(provider)
	if err != nil {
		warnf(opts.Out, "enclosing template repository %s: discovery failed: %v", provider, err)
		return nil
	}
	for _, rel := range paths {
		tpl, err := manifest.LoadTemplate(filepath.Join(provider, filepath.FromSlash(rel), templateManifestFileName))
		if err != nil {
			continue
		}
		if tpl.Metadata.Name == opts.Name {
			return fmt.Errorf("inittemplate: %w", manifest.NewRepositoryError(manifest.CodeRepoDupName, rel,
				fmt.Sprintf("enclosing template repository %s already declares template %q", provider, opts.Name)))
		}
	}
	return nil
}

// enclosingProvider walks up from the parent of repoDir and returns the first
// directory that contains a template or repository manifest. The walk stops
// at a directory containing .git (the repository boundary) or at the
// filesystem root.
func enclosingProvider(repoDir string) (string, bool) {
	abs, err := filepath.Abs(repoDir)
	if err != nil {
		return "", false
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		for _, name := range []string{templateManifestFileName, repoManifestFileName} {
			if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
				return dir, true
			}
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return "", false
		}
		if parent := filepath.Dir(dir); parent == dir {
			return "", false
		}
	}
}

// verifyGenerated proves that the generated repository is discoverable with
// the same rules as `repo add` and `lint-template`: exactly one template, at
// the repository root (single) or at <name>/ (multi).
func verifyGenerated(opts InitOptions, repoDir string) error {
	paths, err := repo.DiscoverTemplatePaths(repoDir)
	if err != nil {
		return fmt.Errorf("inittemplate: generated repository is not discoverable: %w", err)
	}
	want := "."
	if opts.Multi {
		want = opts.Name
	}
	if len(paths) != 1 || paths[0] != want {
		return fmt.Errorf("inittemplate: generated repository discovers %v, want [%s]", paths, want)
	}
	return nil
}
