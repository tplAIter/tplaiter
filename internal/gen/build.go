package gen

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

var errWorkspacePathUnsafe = errors.New("gen: unsafe workspace path")

// runPostFormat best-effort runs gofumpt -w or standard gofmt -w on changed
// .go files. gofmt is mandatory fallback: gofumpt is often absent on clean CI
// or servers, but the generator must still leave gofmt-clean sources. Formatting
// failure does not fail gen; the final build gate remains responsible for code validity.
func runPostFormat(ctx context.Context, opts Options, changed []string, log func(format string, args ...any)) error {
	goFiles := make([]string, 0, len(changed))
	for _, f := range changed {
		if strings.HasSuffix(f, ".go") {
			goFiles = append(goFiles, f)
		}
	}
	if len(goFiles) == 0 {
		return nil
	}
	return ErrExecutionUnavailable
}

// isGoProject limits gofumpt/gofmt to projects with a Go module or workspace.
// Rust and other-language generators must not receive a Go formatter merely
// because every template has a post-generation gate.
func isGoProject(root string) bool {
	for _, name := range []string{"go.mod", "go.work"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			return true
		}
	}
	return false
}

// runBuildGate runs the manifest's commands.build.run build gate once at the
// project root. The command is trusted manifest text and therefore runs like
// `tplater run`, through a POSIX shell. Older Go manifests without a build
// command retain the workspace-aware `go build ./...` fallback.
func runBuildGate(ctx context.Context, tpl *manifest.Template, opts Options) (string, string, error) {
	return "", "", ErrExecutionUnavailable
}

// findFormatter prefers gofumpt from PATH/~/go/bin, then uses the standard gofmt
// from the Go toolchain.
func findFormatter() (path, name string, err error) {
	return "", "", ErrExecutionUnavailable
}

// goBuild runs `go build ./...` in ProjectRoot, returning combined output on
// failure. In a go.work monorepo (root is not a module), it builds per workspace
// use directory (CG-4 finding: otherwise the build gate always failed and rolled
// back generation in workspace projects).
func goBuild(ctx context.Context, opts Options) (string, error) {
	dirs, err := workspaceUseDirs(opts.ProjectRoot)
	if err != nil {
		return "", err
	}
	if dirs == nil {
		dirs = []string{"."}
	}
	_ = dirs
	return "", ErrExecutionUnavailable
}

// workspaceUseDirs returns go.work use directories at the project root (nil when
// there is no go.work, indicating a normal module).
func workspaceUseDirs(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.work"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	wf, err := modfile.ParseWork("go.work", data, nil)
	if err != nil {
		return nil, fmt.Errorf("gen: parsing go.work: %w", err)
	}
	dirs := make([]string, 0, len(wf.Use))
	for _, u := range wf.Use {
		if unsafeWorkspacePath(root, u.Path) {
			return nil, errWorkspacePathUnsafe
		}
		dirs = append(dirs, u.Path)
	}
	return dirs, nil
}

func unsafeWorkspacePath(root, rel string) bool {
	if rel == "" || filepath.IsAbs(filepath.FromSlash(rel)) {
		return true
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	cleanSlash := filepath.ToSlash(clean)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || (rel != cleanSlash && rel != "./"+cleanSlash) {
		return true
	}
	info, err := os.Lstat(filepath.Join(root, clean))
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0 || !info.IsDir()
}
