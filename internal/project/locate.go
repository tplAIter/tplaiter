// Package project discovers a tplaiter project from an arbitrary working
// directory and resolves the template manifest to which it is linked
// (the base infrastructure for `tplaiter run`).
//
// The package does not read or write the ~/.tplaiter/projects.yaml registry;
// that belongs to a separate implementation. It only searches upward for the
// local .tplaiter/project.yaml marker and resolves the template manifest at
// the version recorded in that marker.
package project

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/naming"
)

// MarkerRelPath is the project marker path relative to the project root.
const MarkerRelPath = ".tplaiter/project.yaml"

// LegacyMarkerRelPath remains read-only compatibility. Writers always use
// MarkerRelPath, and two markers at one root are ambiguous rather than merged.
const LegacyMarkerRelPath = ".tplater/project.yaml"

// ErrNotInProject is returned by [FindRoot] when .tplaiter/project.yaml is
// absent from the starting directory and all parents up to $HOME or the file
// system root. errors.Is distinguishes this case from other filesystem or
// parsing errors, which FindRoot returns unchanged.
var ErrNotInProject = errors.New("directory is not a tplaiter project")

// FindRoot searches for the tplaiter project root by walking upward from
// startDir until it finds .tplaiter/project.yaml. It stops at the user's home
// directory ($HOME, when defined) or the filesystem root; each boundary is
// checked before stopping, so a marker directly in $HOME or "/" is found.
//
// root is the absolute path of the directory containing .tplaiter/project.yaml
// (neither the file itself nor .tplaiter). proj is that directory's parsed marker.
//
// Errors: [ErrNotInProject] (wrapped with a human-readable message) if the
// search reaches a boundary without finding anything; a startDir or marker
// parsing error if a marker is found but unreadable or invalid. This means the
// project is broken rather than absent, and callers should distinguish it with errors.Is.
func FindRoot(startDir string) (root string, proj *manifest.Project, err error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", nil, fmt.Errorf("project: determining absolute path for %s: %w", startDir, err)
	}
	dir = filepath.Clean(dir)

	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		home = filepath.Clean(home)
	}

	for {
		markerPath := filepath.Join(dir, MarkerRelPath)
		legacyPath := filepath.Join(dir, LegacyMarkerRelPath)
		_, modernErr := os.Stat(markerPath)
		_, legacyErr := os.Stat(legacyPath)
		// os.Stat of a child below a regular tombstone reports ENOTDIR, which
		// is neither a modern/legacy marker pair nor an absence. Do not let it
		// bypass receipt verification merely because the modern marker exists.
		if legacyInfo, err := os.Lstat(filepath.Join(dir, naming.LegacyProjectDir)); err == nil && legacyInfo.Mode().IsRegular() {
			migrated, migrationErr := naming.MigratedProjectRoot(dir)
			if migrationErr != nil {
				return "", nil, fmt.Errorf("project: verify migration in %s: %w", dir, migrationErr)
			}
			if !migrated {
				return "", nil, fmt.Errorf("project: unverified legacy tombstone in %s", dir)
			}
			legacyErr = os.ErrNotExist
		}
		if modernErr == nil && legacyErr == nil {
			migrated, migrationErr := naming.MigratedProjectRoot(dir)
			if migrationErr != nil {
				return "", nil, fmt.Errorf("project: verify migration in %s: %w", dir, migrationErr)
			}
			if !migrated {
				return "", nil, fmt.Errorf("project: both modern and legacy markers exist in %s", dir)
			}
			legacyErr = os.ErrNotExist
		}
		if os.IsNotExist(modernErr) && legacyErr == nil {
			markerPath, modernErr = legacyPath, nil
		}
		switch {
		case modernErr == nil:
			p, loadErr := manifest.LoadProject(markerPath)
			if loadErr != nil {
				return "", nil, fmt.Errorf("project: loading project marker %s: %w", markerPath, loadErr)
			}
			return dir, p, nil
		case !os.IsNotExist(modernErr):
			return "", nil, fmt.Errorf("project: checking project marker %s: %w", markerPath, modernErr)
		case !os.IsNotExist(legacyErr):
			return "", nil, fmt.Errorf("project: checking legacy project marker %s: %w", legacyPath, legacyErr)
		}

		if homeErr == nil && dir == home {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // Filesystem root: do not walk higher.
		}
		dir = parent
	}

	return "", nil, fmt.Errorf(
		"%w: %s not found in %s or any parent directory — "+
			"command must be run inside a project created with `tplaiter new`",
		ErrNotInProject, MarkerRelPath, startDir,
	)
}
