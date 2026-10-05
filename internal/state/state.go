// Package state manages the tplaiter home directory (~/.tplaiter by default,
// TPLAITER_HOME for tests/CI) and its state files: config.yaml, index.yaml,
// projects.yaml, and state.yaml. See the package documentation for details.
//
// All files are YAML with a version field for compatibility gating and future
// migrations (see migrate.go). Writes are always atomic (tmp+rename, see
// atomic.go); interprocess serialization uses [WithLock].
package state

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/naming"
)

// HomeEnv overrides the tplaiter home directory. Tests and CI use it to avoid
// touching the real ~/.tplaiter.
const HomeEnv = naming.HomeEnv

// reposDirName is the clone cache subdirectory for template repositories.
const reposDirName = "repos"

// homeDirPerm/filePerm are permissions for the state directory and its files.
// The data is not secret (tokens are stored separately in tplater.db), but
// access is restricted to the owner by default to reduce future permission drift.
const (
	homeDirPerm = 0o700
	filePerm    = 0o600
)

// Home returns the tplaiter home path: TPLAITER_HOME when set (even an empty
// directory is an explicit caller choice), otherwise
// ~/.tplaiter.
func Home() (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("state: determining user home directory: %w", err)
	}
	home, err := naming.ResolveHome(os.Getenv, dir)
	if err != nil {
		return "", fmt.Errorf("state: selecting home directory: %w", err)
	}
	return home, nil
}

// EnsureHome ensures the tplaiter home directory and its skeleton (repos/) exist.
// It does not create files (config.yaml, etc.): each Load helper returns a
// default when its file is absent and creates it on the first write. created
// reports whether the directory existed before the call for first-run messaging.
func EnsureHome() (home string, created bool, err error) {
	home, err = Home()
	if err != nil {
		return "", false, err
	}
	if err := naming.GuardLegacyWrite(home); err != nil {
		return "", false, fmt.Errorf("state: legacy writer guard: %w", err)
	}

	_, statErr := os.Stat(home)
	switch {
	case statErr == nil:
		created = false
	case os.IsNotExist(statErr):
		created = true
	default:
		return "", false, fmt.Errorf("state: checking directory %s: %w", home, statErr)
	}

	if err := os.MkdirAll(filepath.Join(home, reposDirName), homeDirPerm); err != nil {
		return "", false, fmt.Errorf("state: creating directory %s: %w", home, err)
	}

	return home, created, nil
}
