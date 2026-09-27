// Package projectsync reconciles the ~/.tplaiter/projects.yaml registry entry
// for the project in the current working directory with the actual state on
// disk (including path tracking).
//
// [SyncCurrent] handles three scenarios:
//   - the project directory moved (same id, different path), so path and
//     lastSeenAt are updated;
//   - the project is absent from the registry (cloned by a colleague, registry
//     lost, and so on), so it is registered automatically: Template/CreatedAt
//     come from .tplaiter/project.yaml and the current time;
//   - stored baselineSHA differs from actual .tplaiter/baseline.json content,
//     meaning the project was updated on another machine, so the registry is
//     updated from the observed state.
//
// One [state.Projects.Upsert] call covers all three cases: its contract always
// updates path/lastSeenAt/baselineSHA and fixes Template/CreatedAt only on the
// first insert. This already implements precisely that behavior, so this
// package need not branch between the scenarios.
package projectsync

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/state"
)

// SyncCurrent synchronizes the ~/.tplaiter/projects.yaml registry entry (home
// directory home) for a tplater project discovered by walking from cwd up its
// directory tree ([project.FindRoot]). now is written as CreatedAt (only on the
// first insert) and LastSeenAt.
//
// A cwd outside a tplater project is not an error: SyncCurrent returns nil
// without changing anything (the registry is a navigation convenience, not a
// source of truth, and there is nothing to synchronize outside a project). It
// returns other errors unchanged (corrupt .tplaiter/project.yaml, inaccessible
// .tplaiter/baseline.json, or a home-directory lock). SyncCurrent itself never
// panics or writes output; its caller decides whether an error is fatal for a
// particular command (see cmd.projectSyncPreRun in internal/cmd/projects.go,
// where it is nonfatal).
func SyncCurrent(home, cwd string, now time.Time) error {
	root, proj, err := project.FindRoot(cwd)
	if err != nil {
		if errors.Is(err, project.ErrNotInProject) {
			return nil
		}
		return fmt.Errorf("projectsync: поиск корня проекта: %w", err)
	}

	baselineSHA, err := hashFile(filepath.Join(root, engine.BaselineRelPath))
	if err != nil {
		return fmt.Errorf("projectsync: хеш %s: %w", engine.BaselineRelPath, err)
	}

	ref := state.ProjectRef{
		ID:   proj.ID,
		Path: root,
		Template: state.TemplateSelection{
			Repo:    proj.Template.Repo,
			Name:    proj.Template.Name,
			Version: proj.Template.Version,
		},
		CreatedAt:   now,
		LastSeenAt:  now,
		BaselineSHA: baselineSHA,
	}

	return state.WithLock(home, func() error {
		projects, err := state.LoadProjects(home)
		if err != nil {
			return err
		}
		projects.Upsert(ref)
		return state.SaveProjects(home, projects)
	})
}

// hashFile returns the hexadecimal SHA-256 of path's content. It uses the same
// formula as [internal/newcmd] during initial project registration in
// `tplater new`, so baselineSHA values are comparable.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
