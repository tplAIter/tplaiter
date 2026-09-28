package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Op is a plan file operation.
type Op int

const (
	// OpKeep leaves the file untouched (informational: unchanged, user version kept, absent, etc.).
	OpKeep Op = iota
	// OpWrite writes Content (update, create, merge, or conflict).
	OpWrite
	// OpDelete deletes a work-tree file.
	OpDelete
)

// Action is the decision for one file.
type Action struct {
	// Path is the file's relative slash path.
	Path string
	// Op is the operation.
	Op Op
	// Content is new content (for OpWrite).
	Content []byte
	// Reason is the human-readable reason (for plan output).
	Reason string
	// Conflict is true when Content contains conflict markers.
	Conflict bool
}

// Plan is a set of update-operation decisions.
type Plan struct {
	Actions  []Action
	Warnings []string
}

// Conflicts returns paths with conflict markers (for exit code and report).
func (p *Plan) Conflicts() []string {
	var out []string
	for _, a := range p.Actions {
		if a.Conflict {
			out = append(out, a.Path)
		}
	}
	sort.Strings(out)
	return out
}

// HasChanges reports whether the plan changes the tree (OpWrite/OpDelete exists).
func (p *Plan) HasChanges() bool {
	for _, a := range p.Actions {
		if a.Op == OpWrite || a.Op == OpDelete {
			return true
		}
	}
	return false
}

// Compute builds a plan using the 3-way model.
//
// Inputs:
//   - baseFiles   — clean render of the OLD template version (common ancestor);
//   - targetFiles — clean render of the NEW template version;
//   - baseline    — file sha256 values from .tplaiter/baseline.json (user-edit
//     detection; missing entry falls back to the base-render hash);
//   - workDir     — project root (actual files are read).
//
// The path universe is the union of baseFiles, targetFiles, and baseline keys;
// arbitrary user files outside the template are untouched.
func Compute(baseFiles, targetFiles map[string][]byte, baseline map[string]string, workDir string) (*Plan, error) {
	paths := unionKeys(baseFiles, targetFiles, baseline)
	plan := &Plan{} //nolint:varnamelen // plan is universally understood.

	for _, rel := range paths {
		bContent, inBase := baseFiles[rel]
		tContent, inTarget := targetFiles[rel]
		wContent, workExists, err := readWork(workDir, rel)
		if err != nil {
			return nil, err
		}

		baseHash := baseline[rel]
		userUnmodified := workExists && isUnmodified(wContent, baseHash, bContent, inBase)

		switch {
		case inBase && inTarget:
			if bytes.Equal(bContent, tContent) {
				// (b) the template did not change the file: keep the user's version.
				if !workExists {
					plan.add(rel, OpWrite, tContent, "recreate (deleted by user, template unchanged)", false)
				} else {
					plan.add(rel, OpKeep, nil, "unchanged", false)
				}
				continue
			}
			// The template changed the file.
			switch {
			case !workExists:
				plan.add(rel, OpWrite, tContent, "recreate (deleted by user, updated upstream)", false)
			case userUnmodified:
				// (a) hash(work)==baseline: overwrite with target.
				plan.add(rel, OpWrite, tContent, "update", false)
			default:
				// (c) all three differ: 3-way merge.
				merged, conflict := merge3(bContent, wContent, tContent)
				reason := "merge"
				if conflict {
					reason = "conflict"
				}
				plan.add(rel, OpWrite, merged, reason, conflict)
			}

		case inTarget && !inBase:
			// (d) new file in target.
			switch {
			case !workExists:
				plan.add(rel, OpWrite, tContent, "create", false)
			case bytes.Equal(wContent, tContent):
				plan.add(rel, OpKeep, nil, "already present", false)
			default:
				// work exists and differs: conflict (empty base).
				merged, _ := merge3(nil, wContent, tContent)
				plan.add(rel, OpWrite, merged, "conflict (created upstream, differs locally)", true)
			}

		default:
			// (e) file was in base/baseline but absent in target: deleted upstream.
			switch {
			case !workExists:
				plan.add(rel, OpKeep, nil, "already absent", false)
			case userUnmodified:
				plan.add(rel, OpDelete, nil, "delete (removed upstream)", false)
			default:
				plan.add(rel, OpKeep, nil, "kept (modified locally, removed upstream)", false)
				plan.Warnings = append(plan.Warnings,
					rel+": удалён в новой версии шаблона, но изменён локально — оставлен без изменений")
			}
		}
	}

	return plan, nil
}

// add adds an action to the plan.
func (p *Plan) add(path string, op Op, content []byte, reason string, conflict bool) {
	p.Actions = append(p.Actions, Action{
		Path:     path,
		Op:       op,
		Content:  content,
		Reason:   reason,
		Conflict: conflict,
	})
}

// Apply materializes the plan in workDir: writes/deletes files and removes empty
// directories left by deletion. It returns conflict paths.
func (p *Plan) Apply(workDir string) ([]string, error) {
	// A decoded or computed legacy plan cannot be materialized until the
	// lifecycle owner supplies the later authenticated apply boundary.
	return nil, ErrLifecycleUnavailable
}

// applyLegacy retains the former materialization algorithm as restoration
// input for the authorized lifecycle owner. T5 deliberately has no caller.
func (p *Plan) applyLegacy(workDir string) ([]string, error) {
	for _, a := range p.Actions {
		full := filepath.Join(workDir, filepath.FromSlash(a.Path))
		switch a.Op {
		case OpWrite:
			if err := writeFile(full, a.Content); err != nil {
				return nil, err
			}
		case OpDelete:
			if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("update: remove %s: %w", a.Path, err)
			}
			pruneEmptyDirs(workDir, filepath.Dir(full))
		case OpKeep:
			// no-op
		}
	}
	return p.Conflicts(), nil
}

// readWork reads a work-tree file and returns (content, exists, err).
func readWork(workDir, rel string) ([]byte, bool, error) {
	full := filepath.Join(workDir, filepath.FromSlash(rel))
	data, err := os.ReadFile(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("update: read work %s: %w", rel, err)
	}
	return data, true, nil
}

// isUnmodified reports whether the work file matches the reference (not edited
// by the user). The reference is the stored baseline hash, or base-render content
// when no hash exists.
func isUnmodified(work []byte, baseHash string, base []byte, inBase bool) bool {
	if baseHash != "" {
		return sha256Hex(work) == baseHash
	}
	if inBase {
		return bytes.Equal(work, base)
	}
	return false
}

// sha256Hex returns hex(sha256(data)), matching engine.ComputeBaseline.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// unionKeys returns the sorted union of base/target render keys and baseline keys.
func unionKeys(baseFiles, targetFiles map[string][]byte, baseline map[string]string) []string {
	seen := make(map[string]struct{}, len(baseFiles)+len(targetFiles)+len(baseline))
	for k := range baseFiles {
		seen[k] = struct{}{}
	}
	for k := range targetFiles {
		seen[k] = struct{}{}
	}
	for k := range baseline {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// writeFile creates parent directories and writes a file (0644).
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("update: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: generated sources are ordinary 0644 files.
		return fmt.Errorf("update: write %s: %w", path, err)
	}
	return nil
}

// pruneEmptyDirs removes empty directories upward from dir without passing root.
func pruneEmptyDirs(root, dir string) {
	root = filepath.Clean(root)
	for cur := filepath.Clean(dir); cur != root && len(cur) > len(root); {
		entries, err := os.ReadDir(cur)
		if err != nil || len(entries) > 0 {
			return
		}
		if err := os.Remove(cur); err != nil {
			return
		}
		cur = filepath.Dir(cur)
	}
}
