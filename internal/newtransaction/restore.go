package newtransaction

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ErrAbortModified reports that a staged tree changed a path that existed
// before the transaction began. Only content-free evidence (digests) of the
// before image is journaled, so such a change cannot be undone; abort refuses
// before touching anything and leaves the staged tree for inspection.
var ErrAbortModified = errors.New("new transaction: staged tree modified pre-existing paths")

type treeEntry struct {
	kind, mode, content string
}

// parseTree decodes the snapshotTree wire: one "path\x00kind\x00mode\x00digest"
// record per line.
func parseTree(raw []byte) (map[string]treeEntry, error) {
	out := map[string]treeEntry{}
	if len(raw) == 0 {
		return out, nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, "\x00")
		if len(fields) != 4 || fields[0] == "" {
			return nil, ErrUnsafe
		}
		out[fields[0]] = treeEntry{kind: fields[1], mode: fields[2], content: fields[3]}
	}
	return out, nil
}

// restoreBeforeTree returns the staged tree to its journaled before image by
// removing every path the transaction added and restoring changed modes. It
// first verifies that no pre-existing path was modified or removed; if one
// was, it returns ErrAbortModified without changing anything.
func (t *Transaction) restoreBeforeTree() error {
	rawBefore, err := t.readBlob(t.j.TargetBeforeTreeSHA)
	if err != nil {
		return err
	}
	before, err := parseTree(rawBefore)
	if err != nil {
		return err
	}
	rawNow, err := snapshotTree(t.j.Staging)
	if err != nil {
		return err
	}
	now, err := parseTree(rawNow)
	if err != nil {
		return err
	}
	var added, modified []string
	chmods := map[string]os.FileMode{}
	for rel, entry := range now {
		old, existed := before[rel]
		switch {
		case !existed:
			added = append(added, rel)
		case old.kind != entry.kind || old.content != entry.content:
			modified = append(modified, rel)
		case old.mode != entry.mode:
			mode, parseErr := strconv.ParseUint(old.mode, 8, 32)
			if parseErr != nil {
				return ErrUnsafe
			}
			chmods[rel] = os.FileMode(mode)
		}
	}
	for rel := range before {
		if _, still := now[rel]; !still {
			modified = append(modified, rel)
		}
	}
	if len(modified) > 0 {
		sort.Strings(modified)
		return fmt.Errorf("%w: %s", ErrAbortModified, strings.Join(modified, ", "))
	}
	// Remove the deepest paths first so directories are empty when reached.
	sort.Slice(added, func(i, j int) bool {
		di, dj := strings.Count(added[i], "/"), strings.Count(added[j], "/")
		if di != dj {
			return di > dj
		}
		return added[i] > added[j]
	})
	for _, rel := range added {
		if err := os.Remove(filepath.Join(t.j.Staging, filepath.FromSlash(rel))); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	for rel, mode := range chmods {
		if now[rel].kind == "symlink" {
			continue
		}
		if err := os.Chmod(filepath.Join(t.j.Staging, filepath.FromSlash(rel)), mode); err != nil {
			return err
		}
	}
	return nil
}
