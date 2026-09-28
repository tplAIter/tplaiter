package update

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultConflictExcludes are directories excluded by default: .tplaiter, .git,
// and docs/ (which may contain marker examples).
var DefaultConflictExcludes = []string{".git", ".tplaiter", "docs"}

// conflictMarkerPrefix is the conflict-marker line prefix (fail-fast when
// `<<<<<<< `).
const conflictMarkerPrefix = "<<<<<<< "

// ScanConflicts walks root and returns sorted files containing `<<<<<<< `. It
// skips excludeDirs (by segment name) and .git. Empty excludeDirs ->
// DefaultConflictExcludes.
func ScanConflicts(root string, excludeDirs []string) ([]string, error) {
	if excludeDirs == nil {
		excludeDirs = DefaultConflictExcludes
	}
	exclude := make(map[string]struct{}, len(excludeDirs))
	for _, d := range excludeDirs {
		exclude[d] = struct{}{}
	}

	var found []string
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, skip := exclude[d.Name()]; skip && path != root {
				return fs.SkipDir
			}
			return nil
		}
		has, herr := fileHasConflictMarker(path)
		if herr != nil {
			return herr
		}
		if has {
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				rel = path
			}
			found = append(found, filepath.ToSlash(rel))
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("update: scan conflicts: %w", walkErr)
	}
	sort.Strings(found)
	return found, nil
}

// fileHasConflictMarker reports whether a file contains a conflict marker.
// Binary files (with NUL in the first block) are skipped.
func fileHasConflictMarker(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if first {
			first = false
			if bytes.IndexByte(line, 0) >= 0 {
				return false, nil // binary file
			}
		}
		if strings.HasPrefix(string(line), conflictMarkerPrefix) {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		// Overlong line/binary data is not a conflict or operation error.
		return false, nil
	}
	return false, nil
}
