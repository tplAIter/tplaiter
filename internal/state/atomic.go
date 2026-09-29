package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// writeFileAtomic writes data to path atomically: first to a temporary file in
// the same directory (so rename stays on one filesystem), then over the final
// path. Other processes and goroutines see either the complete old or new file,
// never a partial write.
//
// Atomic writing does not replace [WithLock]: concurrent writers must still
// serialize the complete read-modify-write sequence, or the last writer will
// overwrite the other's changes. writeFileAtomic only prevents reading half a
// file during a write.
//
// The resulting file always has [filePerm] (0600): all tplater state files are
// equally private (see the package comment in state.go). Permissions are kept
// internal so there is one explicit source of truth instead of N calls passing
// the same value.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, homeDirPerm); err != nil {
		return fmt.Errorf("state: creating directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("state: creating temporary file for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	// A successful Rename makes Remove a no-op (ENOENT is silently ignored).
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: writing temporary file %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: chmod temporary file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state: closing temporary file %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("state: renaming %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// readFile reads path and reports whether it existed. A missing file is not an
// error (existed=false, err=nil); callers return the default.
func readFile(path string) (data []byte, existed bool, err error) {
	data, err = os.ReadFile(path)
	switch {
	case err == nil:
		return data, true, nil
	case os.IsNotExist(err):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("state: reading %s: %w", path, err)
	}
}

// writeFileAtomicDurable is the external-transaction variant of
// writeFileAtomic. It syncs both the replacement file and its parent directory
// before reporting success, so a separately journaled caller may checkpoint
// its applied image only after the rename is durable. The final path must not
// be a symlink or another non-regular file.
func writeFileAtomicDurable(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, homeDirPerm); err != nil {
		return fmt.Errorf("state: creating directory %s: %w", dir, err)
	}
	if err := syncDirectory(filepath.Dir(dir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("state: %s is not a regular file", path)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("state: checking %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("state: creating temporary file for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: writing temporary file %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(mode.Perm()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: chmod temporary file %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: fsync temporary file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state: closing temporary file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("state: renaming %s -> %s: %w", tmpPath, path, err)
	}
	return syncDirectory(dir)
}

// syncDirectory makes a directory entry update (create, rename, unlink)
// durable.
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("state: opening directory %s: %w", path, err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("state: fsync directory %s: %w", path, err)
	}
	return nil
}
