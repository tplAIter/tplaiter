//go:build unix

package state

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/tplAIter/tplaiter/internal/naming"
)

// lockFileName is the interprocess lock file in the tplater home directory.
const lockFileName = ".lock"

// WithLock serializes fn against other tplater processes holding an exclusive
// flock on ~/.tplaiter/.lock (or $TPLAITER_HOME/.lock) for its duration. It is
// used for read-modify-write operations on state files; without it, concurrent
// `tplater repo add` calls could lose each other's changes through
// writeFileAtomic (atomic for one file, not for the complete sequence).
//
// home must exist (see [EnsureHome]); WithLock does not create it, avoiding side
// effects in read-only scenarios.
//
// The implementation uses syscall.Flock, sufficient for darwin/linux (see the build tag
// "unix"); Windows is not supported by this file or by the project documentation.
func WithLock(home string, fn func() error) error {
	if err := naming.GuardLegacyWrite(home); err != nil {
		return fmt.Errorf("state: legacy writer guard: %w", err)
	}
	path := filepath.Join(home, lockFileName)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return fmt.Errorf("state: opening lock file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("state: acquiring lock %s: %w", path, err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	return fn()
}
