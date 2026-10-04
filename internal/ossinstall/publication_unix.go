//go:build linux || darwin

package ossinstall

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func defaultEntropy() io.Reader { return rand.Reader }

// Every directory component is opened relative to a held descriptor with
// O_NOFOLLOW; neither parent replacement nor a CAS symlink can redirect writes.
func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("ossinstall: noncanonical directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}

func syncDirectory(path string) error {
	f, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func leafDirectory(root, rel string, create bool) (*os.File, string, error) {
	if !filepath.IsLocal(rel) || filepath.Clean(rel) != rel {
		return nil, "", errors.New("ossinstall: invalid confined path")
	}
	dir, err := openDirectory(root)
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, p := range parts[:len(parts)-1] {
		if create {
			e := unix.Mkdirat(int(dir.Fd()), p, 0o700)
			if e != nil && !errors.Is(e, unix.EEXIST) {
				_ = dir.Close()
				return nil, "", e
			}
			if e == nil {
				if e = dir.Sync(); e != nil {
					_ = dir.Close()
					return nil, "", e
				}
			}
		}
		fd, e := unix.Openat(int(dir.Fd()), p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = dir.Close()
		if e != nil {
			return nil, "", e
		}
		dir = os.NewFile(uintptr(fd), p)
	}
	return dir, parts[len(parts)-1], nil
}

func readConfined(root, rel string) ([]byte, error) {
	dir, leaf, err := leafDirectory(root, rel, false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), leaf)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxSourcePackageInputBytes {
		return nil, errors.New("ossinstall: invalid immutable file")
	}
	return io.ReadAll(io.LimitReader(f, MaxSourcePackageInputBytes+1))
}

func publishImmutable(root, rel string, raw []byte) error {
	dir, leaf, err := leafDirectory(root, rel, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if errors.Is(err, unix.EEXIST) {
		existing, e := readConfined(root, rel)
		if e != nil || !bytes.Equal(existing, raw) {
			return errors.New("ossinstall: immutable collision (existing bytes preserved)")
		}
		return dir.Sync()
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), leaf)
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return dir.Sync()
}

// installationPublicationHook is a test-only synchronization seam, nil in
// production. It grants no publication authority or path override.
var installationPublicationHook func()

func publishInstallation(stage, root string) error {
	parent, err := openDirectory(filepath.Dir(root))
	if err != nil {
		return err
	}
	defer parent.Close()
	if filepath.Dir(stage) != filepath.Dir(root) {
		return errors.New("ossinstall: staging must share installation parent")
	}
	leaf := filepath.Base(root)
	// The final native exclusive rename is the vacancy decision. No prior
	// emptiness check can authorize replacing an inode created concurrently.
	if err = syncTree(stage); err != nil {
		return err
	}
	if installationPublicationHook != nil {
		installationPublicationHook()
	}
	if err = renameInstallationExclusive(int(parent.Fd()), filepath.Base(stage), leaf); err != nil {
		return classifyPublicationRenameError(err)
	}
	return parent.Sync()
}

func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("ossinstall: symlink in staged publication")
		}
		if d.IsDir() {
			return syncDirectory(path)
		}
		return nil
	})
}

func classifyPublicationRenameError(err error) error {
	if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
		return ErrInstallRootForeign
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return fmt.Errorf("%w: %w", ErrPublicationUnsupported, err)
	}
	return err
}
