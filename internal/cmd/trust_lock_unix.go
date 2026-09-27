//go:build darwin || linux

package cmd

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var errRegisteredLock = errors.New("registered lock unavailable")

// readRegisteredLock walks the registered project root by descriptors. Each
// component is opened O_NOFOLLOW and the final descriptor is checked as a
// bounded regular file, so a project-controlled path cannot redirect the
// source identity lookup outside the registered scope.
func readRegisteredLock(ctx context.Context, root, name string) ([]byte, error) {
	if ctx == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || (name != "root-template.lock.json" && name != "template.lock.json") {
		return nil, errRegisteredLock
	}
	return readFixedTrustDocument(ctx, filepath.Join(root, ".tplaiter", name))
}

// readFixedTrustDocument reads a fixed absolute installation or registered
// metadata document without following any component symlink.
func readFixedTrustDocument(ctx context.Context, path string) ([]byte, error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errRegisteredLock
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errRegisteredLock
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		if err := ctx.Err(); err != nil || part == "" || part == "." || part == ".." {
			return nil, errRegisteredLock
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return nil, errRegisteredLock
		}
		if err := unix.Close(fd); err != nil {
			_ = unix.Close(next)
			return nil, errRegisteredLock
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > trustCommandDocumentLimit {
		return nil, errRegisteredLock
	}
	f := os.NewFile(uintptr(fd), "registered-trust-lock")
	if f == nil {
		return nil, errRegisteredLock
	}
	closeFD = false
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, trustCommandDocumentLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > trustCommandDocumentLimit || ctx.Err() != nil {
		return nil, errRegisteredLock
	}
	return raw, nil
}

// readUntrustedDocument accepts only bytes from a bounded regular file. The
// caller may select the path, but cannot use a symlink, FIFO, device, or an
// over-limit file to redirect or block the command before trust verification.
func readUntrustedDocument(ctx context.Context, path string) ([]byte, error) {
	return readFixedTrustDocument(ctx, path)
}

// readRegisteredPreimageFile reads one project file through the registered
// root's descriptor chain. Unlike trust documents, project files may be empty
// and may use the whole remaining aggregate preview budget.
func readRegisteredPreimageFile(ctx context.Context, root, rel string, remaining int64) ([]byte, error) {
	if ctx == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || !fs.ValidPath(rel) || remaining < 0 {
		return nil, errRegisteredLock
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errRegisteredLock
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()
	parts := append(strings.Split(strings.TrimPrefix(root, "/"), "/"), strings.Split(rel, "/")...)
	for i, part := range parts {
		if err := ctx.Err(); err != nil || part == "" || part == "." || part == ".." {
			return nil, errRegisteredLock
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return nil, errRegisteredLock
		}
		if err := unix.Close(fd); err != nil {
			_ = unix.Close(next)
			return nil, errRegisteredLock
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 0 || st.Size > remaining {
		return nil, errRegisteredLock
	}
	f := os.NewFile(uintptr(fd), "registered-project-preimage")
	if f == nil {
		return nil, errRegisteredLock
	}
	closeFD = false
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, remaining+1))
	if err != nil || int64(len(raw)) > remaining || ctx.Err() != nil {
		return nil, errRegisteredLock
	}
	return raw, nil
}
