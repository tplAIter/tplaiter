//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package contextpack

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type unixSourceReader struct {
	rootFD int
	dirFDs []int
}

func newSourceReader(root string) (sourceReader, error) {
	return newSourceReaderWithHook(root, nil)
}

func newSourceReaderWithHook(root string, beforeOpen func(string) error) (sourceReader, error) {
	if root == "" {
		return nil, errors.New("contextpack: empty source root")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return nil, err
	}
	parts, err := canonicalPathParts(canonical)
	if err != nil {
		return nil, err
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	reader := &unixSourceReader{rootFD: rootFD, dirFDs: []int{rootFD}}
	parentFD := rootFD
	for _, part := range parts {
		var before unix.Stat_t
		if err := unix.Fstatat(parentFD, part, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = reader.close()
			return nil, err
		}
		if before.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = reader.close()
			return nil, errors.New("source root component is not a directory")
		}
		if beforeOpen != nil {
			if err := beforeOpen(part); err != nil {
				_ = reader.close()
				return nil, err
			}
		}
		fd, err := unix.Openat(parentFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			_ = reader.close()
			return nil, err
		}
		var after unix.Stat_t
		if err := unix.Fstat(fd, &after); err != nil {
			_ = unix.Close(fd)
			_ = reader.close()
			return nil, err
		}
		if after.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(fd)
			_ = reader.close()
			return nil, errors.New("opened source root component is not a directory")
		}
		if fileIdentity(before) != fileIdentity(after) {
			_ = unix.Close(fd)
			_ = reader.close()
			return nil, errors.New("source root component changed during open")
		}
		reader.dirFDs = append(reader.dirFDs, fd)
		parentFD = fd
	}
	reader.rootFD = parentFD
	return reader, nil
}

func (r *unixSourceReader) close() error {
	if r == nil || len(r.dirFDs) == 0 {
		return nil
	}
	var firstErr error
	for i := len(r.dirFDs) - 1; i >= 0; i-- {
		if err := unix.Close(r.dirFDs[i]); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.dirFDs = nil
	r.rootFD = -1
	return firstErr
}

func (r *unixSourceReader) read(rel string) ([]byte, error) {
	parts, err := confinedPathParts(rel)
	if err != nil {
		return nil, err
	}
	parentFD := r.rootFD
	openedParents := make([]int, 0, len(parts)-1)
	defer func() {
		for _, fd := range openedParents {
			_ = unix.Close(fd)
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		var st unix.Stat_t
		if err := unix.Fstatat(parentFD, part, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, errors.New("source path component is not a directory")
		}
		fd, err := unix.Openat(parentFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		openedParents = append(openedParents, fd)
		parentFD = fd
	}

	leaf := parts[len(parts)-1]
	var beforeOpen unix.Stat_t
	if err := unix.Fstatat(parentFD, leaf, &beforeOpen, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	// This check happens before opening the leaf. O_NONBLOCK below also makes
	// the check-to-open race non-blocking if the leaf is replaced with a FIFO.
	if beforeOpen.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("source leaf is not a regular file")
	}
	fd, err := unix.Openat(parentFD, leaf, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "contextpack-source")
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("failed to wrap source descriptor")
	}
	defer f.Close()

	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("opened source is not a regular file")
	}
	if opened.Size < 0 || opened.Size > reasonableMaxSourceBytes {
		return nil, fmt.Errorf("source exceeds %d-byte limit", reasonableMaxSourceBytes)
	}

	// The allocation is derived only from the bounded post-open size. The extra
	// byte detects growth without ever reading more than max+1 bytes.
	data := make([]byte, int(opened.Size)+1)
	n, err := io.ReadFull(f, data[:int(opened.Size)])
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, err
		}
		return data[:n], nil
	}
	if extra, err := f.Read(data[int(opened.Size):]); extra != 0 {
		return nil, errors.New("source grew during bounded read")
	} else if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return data[:int(opened.Size)], nil
}

func confinedPathParts(rel string) ([]string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.ContainsRune(rel, '\x00') {
		return nil, errors.New("source path is not relative")
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." {
		return nil, errors.New("source path escapes root")
	}
	parts := strings.Split(clean, string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("source path escapes root")
		}
	}
	return parts, nil
}

func canonicalPathParts(canonical string) ([]string, error) {
	if !filepath.IsAbs(canonical) {
		return nil, errors.New("canonical source root is not absolute")
	}
	clean := filepath.Clean(canonical)
	if clean == string(filepath.Separator) {
		return nil, nil
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("canonical source root is not confined")
		}
	}
	return parts, nil
}

type sourceIdentity struct {
	device string
	inode  string
}

func fileIdentity(st unix.Stat_t) sourceIdentity {
	return sourceIdentity{device: formatStatNumber(st.Dev), inode: formatStatNumber(st.Ino)}
}

func formatStatNumber(value any) string {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(v.Uint(), 10)
	default:
		return ""
	}
}
