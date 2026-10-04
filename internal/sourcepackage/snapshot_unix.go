//go:build darwin || linux

package sourcepackage

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxContainers     = 32
	maxContainerBytes = 128 << 20
	maxCopyBytes      = 256 << 20
	maxLoose          = 8192
)

var errLayout = errors.New("sourcepackage: unsupported or unsafe repository layout")

func directoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errLayout
	}
	return os.NewFile(uintptr(fd), name), nil
}

func directoryPath(path string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errLayout
	}
	f := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := directoryAt(f, part)
		_ = f.Close()
		if e != nil {
			return nil, e
		}
		f = next
	}
	return f, nil
}

func regularAt(parent *os.File, name string, limit int64) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errLayout
	}
	f := os.NewFile(uintptr(fd), name)
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > limit {
		_ = f.Close()
		return nil, errLayout
	}
	return f, nil
}

func absentAt(parent *os.File, name string) bool {
	var st unix.Stat_t
	return errors.Is(unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT)
}

func entries(dir *os.File, limit int) ([]string, error) {
	names, err := dir.Readdirnames(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errLayout
	}
	if len(names) > limit {
		return nil, errLayout
	}
	return names, nil
}

func hexName(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Syntax-only metadata validation. Nothing is expanded or evaluated, and no
// source value is included in errors. Includes and format/worktree extensions
// are refused even when their referenced files are absent.
func validateRepositoryConfig(raw []byte, requireBare bool) error {
	if len(raw) == 0 || len(raw) > 64<<10 || strings.ContainsRune(string(raw), 0) {
		return errLayout
	}
	section := ""
	format := false
	bare := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return errLayout
			}
			s := strings.TrimSpace(line[1 : len(line)-1])
			head := strings.Fields(s)
			if len(head) == 0 {
				return errLayout
			}
			section = strings.ToLower(head[0])
			if section == "include" || section == "includeif" || strings.HasPrefix(section, "includeif.") || section == "extensions" {
				return errLayout
			}
			continue
		}
		if section == "" || strings.HasSuffix(line, "\\") {
			return errLayout
		}
		pair := strings.SplitN(line, "=", 2)
		key := strings.ToLower(strings.TrimSpace(pair[0]))
		if key == "" {
			return errLayout
		}
		for _, c := range key {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return errLayout
			}
		}
		if key == "promisor" || key == "partialclone" {
			return errLayout
		}
		if section == "core" {
			switch key {
			case "repositoryformatversion":
				if format || len(pair) != 2 || strings.TrimSpace(pair[1]) != "0" {
					return errLayout
				}
				format = true
			case "bare":
				if len(pair) != 2 {
					return errLayout
				}
				bare = strings.TrimSpace(pair[1]) == "true"
			case "filemode", "logallrefupdates", "ignorecase", "precomposeunicode", "symlinks":
			default:
				return errLayout
			}
		}
	}
	if !format || requireBare && !bare {
		return errLayout
	}
	return nil
}

func snapshotRepository(ctx context.Context, path string) (string, func(), error) {
	repo, err := directoryPath(path)
	if err != nil {
		return "", nil, err
	}
	defer repo.Close()
	gitdir := repo
	if !absentAt(repo, ".git") {
		gitdir, err = directoryAt(repo, ".git")
		if err != nil {
			return "", nil, err
		}
		defer gitdir.Close()
	}
	for _, name := range []string{"commondir", "gitdir", "shallow", "info/grafts", "refs/replace"} { // Nested probes use held directories below.
		parts := strings.Split(name, "/")
		parent := gitdir
		if len(parts) == 2 {
			if absentAt(gitdir, parts[0]) {
				continue
			}
			parent, err = directoryAt(gitdir, parts[0])
			if err != nil {
				return "", nil, err
			}
			defer parent.Close()
		}
		if !absentAt(parent, parts[len(parts)-1]) {
			return "", nil, errLayout
		}
	}
	config, err := regularAt(gitdir, "config", 64<<10)
	if err != nil {
		return "", nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(config, (64<<10)+1))
	_ = config.Close()
	if err != nil || validateRepositoryConfig(raw, gitdir == repo) != nil {
		return "", nil, errLayout
	}
	objects, err := directoryAt(gitdir, "objects")
	if err != nil {
		return "", nil, err
	}
	defer objects.Close()
	scratch, err := os.MkdirTemp("", "tplaiter-capture-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(scratch) }
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()
	for _, d := range []string{"objects", "objects/pack", "refs"} {
		if err = os.Mkdir(filepath.Join(scratch, d), 0o700); err != nil {
			return "", nil, err
		}
	}
	if err = os.WriteFile(filepath.Join(scratch, "config"), []byte("[core]\nrepositoryformatversion = 0\nbare = true\n"), 0o600); err != nil {
		return "", nil, err
	}
	if err = os.WriteFile(filepath.Join(scratch, "HEAD"), []byte("ref: refs/heads/capture\n"), 0o600); err != nil {
		return "", nil, err
	}
	total := int64(0)
	loose := 0
	copyObject := func(dir *os.File, name, rel string, limit int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := regularAt(dir, name, limit)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.Size() > maxCopyBytes-total {
			return errors.New("sourcepackage: snapshot byte limit")
		}
		out, err := os.OpenFile(filepath.Join(scratch, "objects", rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer out.Close()
		var buf [32768]byte
		written := int64(0)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, e := f.Read(buf[:])
			if n > 0 {
				if int64(n) > limit-written || int64(n) > maxCopyBytes-total {
					return errors.New("sourcepackage: snapshot byte limit")
				}
				if _, err := out.Write(buf[:n]); err != nil {
					return err
				}
				written += int64(n)
				total += int64(n)
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				return errLayout
			}
		}
		if written != st.Size() {
			return errors.New("sourcepackage: object container changed during capture")
		}
		return nil
	}
	dirs, err := entries(objects, 258)
	if err != nil {
		return "", nil, err
	}
	for _, name := range dirs {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		dir, err := directoryAt(objects, name)
		if err != nil {
			return "", nil, err
		}
		e := func() error {
			defer dir.Close()
			if name == "info" {
				names, err := entries(dir, 16)
				if err != nil {
					return err
				}
				for _, n := range names {
					if n != "packs" {
						return errLayout
					}
					f, err := regularAt(dir, n, 64<<10)
					if err != nil {
						return err
					}
					_ = f.Close()
				}
				return nil
			}
			if name == "pack" {
				names, err := entries(dir, maxContainers*3)
				if err != nil {
					return err
				}
				set := map[string]bool{}
				pairs := 0
				for _, n := range names {
					set[n] = true
					if strings.HasSuffix(n, ".pack") {
						pairs++
					}
				}
				if pairs > maxContainers {
					return errLayout
				}
				for _, n := range names {
					ext := filepath.Ext(n)
					base := strings.TrimSuffix(n, ext)
					if !strings.HasPrefix(base, "pack-") || !hexName(strings.TrimPrefix(base, "pack-"), 40) || (ext != ".pack" && ext != ".idx" && ext != ".rev") || !set[base+".pack"] || !set[base+".idx"] {
						return errLayout
					}
					if ext == ".rev" {
						// A matching reverse-index is advisory metadata, not an object or
						// alternate route. Bound/open it no-follow, but never copy it into Git.
						f, err := regularAt(dir, n, maxContainerBytes)
						if err != nil {
							return err
						}
						_ = f.Close()
						continue
					}
					if err := copyObject(dir, n, filepath.Join("pack", n), maxContainerBytes); err != nil {
						return err
					}
				}
				return nil
			}
			if !hexName(name, 2) {
				return errLayout
			}
			names, err := entries(dir, maxLoose-loose)
			if err != nil {
				return err
			}
			loose += len(names)
			if err = os.Mkdir(filepath.Join(scratch, "objects", name), 0o700); err != nil {
				return err
			}
			for _, n := range names {
				if !hexName(n, 38) {
					return errLayout
				}
				if err := copyObject(dir, n, filepath.Join(name, n), maxContainerBytes); err != nil {
					return err
				}
			}
			return nil
		}()
		if e != nil {
			return "", nil, e
		}
	}
	success = true
	return scratch, cleanup, nil
}
