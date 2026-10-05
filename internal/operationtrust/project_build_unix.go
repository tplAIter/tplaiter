//go:build darwin || linux

package operationtrust

import (
	"context"
	"errors"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"sort"
	"strings"
)

func captureProjectBuild(ctx context.Context, root string) ([]trustverify.ContentEntry, [][]byte, error) {
	if !strings.HasPrefix(root, "/") {
		return nil, nil, ErrProjectBuild
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, nil, e
	}
	for _, p := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if p == "" || p == "." || p == ".." {
			unix.Close(fd)
			return nil, nil, ErrProjectBuild
		}
		n, e := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, nil, ErrProjectBuild
		}
		fd = n
	}
	defer unix.Close(fd)
	type pair struct {
		entry trustverify.ContentEntry
		b     []byte
	}
	files := []pair{}
	var total int64
	var directories, entriesSeen int
	var walk func(int, string) error
	walk = func(dir int, prefix string) error {
		directories++
		if directories > 4096 || strings.Count(prefix, "/") > 128 {
			return ErrProjectBuild
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		dup, e := unix.Dup(dir)
		if e != nil {
			return e
		}
		f := os.NewFile(uintptr(dup), "project")
		names, e := f.Readdirnames(20001)
		f.Close()
		if e != nil && e != io.EOF {
			return e
		}
		entriesSeen += len(names)
		if entriesSeen > 20000 {
			return ErrProjectBuild
		}
		sort.Strings(names)
		for _, name := range names {
			if (strings.HasPrefix(name, ".") && !(prefix == "" && name == ".tplaiter")) || strings.HasPrefix(name, "_") {
				continue
			}
			rel := prefix + name
			if prefix == ".tplaiter/" && name != "project.yaml" && name != "root-template.lock.json" && name != "resources.lock.json" {
				continue
			}
			var st unix.Stat_t
			if unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
				return ErrProjectBuild
			}
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				return ErrProjectBuild
			}
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				if name == "vendor" {
					return ErrProjectBuild
				}
				n, e := unix.Openat(dir, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if e != nil {
					return e
				}
				e = walk(n, rel+"/")
				unix.Close(n)
				if e != nil {
					return e
				}
				continue
			}
			if st.Mode&unix.S_IFMT != unix.S_IFREG {
				return ErrProjectBuild
			}
			if name == "go.work" {
				return ErrProjectBuild
			}
			if !strings.HasSuffix(name, ".go") && rel != "go.mod" && rel != "go.sum" && !strings.HasPrefix(rel, ".tplaiter/") {
				continue
			}
			if len(files) >= 4093 || st.Size < 0 || st.Size > 16<<20 {
				return ErrProjectBuild
			}
			total += st.Size
			if total > 64<<20 {
				return ErrProjectBuild
			}
			n, e := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if e != nil {
				return e
			}
			nf := os.NewFile(uintptr(n), "input")
			var before, after unix.Stat_t
			if unix.Fstat(n, &before) != nil {
				nf.Close()
				return ErrProjectBuild
			}
			b, e := io.ReadAll(io.LimitReader(nf, 16<<20+1))
			statErr := unix.Fstat(n, &after)
			nf.Close()
			if e != nil || statErr != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || int64(len(b)) != before.Size || len(b) > 16<<20 || before.Ino != after.Ino || before.Dev != after.Dev || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Ino != st.Ino || before.Dev != st.Dev {
				return ErrProjectBuild
			}
			files = append(files, pair{trustverify.ContentEntry{Root: "project", Path: rel, Mode: "100644", ContentSHA256: evidencecas.Digest(b)}, b})
		}
		return nil
	}
	if e := walk(fd, ""); e != nil {
		return nil, nil, e
	}
	if len(files) == 0 {
		return nil, nil, errors.New("TRUST_PROJECT_BUILD_INPUT_MISSING")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].entry.Path < files[j].entry.Path })
	entries := make([]trustverify.ContentEntry, len(files))
	data := make([][]byte, len(files))
	for i, f := range files {
		entries[i] = f.entry
		data[i] = f.b
	}
	return entries, data, nil
}
