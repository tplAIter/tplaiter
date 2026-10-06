//go:build darwin || linux

package graphcmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/tplAIter/tplaiter/internal/semanticgraph"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

type fileFact struct {
	Path  string `json:"path"`
	Hash  string `json:"hash"`
	Mode  uint32 `json:"mode"`
	Bytes int    `json:"bytes"`
}
type fileSnapshot struct {
	root   string
	fd     int
	dev    uint64
	ino    uint64
	files  []semanticgraph.SourceFile
	facts  []fileFact
	digest string
}

func openDirectory(p string) (int, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return -1, fail("GRAPH_INPUT_TOPOLOGY")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	for _, c := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if c == "" {
			continue
		}
		n, e := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			if e == unix.ENOENT {
				return -1, os.ErrNotExist
			}
			return -1, fail("GRAPH_INPUT_TOPOLOGY")
		}
		fd = n
	}
	return fd, nil
}
func captureFiles(ctx context.Context, root string) (*fileSnapshot, error) {
	fd, e := openDirectory(root)
	if e != nil {
		return nil, e
	}
	s := &fileSnapshot{root: root, fd: fd, files: []semanticgraph.SourceFile{}, facts: []fileFact{}}
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return nil, e
	}
	s.dev = uint64(st.Dev)
	s.ino = st.Ino
	entries, total := 0, 0
	seen := map[string]bool{}
	var walk func(int, string, int) error
	walk = func(dir int, prefix string, depth int) error {
		if depth > 64 {
			return fail("GRAPH_INPUT_LIMIT")
		}
		duplicate, e := unix.Dup(dir)
		if e != nil {
			return e
		}
		f := os.NewFile(uintptr(duplicate), "graph-directory")
		defer f.Close()
		for {
			names, e := f.Readdirnames(128)
			if e != nil && e != io.EOF {
				return e
			}
			sort.Strings(names)
			for _, name := range names {
				if e := ctx.Err(); e != nil {
					return e
				}
				entries++
				if entries > 8192 {
					return fail("GRAPH_INPUT_LIMIT")
				}
				if name == ".git" || name == ".tplaiter" || name == ".tplater" {
					continue
				}
				rel := prefix + name
				lower := strings.ToLower(rel)
				if seen[lower] {
					return fail("GRAPH_INPUT_TOPOLOGY")
				}
				seen[lower] = true
				var before unix.Stat_t
				if e := unix.Fstatat(dir, name, &before, unix.AT_SYMLINK_NOFOLLOW); e != nil {
					return e
				}
				kind := before.Mode & unix.S_IFMT
				if kind == unix.S_IFLNK {
					return fail("GRAPH_INPUT_TOPOLOGY")
				}
				if kind == unix.S_IFDIR {
					child, e := unix.Openat(dir, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
					if e != nil {
						return fail("GRAPH_INPUT_TOPOLOGY")
					}
					var actual unix.Stat_t
					e = unix.Fstat(child, &actual)
					if e == nil && (actual.Dev != before.Dev || actual.Ino != before.Ino) {
						e = fail("GRAPH_INPUT_TOPOLOGY")
					}
					if e == nil {
						e = walk(child, rel+"/", depth+1)
					}
					unix.Close(child)
					if e != nil {
						return e
					}
					continue
				}
				ext := strings.ToLower(filepath.Ext(rel))
				if ext != ".go" && ext != ".rs" {
					continue
				}
				if kind != unix.S_IFREG {
					return fail("GRAPH_INPUT_TOPOLOGY")
				}
				if len(s.files) >= semanticgraph.MaxInputFiles || before.Size > semanticgraph.MaxFileBytes {
					return fail("GRAPH_INPUT_LIMIT")
				}
				leaf, e := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if e != nil {
					return fail("GRAPH_INPUT_TOPOLOGY")
				}
				var opened unix.Stat_t
				e = unix.Fstat(leaf, &opened)
				if e != nil || opened.Dev != before.Dev || opened.Ino != before.Ino || opened.Mode != before.Mode || opened.Mode&unix.S_IFMT != unix.S_IFREG {
					unix.Close(leaf)
					return fail("GRAPH_INPUT_TOPOLOGY")
				}
				image := os.NewFile(uintptr(leaf), rel)
				b, e := io.ReadAll(io.LimitReader(image, semanticgraph.MaxFileBytes+1))
				var after unix.Stat_t
				se := unix.Fstat(leaf, &after)
				image.Close()
				if e != nil {
					return e
				}
				if se != nil || after.Size != opened.Size || !sameTimes(after, opened) || after.Mode != opened.Mode {
					return fail("GRAPH_SOURCE_STALE")
				}
				total += len(b)
				if len(b) > semanticgraph.MaxFileBytes || total > semanticgraph.MaxInputBytes {
					return fail("GRAPH_INPUT_LIMIT")
				}
				s.files = append(s.files, semanticgraph.SourceFile{Path: rel, Bytes: b})
				s.facts = append(s.facts, fileFact{rel, hashBytes(b), uint32(opened.Mode & 0777), len(b)})
			}
			if e == io.EOF {
				break
			}
		}
		return nil
	}
	if e = walk(fd, "", 0); e != nil {
		return nil, e
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].Path < s.files[j].Path })
	sort.Slice(s.facts, func(i, j int) bool { return s.facts[i].Path < s.facts[j].Path })
	s.digest = hashValue(s.facts)
	ok = true
	return s, nil
}
func (s *fileSnapshot) close() {
	if s != nil && s.fd >= 0 {
		unix.Close(s.fd)
		s.fd = -1
	}
}
func (s *fileSnapshot) recheck(ctx context.Context) error {
	if s == nil || s.fd < 0 {
		return fail("GRAPH_SOURCE_STALE")
	}
	n, e := captureFiles(ctx, s.root)
	if e != nil {
		return e
	}
	defer n.close()
	if n.dev != s.dev || n.ino != s.ino || n.digest != s.digest {
		return fail("GRAPH_SOURCE_STALE")
	}
	return nil
}

func sameTimes(a, b unix.Stat_t) bool {
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	for _, name := range []string{"Mtim", "Mtimespec", "Ctim", "Ctimespec"} {
		x, y := av.FieldByName(name), bv.FieldByName(name)
		if x.IsValid() && !reflect.DeepEqual(x.Interface(), y.Interface()) {
			return false
		}
	}
	return true
}
func cacheRead(root, name string) ([]byte, error) {
	fd, e := openDirectory(filepath.Join(root, ".tplaiter", "graph-cache"))
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	leaf, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(leaf), "graph-cache")
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(leaf, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > maxCacheBytes {
		return nil, fail("GRAPH_CACHE_CORRUPT")
	}
	return io.ReadAll(io.LimitReader(f, maxCacheBytes+1))
}
func cachePublish(root, name string, raw []byte) error {
	return cachePublishWithUnlink(root, name, raw, unix.Unlinkat)
}

// cacheCleanup retains the primary error and confines cleanup to the held FD's leaf.
func cacheCleanup(primary error, dir int, leaf string, unlink func(int, string, int) error) error {
	cleanup := unlink(dir, leaf, 0)
	if cleanup == nil || errors.Is(cleanup, unix.ENOENT) {
		return primary
	}
	return errors.Join(primary, cleanup)
}

func cachePublishWithUnlink(root, name string, raw []byte, unlink func(int, string, int) error) (result error) {
	if len(raw) > maxCacheBytes {
		return fail("GRAPH_INPUT_LIMIT")
	}
	fd, e := openDirectory(filepath.Join(root, ".tplaiter"))
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if e = unix.Mkdirat(fd, "graph-cache", 0700); e != nil && e != unix.EEXIST {
		return e
	}
	dir, e := unix.Openat(fd, "graph-cache", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return fail("GRAPH_INPUT_TOPOLOGY")
	}
	defer unix.Close(dir)
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	tmp := ".graph-" + hex.EncodeToString(nonce)
	leaf, e := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	defer func() { result = cacheCleanup(result, dir, tmp, unlink) }()
	f := os.NewFile(uintptr(leaf), "graph-cache-temp")
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	var st unix.Stat_t
	if e = unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); e == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fail("GRAPH_INPUT_TOPOLOGY")
	}
	if e != nil && e != unix.ENOENT {
		return e
	}
	if e = unix.Renameat(dir, tmp, dir, name); e != nil {
		return e
	}
	return unix.Fsync(dir)
}

func readInputFile(p string) ([]byte, error) {
	absolute, e := filepath.Abs(p)
	if e != nil {
		return nil, e
	}
	dir, e := openDirectory(filepath.Dir(absolute))
	if e != nil {
		return nil, e
	}
	defer unix.Close(dir)
	fd, e := unix.Openat(dir, filepath.Base(absolute), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, fail("GRAPH_ARGUMENT_INVALID")
	}
	f := os.NewFile(uintptr(fd), "graph-source-input")
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > 2<<20 {
		return nil, fail("GRAPH_ARGUMENT_INVALID")
	}
	b, e := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if e != nil || len(b) > 2<<20 {
		return nil, fail("GRAPH_ARGUMENT_INVALID")
	}
	return b, nil
}
