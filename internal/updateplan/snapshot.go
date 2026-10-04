package updateplan

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

const (
	maxFiles = 4096
	maxBytes = 64 << 20
)

// Image includes exact file bytes and permission bits. Directories participate
// in the preimage fingerprint too; symlinks and special files are refused.
type Image struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

type observation struct {
	images     []Image
	files      map[string][]byte
	identity   os.FileInfo
	identities map[string]os.FileInfo
}

func observe(ctx context.Context, name string) (*observation, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(name)
	if err != nil || !filepath.IsAbs(name) || canonical != name {
		return nil, ErrUnsafe
	}
	before, err := os.Lstat(name)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafe
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	held, err := root.Stat(".")
	if err != nil || !os.SameFile(before, held) {
		return nil, ErrStale
	}
	out := &observation{files: map[string][]byte{}, identity: held, identities: map[string]os.FileInfo{".": held}}
	var total int64
	var walk func(string) error
	walk = func(dir string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := root.Open(dir)
		if err != nil {
			return err
		}
		entries, err := file.ReadDir(maxFiles + 1)
		closeErr := file.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			rel := path.Join(dir, entry.Name())
			if !safePath(rel) || len(out.images) >= maxFiles {
				return ErrUnsafe
			}
			info, err := root.Lstat(rel)
			if err != nil {
				return err
			}
			image := Image{Path: rel, Mode: uint32(info.Mode().Perm()), SHA256: evidencecas.Digest(nil)}
			if info.Mode()&^fs.ModePerm != 0 && !info.IsDir() {
				return ErrUnsafe
			}
			if info.IsDir() {
				out.identities[rel] = info
				image.Kind = "directory"
				out.images = append(out.images, image)
				if err := walk(rel); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxBytes-total {
				return ErrUnsafe
			}
			file, err := root.Open(rel)
			if err != nil {
				return err
			}
			opened, err := file.Stat()
			if err != nil || !os.SameFile(info, opened) {
				_ = file.Close()
				return ErrStale
			}
			raw, readErr := io.ReadAll(io.LimitReader(file, maxBytes-total+1))
			after, statErr := file.Stat()
			closeErr := file.Close()
			final, finalErr := root.Lstat(rel)
			if readErr != nil || statErr != nil || closeErr != nil || finalErr != nil {
				return errors.Join(readErr, statErr, closeErr, finalErr)
			}
			if int64(len(raw)) > maxBytes-total || int64(len(raw)) != opened.Size() || !os.SameFile(opened, after) || !os.SameFile(after, final) || after.Mode() != opened.Mode() || final.Mode() != opened.Mode() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
				return ErrStale
			}
			total += int64(len(raw))
			image.Kind = "file"
			image.SHA256 = evidencecas.Digest(raw)
			out.images = append(out.images, image)
			out.files[rel] = raw
			out.identities[rel] = opened
		}
		return nil
	}
	out.images = append(out.images, Image{Path: ".", Kind: "directory", Mode: uint32(held.Mode().Perm()), SHA256: evidencecas.Digest(nil)})
	if err := walk("."); err != nil {
		return nil, err
	}
	current, err := os.Lstat(name)
	if err != nil || !os.SameFile(held, current) {
		return nil, ErrStale
	}
	sort.Slice(out.images, func(i, j int) bool { return out.images[i].Path < out.images[j].Path })
	return out, nil
}

func safePath(p string) bool {
	return fs.ValidPath(p) && p != "." && !strings.ContainsAny(p, "\\\x00\n\r")
}

func equalObservation(a, b *observation) bool {
	if a == nil || b == nil || !os.SameFile(a.identity, b.identity) || len(a.images) != len(b.images) {
		return false
	}
	for i := range a.images {
		if a.images[i] != b.images[i] || !os.SameFile(a.identities[a.images[i].Path], b.identities[b.images[i].Path]) {
			return false
		}
	}
	return true
}
