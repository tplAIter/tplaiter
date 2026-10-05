package linkcmd

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

type File struct {
	Data      []byte `json:"data"`
	Mode      uint32 `json:"mode"`
	Directory bool   `json:"directory"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
}

func identity(info os.FileInfo) (uint64, uint64) {
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0, 0
	}
	get := func(n string) uint64 {
		x := v.FieldByName(n)
		if x.IsValid() && x.CanUint() {
			return x.Uint()
		}
		if x.IsValid() && x.CanInt() {
			return uint64(x.Int())
		}
		return 0
	}
	return get("Dev"), get("Ino")
}
func SafeUserPath(p string) bool {
	return fs.ValidPath(p) && p != "." && !strings.ContainsAny(p, "\\\x00\r\n") && p != ".globals" && !strings.HasPrefix(p, ".globals/") && p != ".tplaiter" && !strings.HasPrefix(p, ".tplaiter/") && p != ".tplater" && !strings.HasPrefix(p, ".tplater/")
}

// ObservePath refuses symlink roots, ancestors, leaves, hardlinked files and oversized inputs.
func ObservePath(root, name string) (File, error) {
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || canonical != root {
		return File{}, ErrState
	}
	if !fs.ValidPath(name) {
		return File{}, ErrInput
	}
	held, err := os.OpenRoot(root)
	if err != nil {
		return File{}, err
	}
	defer held.Close()
	prefix := ""
	parts := strings.Split(name, "/")
	for i, s := range parts {
		if prefix == "" {
			prefix = s
		} else {
			prefix += "/" + s
		}
		info, e := held.Lstat(prefix)
		if e != nil {
			return File{}, e
		}
		if info.Mode()&os.ModeSymlink != 0 || i < len(parts)-1 && !info.IsDir() {
			return File{}, ErrState
		}
	}
	info, err := held.Lstat(name)
	if err != nil {
		return File{}, err
	}
	dev, ino := identity(info)
	if ino == 0 {
		return File{}, ErrState
	}
	image := File{Data: []byte{}, Mode: uint32(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)), Directory: info.IsDir(), Device: dev, Inode: ino}
	if info.IsDir() {
		return image, nil
	}
	if !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() > 16<<20 {
		return File{}, ErrState
	}
	v := reflect.ValueOf(info.Sys()).Elem().FieldByName("Nlink")
	if v.IsValid() && v.CanUint() && v.Uint() != 1 {
		return File{}, ErrState
	}
	f, err := held.Open(name)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return File{}, ErrState
	}
	image.Data, err = io.ReadAll(io.LimitReader(f, 16<<20+1))
	if err != nil {
		return File{}, err
	}
	after, e := held.Lstat(name)
	if e != nil || !os.SameFile(info, after) || info.Mode() != after.Mode() || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || len(image.Data) > 16<<20 {
		return File{}, ErrState
	}
	return image, nil
}
func Observe(ctx context.Context, root string, images map[string][]byte) (map[string]File, []string, error) {
	paths := map[string]bool{".": true}
	for p := range images {
		if strings.HasPrefix(p, ".tplaiter/") {
			continue
		}
		if !SafeUserPath(p) {
			return nil, nil, ErrInput
		}
		for n := p; n != "."; n = filepath.ToSlash(filepath.Dir(n)) {
			paths[n] = true
		}
	}
	names := make([]string, 0, len(paths))
	for p := range paths {
		names = append(names, p)
	}
	sort.Strings(names)
	if len(names) > 4096 {
		return nil, nil, ErrInput
	}
	files := map[string]File{}
	missing := []string{}
	total := 0
	for _, p := range names {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		f, err := ObservePath(root, p)
		if errors.Is(err, fs.ErrNotExist) {
			missing = append(missing, p)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		total += len(f.Data)
		if total > 64<<20 {
			return nil, nil, ErrInput
		}
		files[p] = f
	}
	return files, missing, nil
}
