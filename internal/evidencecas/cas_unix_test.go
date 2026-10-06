//go:build darwin || linux

package evidencecas

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixRootRejectsSymlinkComponent(t *testing.T) {
	base := t.TempDir()
	physical := filepath.Join(base, "physical")
	if err := os.MkdirAll(physical, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(physical, alias); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := NewFSReader(alias); err == nil {
		t.Fatal("accepted symlink root")
	}
}

func TestReadBoundedMutationAndCancellation(t *testing.T) {
	for _, value := range []string{"abcdef", "ab"} {
		path := filepath.Join(t.TempDir(), "mutation")
		if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		before, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readBoundedBytes(context.Background(), f, before.Size())
		f.Close()
		if got != nil || !errors.Is(err, ErrBlobChanged) {
			t.Fatalf("growth/truncation %q: %v", value, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	reader := &boundedCancelReader{reader: strings.NewReader(strings.Repeat("x", 70000)), cancel: cancel}
	if got, err := readBoundedBytes(ctx, reader, 70000); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-read cancellation: %v", err)
	}
	if _, err := readBoundedBytes(context.Background(), strings.NewReader(""), maxBlobSize+1); !errors.Is(err, ErrBoundExceeded) {
		t.Fatal(err)
	}
}

type boundedCancelReader struct {
	reader io.Reader
	cancel context.CancelFunc
}

func (r *boundedCancelReader) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	r.cancel()
	return n, err
}

func TestReadBoundedUnsafePathsAndReplacement(t *testing.T) {
	for _, kind := range []string{"leaf-symlink", "shard-symlink", "namespace-symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			root := physicalPath(t.TempDir())
			blob := []byte("owned body")
			ref := Digest(blob)
			path := blobPath(root, ref)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, blob, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "leaf-symlink":
				outside := filepath.Join(t.TempDir(), "body")
				os.WriteFile(outside, blob, 0600)
				os.Remove(path)
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "shard-symlink", "namespace-symlink":
				old := filepath.Dir(path)
				if kind == "namespace-symlink" {
					old = filepath.Dir(old)
				}
				moved := old + "-retained"
				if err := os.Rename(old, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, old); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+"-alias"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				os.Remove(path)
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := NewFSReader(root)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := r.ReadBounded(context.Background(), ref, 100); err == nil {
				t.Fatal("unsafe path accepted")
			}
		})
	}
	root := physicalPath(t.TempDir())
	path := filepath.Join(root, "leaf")
	os.WriteFile(path, []byte("same"), 0600)
	parent, err := openDir(unix.AT_FDCWD, root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parent)
	held, err := openLeaf(parent, "leaf")
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(held)
	if err := os.Rename(path, path+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("same"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := boundedPathIdentity(parent, "leaf", held); !errors.Is(err, ErrBlobChanged) {
		t.Fatalf("same-body replacement: %v", err)
	}
}
