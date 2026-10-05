//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package contextpack

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/graphdoc"

	"golang.org/x/sys/unix"
)

func TestBuildRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "leaf")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// The known hash is intentionally arbitrary: non-regular rejection must
	// happen before provenance matching or any read attempt.
	d := graphdoc.New()
	d.Nodes = []graphdoc.Node{{ID: "fifo", Kind: "file", Path: "leaf", Line: 1, Provenance: []graphdoc.Provenance{{Source: "filesystem", Evidence: "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000", Detected: true}}}}
	if err := d.Canonicalize(); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Build(d, Request{Root: root, MaxBytes: HardLimit, IncludeSource: true})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("source build blocked on FIFO")
	}
}

func TestBuildRejectsLeafSwappedToFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	body := []byte("regular before swap\n")
	d := sourceGraph(t, root, "leaf", body, 1)
	path := filepath.Join(root, "leaf")
	if err := unix.Unlink(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Build(d, Request{Root: root, MaxBytes: HardLimit, IncludeSource: true})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("source build blocked on swapped FIFO")
	}
}

func TestRootAcquisitionRejectsCanonicalAncestorReplacement(t *testing.T) {
	base := t.TempDir()
	ancestor := filepath.Join(base, "ancestor")
	root := filepath.Join(ancestor, "root")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	replaced := false
	_, err := newSourceReaderWithHook(root, func(component string) error {
		if component != filepath.Base(ancestor) || replaced {
			return nil
		}
		replaced = true
		moved := ancestor + ".original"
		if err := os.Rename(ancestor, moved); err != nil {
			return err
		}
		return os.MkdirAll(filepath.Join(ancestor, "root"), 0o700)
	})
	if !replaced {
		t.Fatal("ancestor replacement seam was not exercised")
	}
	if err == nil {
		t.Fatal("accepted a canonical ancestor replacement")
	}
}
