//go:build linux

package mcpsrv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// linuxStageScratch returns a symlink-free private scratch root on the same
// filesystem family the installed runtime would use.
func linuxStageScratch(t *testing.T) string {
	t.Helper()
	scratch, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return scratch
}

// TestLinuxHeldStageIsPrivateVerifiedCopy proves the Linux held stage has the
// same guarantees as Darwin: an immutable copy in a private 0700 directory,
// verified before launch, independent of later source replacement, and
// removed on Close.
func TestLinuxHeldStageIsPrivateVerifiedCopy(t *testing.T) {
	scratch := linuxStageScratch(t)
	source := filepath.Join(scratch, "source")
	original, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, original, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := newHeldStage(source, scratch)
	if err != nil {
		t.Fatalf("newHeldStage: %v", err)
	}
	root := heldStageRoot(stage)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || filepath.Dir(root) != scratch {
		t.Fatalf("stage root %s mode=%v err=%v", root, info.Mode(), err)
	}
	path, err := stage.launchPath()
	if err != nil || filepath.Dir(path) != root {
		t.Fatalf("launchPath=%q err=%v", path, err)
	}
	staged, err := os.Lstat(path)
	if err != nil || staged.Mode().Perm() != 0o500 || !staged.Mode().IsRegular() {
		t.Fatalf("staged file mode=%v err=%v", staged.Mode(), err)
	}
	// Replacing the source after staging must not change what is launched.
	if err := os.WriteFile(source, []byte("replacement"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatalf("staged bytes changed after source replacement: err=%v", err)
	}
	// The held descriptor is close-on-exec, so no child inherits it.
	flags, err := unix.FcntlInt(stage.file.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("held stage descriptor flags=%#x err=%v", flags, err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("stage root remains after Close: %v", err)
	}
	if _, err := stage.launchPath(); err == nil {
		t.Fatal("closed stage still yields a launch path")
	}
	if err := stage.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestLinuxHeldStageRefusesTamperedCopy proves the pre-launch digest and
// inode checks: rewriting the staged bytes, or replacing the staged name with
// another inode or a symlink, makes the stage unusable.
func TestLinuxHeldStageRefusesTamperedCopy(t *testing.T) {
	for _, mode := range []string{"rewrite", "replace", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			scratch := linuxStageScratch(t)
			exe, err := filepath.EvalSymlinks(os.Args[0])
			if err != nil {
				t.Fatal(err)
			}
			stage, err := newHeldStage(exe, scratch)
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Close()
			path, err := stage.launchPath()
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "rewrite":
				if err := os.Chmod(path, 0o700); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.WriteAt([]byte("tampered"), 0); err != nil {
					t.Fatal(err)
				}
				_ = f.Close()
			case "replace":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o500); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(exe, path); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := stage.launchPath(); err == nil {
				t.Fatalf("tampered stage (%s) still launches %q", mode, got)
			}
		})
	}
}

func TestLinuxHeldStageRejectsUnsafeSources(t *testing.T) {
	scratch := linuxStageScratch(t)
	fifo := filepath.Join(scratch, "executable-fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(scratch, "executable-link")
	if err := os.Symlink(os.Args[0], link); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(scratch, "empty")
	if err := os.WriteFile(empty, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	oversize := filepath.Join(scratch, "oversize")
	if err := os.WriteFile(oversize, []byte{0x7f}, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(oversize, maxChildBinary+1); err != nil { // sparse: no 64 MiB write
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, source, scratch string }{
		{"fifo", fifo, scratch},
		{"symlink", link, scratch},
		{"empty", empty, scratch},
		{"oversize", oversize, scratch},
		{"relative", "relative/tplaiter", scratch},
		{"unclean", scratch + "/./empty", scratch},
		{"root", "/", scratch},
		{"relative-scratch", empty, "relative"},
		{"missing-scratch", empty, filepath.Join(scratch, "missing")},
	} {
		done := make(chan error, 1)
		go func() {
			stage, err := newHeldStage(tc.source, tc.scratch)
			if stage != nil {
				_ = stage.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: unsafe source accepted", tc.name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: stage construction blocked", tc.name)
		}
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "tplaiter-held-stage-") {
			t.Fatalf("refused source left stage residue %s", entry.Name())
		}
	}
}

// TestLinuxInstalledTransportRunsThroughHeldStage exercises the production
// launch path (NewInstalled-equivalent wiring) on Linux: the child runs from
// the held copy, not from the original executable path.
func TestLinuxInstalledTransportRunsThroughHeldStage(t *testing.T) {
	s := installedTestServer(t)
	res, err := s.runCLI(context.Background(), "", helperArgs("stdout"), 10*time.Second)
	if err != nil || res.Stdout != "verified-output\n" {
		t.Fatalf("installed Linux transport result=%+v err=%v", res, err)
	}
	if root := heldStageRoot(s.stage); root == "" || !strings.HasPrefix(filepath.Base(root), "tplaiter-held-stage-") {
		t.Fatalf("installed transport did not use a held stage: %q", root)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(heldStageRoot(s.stage)); !os.IsNotExist(err) {
		t.Fatalf("held stage remains after server Close: %v", err)
	}
}
