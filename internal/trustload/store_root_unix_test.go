//go:build darwin || linux

package trustload

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRootLeaseDirectoryLocks(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	first, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openRootLease(context.Background(), root, storeRead); err == nil {
		t.Fatal("exclusive lease allowed a competing reader")
	}
	if _, err := openRootLease(context.Background(), root, storeRefresh); err == nil {
		t.Fatal("exclusive lease allowed a competing writer")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRootLeaseChild$")
	cmd.Env = append(os.Environ(), "TRUSTLOAD_TEST_LOCK_ROOT="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-process lock proof: %v: %s", err, out)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	left, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	right, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	if err := right.Close(); err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := openRootLease(context.Background(), root, storeRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRootLeaseChild(t *testing.T) {
	root := os.Getenv("TRUSTLOAD_TEST_LOCK_ROOT")
	if root == "" {
		t.Skip("helper")
	}
	mode := storeRead
	if os.Getenv("TRUSTLOAD_TEST_LOCK_MODE") == "writer" {
		mode = storeRefresh
	}
	lease, err := openRootLease(context.Background(), root, mode)
	if os.Getenv("TRUSTLOAD_TEST_LOCK_HOLD") != "" {
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(os.Getenv("TRUSTLOAD_TEST_LOCK_READY"), []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	if os.Getenv("TRUSTLOAD_TEST_LOCK_EXPECT") == "allow" {
		if err != nil {
			t.Fatal(err)
		}
		_ = lease.Close()
		return
	}
	if err == nil {
		_ = lease.Close()
		t.Fatal("child acquired conflicting lease")
	}
}

func TestRootLeaseCrossProcessPermutationsAndDeath(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	seed, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	run := func(parent storeMode, child, expect string) {
		lease, err := openRootLease(context.Background(), root, parent)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestRootLeaseChild$")
		cmd.Env = append(os.Environ(), "TRUSTLOAD_TEST_LOCK_ROOT="+root, "TRUSTLOAD_TEST_LOCK_MODE="+child, "TRUSTLOAD_TEST_LOCK_EXPECT="+expect)
		if out, err := cmd.CombinedOutput(); err != nil {
			_ = lease.Close()
			t.Fatalf("%d/%s: %v: %s", parent, child, err, out)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
	run(storeRead, "reader", "allow")
	run(storeRead, "writer", "deny")
	run(storeRefresh, "reader", "deny")
	run(storeRefresh, "writer", "deny")
	ready := filepath.Join(base, "holder-ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestRootLeaseChild$")
	cmd.Env = append(os.Environ(), "TRUSTLOAD_TEST_LOCK_ROOT="+root, "TRUSTLOAD_TEST_LOCK_MODE=reader", "TRUSTLOAD_TEST_LOCK_HOLD=1", "TRUSTLOAD_TEST_LOCK_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatal("reader holder did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	writer, err := openRootLease(context.Background(), root, storeRefresh)
	if err != nil {
		t.Fatalf("writer after reader death: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRootLeaseRejectsSymlinkLeaf(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	outside := filepath.Join(base, "outside")
	if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, storeDBName)); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.openLeaf(storeDBName, os.O_RDONLY, 0); err == nil {
		t.Fatal("symlink leaf was opened")
	}
	if raw, err := os.ReadFile(outside); err != nil || string(raw) != "sentinel" {
		t.Fatalf("outside changed: %q, %v", raw, err)
	}
}

func TestRootLeaseRejectsReplacedLocator(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := os.Rename(root, root+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if lease.valid() {
		t.Fatal("replaced locator remained valid")
	}
	if _, err := lease.openLeaf(storeDBName, os.O_RDONLY, 0); err == nil {
		t.Fatal("open accepted replaced locator")
	}
}

func TestRootLeaseRejectsSubstitutedMarkers(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	out := filepath.Join(base, "outside")
	if err := os.WriteFile(out, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{activeMarkerName, pendingMarkerName} {
		path := filepath.Join(root, marker)
		if err := os.Symlink(out, path); err != nil {
			t.Fatal(err)
		}
		if _, err := lease.markerExists(marker); err == nil {
			t.Fatalf("%s symlink accepted", marker)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := lease.markerExists(marker); err == nil {
			t.Fatalf("%s FIFO accepted", marker)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}
