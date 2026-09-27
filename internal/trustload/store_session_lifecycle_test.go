//go:build darwin || linux

package trustload

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStoreLifecycleLOCK01SameProcessMatrix(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
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
	tests := []struct {
		name   string
		first  storeMode
		second storeMode
	}{
		{"SH-SH", storeRead, storeRead},
		{"SH-EX", storeRead, storeRefresh},
		{"EX-SH", storeRefresh, storeRead},
		{"EX-EX", storeRefresh, storeRefresh},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			first, err := openRootLease(context.Background(), root, tc.first)
			if err != nil {
				t.Fatalf("first lease: %v", err)
			}
			second, secondErr := openRootLease(context.Background(), root, tc.second)
			if tc.first == storeRead && tc.second == storeRead {
				if secondErr != nil {
					t.Fatalf("SH/SH denied: %v", secondErr)
				}
				if _, err := openRootLease(context.Background(), root, storeRefresh); !errors.Is(err, ErrRefreshConflict) {
					t.Fatalf("EX with two SH leases=%v", err)
				}
				if err := first.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := openRootLease(context.Background(), root, storeRefresh); !errors.Is(err, ErrRefreshConflict) {
					t.Fatalf("EX after one SH lease=%v", err)
				}
				if err := second.Close(); err != nil {
					t.Fatal(err)
				}
				second = nil
				writer, err := openRootLease(context.Background(), root, storeRefresh)
				if err != nil {
					t.Fatalf("EX after both SH leases: %v", err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			wantErr := ErrRefreshConflict
			if tc.first == storeRefresh && tc.second == storeRead {
				wantErr = ErrPending
			}
			if !errors.Is(secondErr, wantErr) {
				t.Fatalf("contending lease=%v want=%v", secondErr, wantErr)
			}
			if second != nil {
				if err := second.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			mode := tc.second
			lease, err := openRootLease(context.Background(), root, mode)
			if err != nil {
				t.Fatalf("mode %d after holder close: %v", mode, err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoreLifecycleLOCK02CrossProcessMatrix(t *testing.T) {
	if os.Getenv("TPLAITER_LOCK_CHILD") == "1" {
		t.Helper()
		root := os.Getenv("TPLAITER_LOCK_ROOT")
		mode := storeRead
		if os.Getenv("TPLAITER_LOCK_MODE") == "EX" {
			mode = storeRefresh
		}
		lease, err := openRootLease(context.Background(), root, mode)
		ready := os.NewFile(uintptr(3), "ready")
		control := os.NewFile(uintptr(4), "control")
		if err != nil {
			_, _ = ready.Write([]byte{'E'})
			_ = ready.Close()
			_ = control.Close()
			return
		}
		_, _ = ready.Write([]byte{'R'})
		var command [1]byte
		_, _ = io.ReadFull(control, command[:])
		_ = control.Close()
		_ = ready.Close()
		if command[0] == 'k' {
			return
		}
		_ = lease.Close()
		return
	}
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
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
	for _, holder := range []string{"SH", "EX"} {
		for _, contender := range []string{"SH", "EX"} {
			for _, kill := range []bool{false, true} {
				t.Run(holder+"-"+contender+map[bool]string{false: "-close", true: "-kill"}[kill], func(t *testing.T) {
					readyR, readyW, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					controlR, controlW, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command(os.Args[0], "-test.run=^TestStoreLifecycleLOCK02CrossProcessMatrix$")
					cmd.Env = append(os.Environ(), "TPLAITER_LOCK_CHILD=1", "TPLAITER_LOCK_ROOT="+root, "TPLAITER_LOCK_MODE="+holder)
					cmd.ExtraFiles = []*os.File{readyW, controlR}
					if err := cmd.Start(); err != nil {
						t.Fatal(err)
					}
					_ = readyW.Close()
					_ = controlR.Close()
					var state [1]byte
					if _, err := io.ReadFull(readyR, state[:]); err != nil || state[0] != 'R' {
						_ = cmd.Process.Kill()
						_ = cmd.Wait()
						t.Fatalf("holder startup state=%q err=%v", state, err)
					}
					contenderMode := storeRead
					if contender == "EX" {
						contenderMode = storeRefresh
					}
					contenderLease, contenderErr := openRootLease(context.Background(), root, contenderMode)
					if holder == "SH" && contender == "SH" {
						if contenderErr != nil {
							t.Fatalf("same-mode contender denied: %v", contenderErr)
						}
						_ = contenderLease.Close()
					} else {
						wantErr := ErrRefreshConflict
						if holder == "EX" && contender == "SH" {
							wantErr = ErrPending
						}
						if !errors.Is(contenderErr, wantErr) {
							t.Fatalf("contender error=%v want=%v", contenderErr, wantErr)
						}
					}
					if contenderLease != nil {
						_ = contenderLease.Close()
					}
					if kill {
						if err := cmd.Process.Kill(); err != nil {
							t.Fatal(err)
						}
					} else if _, err := controlW.Write([]byte{'c'}); err != nil {
						t.Fatal(err)
					}
					_ = controlW.Close()
					_ = readyR.Close()
					if err := cmd.Wait(); err != nil && !kill {
						t.Fatal(err)
					}
					fresh, err := openRootLease(context.Background(), root, contenderMode)
					if err != nil {
						t.Fatalf("fresh lease after holder release/death: %v", err)
					}
					if err := fresh.Close(); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestStoreLifecycleLOCK03Cancellation(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "nil-store")
	before := openFDCount(t)
	if lease, err := openRootLease(nil, root, storeEnroll); lease != nil || err == nil {
		t.Fatalf("nil context lease=%v err=%v", lease, err)
	}
	if got := openFDCount(t); got != before {
		t.Fatalf("nil context FD count=%d want=%d", got, before)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	base, err = filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(base, "canceled-store")
	before = openFDCount(t)
	if lease, err := openRootLease(ctx, root, storeEnroll); lease != nil || err == nil {
		t.Fatalf("pre-canceled lease=%v err=%v", lease, err)
	}
	if got := openFDCount(t); got != before {
		t.Fatalf("pre-canceled FD count=%d want=%d", got, before)
	}
	for _, stage := range []string{"post-open-pre-lock", "post-lock-pre-return"} {
		t.Run(stage, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "store")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			old := storeRootLeaseHook
			storeRootLeaseHook = func(got string) {
				if got == stage {
					cancel()
				}
			}
			before := openFDCount(t)
			lease, err := openRootLease(ctx, root, storeEnroll)
			storeRootLeaseHook = old
			if lease != nil || err == nil {
				t.Fatalf("canceled %s lease=%v err=%v", stage, lease, err)
			}
			if got := openFDCount(t); got != before {
				t.Fatalf("canceled %s FD count=%d want=%d", stage, got, before)
			}
			fresh, err := openRootLease(context.Background(), root, storeRefresh)
			if err != nil {
				t.Fatalf("lock/resource retained after %s: %v", stage, err)
			}
			if err := fresh.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
