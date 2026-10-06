//go:build darwin || linux

package graphcmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCachePublicationCleanupCounters(t *testing.T) {
	for _, tc := range []struct {
		name        string
		blocked     bool
		cleanupFail bool
	}{
		{name: "renamed-absent"},
		{name: "blocked-unlinked", blocked: true},
		{name: "renamed-cleanup-error", cleanupFail: true},
		{name: "blocked-joined-error", blocked: true, cleanupFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := graphTree(t)
			cache := filepath.Join(root, ".tplaiter", "graph-cache")
			if err := os.MkdirAll(cache, 0700); err != nil {
				t.Fatal(err)
			}
			if tc.blocked {
				if err := os.Mkdir(filepath.Join(cache, "image"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls, heldFD := 0, -1
			err := cachePublishWithUnlink(root, "image", []byte("finite-cache-image"), func(dir int, leaf string, flags int) error {
				calls++
				heldFD = dir
				var st unix.Stat_t
				if err := unix.Fstat(dir, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
					t.Fatalf("cleanup lost held directory: %v", err)
				}
				if flags != 0 || len(leaf) != len(".graph-")+32 || !strings.HasPrefix(leaf, ".graph-") || filepath.Base(leaf) != leaf {
					t.Fatalf("cleanup widened leaf: %q flags %d", leaf, flags)
				}
				nativeErr := unix.Unlinkat(dir, leaf, flags)
				if tc.blocked && nativeErr != nil || !tc.blocked && !errors.Is(nativeErr, unix.ENOENT) {
					t.Fatalf("unexpected native cleanup: %v", nativeErr)
				}
				if tc.cleanupFail {
					// Inject a syscall error after exact-leaf cleanup; no fixture leak.
					return unix.EPERM
				}
				return nativeErr
			})
			if calls != 1 {
				t.Fatalf("cleanup count %d", calls)
			}
			var st unix.Stat_t
			if closeErr := unix.Fstat(heldFD, &st); !errors.Is(closeErr, unix.EBADF) {
				t.Fatalf("directory FD retained after return: %v", closeErr)
			}
			if tc.blocked {
				var primary *Error
				if Code(err) != "GRAPH_INPUT_TOPOLOGY" || !errors.As(err, &primary) || primary.Code != "GRAPH_INPUT_TOPOLOGY" {
					t.Fatalf("primary code lost: %v", err)
				}
			} else {
				raw, readErr := os.ReadFile(filepath.Join(cache, "image"))
				if readErr != nil || string(raw) != "finite-cache-image" {
					t.Fatalf("publication changed: %q %v", raw, readErr)
				}
				if !tc.cleanupFail && err != nil {
					t.Fatal(err)
				}
				if tc.cleanupFail && (err == nil || Code(err) != "GRAPH_SOURCE_ADMISSION") {
					t.Fatalf("cleanup failure reported success: %v", err)
				}
			}
			if errors.Is(err, unix.EPERM) != tc.cleanupFail {
				t.Fatalf("cleanup error identity lost: %v", err)
			}
			entries, readErr := os.ReadDir(cache)
			if readErr != nil || len(entries) != 1 || entries[0].Name() != "image" {
				t.Fatalf("unexpected cache leaves: %v %v", entries, readErr)
			}
		})
	}
}

func TestCacheCleanupPrimaryErrorRouting(t *testing.T) {
	marker := errors.New("primary marker")
	typed := &Error{Code: "GRAPH_SOURCE_STALE", cause: marker}
	for _, primary := range []error{typed, context.Canceled, context.DeadlineExceeded, marker, nil} {
		for _, secondary := range []error{nil, unix.ENOENT, unix.EPERM} {
			calls := 0
			got := cacheCleanup(primary, 17, ".graph-exact", func(dir int, leaf string, flags int) error {
				calls++
				if dir != 17 || leaf != ".graph-exact" || flags != 0 {
					t.Fatal("cleanup arguments changed")
				}
				return secondary
			})
			if calls != 1 || primary != nil && (!errors.Is(got, primary) || Code(got) != Code(primary)) {
				t.Fatalf("primary routing changed: primary=%v cleanup=%v got=%v", primary, secondary, got)
			}
			if primary == typed {
				var carried *Error
				if !errors.As(got, &carried) || carried != typed || !errors.Is(got, marker) {
					t.Fatal("typed primary identity changed")
				}
			}
			if secondary == unix.EPERM && !errors.Is(got, unix.EPERM) {
				t.Fatal("unexpected cleanup error suppressed")
			}
			if secondary != unix.EPERM && got != primary {
				t.Fatal("successful cleanup replaced primary")
			}
			if primary == nil && secondary == unix.EPERM && (got == nil || Code(got) != "GRAPH_SOURCE_ADMISSION") {
				t.Fatal("cleanup-only failure accepted")
			}
		}
	}
}
