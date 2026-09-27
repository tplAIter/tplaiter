//go:build darwin

package trustload

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestStoreUnavailableSB08 exercises only the preflight unavailable route.
// It deliberately does not make a no-write claim for later fsync or rename
// failures, because those occur after an enrollment artifact may exist.
func TestStoreUnavailableSB08(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	t.Run("open-read-only", testUnavailableOpenReadOnly)
	t.Run("enroll", testUnavailableEnroll)
	t.Run("refresh", testUnavailableRefresh)
	t.Run("recover-state", testUnavailableRecoverState)
}

func testUnavailableOpenReadOnly(t *testing.T) {
	fixture := unavailableEnrolledFixture(t)
	root := fixture.loaded.Install.OSS.StorePath
	before := unavailableSnapshotTree(t, root)
	check := forceUnavailablePreflight(t)
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if store != nil || !errors.Is(err, ErrAnchorMissing) {
		if store != nil {
			_ = store.Close()
		}
		t.Fatalf("OpenReadOnly store=%v err=%v", store, err)
	}
	assertSafeUnavailableError(t, err)
	check()
	assertUnavailableSnapshotTree(t, root, before)
}

func testUnavailableEnroll(t *testing.T) {
	fixture := newBootstrapFixture(t)
	root := fixture.loaded.Install.OSS.StorePath
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("fresh root lstat=%v", err)
	}
	parent := filepath.Dir(root)
	before := unavailableSnapshotTree(t, parent)
	check := forceUnavailablePreflight(t)
	err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence)
	if !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("Enroll err=%v", err)
	}
	assertSafeUnavailableError(t, err)
	check()
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("unavailable Enroll created root: %v", err)
	}
	assertUnavailableSnapshotTree(t, parent, before)
}

func testUnavailableRefresh(t *testing.T) {
	fixture := unavailableEnrolledFixture(t)
	next, evidence := rotateBundle(t, fixture)
	root := fixture.loaded.Install.OSS.StorePath
	before := unavailableSnapshotTree(t, root)
	check := forceUnavailablePreflight(t)
	authority, err := Refresh(context.Background(), fixture.selection, fixture.factory, next, evidence)
	if authority != nil || !errors.Is(err, ErrAnchorMissing) {
		t.Fatalf("Refresh authority=%v err=%v", authority, err)
	}
	assertSafeUnavailableError(t, err)
	check()
	assertUnavailableSnapshotTree(t, root, before)
}

func testUnavailableRecoverState(t *testing.T) {
	fixture := unavailableEnrolledFixture(t)
	root := fixture.loaded.Install.OSS.StorePath
	before := unavailableSnapshotTree(t, root)
	check := forceUnavailablePreflight(t)
	err := RecoverState(context.Background(), fixture.selection, fixture.factory)
	if !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("RecoverState err=%v", err)
	}
	assertSafeUnavailableError(t, err)
	check()
	assertUnavailableSnapshotTree(t, root, before)
}

func unavailableEnrolledFixture(t *testing.T) bootstrapFixture {
	t.Helper()
	fixture := newBootstrapFixture(t)
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// forceUnavailablePreflight preserves the failure-only seam contract: every
// call invokes the actual native predicate before this test denies use of the
// resulting capability. It never synthesizes an available filesystem.
func forceUnavailablePreflight(t *testing.T) func() {
	t.Helper()
	original := storeFilesystemPreflight
	calls, nativeFailures := 0, 0
	storeFilesystemPreflight = func(fd int) bool {
		calls++
		if !original(fd) {
			nativeFailures++
		}
		return false
	}
	t.Cleanup(func() { storeFilesystemPreflight = original })
	return func() {
		if calls == 0 || nativeFailures != 0 {
			t.Fatalf("preflight calls=%d nativeFailures=%d", calls, nativeFailures)
		}
	}
}

func assertSafeUnavailableError(t *testing.T, err error) {
	t.Helper()
	if err == nil || strings.Contains(strings.ToLower(err.Error()), "sqlite") || strings.Contains(err.Error(), string(filepath.Separator)) {
		t.Fatalf("unsafe unavailable error: %v", err)
	}
}

type unavailableEntry struct {
	path                         string
	dev, ino, mode, uid, nlink   uint64
	size, mtimeSec, mtimeNanosec int64
	content                      []byte
	hasContent                   bool
}

// unavailableSnapshotTree intentionally excludes atime, which a read-only
// operation may update under filesystem policy. It records identity, bytes,
// and mtime for every namespace entry.
func unavailableSnapshotTree(t *testing.T, root string) []unavailableEntry {
	t.Helper()
	var out []unavailableEntry
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		mtime := reflect.ValueOf(st).FieldByName("Mtimespec")
		if !mtime.IsValid() {
			mtime = reflect.ValueOf(st).FieldByName("Mtim")
		}
		value := unavailableEntry{
			path: filepath.Clean(path), dev: uint64(st.Dev), ino: uint64(st.Ino), mode: uint64(st.Mode), uid: uint64(st.Uid), nlink: uint64(st.Nlink), size: st.Size,
			mtimeSec: mtime.FieldByName("Sec").Int(), mtimeNanosec: mtime.FieldByName("Nsec").Int(),
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value.content, value.hasContent = content, true
		}
		out = append(out, value)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func assertUnavailableSnapshotTree(t *testing.T, root string, before []unavailableEntry) {
	t.Helper()
	after := unavailableSnapshotTree(t, root)
	if len(after) != len(before) {
		t.Fatalf("namespace entry count changed: before=%d after=%d", len(before), len(after))
	}
	for i := range before {
		if before[i].path != after[i].path || before[i].dev != after[i].dev || before[i].ino != after[i].ino || before[i].mode != after[i].mode || before[i].uid != after[i].uid || before[i].nlink != after[i].nlink || before[i].size != after[i].size || before[i].mtimeSec != after[i].mtimeSec || before[i].mtimeNanosec != after[i].mtimeNanosec || before[i].hasContent != after[i].hasContent || !bytes.Equal(before[i].content, after[i].content) {
			t.Fatalf("namespace changed: before=%+v after=%+v", before[i], after[i])
		}
	}
}
