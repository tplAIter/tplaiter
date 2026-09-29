//go:build darwin || linux

package trustload

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc"
	"modernc.org/libc/sys/types"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestStoreVFSIO01ReadFaultMatrix(t *testing.T) {
	cases := []struct {
		name  string
		read  func(int, []byte, int64) (int, error)
		want  int32
		calls int
		check func(*testing.T, []byte)
	}{
		{"eintr-then-success", func(_ int, b []byte, _ int64) (int, error) { copy(b, []byte("abcd")); return len(b), nil }, sqlite3.SQLITE_OK, 2, func(t *testing.T, b []byte) {
			if !reflect.DeepEqual(b, []byte("abcd")) {
				t.Fatalf("full read buffer=%v", b)
			}
		}},
		{"positive-short", func(_ int, b []byte, _ int64) (int, error) { copy(b[:1], []byte("a")); return 1, nil }, sqlite3.SQLITE_IOERR_SHORT_READ, 1, func(t *testing.T, b []byte) {
			if !reflect.DeepEqual(b, []byte{'a', 0, 0, 0}) {
				t.Fatalf("short read buffer=%v", b)
			}
		}},
		{"eintr-positive-short", func(_ int, b []byte, _ int64) (int, error) { copy(b[:2], []byte("ab")); return 2, nil }, sqlite3.SQLITE_IOERR_SHORT_READ, 2, func(t *testing.T, b []byte) {
			if !reflect.DeepEqual(b, []byte{'a', 'b', 0, 0}) {
				t.Fatalf("short read buffer=%v", b)
			}
		}},
		{"eof", func(_ int, _ []byte, _ int64) (int, error) { return 0, nil }, sqlite3.SQLITE_IOERR_SHORT_READ, 1, func(t *testing.T, b []byte) {
			if !reflect.DeepEqual(b, []byte{0, 0, 0, 0}) {
				t.Fatalf("EOF buffer=%v", b)
			}
		}},
		{"eio", func(_ int, _ []byte, _ int64) (int, error) { return 0, unix.EIO }, sqlite3.SQLITE_IOERR_READ, 1, nil},
		{"impossible-count", func(_ int, _ []byte, _ int64) (int, error) { return 5, nil }, sqlite3.SQLITE_IOERR_READ, 1, nil},
		{"negative-count", func(_ int, _ []byte, _ int64) (int, error) { return -1, nil }, sqlite3.SQLITE_IOERR_READ, 1, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := storePread
			calls := 0
			storePread = func(fd int, b []byte, off int64) (int, error) {
				calls++
				if tc.name == "eintr-then-success" || tc.name == "eintr-positive-short" {
					if calls == 1 {
						return 0, unix.EINTR
					}
				}
				return tc.read(fd, b, off)
			}
			defer func() { storePread = old }()
			_, v, p := newIOFile(t, false)
			buf := libc.Xmalloc(v.tls, types.Size_t(4))
			if buf == 0 {
				t.Fatal("buffer allocation")
			}
			defer libc.Xfree(v.tls, buf)
			for i := 0; i < 4; i++ {
				*(*byte)(libcPtr(buf + uintptr(i))) = 0xcc
			}
			got := storeFileRead(v.tls, p, buf, 4, 0)
			if got != tc.want {
				t.Fatalf("read=%d want=%d", got, tc.want)
			}
			if calls != tc.calls {
				t.Fatalf("pread calls=%d want=%d", calls, tc.calls)
			}
			out := unsafe.Slice((*byte)(libcPtr(buf)), 4)
			if tc.check != nil {
				tc.check(t, out)
			}
		})
	}
	for _, tc := range []struct {
		name string
		n    int32
		off  sqlite3.Tsqlite3_int64
	}{
		{"negative-size", -1, 0}, {"negative-offset", 1, -1}, {"offset-overflow", 1, sqlite3.Tsqlite3_int64(math.MaxInt64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, v, p := newIOFile(t, false)
			called := false
			old := storePread
			storePread = func(int, []byte, int64) (int, error) { called = true; return 0, nil }
			defer func() { storePread = old }()
			if got := storeFileRead(v.tls, p, 0, tc.n, tc.off); got != sqlite3.SQLITE_IOERR_READ || called {
				t.Fatalf("invalid read got=%d called=%v", got, called)
			}
		})
	}
	{
		_, v, p := newIOFile(t, false)
		if got := storeFileRead(v.tls, p, 0, 1, 0); got != sqlite3.SQLITE_IOERR_READ {
			t.Fatalf("null output=%d", got)
		}
	}
	{
		_, v, p := newIOFile(t, false)
		buf := libc.Xmalloc(v.tls, types.Size_t(1))
		if buf == 0 {
			t.Fatal("buffer allocation")
		}
		defer libc.Xfree(v.tls, buf)
		*(*byte)(libcPtr(buf)) = 0xa5
		calls := 0
		old := storePread
		storePread = func(int, []byte, int64) (int, error) { calls++; return 0, nil }
		got := storeFileRead(v.tls, p, buf, 0, 0)
		storePread = old
		if got != sqlite3.SQLITE_OK || calls != 0 || *(*byte)(libcPtr(buf)) != 0xa5 {
			t.Fatalf("zero-length read=%d calls=%d sentinel=%#x", got, calls, *(*byte)(libcPtr(buf)))
		}
	}
}

func TestStoreVFSIO02WriteFaultMatrix(t *testing.T) {
	cases := []struct {
		name    string
		results []struct {
			n   int
			err error
		}
		want  int32
		calls int
	}{
		{"partial-progress", []struct {
			n   int
			err error
		}{{1, nil}, {2, nil}, {1, nil}}, sqlite3.SQLITE_OK, 3},
		{"no-progress", []struct {
			n   int
			err error
		}{{0, nil}}, sqlite3.SQLITE_IOERR_WRITE, 1},
		{"eintr", []struct {
			n   int
			err error
		}{{0, unix.EINTR}, {4, nil}}, sqlite3.SQLITE_OK, 2},
		{"enospc-after-partial", []struct {
			n   int
			err error
		}{{1, nil}, {0, unix.ENOSPC}}, sqlite3.SQLITE_IOERR_WRITE, 2},
		{"eacces", []struct {
			n   int
			err error
		}{{0, unix.EACCES}}, sqlite3.SQLITE_IOERR_WRITE, 1},
		{"eio", []struct {
			n   int
			err error
		}{{0, unix.EIO}}, sqlite3.SQLITE_IOERR_WRITE, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := storePwrite
			calls := 0
			type writeCall struct {
				off   int64
				bytes []byte
			}
			var seen []writeCall
			storePwrite = func(_ int, b []byte, off int64) (int, error) {
				r := tc.results[calls]
				seen = append(seen, writeCall{off: off, bytes: append([]byte(nil), b...)})
				calls++
				return r.n, r.err
			}
			defer func() { storePwrite = old }()
			_, v, p := newIOFile(t, false)
			in := libc.Xmalloc(v.tls, types.Size_t(4))
			if in == 0 {
				t.Fatal("input allocation")
			}
			defer libc.Xfree(v.tls, in)
			copy(unsafe.Slice((*byte)(libcPtr(in)), 4), []byte{0, 1, 2, 3})
			if got := storeFileWrite(v.tls, p, in, 4, 7); got != tc.want {
				t.Fatalf("write=%d want=%d", got, tc.want)
			}
			if calls != tc.calls {
				t.Fatalf("pwrite calls=%d want=%d", calls, tc.calls)
			}
			if tc.name == "partial-progress" {
				want := []writeCall{{7, []byte{0, 1, 2, 3}}, {8, []byte{1, 2, 3}}, {10, []byte{3}}}
				if !reflect.DeepEqual(seen, want) {
					t.Fatalf("pwrite sequence=%v want=%v", seen, want)
				}
			}
		})
	}
}

func TestStoreVFSIO02WriteRangesAndImpossibleCounts(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int32
		off  sqlite3.Tsqlite3_int64
		want int32
	}{
		{"negative-size", -1, 0, sqlite3.SQLITE_IOERR_WRITE},
		{"negative-offset", 1, -1, sqlite3.SQLITE_IOERR_WRITE},
		{"offset-overflow", 1, sqlite3.Tsqlite3_int64(math.MaxInt64), sqlite3.SQLITE_IOERR_WRITE},
		{"null-input", 1, 0, sqlite3.SQLITE_IOERR_WRITE},
		{"impossible-count", 4, 0, sqlite3.SQLITE_IOERR_WRITE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, v, p := newIOFile(t, false)
			in := uintptr(0)
			if tc.name != "null-input" {
				in = libc.Xmalloc(v.tls, types.Size_t(4))
				if in == 0 {
					t.Fatal("input allocation")
				}
				defer libc.Xfree(v.tls, in)
			}
			calls := 0
			old := storePwrite
			storePwrite = func(_ int, _ []byte, _ int64) (int, error) { calls++; return 5, nil }
			got := storeFileWrite(v.tls, p, in, tc.n, tc.off)
			storePwrite = old
			wantCalls := 0
			if tc.name == "impossible-count" {
				wantCalls = 1
			}
			if got != tc.want || calls != wantCalls {
				t.Fatalf("write=%d calls=%d want=%d/%d", got, calls, tc.want, wantCalls)
			}
		})
	}
	for _, errno := range []error{unix.EACCES, unix.EIO} {
		t.Run("partial-"+errno.Error(), func(t *testing.T) {
			_, v, p := newIOFile(t, false)
			in := libc.Xmalloc(v.tls, types.Size_t(4))
			if in == 0 {
				t.Fatal("input allocation")
			}
			defer libc.Xfree(v.tls, in)
			copy(unsafe.Slice((*byte)(libcPtr(in)), 4), []byte{0, 1, 2, 3})
			type writeCall struct {
				off   int64
				bytes []byte
			}
			calls := 0
			var seen []writeCall
			old := storePwrite
			storePwrite = func(_ int, b []byte, off int64) (int, error) {
				calls++
				seen = append(seen, writeCall{off: off, bytes: append([]byte(nil), b...)})
				if calls == 1 {
					return 1, nil
				}
				return 0, errno
			}
			got := storeFileWrite(v.tls, p, in, 4, 3)
			storePwrite = old
			want := []writeCall{{3, []byte{0, 1, 2, 3}}, {4, []byte{1, 2, 3}}}
			if got != sqlite3.SQLITE_IOERR_WRITE || calls != 2 || !reflect.DeepEqual(seen, want) {
				t.Fatalf("write=%d calls=%d sequence=%v want=%v", got, calls, seen, want)
			}
		})
	}
}

func TestStoreVFSIO03SyncDeleteAndTruncateMatrix(t *testing.T) {
	{
		oldFile := storeSyncFile
		storeSyncFile = func(int) error { return unix.EIO }
		_, v, p := newIOFile(t, false)
		if got := storeFileSync(v.tls, p, 0); got != sqlite3.SQLITE_IOERR_FSYNC {
			t.Fatalf("file sync=%d", got)
		}
		storeSyncFile = oldFile
	}
	{
		oldFile, oldDir := storeSyncFile, storeSyncDirectory
		_, v, p := newIOFile(t, true)
		storeSyncFile = func(int) error { return nil }
		storeSyncDirectory = func(int) error { return unix.EIO }
		if got := storeFileSync(v.tls, p, 0); got != sqlite3.SQLITE_IOERR_DIR_FSYNC {
			t.Fatalf("journal dir sync=%d", got)
		}
		storeSyncFile, storeSyncDirectory = oldFile, oldDir
	}
	for _, tc := range []struct {
		name string
		err  error
		want int32
	}{{"truncate-negative", nil, sqlite3.SQLITE_IOERR_TRUNCATE}, {"truncate-eio", unix.EIO, sqlite3.SQLITE_IOERR_TRUNCATE}} {
		t.Run(tc.name, func(t *testing.T) {
			old := storeFtruncate
			_, v, p := newIOFile(t, false)
			storeFtruncate = func(int, int64) error { return tc.err }
			defer func() { storeFtruncate = old }()
			size := sqlite3.Tsqlite3_int64(-1)
			if tc.err != nil {
				size = 0
			}
			if got := storeFileTruncate(v.tls, p, size); got != tc.want {
				t.Fatalf("truncate=%d", got)
			}
		})
	}
	{
		oldUnlink, oldDir := storeUnlinkat, storeSyncDirectory
		_, v, _ := newIOFile(t, false)
		storeUnlinkat = func(int, string, int) error { return unix.ENOENT }
		storeSyncDirectory = func(int) error { return unix.EIO }
		defer func() { storeUnlinkat, storeSyncDirectory = oldUnlink, oldDir }()
		name := nsCString(t, v.main+"-journal", v.tls)
		defer libc.Xfree(v.tls, name)
		if got := storeVFSDelete(v.tls, v.vfs, name, 0); got != sqlite3.SQLITE_IOERR_DIR_FSYNC {
			t.Fatalf("missing journal delete=%d", got)
		}
	}
}

func TestStoreVFSIO03SQLAndEnrollmentSyncErrors(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	oldDir := storeSyncDirectory
	defer func() { storeSyncDirectory = oldDir }()
	storeSyncDirectory = func(int) error { return unix.EIO }
	if lease, got := openRootLease(context.Background(), root, storeEnroll); lease != nil || !errors.Is(got, ErrProvenanceUnavailable) {
		t.Fatalf("enrollment parent sync succeeded: lease=%v err=%v", lease, got)
	}
	storeSyncDirectory = oldDir
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}

	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, storeDBName), []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	fault := storeSetupFault{phase: "exec:PRAGMA query_only=ON", err: errors.New("injected SQL setup failure")}
	ctx := context.WithValue(context.Background(), storeSetupFaultKey{}, fault)
	if binding, got := openSQLBinding(ctx, lease, storeRead); binding != nil || !errors.Is(got, ErrProvenanceUnavailable) {
		t.Fatalf("SQL constructor failure returned usable binding: binding=%v err=%v", binding, got)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreVFSIO03DeleteDirSyncErrnoMatrix(t *testing.T) {
	for _, tc := range []struct {
		name               string
		unlinkErr, syncErr error
		dirSync            int32
		want               int32
		wantSync           int
	}{
		{"missing-dirSync0", unix.ENOENT, nil, 0, sqlite3.SQLITE_OK, 1},
		{"missing-dirSync1", unix.ENOENT, nil, 1, sqlite3.SQLITE_OK, 1},
		{"eacces-dirSync0", unix.EACCES, nil, 0, sqlite3.SQLITE_IOERR_DELETE, 0},
		{"eacces-dirSync1", unix.EACCES, nil, 1, sqlite3.SQLITE_IOERR_DELETE, 0},
		{"eio-dirSync0", unix.EIO, nil, 0, sqlite3.SQLITE_IOERR_DELETE, 0},
		{"eio-dirSync1", unix.EIO, nil, 1, sqlite3.SQLITE_IOERR_DELETE, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, v, _ := newIOFile(t, false)
			oldUnlink, oldDir := storeUnlinkat, storeSyncDirectory
			calls := 0
			storeUnlinkat = func(int, string, int) error { return tc.unlinkErr }
			storeSyncDirectory = func(int) error { calls++; return tc.syncErr }
			name := nsCString(t, v.main+"-journal", v.tls)
			got := storeVFSDelete(v.tls, v.vfs, name, tc.dirSync)
			storeUnlinkat, storeSyncDirectory = oldUnlink, oldDir
			libc.Xfree(v.tls, name)
			if got != tc.want {
				t.Fatalf("delete=%d want=%d", got, tc.want)
			}
			if calls != tc.wantSync {
				t.Fatalf("dir sync calls=%d want=%d", calls, tc.wantSync)
			}
		})
	}
}

func TestStoreVFSIO03RetainedSQLCommitAndCloseFailures(t *testing.T) {
	{
		_, v, p := newIOFile(t, false)
		c := storeContext(v.vfs)
		atomic.StoreInt64(&c.fault, storeFaultClose)
		if got := storeFileClose(v.tls, p); got != sqlite3.SQLITE_IOERR_CLOSE {
			t.Fatalf("first close=%d", got)
		}
		fd, methods, openFiles, closeErrors := storeFile(p).fd, storeFile(p).base.FpMethods, atomic.LoadInt64(&c.openFiles), atomic.LoadInt64(&c.closeErrors)
		if fd != -1 || methods != 0 || openFiles != 0 || closeErrors != 1 {
			t.Fatalf("first close state fd=%d methods=%d open=%d errors=%d", fd, methods, openFiles, closeErrors)
		}
		if got := storeFileClose(v.tls, p); got != sqlite3.SQLITE_IOERR_CLOSE {
			t.Fatalf("repeat close=%d", got)
		}
		if got := storeFile(p); got.fd != fd || got.base.FpMethods != methods || atomic.LoadInt64(&c.openFiles) != openFiles || atomic.LoadInt64(&c.closeErrors) != closeErrors {
			t.Fatalf("repeat close mutated state fd=%d methods=%d open=%d errors=%d", got.fd, got.base.FpMethods, atomic.LoadInt64(&c.openFiles), atomic.LoadInt64(&c.closeErrors))
		}
		if err := v.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("VFS close after callback error=%v", err)
		}
		// The ledger is cleared only after the terminal callback and retained
		// VFS invariants have been observed, so the test cleanup can release it.
		atomic.StoreInt64(&c.closeErrors, 0)
	}
	for _, wantClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "close"}[wantClose], func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			lease, err := openRootLease(context.Background(), filepath.Join(base, "store"), storeEnroll)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := openSQLBinding(context.Background(), lease, storeEnroll)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := binding.conn.ExecContext(context.Background(), "CREATE TABLE io03(v INTEGER)"); err != nil {
				t.Fatal(err)
			}
			oldSync := storeSyncFile
			if !wantClose {
				storeSyncFile = func(int) error { return unix.EIO }
				if _, err := binding.conn.ExecContext(context.Background(), "BEGIN IMMEDIATE; INSERT INTO io03 VALUES(1); COMMIT"); err == nil {
					t.Fatal("COMMIT succeeded despite sync EIO")
				}
				storeSyncFile = oldSync
				if err := binding.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := binding.conn.ExecContext(context.Background(), "BEGIN IMMEDIATE; INSERT INTO io03 VALUES(1)"); err != nil {
					t.Fatal(err)
				}
				atomic.StoreInt64(&storeContext(binding.vfs.vfs).fault, storeFaultClose)
				if err := binding.Close(); err == nil {
					t.Fatal("Close succeeded despite injected close failure")
				}
				if binding.closed {
					t.Fatal("binding marked closed after retained close failure")
				}
				closeErrors := atomic.LoadInt64(&storeContext(binding.vfs.vfs).closeErrors)
				if closeErrors == 0 {
					t.Fatal("close failure was not retained in VFS ledger")
				}
				if err := binding.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
					t.Fatalf("repeat binding.Close=%v", err)
				}
				if atomic.LoadInt64(&storeContext(binding.vfs.vfs).closeErrors) != closeErrors {
					t.Fatal("repeat binding.Close changed close-error ledger")
				}
				atomic.StoreInt64(&storeContext(binding.vfs.vfs).closeErrors, 0)
				if err := binding.vfs.Close(); err != nil {
					t.Fatal("cleanup after retained close failure: ", err)
				}
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoreVFSIO04PermissionMatrix(t *testing.T) {
	{
		old := storeOpenat
		_, v, p := newIOFile(t, false)
		storeOpenat = func(int, string, int, uint32) (int, error) { return -1, unix.EACCES }
		if got := storeVFSOpen(v.tls, v.vfs, nsCString(t, v.main, v.tls), p, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE, 0); got != sqlite3.SQLITE_CANTOPEN {
			t.Fatalf("injected open=%d", got)
		}
		storeOpenat = old
	}
	{
		old := storeFstatat
		_, v, _ := newIOFile(t, false)
		storeFstatat = func(int, string, *unix.Stat_t, int) error { return unix.EACCES }
		name := nsCString(t, v.main, v.tls)
		defer libc.Xfree(v.tls, name)
		if got := storeVFSAccess(v.tls, v.vfs, name, sqlite3.SQLITE_ACCESS_EXISTS, 0); got != sqlite3.SQLITE_IOERR_ACCESS {
			t.Fatalf("injected fstatat=%d", got)
		}
		storeFstatat = old
	}
	{
		old := storeUnlinkat
		_, v, _ := newIOFile(t, false)
		storeUnlinkat = func(int, string, int) error { return unix.EACCES }
		name := nsCString(t, v.main+"-journal", v.tls)
		defer libc.Xfree(v.tls, name)
		if got := storeVFSDelete(v.tls, v.vfs, name, 0); got != sqlite3.SQLITE_IOERR_DELETE {
			t.Fatalf("injected unlink=%d", got)
		}
		storeUnlinkat = old
	}
	{
		old := storePwrite
		_, v, p := newIOFile(t, false)
		storePwrite = func(int, []byte, int64) (int, error) { return 0, unix.EACCES }
		in := libc.Xmalloc(v.tls, types.Size_t(1))
		if in == 0 {
			t.Fatal("input allocation")
		}
		got := storeFileWrite(v.tls, p, in, 1, 0)
		libc.Xfree(v.tls, in)
		storePwrite = old
		if got != sqlite3.SQLITE_IOERR_WRITE {
			t.Fatalf("injected pwrite=%d", got)
		}
	}
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
	path := filepath.Join(root, storeDBName)
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := newStoreVFS(lease, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	name := nsCString(t, v.main, v.tls)
	defer libc.Xfree(v.tls, name)
	if unix.Geteuid() != 0 {
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		fd, nativeErr := unix.Openat(lease.fd, storeDBName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if fd >= 0 {
			unix.Close(fd)
		}
		if !errors.Is(nativeErr, unix.EACCES) {
			t.Fatalf("native euid=%d open errno=%v", unix.Geteuid(), nativeErr)
		}
	} else {
		t.Log("native chmod-000 EACCES unavailable under privileged euid=0")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	p := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if p == 0 {
		t.Fatal("file allocation")
	}
	if got := storeVFSOpen(v.tls, v.vfs, name, p, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE, 0); got != sqlite3.SQLITE_CANTOPEN {
		t.Fatalf("native group/other leaf mode accepted: %d", got)
	}
	libc.Xfree(v.tls, p)
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := openRootLease(context.Background(), root, storeRead); err == nil {
		t.Fatal("native group root mode accepted")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
}

func newIOFile(t *testing.T, journal bool) (*rootLease, *storeVFS, uintptr) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, storeDBName), []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if journal {
		if err := os.WriteFile(filepath.Join(root, storeDBName+"-journal"), []byte("journal"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	v, err := newStoreVFS(lease, storeEnroll)
	if err != nil {
		lease.Close()
		t.Fatal(err)
	}
	name := v.main
	flags := int32(sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READWRITE)
	if journal {
		name += "-journal"
		flags = sqlite3.SQLITE_OPEN_MAIN_JOURNAL | sqlite3.SQLITE_OPEN_READWRITE
	}
	cname := nsCString(t, name, v.tls)
	defer libc.Xfree(v.tls, cname)
	p := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if p == 0 {
		t.Fatal("file allocation")
	}
	if got := storeVFSOpen(v.tls, v.vfs, cname, p, flags, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("open=%d", got)
	}
	t.Cleanup(func() { storeFileClose(v.tls, p); libc.Xfree(v.tls, p); v.Close(); lease.Close() })
	return lease, v, p
}
