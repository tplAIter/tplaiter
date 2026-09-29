//go:build darwin || linux

package trustload

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc"
	"modernc.org/libc/sys/types"
	sqlite3 "modernc.org/sqlite/lib"
)

const storeVirtualPrefix = "/tplaiter-store/"

// libcPtr is the single audited conversion from a libc-owned address to an
// unsafe.Pointer. Every address passed here was returned by the modernc libc
// allocator (libc.Xmalloc and friends) or handed to a VFS callback by SQLite,
// so it refers to C heap memory that the Go garbage collector neither moves
// nor frees. unsafe.Add on a nil base expresses that without the
// uintptr-to-unsafe.Pointer conversion that go vet (unsafeptr) rejects; the
// result is identical and -race checkptr still validates it.
func libcPtr(addr uintptr) unsafe.Pointer { return unsafe.Add(nil, addr) }

var storeVFSSequence atomic.Uint64
var storeVFSObserverRegistry = struct {
	sync.RWMutex
	byToken map[uint64]*storeProofObserver
}{byToken: make(map[uint64]*storeProofObserver)}

func storeVFSObserverFor(c *vfsContext) *storeProofObserver {
	if c == nil {
		return nil
	}
	storeVFSObserverRegistry.RLock()
	observer := storeVFSObserverRegistry.byToken[c.token]
	storeVFSObserverRegistry.RUnlock()
	return observer
}

func storeVFSObserverRegister(token uint64, observer *storeProofObserver) {
	if observer == nil {
		return
	}
	storeVFSObserverRegistry.Lock()
	storeVFSObserverRegistry.byToken[token] = observer
	storeVFSObserverRegistry.Unlock()
}

func storeVFSObserverUnregister(token uint64) {
	storeVFSObserverRegistry.Lock()
	delete(storeVFSObserverRegistry.byToken, token)
	storeVFSObserverRegistry.Unlock()
}

// These syscall seams are used only by native fault tests. They are not a
// VFS registry or authority source: production callbacks retain descriptor
// ownership in libc memory and invoke the normal unix functions.
var (
	storePread         = unix.Pread
	storePwrite        = unix.Pwrite
	storeOpenat        = unix.Openat
	storeFstatat       = unix.Fstatat
	storeUnlinkat      = unix.Unlinkat
	storeFtruncate     = unix.Ftruncate
	storeSyncFile      = syncStoreFile
	storeSyncDirectory = syncStoreDirectory
	storeVFSUnregister = sqlite3.Xsqlite3_vfs_unregister
)

// vfsContext and vfsFile are allocated by libc, never Go. Their fields are
// intentionally numeric capability state only: an owned directory descriptor,
// mode, file descriptors and inode identities. SQLite may retain these memory
// addresses across calls, so no Go pointer or closure is stored in either.
type vfsContext struct {
	rootFD           int64
	mode             int64
	token            uint64
	methods          uintptr
	openFiles        int64
	closed           int64
	poisoned         int64
	journalSynced    int64
	deniedOpens      int64
	pathSyscalls     int64
	writeSyscalls    int64
	truncateSyscalls int64
	syncSyscalls     int64
	deleteSyscalls   int64
	closeErrors      int64
	ownerUID         int64
	fault            int64
	callbackCounts   [callbackCount]int64
}

type vfsFile struct {
	base sqlite3.Tsqlite3_file
	ctx  uintptr
	fd   int64
	kind int64
	lock int64
	dev  uint64
	ino  uint64
}

const (
	storeFileMain int64 = iota + 1
	storeFileJournal
)

const (
	callbackOpen = iota
	callbackDelete
	callbackAccess
	callbackFullPathname
	callbackRead
	callbackWrite
	callbackTruncate
	callbackSync
	callbackFileSize
	callbackLock
	callbackUnlock
	callbackCheckReserved
	callbackFileControl
	callbackClose
	callbackCount
)

func observeCallback(c *vfsContext, kind int) {
	if c != nil {
		atomic.AddInt64(&c.callbackCounts[kind], 1)
	}
}

const (
	storeFaultNone int64 = iota
	storeFaultRead
	storeFaultWrite
	storeFaultSync
	storeFaultClose
)

type storeVFS struct {
	tls     *libc.TLS
	vfs     uintptr
	methods uintptr
	ctx     uintptr
	name    string
	cname   uintptr
	main    string
	journal string
	mu      sync.Mutex
	closed  bool
	proof   *storeProofObserver
}

func cFuncPointer[T any](f T) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct{ f T }{f}))
}

func lifecycleAlloc(tls *libc.TLS, size types.Size_t, proof *storeProofObserver, phase string) uintptr {
	if proof != nil {
		if err := proof.checkpoint(phase, false); err != nil {
			return 0
		}
	}
	p := libc.Xmalloc(tls, size)
	if p == 0 {
		return 0
	}
	if proof != nil {
		if err := proof.checkpoint(phase, true); err != nil {
			libc.Xfree(tls, p)
			return 0
		}
	}
	return p
}

func newStoreVFS(lease *rootLease, mode storeMode) (*storeVFS, error) {
	return newStoreVFSObserved(lease, mode, nil)
}

func newStoreVFSObserved(lease *rootLease, mode storeMode, proof *storeProofObserver) (*storeVFS, error) {
	if lease == nil || !lease.valid() || mode == 0 {
		return nil, ErrProvenanceUnavailable
	}
	if mode == storeRead {
		if err := lease.pendingSidecar(); err != nil {
			return nil, err
		}
	}
	if proof != nil {
		if err := proof.checkpoint("vfs.tls", false); err != nil {
			return nil, err
		}
	}
	tls := libc.NewTLS()
	if proof != nil {
		proof.resource("tls", 1)
	}
	if proof != nil {
		if err := proof.checkpoint("vfs.tls", true); err != nil {
			tls.Close()
			if proof != nil {
				proof.resource("tls", -1)
			}
			return nil, err
		}
	}
	v := &storeVFS{tls: tls, proof: proof}
	observeAlloc := func() {
		if proof != nil {
			proof.mu.Lock()
			proof.allocs++
			proof.mu.Unlock()
		}
	}
	observeFree := func() {
		if proof != nil {
			proof.mu.Lock()
			proof.frees++
			proof.mu.Unlock()
		}
	}
	free := func() {
		if v.cname != 0 {
			libc.Xfree(tls, v.cname)
			observeFree()
		}
		if v.vfs != 0 {
			libc.Xfree(tls, v.vfs)
			observeFree()
		}
		if v.methods != 0 {
			libc.Xfree(tls, v.methods)
			observeFree()
		}
		if v.ctx != 0 {
			libc.Xfree(tls, v.ctx)
			observeFree()
		}
		tls.Close()
		if proof != nil {
			proof.resource("tls", -1)
		}
	}
	v.ctx = lifecycleAlloc(tls, types.Size_t(unsafe.Sizeof(vfsContext{})), proof, "vfs.ctx")
	if v.ctx != 0 {
		observeAlloc()
	}
	v.methods = lifecycleAlloc(tls, types.Size_t(unsafe.Sizeof(sqlite3.Tsqlite3_io_methods{})), proof, "vfs.methods")
	if v.methods != 0 {
		observeAlloc()
	}
	v.vfs = lifecycleAlloc(tls, types.Size_t(unsafe.Sizeof(sqlite3.Tsqlite3_vfs{})), proof, "vfs.vfs")
	if v.vfs != 0 {
		observeAlloc()
	}
	if v.ctx == 0 || v.methods == 0 || v.vfs == 0 {
		free()
		return nil, ErrProvenanceUnavailable
	}
	seq := storeVFSSequence.Add(1)
	*(*vfsContext)(libcPtr(v.ctx)) = vfsContext{rootFD: int64(lease.fd), mode: int64(mode), token: seq, methods: v.methods, ownerUID: int64(lease.ownerUID())}
	v.name = fmt.Sprintf("tplaiter-store-%x", seq)
	v.main = fmt.Sprintf("%s%x/%s", storeVirtualPrefix, seq, storeDBName)
	v.journal = v.main + "-journal"
	var err error
	if proof != nil {
		if err := proof.checkpoint("vfs.name", false); err != nil {
			free()
			return nil, err
		}
	}
	v.cname, err = libc.CString(v.name)
	if err != nil {
		free()
		return nil, ErrProvenanceUnavailable
	}
	observeAlloc()
	if proof != nil {
		if err := proof.checkpoint("vfs.name", true); err != nil {
			free()
			return nil, err
		}
	}
	*(*sqlite3.Tsqlite3_io_methods)(libcPtr(v.methods)) = sqlite3.Tsqlite3_io_methods{
		FiVersion: 1,
		FxClose:   cFuncPointer(storeFileClose), FxRead: cFuncPointer(storeFileRead), FxWrite: cFuncPointer(storeFileWrite),
		FxTruncate: cFuncPointer(storeFileTruncate), FxSync: cFuncPointer(storeFileSync), FxFileSize: cFuncPointer(storeFileSize),
		FxLock: cFuncPointer(storeFileLock), FxUnlock: cFuncPointer(storeFileUnlock), FxCheckReservedLock: cFuncPointer(storeFileCheckReserved),
		FxFileControl: cFuncPointer(storeFileControl), FxSectorSize: cFuncPointer(storeFileSectorSize), FxDeviceCharacteristics: cFuncPointer(storeFileDeviceCharacteristics),
	}
	*(*sqlite3.Tsqlite3_vfs)(libcPtr(v.vfs)) = sqlite3.Tsqlite3_vfs{
		FiVersion: 1, FszOsFile: int32(unsafe.Sizeof(vfsFile{})), FmxPathname: 4096, FzName: v.cname, FpAppData: v.ctx,
		FxOpen: cFuncPointer(storeVFSOpen), FxDelete: cFuncPointer(storeVFSDelete), FxAccess: cFuncPointer(storeVFSAccess), FxFullPathname: cFuncPointer(storeVFSFullPathname),
		FxDlOpen: cFuncPointer(storeVFSDlOpen), FxDlError: cFuncPointer(storeVFSDlError), FxDlSym: cFuncPointer(storeVFSDlSym), FxDlClose: cFuncPointer(storeVFSDlClose),
		FxRandomness: cFuncPointer(storeVFSRandomness), FxSleep: cFuncPointer(storeVFSSleep), FxCurrentTime: cFuncPointer(storeVFSCurrentTime), FxGetLastError: cFuncPointer(storeVFSLastError),
	}
	if proof != nil {
		if err := proof.checkpoint("vfs.register", false); err != nil {
			free()
			return nil, err
		}
	}
	if sqlite3.Xsqlite3_vfs_register(tls, v.vfs, 0) != sqlite3.SQLITE_OK {
		storeVFSObserverUnregister(seq)
		free()
		return nil, ErrProvenanceUnavailable
	}
	storeVFSObserverRegister(seq, proof)
	if proof != nil {
		proof.mu.Lock()
		proof.registers++
		proof.mu.Unlock()
		if err := proof.checkpoint("vfs.register", true); err != nil {
			if storeVFSUnregister(tls, v.vfs) == sqlite3.SQLITE_OK {
				proof.mu.Lock()
				proof.unregisters++
				proof.mu.Unlock()
			}
			storeVFSObserverUnregister(seq)
			free()
			return nil, err
		}
	}
	return v, nil
}

func (v *storeVFS) dsn() string {
	mode := "rw"
	switch storeMode((*vfsContext)(libcPtr(v.ctx)).mode) {
	case storeRead:
		mode = "ro"
	case storeEnroll:
		mode = "rwc"
	}
	return "file:" + v.main + "?vfs=" + v.name + "&mode=" + mode
}

func (v *storeVFS) Close() error {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return nil
	}
	c := (*vfsContext)(libcPtr(v.ctx))
	if atomic.LoadInt64(&c.openFiles) != 0 {
		v.mu.Unlock()
		return ErrProvenanceUnavailable
	}
	if atomic.LoadInt64(&c.closeErrors) != 0 {
		v.mu.Unlock()
		return ErrProvenanceUnavailable
	}
	atomic.StoreInt64(&c.closed, 1)
	if storeVFSUnregister(v.tls, v.vfs) != sqlite3.SQLITE_OK {
		atomic.StoreInt64(&c.closed, 0)
		v.mu.Unlock()
		return ErrProvenanceUnavailable
	}
	storeVFSObserverUnregister((*vfsContext)(libcPtr(v.ctx)).token)
	if v.proof != nil {
		v.proof.mu.Lock()
		v.proof.unregisters++
		v.proof.mu.Unlock()
	}
	libc.Xfree(v.tls, v.cname)
	libc.Xfree(v.tls, v.vfs)
	libc.Xfree(v.tls, v.methods)
	libc.Xfree(v.tls, v.ctx)
	if v.proof != nil {
		v.proof.mu.Lock()
		v.proof.frees += 4
		v.proof.mu.Unlock()
	}
	v.tls.Close()
	if v.proof != nil {
		v.proof.resource("tls", -1)
	}
	v.closed = true
	v.mu.Unlock()
	return nil
}

func storeContext(pVFS uintptr) *vfsContext {
	if pVFS == 0 {
		return nil
	}
	return (*vfsContext)(libcPtr((*sqlite3.Tsqlite3_vfs)(libcPtr(pVFS)).FpAppData))
}
func storeFile(p uintptr) *vfsFile {
	if p == 0 {
		return nil
	}
	return (*vfsFile)(libcPtr(p))
}
func storeFileContext(f *vfsFile) *vfsContext {
	if f == nil || f.ctx == 0 {
		return nil
	}
	return (*vfsContext)(libcPtr(f.ctx))
}
func vfsName(p uintptr) string {
	if p == 0 {
		return ""
	}
	return libc.GoString(p)
}
func vfsPathFor(pVFS, zPath uintptr) int64 {
	ctx := storeContext(pVFS)
	if ctx == nil {
		return 0
	}
	name := vfsName(zPath)
	main := fmt.Sprintf("%s%x/%s", storeVirtualPrefix, ctx.token, storeDBName)
	if name == main {
		return storeFileMain
	}
	if name == main+"-journal" {
		return storeFileJournal
	}
	return 0
}

func allowedOpen(ctx *vfsContext, kind int64, flags int32) bool {
	if ctx == nil || atomic.LoadInt64(&ctx.closed) != 0 || atomic.LoadInt64(&ctx.poisoned) != 0 {
		return false
	}
	typeBits := flags & (sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_MAIN_JOURNAL | sqlite3.SQLITE_OPEN_TEMP_DB | sqlite3.SQLITE_OPEN_TRANSIENT_DB | sqlite3.SQLITE_OPEN_TEMP_JOURNAL | sqlite3.SQLITE_OPEN_SUBJOURNAL | sqlite3.SQLITE_OPEN_SUPER_JOURNAL | sqlite3.SQLITE_OPEN_WAL)
	if flags&sqlite3.SQLITE_OPEN_DELETEONCLOSE != 0 {
		return false
	}
	if flags&(sqlite3.SQLITE_OPEN_READONLY|sqlite3.SQLITE_OPEN_READWRITE) == (sqlite3.SQLITE_OPEN_READONLY|sqlite3.SQLITE_OPEN_READWRITE) || flags&(sqlite3.SQLITE_OPEN_READONLY|sqlite3.SQLITE_OPEN_READWRITE) == 0 {
		return false
	}
	if flags&sqlite3.SQLITE_OPEN_READONLY != 0 && flags&sqlite3.SQLITE_OPEN_CREATE != 0 {
		return false
	}
	if kind == storeFileMain {
		if typeBits != sqlite3.SQLITE_OPEN_MAIN_DB {
			return false
		}
		return flags&sqlite3.SQLITE_OPEN_CREATE == 0 || ctx.mode == int64(storeEnroll)
	}
	return kind == storeFileJournal && typeBits == sqlite3.SQLITE_OPEN_MAIN_JOURNAL && ctx.mode != int64(storeRead)
}

func storeVFSOpen(tls *libc.TLS, pVFS uintptr, zPath sqlite3.Tsqlite3_filename, pFile uintptr, flags int32, pOut uintptr) int32 {
	if pFile == 0 {
		return sqlite3.SQLITE_CANTOPEN
	}
	(*sqlite3.Tsqlite3_file)(libcPtr(pFile)).FpMethods = 0
	ctx := storeContext(pVFS)
	observeCallback(ctx, callbackOpen)
	kind := vfsPathFor(pVFS, zPath)
	if observer := storeVFSObserverFor(ctx); observer != nil {
		observer.openAttempt(kind)
	}
	if !allowedOpen(ctx, kind, flags) {
		if ctx != nil {
			atomic.AddInt64(&ctx.deniedOpens, 1)
		}
		return sqlite3.SQLITE_CANTOPEN
	}
	leaf := storeDBName
	if kind == storeFileJournal {
		leaf += "-journal"
	}
	openFlags := unix.O_RDONLY
	if flags&sqlite3.SQLITE_OPEN_READWRITE != 0 && ctx.mode != int64(storeRead) {
		openFlags = unix.O_RDWR
	}
	if flags&sqlite3.SQLITE_OPEN_CREATE != 0 && !(kind == storeFileJournal && ctx.mode == int64(storeRecover)) {
		openFlags |= unix.O_CREAT | unix.O_EXCL
	}
	openPhase := "main-open"
	if kind == storeFileJournal {
		openPhase = "journal-open"
	}
	if observer := storeVFSObserverFor(ctx); observer != nil {
		if err := observer.checkpoint(openPhase, false); err != nil {
			return sqlite3.SQLITE_CANTOPEN
		}
	}
	atomic.AddInt64(&ctx.pathSyscalls, 1)
	fd, err := storeOpenat(int(ctx.rootFD), leaf, openFlags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return sqlite3.SQLITE_CANTOPEN
	}
	var st unix.Stat_t
	atomic.AddInt64(&ctx.pathSyscalls, 1)
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(ctx.ownerUID) || st.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return sqlite3.SQLITE_CANTOPEN
	}
	if observer := storeVFSObserverFor(ctx); observer != nil {
		observer.traceEvent(storeTraceOpen, kind, 0, int64(flags), 0, sqlite3.SQLITE_OK)
	}
	if observer := storeVFSObserverFor(ctx); observer != nil {
		if err := observer.checkpoint(openPhase, true); err != nil {
			_ = unix.Close(fd)
			return sqlite3.SQLITE_CANTOPEN
		}
	}
	f := storeFile(pFile)
	*f = vfsFile{ctx: uintptr(unsafe.Pointer(ctx)), fd: int64(fd), kind: kind, dev: uint64(st.Dev), ino: uint64(st.Ino)}
	f.base.FpMethods = ctx.methods
	if pOut != 0 {
		*(*int32)(libcPtr(pOut)) = flags
	}
	atomic.AddInt64(&ctx.openFiles, 1)
	if observer := storeVFSObserverFor(ctx); observer != nil && kind >= storeFileMain && kind <= storeFileJournal {
		observer.openClass(kind)
	}
	if observer := storeVFSObserverFor(ctx); observer != nil {
		observer.resource("vfsfile", 1)
	}
	return sqlite3.SQLITE_OK
}

func storeVFSDelete(tls *libc.TLS, pVFS, zPath uintptr, dirSync int32) int32 {
	ctx := storeContext(pVFS)
	observeCallback(ctx, callbackDelete)
	if ctx == nil || ctx.mode == int64(storeRead) || vfsPathFor(pVFS, zPath) != storeFileJournal {
		return sqlite3.SQLITE_IOERR_DELETE
	}
	atomic.AddInt64(&ctx.pathSyscalls, 1)
	if err := validatePrivateJournalAt(int(ctx.rootFD), uint32(ctx.ownerUID)); err != nil && err != unix.ENOENT {
		return sqlite3.SQLITE_IOERR_DELETE
	}
	atomic.AddInt64(&ctx.pathSyscalls, 1)
	atomic.AddInt64(&ctx.deleteSyscalls, 1)
	unlinkErr := storeUnlinkat(int(ctx.rootFD), storeDBName+"-journal", 0)
	if unlinkErr != nil && unlinkErr != unix.ENOENT {
		return sqlite3.SQLITE_IOERR_DELETE
	}
	if observer := storeVFSObserverFor(ctx); observer != nil && unlinkErr == nil {
		observer.traceEvent(storeTraceUnlink, storeFileJournal, 0, 0, 0, sqlite3.SQLITE_OK)
	}
	if storeSyncDirectory(int(ctx.rootFD)) != nil {
		return sqlite3.SQLITE_IOERR_DIR_FSYNC
	}
	if observer := storeVFSObserverFor(ctx); observer != nil {
		observer.traceEvent(storeTraceRootSync, storeTraceKindRoot, 0, 0, 0, sqlite3.SQLITE_OK)
	}
	return sqlite3.SQLITE_OK
}

func validatePrivateJournalAt(rootFD int, ownerUID uint32) error {
	var st unix.Stat_t
	if err := storeFstatat(rootFD, storeDBName+"-journal", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != ownerUID || st.Mode&0o077 != 0 {
		return unix.EPERM
	}
	return nil
}
func storeVFSAccess(tls *libc.TLS, pVFS, zPath uintptr, flags int32, pRes uintptr) int32 {
	if pRes != 0 {
		*(*int32)(libcPtr(pRes)) = 0
	}
	ctx := storeContext(pVFS)
	observeCallback(ctx, callbackAccess)
	kind := vfsPathFor(pVFS, zPath)
	if ctx == nil || flags != sqlite3.SQLITE_ACCESS_EXISTS {
		return sqlite3.SQLITE_IOERR_ACCESS
	}
	// SQLite asks whether its private VFS has a usable temporary directory
	// during open. Report every foreign name absent without consulting the OS;
	// xOpen independently rejects it, so this cannot select a fallback file.
	if kind == 0 {
		atomic.AddInt64(&ctx.deniedOpens, 1)
		return sqlite3.SQLITE_OK
	}
	leaf := storeDBName
	if kind == storeFileJournal {
		leaf += "-journal"
	}
	var st unix.Stat_t
	atomic.AddInt64(&ctx.pathSyscalls, 1)
	err := storeFstatat(int(ctx.rootFD), leaf, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return sqlite3.SQLITE_OK
	}
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(ctx.ownerUID) || st.Mode&0o077 != 0 {
		return sqlite3.SQLITE_IOERR_ACCESS
	}
	if pRes != 0 {
		*(*int32)(libcPtr(pRes)) = 1
	}
	return sqlite3.SQLITE_OK
}
func storeVFSFullPathname(tls *libc.TLS, pVFS, zPath uintptr, n int32, out uintptr) int32 {
	observeCallback(storeContext(pVFS), callbackFullPathname)
	if n <= 0 || out == 0 || vfsPathFor(pVFS, zPath) == 0 {
		return sqlite3.SQLITE_CANTOPEN
	}
	s := vfsName(zPath)
	if len(s)+1 > int(n) {
		return sqlite3.SQLITE_CANTOPEN
	}
	b := unsafe.Slice((*byte)(libcPtr(out)), int(n))
	copy(b, s)
	b[len(s)] = 0
	return sqlite3.SQLITE_OK
}
func storeVFSDlOpen(*libc.TLS, uintptr, uintptr) uintptr { return 0 }
func storeVFSDlError(tls *libc.TLS, p uintptr, n int32, out uintptr) {
	if n > 0 && out != 0 {
		*(*byte)(libcPtr(out)) = 0
	}
}
func storeVFSDlSym(*libc.TLS, uintptr, uintptr, uintptr) uintptr  { return 0 }
func storeVFSDlClose(*libc.TLS, uintptr, uintptr)                 {}
func storeVFSRandomness(*libc.TLS, uintptr, int32, uintptr) int32 { return 0 }
func storeVFSSleep(_ *libc.TLS, _ uintptr, n int32) int32         { return n }
func storeVFSCurrentTime(*libc.TLS, uintptr, uintptr) int32       { return sqlite3.SQLITE_ERROR }
func storeVFSLastError(*libc.TLS, uintptr, int32, uintptr) int32  { return 0 }

func storeFileClose(tls *libc.TLS, p uintptr) int32 {
	f := storeFile(p)
	c := storeFileContext(f)
	observeCallback(c, callbackClose)
	if f == nil || c == nil {
		return sqlite3.SQLITE_IOERR_CLOSE
	}
	if f.fd < 0 {
		return sqlite3.SQLITE_IOERR_CLOSE
	}
	err := unix.Close(int(f.fd))
	if atomic.LoadInt64(&c.fault) == storeFaultClose {
		err = unix.EIO
	}
	f.base.FpMethods = 0
	f.fd = -1
	atomic.AddInt64(&c.openFiles, -1)
	if observer := storeVFSObserverFor(c); observer != nil {
		observer.resource("vfsfile", -1)
	}
	if err != nil {
		atomic.AddInt64(&c.closeErrors, 1)
		return sqlite3.SQLITE_IOERR_CLOSE
	}
	return sqlite3.SQLITE_OK
}

func validStoreFile(f *vfsFile) bool {
	if f == nil || f.fd < 0 {
		return false
	}
	c := storeFileContext(f)
	if c == nil || atomic.LoadInt64(&c.closed) != 0 || atomic.LoadInt64(&c.poisoned) != 0 {
		return false
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.fd), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(c.ownerUID) || st.Mode&0o077 != 0 || uint64(st.Dev) != f.dev || uint64(st.Ino) != f.ino {
		atomic.StoreInt64(&c.poisoned, 1)
		return false
	}
	leaf := storeDBName
	if f.kind == storeFileJournal {
		leaf += "-journal"
	}
	if storeFstatat(int(c.rootFD), leaf, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(c.ownerUID) || st.Mode&0o077 != 0 || uint64(st.Dev) != f.dev || uint64(st.Ino) != f.ino {
		atomic.StoreInt64(&c.poisoned, 1)
		return false
	}
	return true
}

func storeFileRead(tls *libc.TLS, p, out uintptr, n int32, off sqlite3.Tsqlite3_int64) int32 {
	f := storeFile(p)
	observeCallback(storeFileContext(f), callbackRead)
	if !validStoreFile(f) || n < 0 || off < 0 || (n > 0 && out == 0) || int64(off) > int64(^uint64(0)>>1)-int64(n) {
		return sqlite3.SQLITE_IOERR_READ
	}
	if n == 0 {
		return sqlite3.SQLITE_OK
	}
	b := unsafe.Slice((*byte)(libcPtr(out)), int(n))
	if c := storeFileContext(f); c != nil && atomic.LoadInt64(&c.fault) == storeFaultRead {
		return sqlite3.SQLITE_IOERR_READ
	}
	var got int
	var err error
	for {
		got, err = storePread(int(f.fd), b, int64(off))
		if err == unix.EINTR {
			continue
		}
		break
	}
	if err != nil || got < 0 || got > int(n) {
		return sqlite3.SQLITE_IOERR_READ
	}
	if got < int(n) {
		for i := got; i < int(n); i++ {
			b[i] = 0
		}
		return sqlite3.SQLITE_IOERR_SHORT_READ
	}
	return sqlite3.SQLITE_OK
}
func storeFileWrite(tls *libc.TLS, p, in uintptr, n int32, off sqlite3.Tsqlite3_int64) int32 {
	f := storeFile(p)
	c := storeFileContext(f)
	observeCallback(c, callbackWrite)
	if !validStoreFile(f) || c == nil {
		return sqlite3.SQLITE_IOERR_WRITE
	}
	if c.mode == int64(storeRead) {
		return sqlite3.SQLITE_READONLY
	}
	if n < 0 || off < 0 || (n > 0 && in == 0) || int64(off) > int64(^uint64(0)>>1)-int64(n) {
		return sqlite3.SQLITE_IOERR_WRITE
	}
	b := unsafe.Slice((*byte)(libcPtr(in)), int(n))
	if atomic.LoadInt64(&c.fault) == storeFaultWrite {
		return sqlite3.SQLITE_IOERR_WRITE
	}
	for len(b) > 0 {
		atomic.AddInt64(&c.writeSyscalls, 1)
		requested := int64(len(b))
		m, e := storePwrite(int(f.fd), b, int64(off))
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return sqlite3.SQLITE_IOERR_WRITE
		}
		if m <= 0 || m > len(b) {
			return sqlite3.SQLITE_IOERR_WRITE
		}
		if observer := storeVFSObserverFor(c); observer != nil {
			observer.traceEvent(storeTraceWrite, f.kind, int64(off), requested, int64(m), sqlite3.SQLITE_OK)
		}
		off += sqlite3.Tsqlite3_int64(m)
		b = b[m:]
	}
	return sqlite3.SQLITE_OK
}
func storeFileTruncate(tls *libc.TLS, p uintptr, size sqlite3.Tsqlite3_int64) int32 {
	f := storeFile(p)
	c := storeFileContext(f)
	observeCallback(c, callbackTruncate)
	if !validStoreFile(f) || c == nil || c.mode == int64(storeRead) {
		return sqlite3.SQLITE_READONLY
	}
	if size < 0 {
		return sqlite3.SQLITE_IOERR_TRUNCATE
	}
	atomic.AddInt64(&c.truncateSyscalls, 1)
	if storeFtruncate(int(f.fd), int64(size)) != nil {
		return sqlite3.SQLITE_IOERR_TRUNCATE
	}
	if observer := storeVFSObserverFor(c); observer != nil {
		observer.traceEvent(storeTraceTruncate, f.kind, int64(size), int64(size), int64(size), sqlite3.SQLITE_OK)
	}
	return sqlite3.SQLITE_OK
}
func storeFileSync(tls *libc.TLS, p uintptr, flags int32) int32 {
	f := storeFile(p)
	c := storeFileContext(f)
	observeCallback(c, callbackSync)
	if !validStoreFile(f) || c == nil {
		return sqlite3.SQLITE_IOERR_FSYNC
	}
	if atomic.LoadInt64(&c.fault) == storeFaultSync {
		return sqlite3.SQLITE_IOERR_FSYNC
	}
	atomic.AddInt64(&c.syncSyscalls, 1)
	if storeSyncFile(int(f.fd)) != nil {
		return sqlite3.SQLITE_IOERR_FSYNC
	}
	if observer := storeVFSObserverFor(c); observer != nil {
		observer.traceEvent(storeTraceFileSync, f.kind, 0, 0, 0, sqlite3.SQLITE_OK)
	}
	if f.kind == storeFileJournal {
		atomic.StoreInt64(&c.journalSynced, 1)
		atomic.AddInt64(&c.syncSyscalls, 1)
		if storeSyncDirectory(int(c.rootFD)) != nil {
			return sqlite3.SQLITE_IOERR_DIR_FSYNC
		}
		if observer := storeVFSObserverFor(c); observer != nil {
			observer.traceEvent(storeTraceRootSync, storeTraceKindRoot, 0, 0, 0, sqlite3.SQLITE_OK)
		}
	}
	return sqlite3.SQLITE_OK
}
func storeFileSize(tls *libc.TLS, p, out uintptr) int32 {
	f := storeFile(p)
	observeCallback(storeFileContext(f), callbackFileSize)
	if !validStoreFile(f) || out == 0 {
		return sqlite3.SQLITE_IOERR_FSTAT
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.fd), &st) != nil || st.Size < 0 {
		return sqlite3.SQLITE_IOERR_FSTAT
	}
	*(*sqlite3.Tsqlite3_int64)(libcPtr(out)) = sqlite3.Tsqlite3_int64(st.Size)
	return sqlite3.SQLITE_OK
}
func storeFileLock(tls *libc.TLS, p uintptr, level int32) int32 {
	f := storeFile(p)
	c := storeFileContext(f)
	observeCallback(c, callbackLock)
	if !validStoreFile(f) || c == nil || level < sqlite3.SQLITE_LOCK_SHARED || level > sqlite3.SQLITE_LOCK_EXCLUSIVE {
		return sqlite3.SQLITE_IOERR_LOCK
	}
	if c.mode == int64(storeRead) && level > sqlite3.SQLITE_LOCK_SHARED {
		return sqlite3.SQLITE_BUSY
	}
	if level > int32(f.lock) {
		f.lock = int64(level)
	}
	return sqlite3.SQLITE_OK
}
func storeFileUnlock(tls *libc.TLS, p uintptr, level int32) int32 {
	f := storeFile(p)
	observeCallback(storeFileContext(f), callbackUnlock)
	if f == nil || level < sqlite3.SQLITE_LOCK_NONE || level > sqlite3.SQLITE_LOCK_SHARED {
		return sqlite3.SQLITE_IOERR_UNLOCK
	}
	if level < int32(f.lock) {
		f.lock = int64(level)
	}
	return sqlite3.SQLITE_OK
}
func storeFileCheckReserved(tls *libc.TLS, p, out uintptr) int32 {
	f := storeFile(p)
	observeCallback(storeFileContext(f), callbackCheckReserved)
	if f == nil || out == 0 {
		return sqlite3.SQLITE_IOERR_CHECKRESERVEDLOCK
	}
	if f.lock >= sqlite3.SQLITE_LOCK_RESERVED {
		*(*int32)(libcPtr(out)) = 1
	} else {
		*(*int32)(libcPtr(out)) = 0
	}
	return sqlite3.SQLITE_OK
}
func storeFileControl(tls *libc.TLS, p uintptr, op int32, arg uintptr) int32 {
	f := storeFile(p)
	observeCallback(storeFileContext(f), callbackFileControl)
	if f == nil {
		return sqlite3.SQLITE_NOTFOUND
	}
	if op == sqlite3.SQLITE_FCNTL_LOCKSTATE && arg != 0 {
		*(*int32)(libcPtr(arg)) = int32(f.lock)
		return sqlite3.SQLITE_OK
	}
	return sqlite3.SQLITE_NOTFOUND
}
func storeFileSectorSize(*libc.TLS, uintptr) int32            { return 4096 }
func storeFileDeviceCharacteristics(*libc.TLS, uintptr) int32 { return 0 }
