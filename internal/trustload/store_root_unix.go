//go:build darwin || linux

package trustload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const coldJournalInspectBudget int64 = 256 << 20

// Recovery-only syscall/phase seams are private deterministic fault hooks for
// the executable maintenance matrix. They never supply data, authority, or a
// successful health result, and are nil/default in production.
var (
	storeRecoveryClose   = unix.Close
	storeRecoveryFstatat = unix.Fstatat
	storeRecoveryOpenat  = unix.Openat
	storeRecoveryPread   = unix.Pread
	storeRecoveryFstat   = unix.Fstat
	storeRecoveryHook    func(string)
	// storeRecoveryFreshHealthFault is a test-only failure seam for the final
	// readonly health invocation.  It can only force failure; it cannot supply
	// SQL, a tuple, or an approval result.
	storeRecoveryFreshHealthFault error

	// Marker seams are private, failure-only syscall observations for the
	// finite adapter fault matrix. Production uses the real operations; tests
	// must invoke the real operation first and may only return an error, short
	// count, or EINTR afterward. They cannot supply bytes or success.
	storeMarkerOpenat          = unix.Openat
	storeMarkerPread           = unix.Pread
	storeMarkerWrite           = unix.Write
	storeMarkerFstat           = unix.Fstat
	storeMarkerFstatat         = unix.Fstatat
	storeMarkerClose           = unix.Close
	storeMarkerSyncFile        = syncStoreFile
	storeMarkerSyncDirectory   = storeSyncDirectory
	storeMarkerRenameNoReplace = storeRenameNoReplace
	storeMarkerOperationHook   func(string)
	// storeFilesystemPreflight defaults to the native predicate. Tests may
	// invoke that predicate and then force a failure to prove the unavailable
	// route before it can create an enrollment root. It cannot create a
	// capability or report a successful preflight.
	storeFilesystemPreflight = storeFilesystemSupported
)

func observeStoreMarkerOperation(stage string) {
	if storeMarkerOperationHook != nil {
		storeMarkerOperationHook(stage)
	}
}

func observeStoreRecoveryHook(stage string) {
	if storeRecoveryHook != nil {
		storeRecoveryHook(stage)
	}
}

type coldJournalIdentity struct {
	dev, ino uint64
	mode     uint32
	uid      uint32
	nlink    uint64
	size     int64
}

type coldJournalEvidence struct {
	identity                                        coldJournalIdentity
	firstByte                                       byte
	bytesRead                                       int64
	digest                                          string
	zero                                            bool
	atimeBefore, atimeAfterClassify, atimeAfterScan coldJournalAtime
}

type coldJournalAtime struct {
	sec, nsec int64
	valid     bool
}

// openColdJournal is deliberately recovery-only.  It duplicates no generic
// namespace policy: it preserves openLeaf's flags and predicates while making
// an already-attempted open fault observable by the cold helper tests.
func (r *rootLease) openColdJournal() (int, error) {
	if r == nil || !r.valid() {
		return -1, ErrProvenanceUnavailable
	}
	fd, err := storeRecoveryOpenat(r.fd, storeDBName+"-journal", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return -1, ErrProvenanceUnavailable
	}
	var st unix.Stat_t
	if storeRecoveryFstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != r.ownerUID() || st.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return -1, ErrProvenanceUnavailable
	}
	return fd, nil
}

// x/sys exposes Atim on Linux and Atimespec on Darwin. Reflection keeps this
// tagged Unix file portable while recording, never comparing or restoring,
// filesystem-owned atime values.
func coldJournalAtimeOf(st *unix.Stat_t) coldJournalAtime {
	v := reflect.ValueOf(st).Elem()
	field := v.FieldByName("Atim")
	if !field.IsValid() {
		field = v.FieldByName("Atimespec")
	}
	if !field.IsValid() {
		return coldJournalAtime{}
	}
	sec, nsec := field.FieldByName("Sec"), field.FieldByName("Nsec")
	if !sec.IsValid() || !nsec.IsValid() {
		return coldJournalAtime{}
	}
	return coldJournalAtime{sec: sec.Int(), nsec: nsec.Int(), valid: true}
}

func coldJournalStat(st *unix.Stat_t) coldJournalIdentity {
	return coldJournalIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino), mode: uint32(st.Mode), uid: st.Uid, nlink: uint64(st.Nlink), size: st.Size}
}

func (i coldJournalIdentity) equal(other coldJournalIdentity) bool {
	return i == other
}

func (r *rootLease) inspectColdJournal(keepFD bool) (coldJournalEvidence, int, error) {
	return r.inspectColdJournalChecked(context.Background(), nil, keepFD)
}

// inspectColdJournalChecked is the operation-owned inspection path.  The
// borrow checkpoint is deliberately made before every read (including an
// EINTR retry) so a cancellation or waiting Close cannot leave a large
// permitted cold scan running after the operation has ceased to be valid.
func (r *rootLease) inspectColdJournalChecked(ctx context.Context, borrow *storeRecoveryBorrow, keepFD bool) (coldJournalEvidence, int, error) {
	check := func() error {
		if borrow == nil {
			if ctx == nil || ctx.Err() != nil {
				return ErrProvenanceUnavailable
			}
			return nil
		}
		return borrow.check(ctx)
	}
	if r == nil || r.mode != storeRecover || !r.valid() {
		return coldJournalEvidence{}, -1, ErrProvenanceUnavailable
	}
	if err := check(); err != nil {
		return coldJournalEvidence{}, -1, err
	}
	for _, name := range []string{storeDBName + "-wal", storeDBName + "-shm"} {
		var st unix.Stat_t
		err := unix.Fstatat(r.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return coldJournalEvidence{}, -1, ErrPending
		}
		if err != unix.ENOENT {
			return coldJournalEvidence{}, -1, ErrProvenanceUnavailable
		}
	}
	fd, err := r.openColdJournal()
	if err != nil {
		if errors.Is(err, ErrProvenanceUnavailable) {
			var st unix.Stat_t
			if unix.Fstatat(r.fd, storeDBName+"-journal", &st, unix.AT_SYMLINK_NOFOLLOW) == unix.ENOENT {
				return coldJournalEvidence{}, -1, nil
			}
		}
		return coldJournalEvidence{}, -1, err
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()
	var before unix.Stat_t
	if err := storeRecoveryFstat(fd, &before); err != nil || before.Size < 0 {
		return coldJournalEvidence{}, -1, ErrProvenanceUnavailable
	}
	evidence := coldJournalEvidence{identity: coldJournalStat(&before), atimeBefore: coldJournalAtimeOf(&before)}
	if before.Size > 0 {
		var one [1]byte
		var n int
		var readErr error
		for {
			if err := check(); err != nil {
				return coldJournalEvidence{}, -1, err
			}
			n, readErr = storeRecoveryPread(fd, one[:], 0)
			if readErr != unix.EINTR {
				break
			}
		}
		if readErr != nil || n != 1 {
			return coldJournalEvidence{}, -1, ErrProvenanceUnavailable
		}
		evidence.firstByte = one[0]
		evidence.bytesRead = 1
	}
	var stable unix.Stat_t
	if err := storeRecoveryFstat(fd, &stable); err != nil || coldJournalStat(&stable) != evidence.identity {
		return coldJournalEvidence{}, -1, ErrProvenanceUnavailable
	}
	if before.Size > coldJournalInspectBudget && evidence.firstByte == 0 {
		evidence.zero = true
		evidence.atimeAfterClassify = coldJournalAtimeOf(&stable)
		return evidence, -1, ErrPending
	}
	if evidence.firstByte != 0 {
		evidence.atimeAfterClassify = coldJournalAtimeOf(&stable)
		return evidence, -1, nil
	}
	evidence.zero = true
	evidence.atimeAfterClassify = coldJournalAtimeOf(&stable)
	hash := sha256.New()
	const bufferSize = 64 << 10
	buffer := make([]byte, bufferSize)
	for offset := int64(0); offset < before.Size; {
		observeStoreRecoveryHook("cold-scan")
		if err := check(); err != nil {
			return coldJournalEvidence{}, -1, err
		}
		want := int64(len(buffer))
		if remain := before.Size - offset; remain < want {
			want = remain
		}
		n, readErr := storeRecoveryPread(fd, buffer[:want], offset)
		if readErr == unix.EINTR {
			continue
		}
		if readErr != nil || int64(n) != want {
			return coldJournalEvidence{}, -1, ErrProvenanceUnavailable
		}
		if _, err := hash.Write(buffer[:n]); err != nil {
			return coldJournalEvidence{}, -1, ErrProvenanceUnavailable
		}
		if offset == 0 && n > 0 && buffer[0] != evidence.firstByte {
			return coldJournalEvidence{}, -1, ErrProvenanceUnavailable
		}
		evidence.bytesRead += int64(n)
		offset += int64(n)
	}
	var after unix.Stat_t
	if err := storeRecoveryFstat(fd, &after); err != nil || coldJournalStat(&after) != evidence.identity {
		return coldJournalEvidence{}, -1, ErrProvenanceUnavailable
	}
	sum := hash.Sum(nil)
	evidence.digest = hex.EncodeToString(sum)
	evidence.atimeAfterScan = coldJournalAtimeOf(&after)
	if keepFD {
		closeFD = false
		return evidence, fd, nil
	}
	return evidence, -1, nil
}

// closeColdJournalFD consumes the numeric descriptor before calling close.
// A close error is ambiguous on Unix, so callers must never retry the number.
func closeColdJournalFD(fd *int) error {
	if fd == nil || *fd < 0 {
		return nil
	}
	owned := *fd
	*fd = -1
	return storeRecoveryClose(owned)
}

func (r *rootLease) retainRecoveryTerminal(borrow *storeRecoveryBorrow, binding *sqlBinding, journalFD *int, closeAttempted bool, closeErr error) {
	fd := -1
	if journalFD != nil {
		fd = *journalFD
	}
	owner, err := newStoreRecoveryTerminalOwner(binding, fd, closeAttempted, closeErr)
	if err != nil {
		borrow.abort()
		return
	}
	borrow.retainTerminal(owner, closeErr)
}

// runStoreRecoveryHealth opens one fixed-mode binding, executes the accepted
// schema-independent health tuple, and closes the binding before returning.
// A close failure transfers the real binding/VFS into the root terminal owner.
func (r *rootLease) runStoreRecoveryHealth(ctx context.Context, borrow *storeRecoveryBorrow, mode storeMode) (storeRecoveryState, error) {
	if err := borrow.check(ctx); err != nil {
		return storeRecoveryState{}, err
	}
	binding, err := openSQLBinding(ctx, r, mode)
	if err != nil {
		return storeRecoveryState{}, err
	}
	healthCtx := ctx
	if mode == storeRead {
		observeStoreRecoveryHook("fresh-read-binding")
		if storeRecoveryFreshHealthFault != nil {
			healthCtx = context.WithValue(ctx, storeRecoveryHealthFaultKey{}, storeRecoveryHealthFault{phase: "query:0", err: storeRecoveryFreshHealthFault})
		}
	}
	state, healthErr := readStoreRecoveryState(healthCtx, binding)
	closeErr := binding.Close()
	if closeErr != nil {
		r.retainRecoveryTerminal(borrow, binding, nil, false, closeErr)
		return storeRecoveryState{}, ErrProvenanceUnavailable
	}
	if healthErr != nil {
		return storeRecoveryState{}, healthErr
	}
	if err := borrow.check(ctx); err != nil {
		return storeRecoveryState{}, err
	}
	return state, nil
}

// recoverStoreColdJournal is the private, Unix-only maintenance operation.
// It owns all authorization itself: callers cannot provide SQL, callbacks, or
// an expected application tuple.  It is intentionally not a Store authority.
func recoverStoreColdJournal(ctx context.Context, lease *rootLease) error {
	if ctx == nil || lease == nil || lease.mode != storeRecover {
		return ErrProvenanceUnavailable
	}
	borrow, err := lease.beginStoreRecoveryBorrow(ctx)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			borrow.abort()
		}
	}()
	if err := borrow.check(ctx); err != nil {
		return err
	}

	// Keep a pre-inspection fd only long enough to observe its checked close.
	pre, preFD, err := lease.inspectColdJournalChecked(ctx, borrow, true)
	if err != nil {
		return err
	}
	if err := closeColdJournalFD(&preFD); err != nil {
		lease.retainRecoveryTerminal(borrow, nil, &preFD, true, err)
		finished = true
		return ErrProvenanceUnavailable
	}
	if err := borrow.check(ctx); err != nil {
		return err
	}

	recovered, err := lease.runStoreRecoveryHealth(ctx, borrow, storeRecover)
	if err != nil {
		return err
	}
	if err := borrow.check(ctx); err != nil {
		return err
	}
	observeStoreRecoveryHook("after-recovery")

	// No journal and normal nonzero journals stay SQLite-owned. A nonzero
	// journal is never promoted into cold cleanup after recovery.
	if pre.identity.size == 0 && pre.digest == "" && !pre.zero {
		return lease.finishStoreRecoveryRead(ctx, borrow, recovered, &finished)
	}
	if !pre.zero {
		present, presentErr := lease.hasLeaf(storeDBName + "-journal")
		if presentErr != nil {
			return presentErr
		}
		if present {
			return ErrPending
		}
		return lease.finishStoreRecoveryRead(ctx, borrow, recovered, &finished)
	}

	post, postFD, err := lease.inspectColdJournalChecked(ctx, borrow, true)
	if err != nil {
		return err
	}
	closePostFailure := func() error {
		if closeErr := closeColdJournalFD(&postFD); closeErr != nil {
			lease.retainRecoveryTerminal(borrow, nil, &postFD, true, closeErr)
			finished = true
		}
		return ErrProvenanceUnavailable
	}
	if !post.identity.equal(pre.identity) || post.firstByte != pre.firstByte || post.digest != pre.digest || post.bytesRead < pre.identity.size || borrow.check(ctx) != nil {
		return closePostFailure()
	}
	entryMatches := func() bool {
		var entry unix.Stat_t
		return storeRecoveryFstatat(lease.fd, storeDBName+"-journal", &entry, unix.AT_SYMLINK_NOFOLLOW) == nil && coldJournalStat(&entry) == post.identity
	}
	if !entryMatches() {
		return closePostFailure()
	}
	if err := borrow.authorizeUnlink(ctx); err != nil {
		return closePostFailure()
	}
	observeStoreRecoveryHook("before-unlink")
	// The hook is a deterministic test synchronization point. Revalidate the
	// nofollow directory entry after it, immediately before the final unlink
	// authorization, so it cannot widen the checked pathname window.
	if !entryMatches() {
		return closePostFailure()
	}
	if err := borrow.authorizeUnlink(ctx); err != nil {
		return closePostFailure()
	}
	if err := storeUnlinkat(lease.fd, storeDBName+"-journal", 0); err != nil {
		return closePostFailure()
	}

	// Mutation happened. Always observe sync, absence, and descriptor close even
	// when cancellation or Close was recorded after authorization.
	syncErr := storeSyncDirectory(lease.fd)
	var absent unix.Stat_t
	absenceErr := storeRecoveryFstatat(lease.fd, storeDBName+"-journal", &absent, unix.AT_SYMLINK_NOFOLLOW)
	closeErr := closeColdJournalFD(&postFD)
	observeStoreRecoveryHook("after-unlink")
	if syncErr != nil || absenceErr != unix.ENOENT || closeErr != nil || ctx.Err() != nil || borrow.check(ctx) != nil {
		if closeErr != nil {
			lease.retainRecoveryTerminal(borrow, nil, &postFD, true, closeErr)
			finished = true
		}
		return ErrProvenanceUnavailable
	}
	return lease.finishStoreRecoveryRead(ctx, borrow, recovered, &finished)
}

func (r *rootLease) finishStoreRecoveryRead(ctx context.Context, borrow *storeRecoveryBorrow, recovered storeRecoveryState, finished *bool) error {
	if err := borrow.check(ctx); err != nil {
		return err
	}
	readonly, err := r.runStoreRecoveryHealth(ctx, borrow, storeRead)
	if err != nil {
		return err
	}
	if !storeRecoveryStateEqual(recovered, readonly) {
		return ErrProvenanceUnavailable
	}
	if err := borrow.finish(ctx); err != nil {
		return err
	}
	*finished = true
	return nil
}

type rootLease struct {
	fd        int
	dev       uint64
	ino       uint64
	mode      storeMode
	path      string
	mu        sync.Mutex
	closed    bool
	closing   bool
	closeErr  error
	closeDone chan struct{}

	// Recovery maintenance keeps the original EX descriptor alive across the
	// otherwise handle-free gap between SQLite bindings.  These fields are
	// deliberately private: a borrow is an operation lifetime guard, not an
	// additional lease or an authority that can escape this package.
	recoveryUsed           bool
	recoveryStarting       bool
	recoveryActive         bool
	recoveryCloseRequested bool
	recoveryTerminal       bool
	recoveryDone           chan struct{}
	recoveryBorrow         *storeRecoveryBorrow
	recoveryTerminalOwner  *storeRecoveryTerminalOwner

	// A marker operation protects one descriptor-relative marker inspection,
	// write, or activation.  It is intentionally separate from recovery: both
	// own the same root descriptor and must never overlap.
	operationActive         bool
	operationCloseRequested bool
	operationDone           chan struct{}
	operation               *storeRootOperation
	lastMarkerSnapshot      markerSnapshot
	uidOverride             uint32
	observer                *storeProofObserver
}

// storeRecoveryBorrow is a bounded, single-owner guard for one explicit
// storeRecover maintenance operation.  It protects only transitions; callers
// must never hold rootLease.mu while doing SQLite, VFS, or syscall work.
type storeRecoveryBorrow struct {
	lease      *rootLease
	capability storeRecoveryCapability
}

// storeRootOperation is a private, non-authorizing lifetime guard for marker
// I/O. It captures the already-held root capability; it never duplicates an
// FD or returns it to a caller.
type storeRootOperation struct {
	lease      *rootLease
	capability storeRecoveryCapability
}

// storeRecoveryCapability is the exact pre-existing root descriptor capability
// captured by a recovery borrow.  It deliberately contains no duplicated file
// descriptor and no callback or authority supplied by a caller.
type storeRecoveryCapability struct {
	fd       int
	dev, ino uint64
}

// storeRecoveryTerminalOwner is transferred once into rootLease when native
// teardown is uncertain.  It keeps the actual binding/VFS reachable after the
// recovery stack unwinds, and records the journal descriptor disposition.  A
// journal fd is valid only while close has not been attempted; an ambiguous
// close must invalidate its number rather than risk descriptor reuse.
type storeRecoveryTerminalOwner struct {
	mu                    sync.Mutex
	transferred           bool
	binding               *sqlBinding
	journalFD             int
	journalCloseAttempted bool
	journalCloseErr       error
}

// storeRecoveryBorrowHook is a private test seam for the start-validation
// window.  It is inert in production and cannot supply a capability or alter a
// transition.
var storeRecoveryBorrowHook func(string)

func observeStoreRecoveryBorrowHook(stage string) {
	if storeRecoveryBorrowHook != nil {
		storeRecoveryBorrowHook(stage)
	}
}

func newStoreRecoveryTerminalOwner(binding *sqlBinding, journalFD int, journalCloseAttempted bool, journalCloseErr error) (*storeRecoveryTerminalOwner, error) {
	if journalFD < -1 || (journalFD >= 0 && journalCloseAttempted) || (binding == nil && journalFD < 0 && !journalCloseAttempted) {
		return nil, ErrProvenanceUnavailable
	}
	return &storeRecoveryTerminalOwner{
		binding:               binding,
		journalFD:             journalFD,
		journalCloseAttempted: journalCloseAttempted,
		journalCloseErr:       journalCloseErr,
	}, nil
}

// storeRootLeaseHook is a private deterministic cancellation seam used by
// lifecycle tests. It carries no authority and remains nil in production.
var storeRootLeaseHook func(string)

func observeRootLeaseHook(stage string) {
	if storeRootLeaseHook != nil {
		storeRootLeaseHook(stage)
	}
}

func openRootLease(ctx context.Context, path string, mode storeMode) (*rootLease, error) {
	if ctx == nil || ctx.Err() != nil || !absolutePath(path) || mode == 0 {
		return nil, ErrProvenanceUnavailable
	}
	if !storePlatformAvailable() {
		return nil, ErrProvenanceUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	observer := storeProofObserverFrom(ctx)
	if observer != nil {
		if err := observer.checkpoint("root-open", false); err != nil {
			return nil, err
		}
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrProvenanceUnavailable
	}
	if observer != nil {
		observer.rootFD(fd, true)
	}
	if observer != nil {
		if err := observer.checkpoint("root-open", true); err != nil {
			_ = unix.Close(fd)
			observer.rootFD(fd, false)
			return nil, err
		}
	}
	createdRoot := false
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			if observer != nil {
				observer.rootFD(fd, false)
			}
			return nil, ErrProvenanceUnavailable
		}
		phase := fmt.Sprintf("ancestor-open-%d", i)
		if observer != nil {
			if err := observer.checkpoint(phase, false); err != nil {
				_ = unix.Close(fd)
				observer.rootFD(fd, false)
				return nil, err
			}
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr == nil && i == len(parts)-1 && mode == storeEnroll {
			_ = unix.Close(next)
			if observer != nil {
				observer.rootFD(next, false)
			}
			_ = unix.Close(fd)
			if observer != nil {
				observer.rootFD(fd, false)
			}
			return nil, ErrAnchorMissing
		}
		if openErr != nil && i == len(parts)-1 && mode == storeEnroll && openErr == unix.ENOENT {
			if !storeFilesystemPreflight(fd) {
				_ = unix.Close(fd)
				if observer != nil {
					observer.rootFD(fd, false)
				}
				return nil, ErrProvenanceUnavailable
			}
			if unix.Mkdirat(fd, part, 0o700) == nil {
				createdRoot = true
				observeStoreEnrollmentPhase("mkdir")
				if storeSyncDirectory(fd) != nil {
					_ = unix.Close(fd)
					if observer != nil {
						observer.rootFD(fd, false)
					}
					return nil, ErrProvenanceUnavailable
				}
				observeStoreEnrollmentPhase("parent-sync")
				next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			}
		}
		if observer != nil && openErr == nil {
			observer.rootFD(next, true)
		}
		_ = unix.Close(fd)
		if observer != nil {
			observer.rootFD(fd, false)
		}
		if openErr != nil {
			return nil, ErrProvenanceUnavailable
		}
		fd = next
		if observer != nil {
			if err := observer.checkpoint(phase, true); err != nil {
				_ = unix.Close(fd)
				observer.rootFD(fd, false)
				return nil, err
			}
		}
	}
	if mode == storeEnroll && !createdRoot {
		_ = unix.Close(fd)
		if observer != nil {
			observer.rootFD(fd, false)
		}
		return nil, ErrAnchorMissing
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(unix.Geteuid()) || st.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		if observer != nil {
			observer.rootFD(fd, false)
		}
		return nil, ErrProvenanceUnavailable
	}
	if !storeFilesystemPreflight(fd) {
		_ = unix.Close(fd)
		if observer != nil {
			observer.rootFD(fd, false)
		}
		return nil, ErrProvenanceUnavailable
	}
	observeRootLeaseHook("post-open-pre-lock")
	if err := ctx.Err(); err != nil {
		_ = unix.Close(fd)
		if observer != nil {
			observer.rootFD(fd, false)
		}
		return nil, ErrProvenanceUnavailable
	}
	lock := unix.LOCK_SH | unix.LOCK_NB
	if mode.writable() {
		lock = unix.LOCK_EX | unix.LOCK_NB
	}
	if unix.Flock(fd, lock) != nil {
		_ = unix.Close(fd)
		if observer != nil {
			observer.rootFD(fd, false)
		}
		if mode.writable() {
			return nil, ErrRefreshConflict
		}
		return nil, ErrPending
	}
	observeRootLeaseHook("post-lock-pre-return")
	if err := ctx.Err(); err != nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
		if observer != nil {
			observer.rootFD(fd, false)
		}
		return nil, ErrProvenanceUnavailable
	}
	return &rootLease{
		fd:        fd,
		dev:       uint64(st.Dev),
		ino:       uint64(st.Ino),
		mode:      mode,
		path:      path,
		closeDone: make(chan struct{}),
		observer:  observer,
	}, nil
}

// beginStoreRecoveryBorrow linearizes the start of the one private recovery
// operation permitted on a storeRecover lease.  The EX lock and descriptor are
// captured by ownership rather than duplicated or reacquired.
func (r *rootLease) beginStoreRecoveryBorrow(ctx context.Context) (*storeRecoveryBorrow, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.mode != storeRecover {
		return nil, ErrProvenanceUnavailable
	}
	r.mu.Lock()
	if r.closed || r.closing || r.recoveryTerminal || r.recoveryStarting || r.recoveryActive || r.recoveryUsed || r.operationActive {
		r.mu.Unlock()
		return nil, ErrProvenanceUnavailable
	}
	// Starting is visible to Close before validation begins.  This keeps the
	// original descriptor alive without holding rootLease.mu over Fstat or the
	// path walk below.
	r.recoveryStarting = true
	r.recoveryDone = make(chan struct{})
	r.mu.Unlock()
	observeStoreRecoveryBorrowHook("started-before-capability")

	capability, err := r.captureStoreRecoveryCapability()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || ctx.Err() != nil || !r.recoveryStarting || r.recoveryCloseRequested || r.closed || r.closing || r.recoveryTerminal {
		r.finishRecoveryStartLocked()
		return nil, ErrProvenanceUnavailable
	}
	b := &storeRecoveryBorrow{lease: r, capability: capability}
	r.recoveryStarting = false
	r.recoveryUsed = true
	r.recoveryActive = true
	r.recoveryBorrow = b
	return b, nil
}

// beginStoreRootOperation publishes ownership before checking the descriptor,
// so Close cannot release or reuse it between the caller's decision and the
// first marker syscall.  It is a lifecycle guard only, never authority.
func (r *rootLease) beginStoreRootOperation(ctx context.Context, mode storeMode) (*storeRootOperation, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || r.mode != mode {
		return nil, ErrProvenanceUnavailable
	}
	r.mu.Lock()
	if r.closed || r.closing || r.recoveryTerminal || r.recoveryStarting || r.recoveryActive || r.operationActive {
		r.mu.Unlock()
		return nil, ErrProvenanceUnavailable
	}
	r.operationActive = true
	r.operationDone = make(chan struct{})
	op := &storeRootOperation{lease: r}
	r.operation = op
	r.mu.Unlock()
	observeStoreMarkerOperation("started-before-capability")

	capability, err := r.captureStoreRootOperationCapability(op)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || ctx.Err() != nil || !r.operationActive || r.operation != op || r.operationCloseRequested || r.closed || r.closing || r.recoveryTerminal {
		r.finishStoreRootOperationLocked(op)
		return nil, ErrProvenanceUnavailable
	}
	op.capability = capability
	return op, nil
}

func (r *rootLease) captureStoreRootOperationCapability(op *storeRootOperation) (storeRecoveryCapability, error) {
	r.mu.Lock()
	if r.closed || r.closing || !r.operationActive || r.operation != op || r.operationCloseRequested {
		r.mu.Unlock()
		return storeRecoveryCapability{}, ErrProvenanceUnavailable
	}
	capability := storeRecoveryCapability{fd: r.fd, dev: r.dev, ino: r.ino}
	path, uid := r.path, r.ownerUID()
	r.mu.Unlock()
	var st unix.Stat_t
	if unix.Fstat(capability.fd, &st) != nil || uint64(st.Dev) != capability.dev || uint64(st.Ino) != capability.ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Mode&0o077 != 0 || !rootPathMatches(path, capability.dev, capability.ino) {
		return storeRecoveryCapability{}, ErrProvenanceUnavailable
	}
	return capability, nil
}

func (o *storeRootOperation) check(ctx context.Context) error {
	if o == nil || o.lease == nil || ctx == nil || ctx.Err() != nil {
		return ErrProvenanceUnavailable
	}
	r := o.lease
	r.mu.Lock()
	if r.closed || r.closing || r.operation != o || !r.operationActive || r.operationCloseRequested || r.fd != o.capability.fd || r.dev != o.capability.dev || r.ino != o.capability.ino {
		r.mu.Unlock()
		return ErrProvenanceUnavailable
	}
	path, uid := r.path, r.ownerUID()
	r.mu.Unlock()
	var st unix.Stat_t
	if unix.Fstat(o.capability.fd, &st) != nil || uint64(st.Dev) != o.capability.dev || uint64(st.Ino) != o.capability.ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Mode&0o077 != 0 || !rootPathMatches(path, o.capability.dev, o.capability.ino) {
		return ErrProvenanceUnavailable
	}
	return nil
}

func (o *storeRootOperation) finish(ctx context.Context) error {
	if o == nil || o.lease == nil {
		return ErrProvenanceUnavailable
	}
	err := o.check(ctx)
	r := o.lease
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.operation != o || !r.operationActive {
		return ErrProvenanceUnavailable
	}
	r.finishStoreRootOperationLocked(o)
	return err
}

func (o *storeRootOperation) abort() {
	if o == nil || o.lease == nil {
		return
	}
	r := o.lease
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.operation == o && r.operationActive {
		r.finishStoreRootOperationLocked(o)
	}
}

// retainMarkerTerminal records an ambiguous marker-FD close after its numeric
// descriptor has been consumed. The root lease/lock remains held; Close must
// report the typed failure rather than unlock a possibly reused capability.
func (r *rootLease) retainMarkerTerminal(op *storeRootOperation, err error) {
	owner, ownerErr := newStoreRecoveryTerminalOwner(nil, -1, true, err)
	if r == nil || ownerErr != nil || op == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.operation != op || !r.operationActive || r.recoveryTerminal {
		return
	}
	owner.transferred = true
	r.closeErr = ErrProvenanceUnavailable
	r.recoveryTerminal = true
	r.recoveryTerminalOwner = owner
	r.finishStoreRootOperationLocked(op)
}

func (r *rootLease) finishStoreRootOperationLocked(op *storeRootOperation) {
	if r.operation != op {
		return
	}
	done := r.operationDone
	r.operationActive = false
	r.operation = nil
	r.operationDone = nil
	if done != nil {
		close(done)
	}
}

// captureStoreRecoveryCapability validates the already-held descriptor and
// locator without taking rootLease.mu.  beginStoreRecoveryBorrow has published
// recoveryStarting first, so Close cannot release the descriptor while this
// validation and capture are in progress.
func (r *rootLease) captureStoreRecoveryCapability() (storeRecoveryCapability, error) {
	if r == nil {
		return storeRecoveryCapability{}, ErrProvenanceUnavailable
	}
	r.mu.Lock()
	if r.closed || r.closing || r.recoveryTerminal || !r.recoveryStarting || r.mode != storeRecover {
		r.mu.Unlock()
		return storeRecoveryCapability{}, ErrProvenanceUnavailable
	}
	capability := storeRecoveryCapability{fd: r.fd, dev: r.dev, ino: r.ino}
	path := r.path
	uid := r.ownerUID()
	r.mu.Unlock()
	var st unix.Stat_t
	if unix.Fstat(capability.fd, &st) != nil || uint64(st.Dev) != capability.dev || uint64(st.Ino) != capability.ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Mode&0o077 != 0 || !rootPathMatches(path, capability.dev, capability.ino) {
		return storeRecoveryCapability{}, ErrProvenanceUnavailable
	}
	return capability, nil
}

func (r *rootLease) recoveryCapabilityCurrent(capability storeRecoveryCapability, requireActive bool, borrow *storeRecoveryBorrow) error {
	if r == nil {
		return ErrProvenanceUnavailable
	}
	r.mu.Lock()
	if r.closed || r.closing || r.recoveryTerminal || r.recoveryCloseRequested || (requireActive && (!r.recoveryActive || r.recoveryBorrow != borrow)) || r.fd != capability.fd || r.dev != capability.dev || r.ino != capability.ino {
		r.mu.Unlock()
		return ErrProvenanceUnavailable
	}
	path := r.path
	uid := r.ownerUID()
	r.mu.Unlock()
	var st unix.Stat_t
	if unix.Fstat(capability.fd, &st) != nil || uint64(st.Dev) != capability.dev || uint64(st.Ino) != capability.ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Mode&0o077 != 0 || !rootPathMatches(path, capability.dev, capability.ino) {
		return ErrProvenanceUnavailable
	}
	return nil
}

func (r *rootLease) finishRecoveryStartLocked() {
	if !r.recoveryStarting {
		return
	}
	done := r.recoveryDone
	r.recoveryStarting = false
	r.recoveryDone = nil
	if done != nil {
		close(done)
	}
}

// check is the inexpensive cancellation/Close-request checkpoint used around
// operations performed by the maintenance owner.  It intentionally does no
// descriptor work while holding the transition lock.
func (b *storeRecoveryBorrow) check(ctx context.Context) error {
	if b == nil || b.lease == nil || ctx == nil || ctx.Err() != nil {
		return ErrProvenanceUnavailable
	}
	return b.lease.recoveryCapabilityCurrent(b.capability, true, b)
}

// authorizeUnlink is the final pre-unlink gate.  It is deliberately separate
// from check so the decision is linearized under rootLease.mu immediately
// before the caller invokes unlinkat.  A later Close is recorded and waits for
// the operation; it cannot release or reuse this descriptor in the gap.
func (b *storeRecoveryBorrow) authorizeUnlink(ctx context.Context) error {
	return b.check(ctx)
}

// finish publishes a successful maintenance operation only if neither
// cancellation nor Close was observed at the final transition.  It releases
// the borrow and wakes a waiting Close after the caller has quiesced every
// resource capable of using the root descriptor.
func (b *storeRecoveryBorrow) finish(ctx context.Context) error {
	if b == nil || b.lease == nil || ctx == nil {
		return ErrProvenanceUnavailable
	}
	capabilityErr := b.check(ctx)
	r := b.lease
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.recoveryActive || r.recoveryBorrow != b {
		return ErrProvenanceUnavailable
	}
	err := capabilityErr
	if err == nil && (ctx.Err() != nil || r.recoveryCloseRequested) {
		err = ErrProvenanceUnavailable
	}
	r.finishRecoveryBorrowLocked(b)
	return err
}

// abort ends a non-terminal failed operation.  It is safe to call after any
// earlier checkpoint failure and intentionally does not interpret cancellation
// as permission to omit caller-owned post-mutation observation.
func (b *storeRecoveryBorrow) abort() {
	if b == nil || b.lease == nil {
		return
	}
	r := b.lease
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.recoveryActive && r.recoveryBorrow == b {
		r.finishRecoveryBorrowLocked(b)
	}
}

// retainTerminal records that a binding/VFS teardown was uncertain and keeps
// the original root descriptor and EX lock owned by this lease.  A waiter is
// woken so Close returns the typed failure instead of deadlocking; it must not
// unlock, close, free callbacks, or retry an ambiguous native close.
func (b *storeRecoveryBorrow) retainTerminal(owner *storeRecoveryTerminalOwner, err error) {
	if b == nil || b.lease == nil || owner == nil {
		return
	}
	r := b.lease
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.recoveryActive || r.recoveryBorrow != b {
		return
	}
	owner.mu.Lock()
	if owner.transferred {
		owner.mu.Unlock()
		return
	}
	owner.transferred = true
	owner.mu.Unlock()
	if err == nil {
		err = ErrProvenanceUnavailable
	}
	r.closeErr = err
	r.recoveryTerminal = true
	r.recoveryTerminalOwner = owner
	r.finishRecoveryBorrowLocked(b)
}

func (r *rootLease) finishRecoveryBorrowLocked(b *storeRecoveryBorrow) {
	if r.recoveryBorrow != b {
		return
	}
	done := r.recoveryDone
	r.recoveryActive = false
	r.recoveryBorrow = nil
	r.recoveryDone = nil
	if done != nil {
		close(done)
	}
}

func (r *rootLease) closedState() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *rootLease) valid() bool {
	if r == nil || r.closedState() {
		return false
	}
	var st unix.Stat_t
	if unix.Fstat(r.fd, &st) != nil || uint64(st.Dev) != r.dev || uint64(st.Ino) != r.ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(unix.Geteuid()) || st.Mode&0o077 != 0 {
		return false
	}
	// A held directory fd cannot be redirected, but an installation locator
	// replaced after lease acquisition must not be reported as the same store.
	return rootPathMatches(r.path, r.dev, r.ino)
}

func rootPathMatches(path string, dev, ino uint64) bool {
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false
		}
		_ = unix.Close(fd)
		fd = next
	}
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && uint64(st.Dev) == dev && uint64(st.Ino) == ino
}

func (r *rootLease) ownerUID() uint32 {
	if r != nil && r.uidOverride != 0 {
		return r.uidOverride
	}
	return uint32(unix.Geteuid())
}

func (r *rootLease) openLeaf(name string, flags int, perm uint32) (int, error) {
	if !r.valid() || (name != storeDBName && name != storeDBName+"-journal") {
		return -1, ErrProvenanceUnavailable
	}
	fd, err := unix.Openat(r.fd, name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, perm)
	if err != nil {
		return -1, ErrProvenanceUnavailable
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != r.ownerUID() || st.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return -1, ErrProvenanceUnavailable
	}
	return fd, nil
}

func (r *rootLease) hasLeaf(name string) (bool, error) {
	if !r.valid() || (name != storeDBName && name != storeDBName+"-journal") {
		return false, ErrProvenanceUnavailable
	}
	var st unix.Stat_t
	if err := unix.Fstatat(r.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return false, nil
		}
		return false, ErrProvenanceUnavailable
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != r.ownerUID() || st.Mode&0o077 != 0 {
		return false, ErrProvenanceUnavailable
	}
	return true, nil
}

func (r *rootLease) pendingSidecar() error {
	if !r.valid() {
		return ErrProvenanceUnavailable
	}
	for _, name := range []string{storeDBName + "-journal", storeDBName + "-wal", storeDBName + "-shm"} {
		var st unix.Stat_t
		err := unix.Fstatat(r.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == unix.ENOENT {
			continue
		}
		// A reader never decides whether an observed sidecar is recoverable.
		// Non-regular and symlink entries are also pending rather than absent.
		return ErrPending
	}
	return nil
}

func (r *rootLease) markerExists(name string) (bool, error) {
	if !r.valid() || (name != activeMarkerName && name != pendingMarkerName) {
		return false, ErrProvenanceUnavailable
	}
	var st unix.Stat_t
	err := unix.Fstatat(r.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return false, nil
	}
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != r.ownerUID() || st.Mode&0o077 != 0 {
		return false, ErrProvenanceUnavailable
	}
	return true, nil
}

func markerIdentity(st *unix.Stat_t) markerSnapshot {
	return markerSnapshot{dev: uint64(st.Dev), ino: uint64(st.Ino), mode: uint32(st.Mode), uid: st.Uid, nlink: uint64(st.Nlink), size: st.Size}
}

func (r *rootLease) validMarkerStat(st *unix.Stat_t, max int) bool {
	return st != nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && st.Uid == r.ownerUID() && st.Mode&0o077 == 0 && st.Size >= 0 && st.Size <= int64(max)
}

func validMarkerName(name string) bool { return name == activeMarkerName || name == pendingMarkerName }

// readMarker reads one fixed marker through the held root descriptor. It
// records no authority; callers still decode and compare the returned bytes.
func (r *rootLease) readMarker(ctx context.Context, name string, max int) ([]byte, error) {
	raw, _, err := r.readMarkerSnapshot(ctx, name, max)
	return raw, err
}

func (r *rootLease) readMarkerSnapshot(ctx context.Context, name string, max int) ([]byte, markerSnapshot, error) {
	if r == nil || (r.mode != storeRead && r.mode != storeEnroll && r.mode != storeRefresh && r.mode != storeRecover) {
		return nil, markerSnapshot{}, ErrProvenanceUnavailable
	}
	op, err := r.beginStoreRootOperation(ctx, r.mode)
	if err != nil {
		return nil, markerSnapshot{}, err
	}
	finished := false
	defer func() {
		if !finished {
			op.abort()
		}
	}()
	raw, err := r.readMarkerOperation(ctx, op, name, max)
	if err != nil {
		return nil, markerSnapshot{}, err
	}
	snapshot := r.lastMarkerSnapshot
	if err := op.finish(ctx); err != nil {
		return nil, markerSnapshot{}, err
	}
	finished = true
	return raw, snapshot, nil
}

func (r *rootLease) readMarkerOperation(ctx context.Context, op *storeRootOperation, name string, max int) ([]byte, error) {
	if !validMarkerName(name) || max <= 0 || op.check(ctx) != nil {
		return nil, ErrProvenanceUnavailable
	}
	fd, err := storeMarkerOpenat(r.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrProvenanceUnavailable
	}
	closed := false
	defer func() {
		if !closed {
			_ = storeMarkerClose(fd)
		}
	}()
	var before unix.Stat_t
	if storeMarkerFstat(fd, &before) != nil || !r.validMarkerStat(&before, max) || op.check(ctx) != nil {
		return nil, ErrProvenanceUnavailable
	}
	identity := markerIdentity(&before)
	var entry unix.Stat_t
	observeStoreMarkerOperation("read-before-entry-check")
	if storeMarkerFstatat(r.fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || markerIdentity(&entry) != identity {
		return nil, ErrProvenanceUnavailable
	}
	raw := make([]byte, int(before.Size))
	for offset := 0; offset < len(raw); {
		if op.check(ctx) != nil {
			return nil, ErrProvenanceUnavailable
		}
		n, readErr := storeMarkerPread(fd, raw[offset:], int64(offset))
		if readErr == unix.EINTR {
			continue
		}
		if readErr != nil || n <= 0 || n > len(raw)-offset {
			return nil, ErrProvenanceUnavailable
		}
		offset += n
	}
	observeStoreMarkerOperation("read-after-payload-before-final-identity")
	var after unix.Stat_t
	if storeMarkerFstat(fd, &after) != nil || markerIdentity(&after) != identity || op.check(ctx) != nil || storeMarkerFstatat(r.fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || markerIdentity(&entry) != identity {
		return nil, ErrProvenanceUnavailable
	}
	closeErr := storeMarkerClose(fd)
	closed = true
	if closeErr != nil {
		r.retainMarkerTerminal(op, closeErr)
		return nil, ErrProvenanceUnavailable
	}
	if op.check(ctx) != nil {
		return nil, ErrProvenanceUnavailable
	}
	r.lastMarkerSnapshot = identity
	return raw, nil
}

// writePendingMarker is enrollment-only. A fault deliberately leaves an
// exclusive pending artifact for explicit recovery; it never cleans it up.
func (r *rootLease) writePendingMarker(ctx context.Context, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxDocument {
		return ErrConfigInvalid
	}
	op, err := r.beginStoreRootOperation(ctx, storeEnroll)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			op.abort()
		}
	}()
	if op.check(ctx) != nil {
		return ErrProvenanceUnavailable
	}
	fd, err := storeMarkerOpenat(r.fd, pendingMarkerName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return ErrProvenanceUnavailable
	}
	observeStoreEnrollmentPhase("pending-write-before")
	closed := false
	defer func() {
		if !closed {
			_ = storeMarkerClose(fd)
		}
	}()
	for offset := 0; offset < len(raw); {
		if op.check(ctx) != nil {
			return ErrProvenanceUnavailable
		}
		n, writeErr := storeMarkerWrite(fd, raw[offset:])
		if writeErr == unix.EINTR {
			continue
		}
		if writeErr != nil || n <= 0 || n > len(raw)-offset {
			return ErrProvenanceUnavailable
		}
		offset += n
	}
	observeStoreEnrollmentPhase("pending-write")
	var st unix.Stat_t
	if storeMarkerFstat(fd, &st) != nil || !r.validMarkerStat(&st, maxDocument) || st.Size != int64(len(raw)) || op.check(ctx) != nil || storeMarkerSyncFile(fd) != nil {
		return ErrProvenanceUnavailable
	}
	observeStoreEnrollmentPhase("pending-filesync")
	closeErr := storeMarkerClose(fd)
	closed = true
	var entry unix.Stat_t
	if closeErr != nil {
		r.retainMarkerTerminal(op, closeErr)
		finished = true
		return ErrProvenanceUnavailable
	}
	if op.check(ctx) != nil || storeMarkerFstatat(r.fd, pendingMarkerName, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || markerIdentity(&entry) != markerIdentity(&st) || storeMarkerSyncDirectory(r.fd) != nil || op.check(ctx) != nil {
		return ErrProvenanceUnavailable
	}
	observeStoreEnrollmentPhase("pending-dirsync")
	if err := op.finish(ctx); err != nil {
		return err
	}
	finished = true
	return nil
}

func (r *rootLease) activatePendingMarker(ctx context.Context, expected []byte) error {
	if len(expected) == 0 || len(expected) > maxDocument || (r.mode != storeEnroll && r.mode != storeRecover) {
		return ErrProvenanceUnavailable
	}
	op, err := r.beginStoreRootOperation(ctx, r.mode)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			op.abort()
		}
	}()
	raw, err := r.readMarkerOperation(ctx, op, pendingMarkerName, maxDocument)
	if err != nil || !bytes.Equal(raw, expected) || op.check(ctx) != nil {
		return ErrProvenanceUnavailable
	}
	var pending unix.Stat_t
	if storeMarkerFstatat(r.fd, pendingMarkerName, &pending, unix.AT_SYMLINK_NOFOLLOW) != nil || !r.validMarkerStat(&pending, maxDocument) {
		return ErrProvenanceUnavailable
	}
	var active unix.Stat_t
	if err := storeMarkerFstatat(r.fd, activeMarkerName, &active, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return ErrProvenanceUnavailable
	}
	if op.check(ctx) != nil {
		return ErrProvenanceUnavailable
	}
	renameErr := storeMarkerRenameNoReplace(r.fd, pendingMarkerName, activeMarkerName)
	// An injected or kernel-reported rename error can still have mutated the
	// namespace. Always sync and inspect before returning that uncertainty.
	if renameErr != nil {
		_ = storeMarkerSyncDirectory(r.fd)
		var observed, absent unix.Stat_t
		_ = storeMarkerFstatat(r.fd, activeMarkerName, &observed, unix.AT_SYMLINK_NOFOLLOW)
		_ = storeMarkerFstatat(r.fd, pendingMarkerName, &absent, unix.AT_SYMLINK_NOFOLLOW)
		return ErrProvenanceUnavailable
	}
	observeStoreEnrollmentPhase("rename")
	// Publication has mutated the namespace. Always attempt both durable sync
	// and the final descriptor-relative observation before reporting failure.
	observeStoreMarkerOperation("activation-post-rename-pre-sync")
	syncErr := storeMarkerSyncDirectory(r.fd)
	var observed unix.Stat_t
	activeErr := storeMarkerFstatat(r.fd, activeMarkerName, &observed, unix.AT_SYMLINK_NOFOLLOW)
	var absent unix.Stat_t
	pendingErr := storeMarkerFstatat(r.fd, pendingMarkerName, &absent, unix.AT_SYMLINK_NOFOLLOW)
	if syncErr != nil || activeErr != nil || markerIdentity(&observed) != markerIdentity(&pending) || pendingErr != unix.ENOENT || op.check(ctx) != nil {
		return ErrProvenanceUnavailable
	}
	observeStoreEnrollmentPhase("final-dirsync")
	if err := op.finish(ctx); err != nil {
		return err
	}
	finished = true
	return nil
}

func (r *rootLease) deleteJournal() error {
	if r == nil || !r.mode.writable() || !r.valid() {
		return ErrProvenanceUnavailable
	}
	if err := validatePrivateJournalAt(r.fd, r.ownerUID()); err != nil && err != unix.ENOENT {
		return ErrProvenanceUnavailable
	}
	if err := storeUnlinkat(r.fd, storeDBName+"-journal", 0); err != nil && err != unix.ENOENT {
		return ErrProvenanceUnavailable
	}
	if err := storeSyncDirectory(r.fd); err != nil {
		return ErrProvenanceUnavailable
	}
	return nil
}

func (r *rootLease) Close() error {
	if r == nil {
		return nil
	}
	for {
		r.mu.Lock()
		if r.recoveryTerminal {
			err := r.closeErr
			if err == nil {
				err = ErrProvenanceUnavailable
			}
			r.mu.Unlock()
			return err
		}
		if r.recoveryStarting || r.recoveryActive {
			// Close is ordered as a request while recovery owns the descriptor.
			// Waiting occurs without the transition lock, so callbacks and SQL
			// teardown can make progress.
			r.recoveryCloseRequested = true
			done := r.recoveryDone
			r.mu.Unlock()
			if done != nil {
				<-done
			}
			continue
		}
		if r.operationActive {
			r.operationCloseRequested = true
			done := r.operationDone
			r.mu.Unlock()
			if done != nil {
				<-done
			}
			continue
		}
		if r.closed || r.closing {
			done := r.closeDone
			r.mu.Unlock()
			if done != nil {
				<-done
			}
			r.mu.Lock()
			err := r.closeErr
			r.mu.Unlock()
			return err
		}
		r.closed = true
		r.closing = true
		fd := r.fd
		done := r.closeDone
		r.mu.Unlock()

		unlockErr := unix.Flock(fd, unix.LOCK_UN)
		closeErr := unix.Close(fd)
		if r.observer != nil {
			r.observer.rootFD(fd, false)
		}
		r.mu.Lock()
		if unlockErr != nil || closeErr != nil {
			r.closeErr = ErrProvenanceUnavailable
		}
		err := r.closeErr
		r.closing = false
		r.mu.Unlock()
		if done != nil {
			close(done)
		}
		return err
	}
}
