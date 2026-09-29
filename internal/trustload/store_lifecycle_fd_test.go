//go:build darwin || linux

package trustload

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

// LIFE05 runs its resource ledger in a separate test process. The report pipe
// is inherited by the child and is included in the baseline, so the scan does
// not mistake the harness transport for an adapter-owned descriptor.
func TestStoreLifecycleLIFE05IsolatedChildResourceLedger(t *testing.T) {
	if os.Getenv("TPLAITER_LIFE05_CHILD") == "1" {
		t.Helper()
		life05Child(t, os.Getenv("TPLAITER_LIFE05_PHASE"))
		return
	}
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	phases := append([]string{""}, life05FailurePhases()...)
	phases = append(phases, "terminal-live-file", "terminal-post-native-close", "terminal-physical-close", "terminal-vfs-unregister")
	for _, phase := range phases {
		name := "normal-construction-work-close"
		if phase != "" {
			name = "failure-" + phase
		}
		t.Run(name, func(t *testing.T) { runLIFE05Child(t, phase) })
	}
}

type life05Report struct {
	Phase        string `json:"phase"`
	Baseline     []int  `json:"baseline"`
	Constructed  []int  `json:"constructed"`
	Worked       []int  `json:"worked"`
	Final        []int  `json:"final"`
	Owned        []int  `json:"owned"`
	RootFD       int    `json:"rootFD"`
	VFSBefore    bool   `json:"vfsBefore"`
	VFSLive      bool   `json:"vfsLive"`
	VFSAfter     bool   `json:"vfsAfter"`
	AllBalanced  bool   `json:"allBalanced"`
	Retained     bool   `json:"retained"`
	Cleaned      bool   `json:"cleaned"`
	BeforeHits   int    `json:"beforeHits,omitempty"`
	AfterHits    int    `json:"afterHits,omitempty"`
	RootFDOpened []int  `json:"rootFDOpened,omitempty"`
	RootFDClosed []int  `json:"rootFDClosed,omitempty"`
	EBADFOwned   bool   `json:"ebadfOwned,omitempty"`
	ErrText      string `json:"err,omitempty"`
}

func life05FailurePhases() []string {
	return []string{
		"root-open", "ancestor-open-0", "ancestor-open-1", "main-open", "journal-open",
		"vfs.tls", "vfs.ctx", "vfs.methods", "vfs.vfs", "vfs.name", "vfs.register",
		"driver.open", "db.Conn", "conn.ATTACHED",
		"exec:PRAGMA temp_store=MEMORY", "exec:PRAGMA mmap_size=0", "exec:PRAGMA trusted_schema=OFF",
		"exec:PRAGMA query_only=ON", "exec:PRAGMA journal_mode=DELETE", "exec:PRAGMA synchronous=FULL",
		"query:PRAGMA temp_store", "query:PRAGMA mmap_size", "query:PRAGMA trusted_schema",
		"query:PRAGMA query_only", "query:PRAGMA journal_mode", "query:PRAGMA synchronous",
	}
}

func runLIFE05Child(t *testing.T, phase string) {
	t.Helper()
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreLifecycleLIFE05IsolatedChildResourceLedger$")
	cmd.Env = append(os.Environ(), "TPLAITER_LIFE05_CHILD=1", "TPLAITER_LIFE05_PHASE="+phase)
	cmd.ExtraFiles = []*os.File{writePipe}
	if err := cmd.Start(); err != nil {
		_ = readPipe.Close()
		_ = writePipe.Close()
		t.Fatal(err)
	}
	_ = writePipe.Close()
	reportBytes, readErr := io.ReadAll(readPipe)
	_ = readPipe.Close()
	waitErr := cmd.Wait()
	if readErr != nil {
		t.Fatalf("child report read: %v", readErr)
	}
	if waitErr != nil {
		t.Fatalf("child lifecycle phase %q: %v report=%s", phase, waitErr, reportBytes)
	}
	var report life05Report
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		t.Fatalf("child report phase %q: %v (%s)", phase, err, reportBytes)
	}
	if report.ErrText != "" {
		t.Fatalf("child phase %q reported failure: %s", phase, report.ErrText)
	}
	if !sameFDSet(report.Baseline, report.Final) {
		t.Fatalf("phase %q changed exact child FD set: baseline=%v final=%v", phase, report.Baseline, report.Final)
	}
	if !containsFDSet(report.Constructed, report.Baseline) || !containsFDSet(report.Worked, report.Baseline) {
		t.Fatalf("phase %q lost a baseline descriptor in intermediate set: baseline=%v constructed=%v worked=%v", phase, report.Baseline, report.Constructed, report.Worked)
	}
	if !report.AllBalanced {
		t.Fatalf("phase %q did not balance observer resources", phase)
	}
	if phase != "" && !strings.HasPrefix(phase, "terminal-") && !report.EBADFOwned {
		t.Fatalf("phase %q did not prove EBADF for every owned descriptor: owned=%v", phase, report.Owned)
	}
	if strings.HasPrefix(phase, "root-open") || strings.HasPrefix(phase, "ancestor-open") {
		if report.BeforeHits != 1 || report.AfterHits != 0 {
			t.Fatalf("phase %q checkpoint hits before=%d after=%d", phase, report.BeforeHits, report.AfterHits)
		}
		if !report.EBADFOwned || len(report.RootFDOpened) != len(report.RootFDClosed) {
			t.Fatalf("phase %q root descriptor ledger opened=%v closed=%v ebadf=%v", phase, report.RootFDOpened, report.RootFDClosed, report.EBADFOwned)
		}
		if strings.HasPrefix(phase, "ancestor-open") && len(report.RootFDClosed) == 0 {
			t.Fatalf("phase %q acquired no prior root descriptor", phase)
		}
		if report.VFSBefore || report.VFSLive || report.VFSAfter {
			t.Fatalf("phase %q unexpectedly changed VFS before=%v live=%v after=%v", phase, report.VFSBefore, report.VFSLive, report.VFSAfter)
		}
	}
	if phase == "" {
		if report.VFSBefore || !report.VFSLive || report.VFSAfter {
			t.Fatalf("normal VFS lifecycle before=%v live=%v after=%v", report.VFSBefore, report.VFSLive, report.VFSAfter)
		}
		if len(report.Owned) == 0 || report.RootFD < 0 {
			t.Fatalf("normal child recorded no owned descriptors: %+v", report)
		}
	}
	if strings.HasPrefix(phase, "terminal-") && (!report.Retained || !report.Cleaned) {
		t.Fatalf("terminal phase %q retained=%v cleaned=%v", phase, report.Retained, report.Cleaned)
	}
}

func life05Child(t *testing.T, phase string) {
	t.Helper()
	reportFile := os.NewFile(uintptr(3), "life05-report")
	if reportFile == nil {
		t.Fatal("missing report pipe")
	}
	defer reportFile.Close()
	report := life05Report{Phase: phase}
	writeReport := func() {
		if err := json.NewEncoder(reportFile).Encode(report); err != nil {
			t.Fatal(err)
		}
	}
	report.Baseline = life05ScanFDs(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		report.ErrText = err.Error()
		writeReport()
		return
	}
	root := filepath.Join(base, "store")
	observer := &storeProofObserver{}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
	if strings.HasPrefix(phase, "root-open") || strings.HasPrefix(phase, "ancestor-open") {
		report.Constructed = append([]int(nil), report.Baseline...)
		life05ChildFailure(t, &report, phase, observer)
		writeReport()
		return
	}
	lease, err := openRootLease(ctx, root, storeEnroll)
	if err != nil {
		report.ErrText = fmt.Sprintf("root lease: %v", err)
		writeReport()
		return
	}
	report.RootFD = lease.fd
	report.Owned = []int{lease.fd}
	if err := os.WriteFile(filepath.Join(root, storeDBName), nil, 0o600); err != nil {
		_ = lease.Close()
		report.ErrText = err.Error()
		writeReport()
		return
	}
	bindingMode := storeMode(storeEnroll)
	if phase != "" && (phase == "exec:PRAGMA query_only=ON" || phase == "query:PRAGMA query_only") {
		bindingMode = storeRead
	} else if err := os.Remove(filepath.Join(root, storeDBName)); err != nil {
		_ = lease.Close()
		report.ErrText = err.Error()
		writeReport()
		return
	}
	report.Constructed = life05ScanFDs(t)

	if phase == "" {
		predicted := fmt.Sprintf("tplaiter-store-%x", storeVFSSequence.Load()+1)
		report.VFSBefore = life05VFSFound(t, predicted)
	}
	if phase != "" && !strings.HasPrefix(phase, "terminal-") {
		if phase != "journal-open" {
			observer.failPhase = phase
		}
	}
	binding, bindErr := openSQLBinding(ctx, lease, bindingMode)
	if strings.HasPrefix(phase, "terminal-") {
		life05ChildTerminal(t, &report, phase, lease, binding, bindErr, observer)
		writeReport()
		return
	}
	if phase != "" {
		if phase == "journal-open" {
			if bindErr != nil || binding == nil {
				report.ErrText = fmt.Sprintf("journal setup binding: %v", bindErr)
				_ = lease.Close()
				life05CheckOwnedFDs(&report)
				writeReport()
				return
			}
			observer.failPhase = "journal-open"
			_, execErr := binding.conn.ExecContext(ctx, "CREATE TABLE lifecycle_fd(id INTEGER PRIMARY KEY, payload TEXT)")
			if execErr == nil {
				report.ErrText = "journal-open did not fail"
			} else {
				_ = binding.Close()
				_ = lease.Close()
			}
			life05CheckOwnedFDs(&report)
			report.Worked = life05ScanFDs(t)
			report.Final = life05ScanFDs(t)
			report.AllBalanced = life05Balanced(observer)
			writeReport()
			return
		}
		if binding != nil || !errors.Is(bindErr, ErrProvenanceUnavailable) {
			_ = lease.Close()
			life05CheckOwnedFDs(&report)
			report.ErrText = fmt.Sprintf("phase %q binding=%v err=%v", phase, binding, bindErr)
			writeReport()
			return
		}
		if err := lease.Close(); err != nil {
			report.ErrText = fmt.Sprintf("phase %q lease close: %v", phase, err)
		}
		life05CheckOwnedFDs(&report)
		report.Worked = life05ScanFDs(t)
		report.Final = life05ScanFDs(t)
		report.AllBalanced = life05Balanced(observer)
		writeReport()
		return
	}
	if bindErr != nil {
		_ = lease.Close()
		report.ErrText = fmt.Sprintf("normal binding: %v", bindErr)
		writeReport()
		return
	}
	report.VFSLive = life05VFSFound(t, binding.vfs.name)
	if _, err := binding.conn.ExecContext(ctx, "CREATE TABLE lifecycle_fd(id INTEGER PRIMARY KEY, payload TEXT)"); err != nil {
		_ = binding.Close()
		_ = lease.Close()
		report.ErrText = err.Error()
		writeReport()
		return
	}
	if _, err := binding.conn.ExecContext(ctx, "INSERT INTO lifecycle_fd(id,payload) VALUES(1,'life05')"); err != nil {
		_ = binding.Close()
		_ = lease.Close()
		report.ErrText = err.Error()
		writeReport()
		return
	}
	report.Worked = life05ScanFDs(t)
	report.Owned = appendUniqueFD(report.Owned, fdDifference(report.Worked, report.Baseline)...)
	if err := binding.Close(); err != nil {
		_ = lease.Close()
		report.ErrText = fmt.Sprintf("binding close: %v", err)
		writeReport()
		return
	}
	report.VFSAfter = life05VFSFound(t, binding.vfs.name)
	if err := lease.Close(); err != nil {
		report.ErrText = fmt.Sprintf("lease close: %v", err)
		writeReport()
		return
	}
	for _, fd := range report.Owned {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			report.ErrText = fmt.Sprintf("owned fd %d after close: %v", fd, err)
			break
		}
	}
	report.Final = life05ScanFDs(t)
	report.AllBalanced = life05Balanced(observer)
	writeReport()
}

func life05ChildTerminal(t *testing.T, report *life05Report, phase string, lease *rootLease, binding *sqlBinding, bindErr error, observer *storeProofObserver) {
	t.Helper()
	defer func() {
		report.Final = life05ScanFDs(t)
		report.AllBalanced = life05Balanced(observer)
		for _, fd := range report.Owned {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) && report.ErrText == "" {
				report.ErrText = fmt.Sprintf("terminal owned fd %d after cleanup: %v", fd, err)
			}
		}
	}()
	if bindErr != nil || binding == nil {
		report.ErrText = fmt.Sprintf("terminal binding: %v", bindErr)
		return
	}
	report.VFSLive = life05VFSFound(t, binding.vfs.name)
	if _, err := binding.conn.ExecContext(context.Background(), "CREATE TABLE lifecycle_fd(id INTEGER PRIMARY KEY, payload TEXT)"); err != nil {
		report.ErrText = err.Error()
		return
	}
	report.Worked = life05ScanFDs(t)
	report.Owned = fdDifference(report.Worked, report.Baseline)
	if phase == "terminal-live-file" {
		file, name := lifecycleOpenExtraFile(t, binding)
		report.Owned = appendUniqueFD(report.Owned, int((*vfsFile)(libcPtr(file)).fd))
		rootFD := lease.fd
		if err := (&storeSession{lease: lease, binding: binding}).Close(); !errors.Is(err, ErrProvenanceUnavailable) {
			report.ErrText = fmt.Sprintf("live-file close=%v", err)
			return
		}
		report.Retained = life05VFSFound(t, name) && lease.valid()
		if got := storeFileClose(binding.vfs.tls, file); got != sqlite3.SQLITE_OK {
			report.ErrText = fmt.Sprintf("live-file xClose=%d", got)
			return
		}
		if err := binding.vfs.Close(); err != nil {
			report.ErrText = fmt.Sprintf("live-file VFS close=%v", err)
			return
		}
		if err := lease.Close(); err != nil {
			report.ErrText = err.Error()
			return
		}
		_, fdErr := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0)
		report.Cleaned = errors.Is(fdErr, unix.EBADF) && !life05VFSFound(t, name) && life05Balanced(observer)
		return
	}
	if phase == "terminal-post-native-close" {
		c := (*vfsContext)(libcPtr(binding.vfs.ctx))
		atomic.StoreInt64(&c.fault, storeFaultClose)
		rootFD := lease.fd
		session := &storeSession{lease: lease, binding: binding}
		if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
			report.ErrText = fmt.Sprintf("post-native close=%v", err)
			return
		}
		report.Retained = life05VFSFound(t, binding.vfs.name) && lease.valid()
		atomic.StoreInt64(&c.fault, storeFaultNone)
		atomic.StoreInt64(&c.closeErrors, 0)
		if err := binding.vfs.Close(); err != nil {
			report.ErrText = fmt.Sprintf("post-native cleanup VFS close=%v", err)
			return
		}
		if err := lease.Close(); err != nil {
			report.ErrText = err.Error()
			return
		}
		_, fdErr := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0)
		report.Cleaned = errors.Is(fdErr, unix.EBADF) && !life05VFSFound(t, binding.vfs.name) && life05Balanced(observer)
		return
	}
	if phase == "terminal-physical-close" {
		original := storePhysicalClose
		defer func() { storePhysicalClose = original }()
		var closeCalls atomic.Int64
		storePhysicalClose = func(conn *sql.Conn) error {
			closeCalls.Add(1)
			if err := conn.Close(); err != nil {
				return err
			}
			return errors.New("injected physical close error")
		}
		rootFD := lease.fd
		session := &storeSession{lease: lease, binding: binding}
		if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
			report.ErrText = fmt.Sprintf("physical close=%v", err)
			return
		}
		fresh, err := openRootLease(context.Background(), lease.path, storeRefresh)
		report.Retained = fresh == nil && errors.Is(err, ErrRefreshConflict) && lease.valid()
		if fresh != nil {
			_ = fresh.Close()
		}
		if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
			report.ErrText = fmt.Sprintf("repeat physical close=%v", err)
			return
		}
		if closeCalls.Load() != 1 {
			report.ErrText = fmt.Sprintf("physical close calls=%d", closeCalls.Load())
			return
		}
		if err := lease.Close(); err != nil {
			report.ErrText = err.Error()
			return
		}
		_, fdErr := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0)
		report.Cleaned = errors.Is(fdErr, unix.EBADF) && life05Balanced(observer)
		return
	}
	original := storeVFSUnregister
	defer func() { storeVFSUnregister = original }()
	storeVFSUnregister = func(*libc.TLS, uintptr) int32 { return sqlite3.SQLITE_BUSY }
	name := binding.vfs.name
	rootFD := lease.fd
	session := &storeSession{lease: lease, binding: binding}
	if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		report.ErrText = fmt.Sprintf("unregister close=%v", err)
		return
	}
	report.Retained = life05VFSFound(t, name) && lease.valid()
	storeVFSUnregister = original
	if err := binding.vfs.Close(); err != nil {
		report.ErrText = fmt.Sprintf("unregister cleanup VFS close=%v", err)
		return
	}
	if err := lease.Close(); err != nil {
		report.ErrText = err.Error()
		return
	}
	_, fdErr := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0)
	report.Cleaned = errors.Is(fdErr, unix.EBADF) && !life05VFSFound(t, name) && life05Balanced(observer)
}

func life05ChildFailure(t *testing.T, report *life05Report, phase string, observer *storeProofObserver) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		report.ErrText = err.Error()
		return
	}
	// Keep every path component reachable. The observer selects the actual
	// checkpoint boundary; synthetic missing components would fail earlier and
	// leave the requested ancestor row untested.
	root := filepath.Join(base, "store")
	observer.failPhase = phase
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
	lease, err := openRootLease(ctx, root, storeEnroll)
	if lease != nil {
		_ = lease.Close()
		report.ErrText = "root failure unexpectedly acquired lease"
		return
	}
	if !errors.Is(err, ErrProvenanceUnavailable) {
		report.ErrText = fmt.Sprintf("phase %q err=%v", phase, err)
		return
	}
	observer.mu.Lock()
	if counts := observer.hits[phase]; counts != [2]int{} {
		report.BeforeHits = counts[0]
		report.AfterHits = counts[1]
	}
	report.RootFDOpened = append([]int(nil), observer.rootFDOpened...)
	report.RootFDClosed = append([]int(nil), observer.rootFDClosed...)
	observer.mu.Unlock()
	if strings.HasPrefix(phase, "ancestor-open") && len(report.RootFDClosed) == 0 {
		report.ErrText = fmt.Sprintf("phase %q acquired no prior root descriptor", phase)
		return
	}
	report.EBADFOwned = true
	for _, fd := range report.RootFDClosed {
		if _, fdErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(fdErr, unix.EBADF) {
			report.EBADFOwned = false
			report.ErrText = fmt.Sprintf("phase %q released fd %d remains usable: %v", phase, fd, fdErr)
			break
		}
	}
	report.VFSBefore = false
	report.VFSLive = false
	report.VFSAfter = false
	report.Worked = life05ScanFDs(t)
	report.Final = life05ScanFDs(t)
	report.AllBalanced = life05Balanced(observer)
}

func life05ScanFDs(t *testing.T) []int {
	t.Helper()
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	maxFDs := limit.Cur
	if maxFDs == unix.RLIM_INFINITY || maxFDs > 1<<20 {
		t.Fatalf("RLIMIT_NOFILE=%d exceeds bounded scan maximum; refusing incomplete FD proof", maxFDs)
	}
	open := make([]int, 0, 16)
	for fd := uint64(0); fd < maxFDs; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			open = append(open, int(fd))
		}
	}
	return open
}

func life05VFSFound(t *testing.T, name string) bool {
	t.Helper()
	tls := libc.NewTLS()
	defer tls.Close()
	cname, err := libc.CString(name)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, cname)
	return sqlite3.Xsqlite3_vfs_find(tls, cname) != 0
}

func life05Balanced(observer *storeProofObserver) bool {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return observer.allocs == observer.frees && observer.registers == observer.unregisters &&
		observer.tlsCreates == observer.tlsCloses && observer.rootFDs == observer.rootFDCloses &&
		observer.vfsOpens == observer.vfsCloses && observer.physicalOpens == observer.physicalCloses
}

func life05CheckOwnedFDs(report *life05Report) {
	report.EBADFOwned = true
	for _, fd := range report.Owned {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			report.EBADFOwned = false
			if report.ErrText == "" {
				report.ErrText = fmt.Sprintf("owned fd %d after close: %v", fd, err)
			}
			return
		}
	}
}

func fdDifference(after, before []int) []int {
	seen := make(map[int]struct{}, len(before))
	for _, fd := range before {
		seen[fd] = struct{}{}
	}
	var result []int
	for _, fd := range after {
		if _, ok := seen[fd]; !ok {
			result = append(result, fd)
		}
	}
	sort.Ints(result)
	return result
}

func appendUniqueFD(dst []int, values ...int) []int {
	seen := make(map[int]struct{}, len(dst)+len(values))
	for _, fd := range dst {
		seen[fd] = struct{}{}
	}
	for _, fd := range values {
		if _, ok := seen[fd]; !ok {
			dst = append(dst, fd)
			seen[fd] = struct{}{}
		}
	}
	sort.Ints(dst)
	return dst
}

func containsFDSet(have, want []int) bool {
	seen := make(map[int]struct{}, len(have))
	for _, fd := range have {
		seen[fd] = struct{}{}
	}
	for _, fd := range want {
		if _, ok := seen[fd]; !ok {
			return false
		}
	}
	return true
}

func sameFDSet(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
