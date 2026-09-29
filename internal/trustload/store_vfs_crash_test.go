//go:build darwin || linux

package trustload

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type crashTuple struct {
	Head       string
	Generation int64
	Links      string
	Rows       map[int]string
	Lengths    map[int]int
}

type crashFixture struct {
	root     string
	lease    *rootLease
	binding  *sqlBinding
	observer *storeProofObserver
}

var crashSeedRows = []struct{ id, seed int }{{1, 11}, {2, 12}}

func TestStoreVFSCrash00DiscoveryCommitAndRollback(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	t.Run("commit", func(t *testing.T) {
		f, old := newCrashFixture(t)
		ctx := context.Background()
		f.observer.traceReset()
		if _, err := f.binding.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		newBlob := crashBlob(31, 32768)
		if _, err := f.binding.conn.ExecContext(ctx, "UPDATE crash_blobs SET bytes=?, digest=? WHERE id=1", newBlob, workloadDigest(newBlob)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.binding.conn.ExecContext(ctx, "INSERT INTO crash_blobs(id,bytes,digest) VALUES(3,?,?)", crashBlob(33, 16384), workloadDigest(crashBlob(33, 16384))); err != nil {
			t.Fatal(err)
		}
		if _, err := f.binding.conn.ExecContext(ctx, "UPDATE crash_meta SET head='head-new', generation=2, links='1,2,3' WHERE singleton=1"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.binding.conn.ExecContext(ctx, "COMMIT"); err != nil {
			t.Fatal(err)
		}
		f.observer.traceEvent(storeTraceCommitControl, storeTraceKindRoot, 0, 0, 0, 0)
		if err := closeCrashFixture(f); err != nil {
			t.Fatal(err)
		}
		f.observer.traceEvent(storeTraceCloseControl, storeTraceKindRoot, 0, 0, 0, 0)
		trace := f.observer.traceSnapshot()
		assertCrashTrace(t, trace, true)
		commitCuts := commitCutIDs(trace)
		assertCommitCutIDs(t, trace, commitCuts)
		want := crashTuple{Head: "head-new", Generation: 2, Links: "1,2,3", Rows: map[int]string{1: workloadDigest(newBlob), 2: old.Rows[2], 3: workloadDigest(crashBlob(33, 16384))}, Lengths: map[int]int{1: len(newBlob), 2: old.Lengths[2], 3: 16384}}
		checkCrashReopen(t, f.root, want)
		t.Logf("CRASH00 commit trace=%s cuts=%s", encodeCrashTrace(trace), encodeCutIDs(trace))
	})

	t.Run("rollback-and-journal-cleanup", func(t *testing.T) {
		f, old := newCrashFixture(t)
		ctx := context.Background()
		f.observer.traceReset()
		if _, err := f.binding.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		changed := crashBlob(41, 24576)
		if _, err := f.binding.conn.ExecContext(ctx, "UPDATE crash_blobs SET bytes=?, digest=? WHERE id=1", changed, workloadDigest(changed)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.binding.conn.ExecContext(ctx, "UPDATE crash_meta SET head='head-rollback', generation=7, links='changed' WHERE singleton=1"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.binding.conn.ExecContext(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		f.observer.traceEvent(storeTraceCommitControl, storeTraceKindRoot, 0, 0, 0, 0)
		if err := closeCrashFixture(f); err != nil {
			t.Fatal(err)
		}
		f.observer.traceEvent(storeTraceCloseControl, storeTraceKindRoot, 0, 0, 0, 0)
		trace := f.observer.traceSnapshot()
		assertCrashTrace(t, trace, false)
		rollbackCuts := rollbackDiscoveryIDs(trace)
		assertRollbackDiscoveryIDs(t, trace, rollbackCuts)
		checkCrashReopen(t, f.root, old)
		t.Logf("CRASH00 rollback trace=%s discovery=%s", encodeCrashTrace(trace), encodeRollbackIDs(trace))
	})
}

// TestStoreVFSCrash00TraceSchema keeps the discovery proof honest even when a
// future observer change emits a syntactically plausible, but malformed, tuple.
func TestStoreVFSCrash00TraceSchema(t *testing.T) {
	base := []storeTraceEvent{
		{Seq: 1, Op: storeTraceOpen, Kind: storeFileJournal, Requested: 1},
		{Seq: 2, Op: storeTraceWrite, Kind: storeFileJournal, Requested: 4, Completed: 4},
		{Seq: 3, Op: storeTraceFileSync, Kind: storeFileJournal},
		{Seq: 4, Op: storeTraceRootSync, Kind: storeTraceKindRoot},
		{Seq: 5, Op: storeTraceUnlink, Kind: storeFileJournal},
		{Seq: 6, Op: storeTraceCommitControl, Kind: storeTraceKindRoot},
		{Seq: 7, Op: storeTraceCloseControl, Kind: storeTraceKindRoot},
	}
	if err := validateCrashTraceSchema(base); err != nil {
		t.Fatalf("valid trace rejected: %v", err)
	}
	cases := map[string]func(*storeTraceEvent){
		"unknown-op":                func(e *storeTraceEvent) { e.Op = 99 },
		"unknown-kind":              func(e *storeTraceEvent) { e.Kind = 99 },
		"invalid-open-kind":         func(e *storeTraceEvent) { e.Kind = storeFileMain },
		"sequence-zero":             func(e *storeTraceEvent) { e.Seq = 0 },
		"sequence-gap":              func(e *storeTraceEvent) { e.Seq = 9 },
		"sequence-duplicate":        func(e *storeTraceEvent) { e.Seq = 1 },
		"native-result":             func(e *storeTraceEvent) { e.Result = 1 },
		"negative-offset":           func(e *storeTraceEvent) { e.Offset = -1 },
		"write-requested-zero":      func(e *storeTraceEvent) { e.Requested = 0 },
		"write-completed-zero":      func(e *storeTraceEvent) { e.Completed = 0 },
		"write-completed-too-large": func(e *storeTraceEvent) { e.Completed = 5 },
		"sync-fields":               func(e *storeTraceEvent) { e.Requested = 1 },
		"control-fields":            func(e *storeTraceEvent) { e.Offset = 1 },
		"invalid-unlink-kind":       func(e *storeTraceEvent) { e.Kind = storeFileMain },
		"duplicate-control":         func(e *storeTraceEvent) { e.Op = storeTraceCloseControl },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			trace := append([]storeTraceEvent(nil), base...)
			switch name {
			case "sequence-zero", "sequence-gap", "native-result", "negative-offset":
				mutate(&trace[0])
			case "sequence-duplicate":
				mutate(&trace[1])
			case "sync-fields":
				mutate(&trace[2])
			case "control-fields":
				mutate(&trace[5])
			case "invalid-unlink-kind":
				mutate(&trace[4])
			case "duplicate-control":
				mutate(&trace[5])
			case "unknown-op", "unknown-kind":
				mutate(&trace[1])
			case "invalid-open-kind":
				mutate(&trace[0])
			default:
				mutate(&trace[1])
			}
			if err := validateCrashTraceSchema(trace); err == nil {
				t.Fatalf("malformed trace accepted: %s", name)
			}
		})
	}
}

// TestStoreVFSCrash00DeterministicSeedRepeat keeps the frozen CRASH01 trace
// premise explicit: insertion order is 1 then 2 and two discovery fixtures
// emit the same native seed trace. The frozen expected trace is not generated
// or changed by this test.
func TestStoreVFSCrash00DeterministicSeedRepeat(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	var traces []string
	for run := 0; run < 2; run++ {
		f, _ := newCrashFixture(t)
		rows, err := f.binding.conn.QueryContext(context.Background(), "SELECT id FROM crash_blobs ORDER BY rowid")
		if err != nil {
			_ = closeCrashFixture(f)
			t.Fatal(err)
		}
		var ids []int
		for rows.Next() {
			var id int
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				_ = closeCrashFixture(f)
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		if err := rows.Close(); err != nil || fmt.Sprint(ids) != "[1 2]" {
			_ = closeCrashFixture(f)
			t.Fatalf("seed ids=%v err=%v", ids, err)
		}
		traces = append(traces, encodeCrashTrace(f.observer.traceSnapshot()))
		if err := closeCrashFixture(f); err != nil {
			t.Fatal(err)
		}
	}
	if traces[0] != traces[1] {
		t.Fatalf("seed trace drift: first=%s second=%s", traces[0], traces[1])
	}
}

const (
	crash01ChildEnv = "TPLAITER_CRASH01_CHILD"
	crash01RootEnv  = "TPLAITER_CRASH01_ROOT"
)

// TestStoreVFSCrash01SIGKILL exercises every frozen commit cut. The child
// blocks immediately after each successful native callback; the parent ACKs
// only earlier records and kills the child at the selected cut.
func TestStoreVFSCrash01SIGKILL(t *testing.T) {
	if os.Getenv(crash01ChildEnv) == "1" {
		runCrash01Child(t)
		return
	}
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	wantTrace := frozenCrash01CommitTrace()
	if len(wantTrace) != 48 {
		t.Fatalf("frozen trace length=%d want=48", len(wantTrace))
	}
	for cut := 0; cut < len(wantTrace)+1; cut++ {
		t.Run(fmt.Sprintf("cut-%02d", cut), func(t *testing.T) {
			runCrash01Cut(t, cut, wantTrace)
		})
	}
}

func TestStoreColdJournalInspectionBounds(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	cases := []struct {
		name       string
		size       int64
		first      byte
		wantErr    bool
		wantZero   bool
		wantBytes  int64
		wantDigest bool
	}{
		{name: "zero", size: 0, wantZero: true, wantBytes: 0, wantDigest: true},
		{name: "one", size: 1, wantZero: true, wantBytes: 2, wantDigest: true},
		{name: "page", size: 4096, wantZero: true, wantBytes: 4097, wantDigest: true},
		{name: "budget", size: coldJournalInspectBudget, wantZero: true, wantBytes: coldJournalInspectBudget + 1, wantDigest: true},
		{name: "cold-oversize", size: coldJournalInspectBudget + 1, wantZero: true, wantErr: true, wantBytes: 1},
		{name: "hot-oversize", size: coldJournalInspectBudget + 1, first: 1, wantBytes: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseRoot, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			base := filepath.Join(baseRoot, "store")
			lease, err := openRootLease(context.Background(), base, storeEnroll)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(base, storeDBName+"-journal")
			file, err := os.OpenFile(journal, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(tc.size); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if tc.size > 0 && tc.first != 0 {
				if _, err := file.WriteAt([]byte{tc.first}, 0); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			recoverLease, err := openRootLease(context.Background(), base, storeRecover)
			if err != nil {
				t.Fatal(err)
			}
			got, fd, gotErr := recoverLease.inspectColdJournal(false)
			_ = recoverLease.Close()
			if fd != -1 {
				t.Fatalf("inspection leaked fd=%d", fd)
			}
			if tc.wantErr != (gotErr != nil) {
				t.Fatalf("inspection err=%v wantErr=%v", gotErr, tc.wantErr)
			}
			if tc.wantErr {
				if !errors.Is(gotErr, ErrPending) {
					t.Fatalf("oversize error=%v want ErrPending", gotErr)
				}
			} else {
				if got.zero != tc.wantZero || got.bytesRead != tc.wantBytes || (got.digest != "") != tc.wantDigest {
					t.Fatalf("evidence zero=%v bytes=%d digest=%q", got.zero, got.bytesRead, got.digest)
				}
			}
		})
	}
}

// TestStoreColdJournalRecoveryUsesFixedHealth exercises the integrated
// no-callback path with a real SQLite database and a cold zero sidecar.  The
// test deliberately validates only engine maintenance; application authority
// remains outside this helper.
func TestStoreColdJournalRecoveryUsesFixedHealth(t *testing.T) {
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
	seedBinding, err := openSQLBinding(context.Background(), seed, storeEnroll)
	if err != nil {
		_ = seed.Close()
		t.Fatal(err)
	}
	if _, err := seedBinding.conn.ExecContext(context.Background(), "CREATE TABLE cold_recovery_probe(v INTEGER); INSERT INTO cold_recovery_probe VALUES(1)"); err != nil {
		_ = seedBinding.Close()
		_ = seed.Close()
		t.Fatal(err)
	}
	if err := seedBinding.Close(); err != nil {
		_ = seed.Close()
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, storeDBName+"-journal"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lease, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverStoreColdJournal(context.Background(), lease); err != nil {
		_ = lease.Close()
		t.Fatalf("fixed cold recovery: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); !os.IsNotExist(err) {
		t.Fatalf("cold journal remained after fixed recovery: %v", err)
	}
	read, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	readBinding, err := openSQLBinding(context.Background(), read, storeRead)
	if err != nil {
		_ = read.Close()
		t.Fatal(err)
	}
	var got int
	if err := readBinding.conn.QueryRowContext(context.Background(), "SELECT v FROM cold_recovery_probe").Scan(&got); err != nil || got != 1 {
		_ = readBinding.Close()
		_ = read.Close()
		t.Fatalf("readonly probe=%d err=%v", got, err)
	}
	if err := readBinding.Close(); err != nil {
		_ = read.Close()
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreColdJournalInspectionRejectsUnsafeSidecars(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	baseRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(baseRoot, "store")
	seed, err := openRootLease(context.Background(), base, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	openRecover := func() *rootLease {
		t.Helper()
		lease, err := openRootLease(context.Background(), base, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		return lease
	}
	t.Run("wal-present", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(base, storeDBName+"-wal"), []byte{1}, 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(filepath.Join(base, storeDBName+"-wal"))
		lease := openRecover()
		_, fd, gotErr := lease.inspectColdJournal(false)
		_ = lease.Close()
		if fd != -1 || !errors.Is(gotErr, ErrPending) {
			t.Fatalf("wal inspection fd=%d err=%v want ErrPending", fd, gotErr)
		}
	})
	t.Run("journal-symlink", func(t *testing.T) {
		outside := filepath.Join(baseRoot, "outside-journal")
		if err := os.WriteFile(outside, []byte{0}, 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(outside)
		if err := os.Symlink(outside, filepath.Join(base, storeDBName+"-journal")); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(filepath.Join(base, storeDBName+"-journal"))
		lease := openRecover()
		_, fd, gotErr := lease.inspectColdJournal(false)
		_ = lease.Close()
		if fd != -1 || !errors.Is(gotErr, ErrProvenanceUnavailable) {
			t.Fatalf("symlink inspection fd=%d err=%v want provenance error", fd, gotErr)
		}
	})
	t.Run("journal-permission", func(t *testing.T) {
		journal := filepath.Join(base, storeDBName+"-journal")
		if err := os.WriteFile(journal, []byte{0}, 0o644); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(journal)
		lease := openRecover()
		_, fd, gotErr := lease.inspectColdJournal(false)
		_ = lease.Close()
		if fd != -1 || !errors.Is(gotErr, ErrProvenanceUnavailable) {
			t.Fatalf("permission inspection fd=%d err=%v want provenance error", fd, gotErr)
		}
	})
}

type crash01WireRecord struct {
	Ordinal   int64
	Seq       int64
	Op        int64
	Kind      int64
	Offset    int64
	Requested int64
	Completed int64
	Result    int64
}

type crash01JournalObservation struct {
	Present  bool   `json:"present"`
	Dev      uint64 `json:"dev,omitempty"`
	Ino      uint64 `json:"ino,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`
	UID      uint32 `json:"uid,omitempty"`
	Nlink    uint64 `json:"nlink,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Header28 string `json:"header28,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	ReadErr  string `json:"readErr,omitempty"`
}

type crash01RecoveryObservation struct {
	OpenErr        string                    `json:"openErr,omitempty"`
	QueryErr       string                    `json:"queryErr,omitempty"`
	JournalMode    string                    `json:"journalMode,omitempty"`
	Count          int                       `json:"count,omitempty"`
	Integrity      string                    `json:"integrity,omitempty"`
	Trace          []storeTraceEvent         `json:"trace,omitempty"`
	CallbackCounts [callbackCount]int64      `json:"callbackCounts"`
	BeforeJournal  crash01JournalObservation `json:"beforeJournal"`
	AfterJournal   crash01JournalObservation `json:"afterJournal"`
}

func writeCrash01Record(w io.Writer, record crash01WireRecord) error {
	var raw [8]int64
	raw[0], raw[1], raw[2], raw[3] = record.Ordinal, record.Seq, record.Op, record.Kind
	raw[4], raw[5], raw[6], raw[7] = record.Offset, record.Requested, record.Completed, record.Result
	return binary.Write(w, binary.LittleEndian, raw[:])
}

func readCrash01Record(r io.Reader) (crash01WireRecord, error) {
	var raw [8]int64
	if err := binary.Read(r, binary.LittleEndian, &raw); err != nil {
		return crash01WireRecord{}, err
	}
	return crash01WireRecord{Ordinal: raw[0], Seq: raw[1], Op: raw[2], Kind: raw[3], Offset: raw[4], Requested: raw[5], Completed: raw[6], Result: raw[7]}, nil
}

func observeCrash01Journal(t *testing.T, root string) crash01JournalObservation {
	t.Helper()
	lease, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		return crash01JournalObservation{ReadErr: err.Error()}
	}
	defer lease.Close()
	fd, err := lease.openLeaf(storeDBName+"-journal", unix.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, ErrProvenanceUnavailable) {
			return crash01JournalObservation{}
		}
		return crash01JournalObservation{ReadErr: err.Error()}
	}
	file := os.NewFile(uintptr(fd), "journal-observation")
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return crash01JournalObservation{Present: true, ReadErr: err.Error()}
	}
	obs := crash01JournalObservation{Present: true, Dev: uint64(st.Dev), Ino: uint64(st.Ino), Mode: uint32(st.Mode), UID: st.Uid, Nlink: uint64(st.Nlink), Size: st.Size}
	data, err := io.ReadAll(io.LimitReader(file, 16<<20))
	if err != nil {
		obs.ReadErr = err.Error()
		return obs
	}
	sum := sha256.Sum256(data)
	obs.SHA256 = hex.EncodeToString(sum[:])
	if len(data) > 28 {
		data = data[:28]
	}
	obs.Header28 = hex.EncodeToString(data)
	return obs
}

func runCrash01Child(t *testing.T) {
	eventFD := os.NewFile(uintptr(3), "crash01-events")
	ackFD := os.NewFile(uintptr(4), "crash01-acks")
	if eventFD == nil || ackFD == nil {
		t.Fatal("missing crash01 inherited pipes")
	}
	defer eventFD.Close()
	defer ackFD.Close()
	root := os.Getenv(crash01RootEnv)
	if root == "" {
		t.Fatal("missing crash01 root")
	}
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(root), "outside-sentinel"), []byte("crash-outside-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	observer := &storeProofObserver{}
	gate := func(event storeTraceEvent) {
		if err := writeCrash01Record(eventFD, crash01WireRecord{Ordinal: event.Seq, Seq: event.Seq, Op: event.Op, Kind: event.Kind, Offset: event.Offset, Requested: event.Requested, Completed: event.Completed, Result: event.Result}); err != nil {
			os.Exit(2)
		}
		var ack [1]byte
		if _, err := io.ReadFull(ackFD, ack[:]); err != nil || ack[0] != 1 {
			os.Exit(2)
		}
	}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
	lease, err := openRootLease(ctx, root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(ctx, lease, storeEnroll)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if err := configureWorkloadConnection(ctx, binding); err != nil {
		_ = binding.Close()
		_ = lease.Close()
		t.Fatal(err)
	}
	if err := seedCrashFixture(t, binding); err != nil {
		_ = binding.Close()
		_ = lease.Close()
		t.Fatal(err)
	}
	observer.traceHook = gate
	observer.traceReset()
	if err := writeCrash01Record(eventFD, crash01WireRecord{Ordinal: 0}); err != nil {
		os.Exit(2) //nolint:gocritic // crash child: exit immediately, deferred cleanup must not run
	}
	var ack [1]byte
	if _, err := io.ReadFull(ackFD, ack[:]); err != nil || ack[0] != 1 {
		os.Exit(2)
	}
	ctx = context.Background()
	if _, err := binding.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	newBlob := crashBlob(31, 32768)
	if _, err := binding.conn.ExecContext(ctx, "UPDATE crash_blobs SET bytes=?, digest=? WHERE id=1", newBlob, workloadDigest(newBlob)); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.conn.ExecContext(ctx, "INSERT INTO crash_blobs(id,bytes,digest) VALUES(3,?,?)", crashBlob(33, 16384), workloadDigest(crashBlob(33, 16384))); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.conn.ExecContext(ctx, "UPDATE crash_meta SET head='head-new', generation=2, links='1,2,3' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	observer.traceEvent(storeTraceCommitControl, storeTraceKindRoot, 0, 0, 0, 0)
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	observer.traceEvent(storeTraceCloseControl, storeTraceKindRoot, 0, 0, 0, 0)
}

func seedCrashFixture(t *testing.T, binding *sqlBinding) error {
	if _, err := binding.conn.ExecContext(context.Background(), `CREATE TABLE crash_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), head TEXT NOT NULL, generation INTEGER NOT NULL, links TEXT NOT NULL); CREATE TABLE crash_blobs(id INTEGER PRIMARY KEY, bytes BLOB NOT NULL, digest TEXT NOT NULL); INSERT INTO crash_meta VALUES(1,'head-old',1,'1,2')`); err != nil {
		return err
	}
	for _, row := range crashSeedRows {
		blob := crashBlob(row.seed, 8192)
		if _, err := binding.conn.ExecContext(context.Background(), "INSERT INTO crash_blobs(id,bytes,digest) VALUES(?,?,?)", row.id, blob, workloadDigest(blob)); err != nil {
			return err
		}
	}
	return nil
}

func oldCrashTuple() crashTuple {
	rows := map[int]string{}
	lengths := map[int]int{}
	for _, row := range crashSeedRows {
		blob := crashBlob(row.seed, 8192)
		rows[row.id], lengths[row.id] = workloadDigest(blob), len(blob)
	}
	return crashTuple{Head: "head-old", Generation: 1, Links: "1,2", Rows: rows, Lengths: lengths}
}

func newCrashTuple() crashTuple {
	old := oldCrashTuple()
	newBlob := crashBlob(31, 32768)
	inserted := crashBlob(33, 16384)
	old.Head, old.Generation, old.Links = "head-new", 2, "1,2,3"
	old.Rows[1], old.Lengths[1] = workloadDigest(newBlob), len(newBlob)
	old.Rows[3], old.Lengths[3] = workloadDigest(inserted), len(inserted)
	return old
}

func assertCrash01Sentinel(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "crash-outside-sentinel" {
		t.Fatalf("outside sentinel changed: %q err=%v", data, err)
	}
}

func loadCrashTuple(t *testing.T, root string) crashTuple {
	t.Helper()
	lease, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(context.Background(), lease, storeRead)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	defer func() { _ = binding.Close(); _ = lease.Close() }()
	var got crashTuple
	if err := binding.conn.QueryRowContext(context.Background(), "SELECT head,generation,links FROM crash_meta WHERE singleton=1").Scan(&got.Head, &got.Generation, &got.Links); err != nil {
		t.Fatal(err)
	}
	got.Rows, got.Lengths = map[int]string{}, map[int]int{}
	rows, err := binding.conn.QueryContext(context.Background(), "SELECT id,bytes,digest FROM crash_blobs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int
		var bytes []byte
		var digest string
		if err := rows.Scan(&id, &bytes, &digest); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		if digest != workloadDigest(bytes) {
			_ = rows.Close()
			t.Fatalf("row %d digest mismatch", id)
		}
		got.Rows[id], got.Lengths[id] = digest, len(bytes)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	var integrity string
	if err := binding.conn.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity=%q err=%v", integrity, err)
	}
	return got
}

func crashTupleEqual(a, b crashTuple) bool {
	return a.Head == b.Head && a.Generation == b.Generation && a.Links == b.Links && fmt.Sprint(a.Rows) == fmt.Sprint(b.Rows) && fmt.Sprint(a.Lengths) == fmt.Sprint(b.Lengths)
}

func assertCrashTupleEqual(t *testing.T, got, want crashTuple, label string) {
	t.Helper()
	if !crashTupleEqual(got, want) {
		t.Fatalf("%s tuple=%+v want=%+v", label, got, want)
	}
}

func frozenCrash01CommitTrace() []storeTraceEvent {
	return []storeTraceEvent{
		{1, 1, 2, 0, 2054, 0, 0},
		{2, 2, 2, 0, 4096, 4096, 0},
		{3, 2, 2, 4096, 4, 4, 0},
		{4, 2, 2, 4100, 4096, 4096, 0},
		{5, 2, 2, 8196, 4, 4, 0},
		{6, 2, 2, 8200, 4, 4, 0},
		{7, 2, 2, 8204, 4096, 4096, 0},
		{8, 2, 2, 12300, 4, 4, 0},
		{9, 2, 2, 12304, 4, 4, 0},
		{10, 2, 2, 12308, 4096, 4096, 0},
		{11, 2, 2, 16404, 4, 4, 0},
		{12, 2, 2, 16408, 4, 4, 0},
		{13, 2, 2, 16412, 4096, 4096, 0},
		{14, 2, 2, 20508, 4, 4, 0},
		{15, 3, 2, 0, 0, 0, 0},
		{16, 4, 3, 0, 0, 0, 0},
		{17, 2, 2, 0, 12, 12, 0},
		{18, 3, 2, 0, 0, 0, 0},
		{19, 4, 3, 0, 0, 0, 0},
		{20, 2, 2, 24576, 4096, 4096, 0},
		{21, 2, 1, 28672, 4096, 4096, 0},
		{22, 2, 1, 32768, 4096, 4096, 0},
		{23, 2, 2, 28672, 4, 4, 0},
		{24, 2, 2, 28676, 4096, 4096, 0},
		{25, 2, 2, 32772, 4, 4, 0},
		{26, 3, 2, 0, 0, 0, 0},
		{27, 4, 3, 0, 0, 0, 0},
		{28, 2, 2, 24576, 12, 12, 0},
		{29, 3, 2, 0, 0, 0, 0},
		{30, 4, 3, 0, 0, 0, 0},
		{31, 2, 1, 0, 4096, 4096, 0},
		{32, 2, 1, 4096, 4096, 4096, 0},
		{33, 2, 1, 8192, 4096, 4096, 0},
		{34, 2, 1, 12288, 4096, 4096, 0},
		{35, 2, 1, 16384, 4096, 4096, 0},
		{36, 2, 1, 36864, 4096, 4096, 0},
		{37, 2, 1, 40960, 4096, 4096, 0},
		{38, 2, 1, 45056, 4096, 4096, 0},
		{39, 2, 1, 49152, 4096, 4096, 0},
		{40, 2, 1, 53248, 4096, 4096, 0},
		{41, 2, 1, 57344, 4096, 4096, 0},
		{42, 2, 1, 61440, 4096, 4096, 0},
		{43, 2, 1, 65536, 4096, 4096, 0},
		{44, 3, 1, 0, 0, 0, 0},
		{45, 6, 2, 0, 0, 0, 0},
		{46, 4, 3, 0, 0, 0, 0},
		{47, 7, 3, 0, 0, 0, 0},
		{48, 8, 3, 0, 0, 0, 0},
	}
}

func runCrash01Cut(t *testing.T, cut int, wantTrace []storeTraceEvent) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	eventR, eventW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		eventR.Close()
		eventW.Close()
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreVFSCrash01SIGKILL$")
	cmd.Env = append(os.Environ(), crash01ChildEnv+"=1", crash01RootEnv+"="+root)
	cmd.ExtraFiles = []*os.File{eventW, ackR}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	eventW.Close()
	ackR.Close()
	defer eventR.Close()
	defer ackW.Close()
	for ordinal := 0; ordinal <= cut; ordinal++ {
		if err := eventR.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		record, err := readCrash01Record(eventR)
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("cut %d record %d: %v", cut, ordinal, err)
		}
		want := crash01WireRecord{Ordinal: int64(ordinal)}
		if ordinal > 0 {
			event := wantTrace[ordinal-1]
			want.Seq, want.Op, want.Kind, want.Offset = event.Seq, event.Op, event.Kind, event.Offset
			want.Requested, want.Completed, want.Result = event.Requested, event.Completed, event.Result
		}
		if record != want {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("cut %d record=%+v want=%+v", cut, record, want)
		}
		if ordinal == cut {
			break
		}
		if _, err := ackW.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	stateErr := cmd.Wait()
	status, ok := syscall.WaitStatus(0), false
	if cmd.ProcessState != nil {
		status, ok = cmd.ProcessState.Sys().(syscall.WaitStatus)
	}
	if stateErr == nil || cmd.ProcessState == nil || !ok || (!cmd.ProcessState.Exited() && !status.Signaled()) {
		t.Fatalf("child wait state=%v", stateErr)
	}
	assertCrash01Sentinel(t, filepath.Join(base, "outside-sentinel"))
	readLease, readErr := openRootLease(context.Background(), root, storeRead)
	if cut == 0 {
		if readErr != nil {
			t.Fatalf("ordinary read before journal after SIGKILL err=%v", readErr)
		}
		readBinding, err := openSQLBinding(context.Background(), readLease, storeRead)
		if err != nil {
			_ = readLease.Close()
			t.Fatalf("ordinary read binding before journal: %v", err)
		}
		if err := readBinding.Close(); err != nil {
			_ = readLease.Close()
			t.Fatal(err)
		}
		if err := readLease.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		if readErr != nil {
			t.Fatalf("ordinary read lease after SIGKILL err=%v", readErr)
		}
		readBinding, bindingErr := openSQLBinding(context.Background(), readLease, storeRead)
		journalPresent := exists(filepath.Join(root, storeDBName+"-journal"))
		if readBinding != nil {
			_ = readBinding.Close()
		}
		_ = readLease.Close()
		if journalPresent && !errors.Is(bindingErr, ErrPending) {
			entries, _ := os.ReadDir(root)
			t.Fatalf("ordinary read binding after SIGKILL err=%v want ErrPending entries=%v", bindingErr, entries)
		}
		if !journalPresent && bindingErr != nil {
			t.Fatalf("ordinary read after SIGKILL without journal err=%v", bindingErr)
		}
	}
	beforeJournal := observeCrash01Journal(t, root)
	proof := &storeProofObserver{}
	recoveryContext := context.WithValue(context.Background(), storeProofObserverKey{}, proof)
	recoveryLease, err := openRootLease(recoveryContext, root, storeRecover)
	if err != nil {
		t.Fatalf("recovery lease: %v", err)
	}
	recoveryErr := recoverStoreColdJournal(recoveryContext, recoveryLease)
	_ = recoveryLease.Close()
	recoveryObservation := crash01RecoveryObservation{BeforeJournal: beforeJournal, Trace: proof.traceSnapshot()}
	recoveryObservation.AfterJournal = observeCrash01Journal(t, root)
	if recoveryErr != nil {
		recoveryObservation.QueryErr = recoveryErr.Error()
		t.Fatalf("CRASH01 cut %d helper recovery failed: %v", cut, recoveryErr)
	}
	encodedRecovery, err := json.Marshal(recoveryObservation)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CRASH01 cut=%d recovery-diagnostic=%s", cut, encodedRecovery)
	got := loadCrashTuple(t, root)
	old := oldCrashTuple()
	next := newCrashTuple()
	if cut >= len(wantTrace)-2 {
		assertCrashTupleEqual(t, got, next, "post-control")
	} else if !crashTupleEqual(got, old) && !crashTupleEqual(got, next) {
		t.Fatalf("cut %d produced mixed tuple: got=%+v", cut, got)
	}
}

func newCrashFixture(t *testing.T) (crashFixture, crashTuple) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "outside-sentinel"), []byte("crash-outside-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	observer := &storeProofObserver{}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
	binding, err := openSQLBinding(ctx, lease, storeEnroll)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if err := configureWorkloadConnection(context.Background(), binding); err != nil {
		_ = binding.Close()
		_ = lease.Close()
		t.Fatal(err)
	}
	old := crashTuple{Head: "head-old", Generation: 1, Links: "1,2", Rows: map[int]string{}, Lengths: map[int]int{}}
	for _, row := range crashSeedRows {
		blob := crashBlob(row.seed, 8192)
		old.Rows[row.id] = workloadDigest(blob)
		old.Lengths[row.id] = len(blob)
	}
	if _, err := binding.conn.ExecContext(context.Background(), `CREATE TABLE crash_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), head TEXT NOT NULL, generation INTEGER NOT NULL, links TEXT NOT NULL); CREATE TABLE crash_blobs(id INTEGER PRIMARY KEY, bytes BLOB NOT NULL, digest TEXT NOT NULL); INSERT INTO crash_meta VALUES(1,'head-old',1,'1,2')`); err != nil {
		t.Fatal(err)
	}
	for _, row := range crashSeedRows {
		blob := crashBlob(row.seed, 8192)
		if _, err := binding.conn.ExecContext(context.Background(), "INSERT INTO crash_blobs(id,bytes,digest) VALUES(?,?,?)", row.id, blob, workloadDigest(blob)); err != nil {
			t.Fatal(err)
		}
	}
	return crashFixture{root: root, lease: lease, binding: binding, observer: observer}, old
}

func closeCrashFixture(f crashFixture) error {
	if err := f.binding.Close(); err != nil {
		_ = f.lease.Close()
		return err
	}
	return f.lease.Close()
}

func checkCrashReopen(t *testing.T, root string, want crashTuple) {
	t.Helper()
	lease, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(context.Background(), lease, storeRead)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	defer func() { _ = binding.Close(); _ = lease.Close() }()
	var head, links string
	var generation int64
	if err := binding.conn.QueryRowContext(context.Background(), "SELECT head,generation,links FROM crash_meta WHERE singleton=1").Scan(&head, &generation, &links); err != nil {
		t.Fatal(err)
	}
	if head != want.Head || generation != want.Generation || links != want.Links {
		t.Fatalf("metadata=%q/%d/%q want=%q/%d/%q", head, generation, links, want.Head, want.Generation, want.Links)
	}
	rows, err := binding.conn.QueryContext(context.Background(), "SELECT id,bytes,digest FROM crash_blobs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[int]string)
	for rows.Next() {
		var id int
		var bytes []byte
		var stored string
		if err := rows.Scan(&id, &bytes, &stored); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		computed := workloadDigest(bytes)
		if stored != computed || want.Rows[id] != computed || want.Lengths[id] != len(bytes) {
			_ = rows.Close()
			t.Fatalf("row %d stored=%s computed=%s length=%d", id, stored, computed, len(bytes))
		}
		got[id] = computed
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want.Rows) {
		t.Fatalf("rows=%v want=%v", got, want.Rows)
	}
	var integrity string
	if err := binding.conn.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity=%q err=%v", integrity, err)
	}
	for _, sidecar := range []string{storeDBName + "-journal", storeDBName + "-wal", storeDBName + "-shm"} {
		if _, err := os.Stat(filepath.Join(root, sidecar)); !os.IsNotExist(err) {
			t.Fatalf("left sidecar %s: %v", sidecar, err)
		}
	}
	sentinel, err := os.ReadFile(filepath.Join(filepath.Dir(root), "outside-sentinel"))
	if err != nil || string(sentinel) != "crash-outside-sentinel" {
		t.Fatalf("outside sentinel changed: %q err=%v", sentinel, err)
	}
}

func assertCrashTrace(t *testing.T, trace []storeTraceEvent, committed bool) {
	t.Helper()
	if err := validateCrashTraceSchema(trace); err != nil {
		t.Fatalf("invalid native trace schema: %v", err)
	}
	if len(trace) == 0 {
		t.Fatal("empty native trace")
	}
	firstMainWrite, journalSync, journalRootSync := -1, -1, -1
	pendingUnlink := -1
	commitControl, closeControl := -1, -1
	journalOpen, journalWrite, unlink, rootSync := false, false, false, false
	truncate := false
	for i, event := range trace {
		if event.Result != 0 && event.Op < storeTraceCommitControl {
			t.Fatalf("native event %d has non-success result=%d", i, event.Result)
		}
		switch event.Op {
		case storeTraceOpen:
			if event.Kind == storeFileJournal {
				journalOpen = true
			}
		case storeTraceWrite:
			if event.Kind == storeFileJournal {
				journalWrite = true
			}
			if event.Kind == storeFileMain && firstMainWrite < 0 {
				firstMainWrite = i
			}
		case storeTraceFileSync:
			if event.Kind == storeFileJournal && journalSync < 0 {
				journalSync = i
			}
		case storeTraceRootSync:
			rootSync = true
			if journalSync >= 0 && journalRootSync < 0 && i > journalSync {
				journalRootSync = i
			}
			if pendingUnlink >= 0 {
				pendingUnlink = -1
			}
		case storeTraceUnlink:
			unlink = true
			if pendingUnlink >= 0 {
				t.Fatalf("unlink seq %d lacked a following root sync before unlink seq %d", trace[pendingUnlink].Seq, event.Seq)
			}
			pendingUnlink = i
		case storeTraceTruncate:
			truncate = true
		case storeTraceCommitControl:
			commitControl = i
		case storeTraceCloseControl:
			closeControl = i
		}
	}
	if !journalOpen || !journalWrite || !unlink || !rootSync {
		t.Fatalf("required journal lifecycle categories missing: open=%v write=%v unlink=%v rootSync=%v trace=%s", journalOpen, journalWrite, unlink, rootSync, encodeCrashTrace(trace))
	}
	if firstMainWrite >= 0 && (journalSync < 0 || journalRootSync < 0) {
		t.Fatalf("main overwrite requires journalSync/rootSync: journalSync=%d journalRootSync=%d firstMainWrite=%d trace=%s", journalSync, journalRootSync, firstMainWrite, encodeCrashTrace(trace))
	}
	if firstMainWrite >= 0 && journalRootSync > firstMainWrite {
		t.Fatalf("journal/root sync occurred after first main write: journalRootSync=%d firstMainWrite=%d", journalRootSync, firstMainWrite)
	}
	if pendingUnlink >= 0 {
		t.Fatalf("unlink seq %d lacked a following root sync before control", trace[pendingUnlink].Seq)
	}
	if commitControl < 0 {
		t.Fatal("missing commit/rollback control")
	}
	if closeControl < 0 || closeControl < commitControl {
		t.Fatalf("missing close control after commit/rollback control: commit=%d close=%d", commitControl, closeControl)
	}
	if !committed && firstMainWrite >= 0 && (journalSync < 0 || journalRootSync < 0) {
		t.Fatal("rollback main overwrite lacked journal sync ordering")
	}
	if !committed && firstMainWrite < 0 {
		t.Log("rollback had no main overwrite; journal sync ordering is conditionally inapplicable")
	}
	t.Logf("trace categories journalSync=%d journalRootSync=%d firstMainWrite=%d truncate=%v", journalSync, journalRootSync, firstMainWrite, truncate)
}

func validateCrashTraceSchema(trace []storeTraceEvent) error {
	if len(trace) == 0 {
		return errors.New("empty trace")
	}
	commitControls, closeControls := 0, 0
	commitIndex, closeIndex := -1, -1
	for i, event := range trace {
		if event.Seq != int64(i+1) {
			return fmt.Errorf("event %d has seq %d, want %d", i, event.Seq, i+1)
		}
		if event.Result != 0 {
			return fmt.Errorf("event %d has result %d", event.Seq, event.Result)
		}
		if event.Offset < 0 {
			return fmt.Errorf("event %d has negative offset", event.Seq)
		}
		switch event.Op {
		case storeTraceOpen:
			if event.Kind != storeFileJournal || event.Offset != 0 || event.Requested <= 0 || event.Completed != 0 {
				return fmt.Errorf("event %d has invalid open tuple", event.Seq)
			}
		case storeTraceWrite:
			if event.Kind != storeFileMain && event.Kind != storeFileJournal {
				return fmt.Errorf("event %d has invalid write kind %d", event.Seq, event.Kind)
			}
			if event.Requested <= 0 || event.Completed <= 0 || event.Completed > event.Requested {
				return fmt.Errorf("event %d has invalid write lengths %d/%d", event.Seq, event.Requested, event.Completed)
			}
		case storeTraceFileSync:
			if event.Kind != storeFileMain && event.Kind != storeFileJournal || event.Offset != 0 || event.Requested != 0 || event.Completed != 0 {
				return fmt.Errorf("event %d has invalid file-sync tuple", event.Seq)
			}
		case storeTraceRootSync:
			if event.Kind != storeTraceKindRoot || event.Offset != 0 || event.Requested != 0 || event.Completed != 0 {
				return fmt.Errorf("event %d has invalid root-sync tuple", event.Seq)
			}
		case storeTraceTruncate:
			if event.Kind != storeFileMain && event.Kind != storeFileJournal || event.Requested != event.Offset || event.Completed != event.Offset {
				return fmt.Errorf("event %d has invalid truncate tuple", event.Seq)
			}
		case storeTraceUnlink:
			if event.Kind != storeFileJournal || event.Offset != 0 || event.Requested != 0 || event.Completed != 0 {
				return fmt.Errorf("event %d has invalid unlink tuple", event.Seq)
			}
		case storeTraceCommitControl:
			if event.Kind != storeTraceKindRoot || event.Offset != 0 || event.Requested != 0 || event.Completed != 0 {
				return fmt.Errorf("event %d has invalid commit-control tuple", event.Seq)
			}
			commitControls++
			commitIndex = i
		case storeTraceCloseControl:
			if event.Kind != storeTraceKindRoot || event.Offset != 0 || event.Requested != 0 || event.Completed != 0 {
				return fmt.Errorf("event %d has invalid close-control tuple", event.Seq)
			}
			closeControls++
			closeIndex = i
		default:
			return fmt.Errorf("event %d has unknown op %d", event.Seq, event.Op)
		}
	}
	if commitControls != 1 || closeControls != 1 {
		return fmt.Errorf("controls commit=%d close=%d", commitControls, closeControls)
	}
	if closeIndex <= commitIndex {
		return errors.New("close control does not follow commit/rollback control")
	}
	for i, event := range trace {
		if event.Op < storeTraceCommitControl && i > commitIndex {
			return fmt.Errorf("native event %d follows control", event.Seq)
		}
	}
	return nil
}

func nativeCrashID(event storeTraceEvent) string {
	return fmt.Sprintf("native-%d-op%d-kind%d-off%d-req%d-done%d", event.Seq, event.Op, event.Kind, event.Offset, event.Requested, event.Completed)
}

func commitCutIDs(trace []storeTraceEvent) []string {
	ids := []string{"baseline-before-first-journal-create"}
	for _, event := range trace {
		if event.Op < storeTraceCommitControl {
			ids = append(ids, nativeCrashID(event))
		}
	}
	for _, event := range trace {
		if event.Op == storeTraceCommitControl {
			ids = append(ids, fmt.Sprintf("after-commit-success-seq%d", event.Seq))
		}
		if event.Op == storeTraceCloseControl {
			ids = append(ids, fmt.Sprintf("after-ordinary-close-seq%d", event.Seq))
		}
	}
	return ids
}

func rollbackDiscoveryIDs(trace []storeTraceEvent) []string {
	ids := make([]string, 0, len(trace))
	for _, event := range trace {
		switch event.Op {
		case storeTraceCommitControl:
			ids = append(ids, fmt.Sprintf("after-rollback-success-seq%d", event.Seq))
		case storeTraceCloseControl:
			ids = append(ids, fmt.Sprintf("after-ordinary-close-seq%d", event.Seq))
		default:
			ids = append(ids, "rollback-observed-"+nativeCrashID(event))
		}
	}
	return ids
}

func assertCommitCutIDs(t *testing.T, trace []storeTraceEvent, ids []string) {
	t.Helper()
	if len(ids) != len(trace)+1 {
		t.Fatalf("commit cuts=%d trace=%d", len(ids), len(trace))
	}
	if ids[0] != "baseline-before-first-journal-create" || ids[len(ids)-2] != fmt.Sprintf("after-commit-success-seq%d", trace[len(trace)-2].Seq) || ids[len(ids)-1] != fmt.Sprintf("after-ordinary-close-seq%d", trace[len(trace)-1].Seq) {
		t.Fatalf("commit cut boundaries=%v", ids)
	}
	assertUniqueStrings(t, ids)
}

func assertRollbackDiscoveryIDs(t *testing.T, trace []storeTraceEvent, ids []string) {
	t.Helper()
	if len(ids) != len(trace) {
		t.Fatalf("rollback IDs=%d trace=%d", len(ids), len(trace))
	}
	if !strings.HasPrefix(ids[len(ids)-2], "after-rollback-success-seq") || !strings.HasPrefix(ids[len(ids)-1], "after-ordinary-close-seq") {
		t.Fatalf("rollback cut boundaries=%v", ids)
	}
	assertUniqueStrings(t, ids)
}

func assertUniqueStrings(t *testing.T, values []string) {
	t.Helper()
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			t.Fatalf("duplicate cut ID %q", value)
		}
		seen[value] = struct{}{}
	}
}

func encodeCutIDs(trace []storeTraceEvent) string {
	ids := commitCutIDs(trace)
	raw, err := json.Marshal(ids)
	if err != nil {
		return fmt.Sprintf("cut-encode-error:%v", err)
	}
	return string(raw)
}

func encodeRollbackIDs(trace []storeTraceEvent) string {
	raw, err := json.Marshal(rollbackDiscoveryIDs(trace))
	if err != nil {
		return fmt.Sprintf("rollback-encode-error:%v", err)
	}
	return string(raw)
}

func encodeCrashTrace(trace []storeTraceEvent) string {
	raw, err := json.Marshal(trace)
	if err != nil {
		return fmt.Sprintf("trace-encode-error:%v", err)
	}
	return string(raw)
}

func crashBlob(seed, size int) []byte { return workloadBlob(seed, size) }
