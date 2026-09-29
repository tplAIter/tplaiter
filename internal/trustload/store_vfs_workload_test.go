//go:build darwin || linux

package trustload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"golang.org/x/sys/unix"
)

const workloadBlobSize = 16 << 20

type workloadMemory struct {
	NativeRSSBaseline uint64
	NativeRSSPeak     uint64
	NativeRSSDelta    uint64
	HeapBaseline      uint64
	HeapPeak          uint64
	HeapDelta         uint64
}

type workloadTuple struct {
	IDs        []int
	Lengths    []int
	Digests    []string
	Head       string
	Generation int64
	Links      string
}

func TestStoreVFSWorkloadWORK01AndWORK02(t *testing.T) {
	t.Run("WORK01-commit-constrained-64MiB", func(t *testing.T) {
		old, _ := newWorkloadFixture(t, false)
		mem := workloadMemoryStart()
		ctx := context.Background()
		if err := configureWorkloadConnection(ctx, old.binding); err != nil {
			t.Fatal(err)
		}
		if _, err := old.binding.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		for id := 1; id <= 4; id++ {
			blob := workloadBlob(id, workloadBlobSize)
			if _, err := old.binding.conn.ExecContext(ctx, "INSERT INTO workload_blobs(id,bytes,digest) VALUES(?,?,?)", id, blob, workloadDigest(blob)); err != nil {
				_ = workloadRollback(old.binding)
				t.Fatal(err)
			}
			workloadMemorySample(&mem)
		}
		if _, err := old.binding.conn.ExecContext(ctx, "UPDATE workload_meta SET head='head-commit', generation=2, links='1,2,3,4' WHERE singleton=1"); err != nil {
			_ = workloadRollback(old.binding)
			t.Fatal(err)
		}
		if _, err := old.binding.conn.ExecContext(ctx, "COMMIT"); err != nil {
			t.Fatal(err)
		}
		workloadMemorySample(&mem)
		got := workloadOpenClasses(old.binding)
		attempts := workloadOpenAttempts(old.binding)
		if got[storeFileMain] == 0 || got[storeFileJournal] == 0 {
			t.Fatalf("actual open classes main/journal=%v", got)
		}
		if attempts[0] != 0 || attempts[storeFileMain] == 0 || attempts[storeFileJournal] == 0 {
			t.Fatalf("WORK01 forbidden/unknown open attempts=%v successful=%v", attempts, got)
		}
		t.Logf("WORK01 actual_open_classes main=%d journal=%d attempts=%v", got[storeFileMain], got[storeFileJournal], attempts)
		if err := workloadClose(old); err != nil {
			t.Fatal(err)
		}
		want := workloadCommittedTuple()
		checkWorkloadReopen(t, old.root, want, true, "head-commit", 2, "1,2,3,4")
		workloadMemoryFinish(&mem)
		t.Logf("WORK01 memory native_rss_baseline=%d peak=%d delta=%d bytes go_heap_baseline=%d peak=%d delta=%d bytes cache_kib=64 blobs=%d aggregate=%d", mem.NativeRSSBaseline, mem.NativeRSSPeak, mem.NativeRSSDelta, mem.HeapBaseline, mem.HeapPeak, mem.HeapDelta, workloadBlobSize, 4*workloadBlobSize)
	})

	t.Run("WORK02A-rollback-new-64MiB", func(t *testing.T) {
		old, want := newWorkloadFixture(t, false)
		mem := workloadMemoryStart()
		ctx := context.Background()
		if err := configureWorkloadConnection(ctx, old.binding); err != nil {
			t.Fatal(err)
		}
		if _, err := old.binding.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		for id := 1; id <= 4; id++ {
			blob := workloadBlob(id, workloadBlobSize)
			if _, err := old.binding.conn.ExecContext(ctx, "INSERT INTO workload_blobs(id,bytes,digest) VALUES(?,?,?)", id, blob, workloadDigest(blob)); err != nil {
				_ = workloadRollback(old.binding)
				t.Fatal(err)
			}
			workloadMemorySample(&mem)
		}
		if _, err := old.binding.conn.ExecContext(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		workloadMemorySample(&mem)
		got := workloadOpenClasses(old.binding)
		attempts := workloadOpenAttempts(old.binding)
		if got[storeFileMain] == 0 || got[storeFileJournal] == 0 {
			t.Fatalf("actual open classes main/journal=%v", got)
		}
		if attempts[0] != 0 || attempts[storeFileMain] == 0 || attempts[storeFileJournal] == 0 {
			t.Fatalf("WORK02A forbidden/unknown open attempts=%v successful=%v", attempts, got)
		}
		t.Logf("WORK02A actual_open_classes main=%d journal=%d attempts=%v", got[storeFileMain], got[storeFileJournal], attempts)
		if err := workloadClose(old); err != nil {
			t.Fatal(err)
		}
		checkWorkloadReopen(t, old.root, want, false, "head-old", 1, "old-link")
		workloadMemoryFinish(&mem)
		t.Logf("WORK02A memory native_rss_baseline=%d peak=%d delta=%d bytes go_heap_baseline=%d peak=%d delta=%d bytes cache_kib=64 blobs=%d aggregate=%d", mem.NativeRSSBaseline, mem.NativeRSSPeak, mem.NativeRSSDelta, mem.HeapBaseline, mem.HeapPeak, mem.HeapDelta, workloadBlobSize, 4*workloadBlobSize)
	})

	t.Run("WORK02B-rollback-existing-large-rows", func(t *testing.T) {
		old, want := newWorkloadFixture(t, true)
		mem := workloadMemoryStart()
		ctx := context.Background()
		if err := configureWorkloadConnection(ctx, old.binding); err != nil {
			t.Fatal(err)
		}
		if _, err := old.binding.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		for id := 1; id <= 2; id++ {
			blob := workloadBlob(id+11, 8<<20)
			if _, err := old.binding.conn.ExecContext(ctx, "UPDATE workload_blobs SET bytes=?, digest=? WHERE id=?", blob, workloadDigest(blob), id); err != nil {
				_ = workloadRollback(old.binding)
				t.Fatal(err)
			}
			workloadMemorySample(&mem)
		}
		if _, err := old.binding.conn.ExecContext(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		workloadMemorySample(&mem)
		got := workloadOpenClasses(old.binding)
		attempts := workloadOpenAttempts(old.binding)
		if got[storeFileMain] == 0 || got[storeFileJournal] == 0 {
			t.Fatalf("actual open classes main/journal=%v", got)
		}
		if attempts[0] != 0 || attempts[storeFileMain] == 0 || attempts[storeFileJournal] == 0 {
			t.Fatalf("WORK02B forbidden/unknown open attempts=%v successful=%v", attempts, got)
		}
		t.Logf("WORK02B actual_open_classes main=%d journal=%d attempts=%v", got[storeFileMain], got[storeFileJournal], attempts)
		if err := workloadClose(old); err != nil {
			t.Fatal(err)
		}
		checkWorkloadReopen(t, old.root, want, false, "head-old", 1, "old-link")
		workloadMemoryFinish(&mem)
		t.Logf("WORK02B memory native_rss_baseline=%d peak=%d delta=%d bytes go_heap_baseline=%d peak=%d delta=%d bytes cache_kib=64 blobs=2 aggregate=%d", mem.NativeRSSBaseline, mem.NativeRSSPeak, mem.NativeRSSDelta, mem.HeapBaseline, mem.HeapPeak, mem.HeapDelta, 16<<20)
	})
}

type workloadFixture struct {
	root     string
	lease    *rootLease
	binding  *sqlBinding
	observer *storeProofObserver
}

func newWorkloadFixture(t *testing.T, large bool) (workloadFixture, workloadTuple) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside-sentinel")
	if err := os.WriteFile(outside, []byte("outside-workload-sentinel"), 0o600); err != nil {
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
	ctx = context.Background()
	if err := configureWorkloadConnection(ctx, binding); err != nil {
		_ = binding.Close()
		_ = lease.Close()
		t.Fatal(err)
	}
	if _, err := binding.conn.ExecContext(ctx, `CREATE TABLE workload_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), head TEXT NOT NULL, generation INTEGER NOT NULL, links TEXT NOT NULL); CREATE TABLE workload_blobs(id INTEGER PRIMARY KEY, bytes BLOB NOT NULL, digest TEXT NOT NULL); INSERT INTO workload_meta VALUES(1,'head-old',1,'old-link')`); err != nil {
		_ = binding.Close()
		_ = lease.Close()
		t.Fatal(err)
	}
	if large {
		for id := 1; id <= 2; id++ {
			blob := workloadBlob(id+7, 8<<20)
			if _, err := binding.conn.ExecContext(ctx, "INSERT INTO workload_blobs(id,bytes,digest) VALUES(?,?,?)", id, blob, workloadDigest(blob)); err != nil {
				_ = binding.Close()
				_ = lease.Close()
				t.Fatal(err)
			}
		}
	}
	want := workloadTuple{Head: "head-old", Generation: 1, Links: "old-link"}
	if large {
		for id := 1; id <= 2; id++ {
			blob := workloadBlob(id+7, 8<<20)
			want.IDs = append(want.IDs, id)
			want.Lengths = append(want.Lengths, len(blob))
			want.Digests = append(want.Digests, workloadDigest(blob))
		}
	}
	return workloadFixture{root: root, lease: lease, binding: binding, observer: observer}, want
}

func configureWorkloadConnection(ctx context.Context, binding *sqlBinding) error {
	for _, stmt := range []string{"PRAGMA temp_store=MEMORY", "PRAGMA cache_size=-64", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL"} {
		if _, err := binding.conn.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	var temp string
	var cache int
	var journal, syncMode string
	if err := binding.conn.QueryRowContext(ctx, "PRAGMA temp_store").Scan(&temp); err != nil || temp != "2" {
		return fmt.Errorf("temp_store readback=%q err=%w", temp, err)
	}
	if err := binding.conn.QueryRowContext(ctx, "PRAGMA cache_size").Scan(&cache); err != nil || cache != -64 {
		return fmt.Errorf("cache_size readback=%d err=%w", cache, err)
	}
	if err := binding.conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil || journal != "delete" {
		return fmt.Errorf("journal_mode readback=%q err=%w", journal, err)
	}
	if err := binding.conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&syncMode); err != nil || syncMode != "2" {
		return fmt.Errorf("synchronous readback=%q err=%w", syncMode, err)
	}
	return nil
}

func workloadRollback(binding *sqlBinding) error {
	_, err := binding.conn.ExecContext(context.Background(), "ROLLBACK")
	return err
}

func workloadClose(f workloadFixture) error {
	if err := f.binding.Close(); err != nil {
		_ = f.lease.Close()
		return err
	}
	return f.lease.Close()
}

func checkWorkloadReopen(t *testing.T, root string, want workloadTuple, committed bool, head string, generation int64, links string) {
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
	if err := configureWorkloadConnection(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	var gotHead, gotLinks string
	var gotGeneration int64
	if err := binding.conn.QueryRowContext(context.Background(), "SELECT head,generation,links FROM workload_meta WHERE singleton=1").Scan(&gotHead, &gotGeneration, &gotLinks); err != nil {
		t.Fatal(err)
	}
	if gotHead != head || gotGeneration != generation || gotLinks != links {
		t.Fatalf("metadata=%q/%d/%q want=%q/%d/%q", gotHead, gotGeneration, gotLinks, head, generation, links)
	}
	rows, err := binding.conn.QueryContext(context.Background(), "SELECT id,bytes,digest FROM workload_blobs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	var got workloadTuple
	for rows.Next() {
		var id int
		var bytes []byte
		var digest string
		if err := rows.Scan(&id, &bytes, &digest); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		got.IDs = append(got.IDs, id)
		got.Lengths = append(got.Lengths, len(bytes))
		got.Digests = append(got.Digests, workloadDigest(bytes))
		if digest != got.Digests[len(got.Digests)-1] {
			_ = rows.Close()
			t.Fatalf("row %d persisted digest=%s recomputed digest=%s", id, digest, got.Digests[len(got.Digests)-1])
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got.IDs) != fmt.Sprint(want.IDs) || fmt.Sprint(got.Lengths) != fmt.Sprint(want.Lengths) || fmt.Sprint(got.Digests) != fmt.Sprint(want.Digests) {
		t.Fatalf("rows=%v/%v/%v want=%v/%v/%v committed=%v", got.IDs, got.Lengths, got.Digests, want.IDs, want.Lengths, want.Digests, committed)
	}
	var integrity string
	if err := binding.conn.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity_check=%q err=%v", integrity, err)
	}
	for _, sidecar := range []string{storeDBName + "-journal", storeDBName + "-wal", storeDBName + "-shm", "sqlite-temp"} {
		if _, err := os.Stat(filepath.Join(root, sidecar)); !os.IsNotExist(err) {
			t.Fatalf("left sidecar %s: %v", sidecar, err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if fmt.Sprint(names) != fmt.Sprint([]string{storeDBName}) {
		t.Fatalf("unexpected root entries=%v", names)
	}
	sentinel, err := os.ReadFile(filepath.Join(filepath.Dir(root), "outside-sentinel"))
	if err != nil || string(sentinel) != "outside-workload-sentinel" {
		t.Fatalf("outside sentinel changed: %q err=%v", sentinel, err)
	}
}

func workloadBlob(seed, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte((i + seed*31) % 251)
	}
	return b
}

func workloadDigest(b []byte) string {
	d := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(d[:])
}

func workloadOpenClasses(binding *sqlBinding) [3]int64 {
	observer := binding.gate.proof
	observer.mu.Lock()
	defer observer.mu.Unlock()
	var classes [3]int64
	for i, count := range observer.openClasses {
		classes[i] = int64(count)
	}
	return classes
}

func workloadOpenAttempts(binding *sqlBinding) [3]int {
	observer := binding.gate.proof
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return observer.openAttempts
}

func workloadCommittedTuple() workloadTuple {
	var tuple workloadTuple
	for id := 1; id <= 4; id++ {
		blob := workloadBlob(id, workloadBlobSize)
		tuple.IDs = append(tuple.IDs, id)
		tuple.Lengths = append(tuple.Lengths, len(blob))
		tuple.Digests = append(tuple.Digests, workloadDigest(blob))
	}
	return tuple
}

func workloadMemoryStart() workloadMemory {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rss := workloadRSS()
	return workloadMemory{NativeRSSBaseline: rss, NativeRSSPeak: rss, HeapBaseline: ms.HeapAlloc, HeapPeak: ms.HeapAlloc}
}

func workloadMemorySample(m *workloadMemory) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if rss := workloadRSS(); rss > m.NativeRSSPeak {
		m.NativeRSSPeak = rss
	}
	if ms.HeapAlloc > m.HeapPeak {
		m.HeapPeak = ms.HeapAlloc
	}
}

func workloadMemoryFinish(m *workloadMemory) {
	if m.NativeRSSPeak >= m.NativeRSSBaseline {
		m.NativeRSSDelta = m.NativeRSSPeak - m.NativeRSSBaseline
	}
	if m.HeapPeak >= m.HeapBaseline {
		m.HeapDelta = m.HeapPeak - m.HeapBaseline
	}
}

func workloadRSS() uint64 {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	rss := uint64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		rss *= 1024
	}
	return rss
}
