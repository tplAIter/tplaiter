//go:build darwin || linux

package trustload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
)

const hostileRecoveryChildEnv = "TPLAITER_HOSTILE_RECOVERY_CHILD"

type hostileRecoveryJournalEvent struct {
	Seq       int64 `json:"seq"`
	Op        int64 `json:"op"`
	Kind      int64 `json:"kind"`
	Offset    int64 `json:"offset"`
	Requested int64 `json:"requested"`
	Completed int64 `json:"completed"`
	Result    int64 `json:"result"`
}

// TestRefreshHostileRecoverySB06Composition keeps hostile sidecars in an
// active signed store and proves both ordinary and recovery routes fail closed
// without changing the active namespace. Journal corruption from a killed
// Refresh is covered by TestRefreshJournalCrashSB06; this row covers hostile
// replacement forms at the composition boundary.
func TestRefreshHostileRecoverySB06Composition(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(*testing.T, string)
	}{
		{"wal", func(t *testing.T, r string) {
			if err := os.WriteFile(filepath.Join(r, storeDBName+"-wal"), []byte("hostile"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"shm", func(t *testing.T, r string) {
			if err := os.WriteFile(filepath.Join(r, storeDBName+"-shm"), []byte("hostile"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"journal-symlink", func(t *testing.T, r string) {
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(r, storeDBName+"-journal")); err != nil {
				t.Fatal(err)
			}
		}},
		{"journal-permission", func(t *testing.T, r string) {
			p := filepath.Join(r, storeDBName+"-journal")
			if err := os.WriteFile(p, []byte("bad"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := unavailableEnrolledFixture(t)
			root := f.loaded.Install.OSS.StorePath
			tc.make(t, root)
			before := unavailableSnapshotTree(t, root)
			s, err := OpenReadOnly(context.Background(), f.selection)
			if s != nil || err == nil {
				if s != nil {
					s.Close()
				}
				t.Fatalf("ordinary accepted err=%v", err)
			}
			assertSafeUnavailableError(t, err)
			assertUnavailableSnapshotTree(t, root, before)
			err = RecoverState(context.Background(), f.selection, f.factory)
			if err == nil || (!errors.Is(err, ErrPending) && !errors.Is(err, ErrProvenanceUnavailable)) {
				t.Fatalf("recover err=%v", err)
			}
			assertSafeUnavailableError(t, err)
			assertUnavailableSnapshotTree(t, root, before)
		})
	}
}

// TestRefreshHostileRecoveryCorruptJournalSB06 starts actual signed Refresh,
// stops it only after the VFS reports a real hot journal sync, then changes
// one byte in that journal. The corrupt sidecar is attacker input, never a
// recovery aid: both ordinary and explicit recovery must retain it unchanged.
func TestRefreshHostileRecoveryCorruptJournalSB06(t *testing.T) {
	f := unavailableEnrolledFixture(t)
	next, evidence := rotateBundle(t, f)
	old, wantNew := deriveRefreshSB06Heads(t, f, next, evidence)
	payload, err := json.Marshal(refreshSB06Payload{Selection: f.selection, NextBundle: next, NextEvidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(f.load.dir, "hostile-recovery-payload.json")
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	eventR, eventW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		_ = eventR.Close()
		_ = eventW.Close()
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRefreshHostileRecoveryChild$")
	cmd.Env = append(os.Environ(), hostileRecoveryChildEnv+"=1", "TPLAITER_HOSTILE_RECOVERY_PAYLOAD="+payloadPath)
	cmd.ExtraFiles = []*os.File{eventW, ackR}
	if err := cmd.Start(); err != nil {
		_ = eventR.Close()
		_ = eventW.Close()
		_ = ackR.Close()
		_ = ackW.Close()
		t.Fatal(err)
	}
	killed, reaped := false, false
	var killErr, waitErr error
	killAndReap := func() {
		if !killed {
			killErr = cmd.Process.Kill()
			killed = true
		}
		if !reaped {
			waitErr = cmd.Wait()
			reaped = true
		}
	}
	defer killAndReap()
	_ = eventW.Close()
	_ = ackR.Close()
	defer eventR.Close()
	defer ackW.Close()
	journal := filepath.Join(f.loaded.Install.OSS.StorePath, storeDBName+"-journal")
	decoder := json.NewDecoder(eventR)
	journalSynced, journalRootSynced := false, false
	var selected hostileRecoveryJournalEvent
	var trace []hostileRecoveryJournalEvent
	for {
		if err := eventR.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var event hostileRecoveryJournalEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatalf("hostile journal event: %v", err)
		}
		trace = append(trace, event)
		snapshot := refreshJournalSnapshot(t, journal)
		if event.Kind == storeFileJournal && event.Op == storeTraceFileSync && event.Result == 0 && snapshot.Present && len(snapshot.Bytes) > 0 && snapshot.Bytes[0] != 0 {
			journalSynced = true
		}
		if journalSynced && event.Kind == storeTraceKindRoot && event.Op == storeTraceRootSync && event.Result == 0 {
			journalRootSynced = true
		}
		if journalRootSynced && event.Kind == storeFileMain && event.Op == storeTraceWrite && event.Result == 0 && event.Completed > 0 {
			selected = event
			break
		}
		if _, err := ackW.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	killAndReap()
	if killErr != nil || waitErr == nil || cmd.ProcessState == nil {
		t.Fatalf("child kill=%v wait=%v", killErr, waitErr)
	}
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !status.Signaled() {
		t.Fatalf("child wait status=%v", cmd.ProcessState.Sys())
	}
	preCorrupt := refreshJournalSnapshot(t, journal)
	if !preCorrupt.Present || len(preCorrupt.Bytes) == 0 {
		t.Fatal("selected hot journal disappeared before corruption")
	}
	corrupt := append([]byte(nil), preCorrupt.Bytes...)
	// SQLite rollback journals start with an eight-byte magic header. Corrupt
	// its first magic byte, rather than an arbitrary midpoint, after a traced
	// journal sync and traced main-page overwrite.
	const corruptOffset = 0
	corrupt[corruptOffset] ^= 0x80
	file, err := os.OpenFile(journal, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(corrupt[corruptOffset:corruptOffset+1], corruptOffset); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	before := unavailableSnapshotTree(t, f.loaded.Install.OSS.StorePath)
	if after := refreshJournalSnapshot(t, journal); after.Dev != preCorrupt.Dev || after.Ino != preCorrupt.Ino || string(after.Bytes) != string(corrupt) {
		t.Fatal("corruption did not retain the real journal identity and controlled bytes")
	}
	store, err := OpenReadOnly(context.Background(), f.selection)
	if store != nil || !errors.Is(err, ErrPending) {
		if store != nil {
			_ = store.Close()
		}
		t.Fatal("ordinary reader did not return typed pending denial")
	}
	assertSafeUnavailableError(t, err)
	assertUnavailableSnapshotTree(t, f.loaded.Install.OSS.StorePath, before)
	recoveryObserver := &storeProofObserver{}
	var recoveryTrace []storeTraceEvent
	recoveryObserver.traceHook = func(event storeTraceEvent) { recoveryTrace = append(recoveryTrace, event) }
	previousRecoveryHook := storeRecoveryHook
	var recoveryStages []string
	storeRecoveryHook = func(stage string) {
		recoveryStages = append(recoveryStages, stage)
		if previousRecoveryHook != nil {
			previousRecoveryHook(stage)
		}
	}
	t.Cleanup(func() { storeRecoveryHook = previousRecoveryHook })
	recoveryCtx := context.WithValue(context.Background(), storeProofObserverKey{}, recoveryObserver)
	err = RecoverState(recoveryCtx, f.selection, f.factory)
	if err == nil || (!errors.Is(err, ErrPending) && !errors.Is(err, ErrProvenanceUnavailable)) {
		t.Fatalf("recovery did not return declared hostile-journal denial after traced main write seq=%d offset=%d bytes=%d trace=%v", selected.Seq, selected.Offset, selected.Completed, trace)
	}
	assertSafeUnavailableError(t, err)
	if containsHostileRecoveryStage(recoveryStages, "after-recovery") {
		t.Fatal("corrupt witness unexpectedly reached after-recovery; this row must not claim final VerifyOSS failure")
	}
	recoveryFailureStage := "before-after-recovery"
	afterFirst := assertHostileRecoveryFailureState(t, f.loaded.Install.OSS.StorePath, before, recoveryTrace, true)

	secondObserver := &storeProofObserver{}
	var secondTrace []storeTraceEvent
	secondObserver.traceHook = func(event storeTraceEvent) { secondTrace = append(secondTrace, event) }
	err = RecoverState(context.WithValue(context.Background(), storeProofObserverKey{}, secondObserver), f.selection, f.factory)
	if err == nil || (!errors.Is(err, ErrPending) && !errors.Is(err, ErrProvenanceUnavailable)) {
		t.Fatal("repeat recovery did not return declared denial for its current state")
	}
	assertSafeUnavailableError(t, err)
	assertHostileRecoveryFailureState(t, f.loaded.Install.OSS.StorePath, afterFirst, secondTrace, false)
	ordinaryStage := assertHostileOrdinaryResult(t, f, old, wantNew)
	if ordinaryStage == "" {
		t.Fatal("ordinary result did not record a denial gate")
	}
	t.Logf("corrupt recovery_failure_stage=%s stages=%v ordinary_denial_gate=%s", recoveryFailureStage, recoveryStages, ordinaryStage)
}

func containsHostileRecoveryStage(stages []string, want string) bool {
	for _, stage := range stages {
		if stage == want {
			return true
		}
	}
	return false
}

func TestRefreshHostileRecoveryChild(t *testing.T) {
	if os.Getenv(hostileRecoveryChildEnv) != "1" {
		t.Skip("child")
	}
	event := os.NewFile(uintptr(3), "hostile-recovery-events")
	ack := os.NewFile(uintptr(4), "hostile-recovery-acks")
	if event == nil || ack == nil {
		t.Fatal("missing inherited hostile recovery pipes")
	}
	defer event.Close()
	defer ack.Close()
	payload, err := os.ReadFile(os.Getenv("TPLAITER_HOSTILE_RECOVERY_PAYLOAD"))
	if err != nil {
		t.Fatal(err)
	}
	var request refreshSB06Payload
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	observer := &storeProofObserver{}
	observer.traceHook = func(trace storeTraceEvent) {
		if (trace.Kind != storeFileJournal && trace.Kind != storeFileMain && trace.Kind != storeTraceKindRoot) || (trace.Op != storeTraceOpen && trace.Op != storeTraceWrite && trace.Op != storeTraceFileSync && trace.Op != storeTraceRootSync) {
			return
		}
		if err := json.NewEncoder(event).Encode(hostileRecoveryJournalEvent(trace)); err != nil {
			os.Exit(2)
		}
		var reply [1]byte
		if _, err := io.ReadFull(ack, reply[:]); err != nil || reply[0] != 1 {
			os.Exit(2)
		}
	}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
	if _, err := Refresh(ctx, request.Selection, refreshSB06Factory, request.NextBundle, request.NextEvidence); err == nil {
		t.Fatal("child refresh returned before parent kill")
	}
}

func assertHostileRecoveryFailureState(t *testing.T, root string, before []unavailableEntry, trace []storeTraceEvent, requireUnlink bool) []unavailableEntry {
	t.Helper()
	after := unavailableSnapshotTree(t, root)
	journal := filepath.Join(root, storeDBName+"-journal")
	beforeByPath := make(map[string]unavailableEntry, len(before))
	for _, entry := range before {
		beforeByPath[entry.path] = entry
	}
	afterByPath := make(map[string]unavailableEntry, len(after))
	for _, entry := range after {
		afterByPath[entry.path] = entry
	}
	mainChangedBySQLite := false
	for _, event := range trace {
		if event.Kind == storeFileMain && (event.Op == storeTraceWrite || event.Op == storeTraceTruncate) && event.Result == 0 {
			mainChangedBySQLite = true
		}
	}
	for path, prior := range beforeByPath {
		current, present := afterByPath[path]
		if path == journal && requireUnlink {
			if present {
				t.Fatal("SQLite recovery did not remove its traced corrupt journal")
			}
			continue
		}
		if !present {
			t.Fatalf("recovery removed non-journal entry %q", path)
		}
		metadataEqual := prior.dev == current.dev && prior.ino == current.ino && prior.mode == current.mode && prior.uid == current.uid && prior.nlink == current.nlink && prior.size == current.size && prior.mtimeSec == current.mtimeSec && prior.mtimeNanosec == current.mtimeNanosec
		contentEqual := prior.hasContent == current.hasContent && bytes.Equal(prior.content, current.content)
		if metadataEqual && contentEqual {
			continue
		}
		if !prior.hasContent && prior.dev == current.dev && prior.ino == current.ino {
			continue // SQLite xDelete's required root sync legitimately updates directory mtime.
		}
		if filepath.Base(path) != storeDBName || !mainChangedBySQLite || prior.dev != current.dev || prior.ino != current.ino || prior.mode != current.mode || prior.uid != current.uid || prior.nlink != current.nlink {
			t.Fatalf("recovery changed protected entry %q", path)
		}
	}
	for path := range afterByPath {
		if _, present := beforeByPath[path]; !present {
			t.Fatalf("recovery created unexpected entry %q", path)
		}
	}
	if requireUnlink {
		unlink, rootSyncAfter := -1, false
		for i, event := range trace {
			if event.Op == storeTraceUnlink && event.Kind == storeFileJournal && event.Result == 0 {
				unlink = i
			}
			if unlink >= 0 && i > unlink && event.Op == storeTraceRootSync && event.Kind == storeTraceKindRoot && event.Result == 0 {
				rootSyncAfter = true
			}
		}
		if unlink < 0 || !rootSyncAfter {
			t.Fatal("failed recovery lacked traced SQLite journal unlink followed by root sync")
		}
	}
	return after
}

func assertHostileOrdinaryResult(t *testing.T, fixture bootstrapFixture, old, wantNew refreshSB06Head) string {
	t.Helper()
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		assertSafeUnavailableError(t, err)
		return "OpenReadOnly"
	}
	defer store.Close()
	if _, err := store.Load(context.Background()); err != nil {
		assertSafeUnavailableError(t, err)
		return "Store.Load"
	}
	external, err := bootstrap.LoadExternal(context.Background(), store)
	if err != nil || external == nil {
		if err == nil {
			t.Fatal("LoadExternal returned nil context without error")
		}
		if external != nil {
			t.Fatal("LoadExternal returned context with error")
		}
		assertSafeUnavailableError(t, err)
		return "LoadExternal"
	}
	authority, err := verifyCurrent(context.Background(), store, fixture.factory)
	if err != nil || authority == nil {
		if err == nil {
			t.Fatal("VerifyOSS returned nil authority without error")
		}
		if authority != nil {
			t.Fatal("VerifyOSS returned authority with error")
		}
		assertSafeUnavailableError(t, err)
		return "VerifyOSS"
	}
	got := readRefreshSB06Head(t, store)
	if !refreshSB06HeadsEqual(got, old) && !refreshSB06HeadsEqual(got, wantNew) {
		t.Fatal("ordinary authority followed corrupt recovery without a complete old/new head")
	}
	t.Fatal("ordinary authority unexpectedly followed typed corrupt-recovery denial")
	return ""
}
