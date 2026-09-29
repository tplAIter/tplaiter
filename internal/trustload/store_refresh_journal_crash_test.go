//go:build darwin || linux

package trustload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const refreshJournalChildEnv = "TPLAITER_REFRESH_JOURNAL_CHILD"

type refreshJournalEvent struct {
	Op        int64 `json:"op"`
	Kind      int64 `json:"kind"`
	Offset    int64 `json:"offset"`
	Requested int64 `json:"requested"`
	Completed int64 `json:"completed"`
}

// TestRefreshJournalCrashSB06 obtains journal classes from actual Refresh VFS
// events. The test never creates, truncates, or edits a journal itself.
func TestRefreshJournalCrashSB06(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, class := range []string{"empty", "cold", "hot"} {
		t.Run(class, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
				t.Fatal(err)
			}
			next, evidence := rotateBundle(t, fixture)
			old, nextHead := deriveRefreshSB06Heads(t, fixture, next, evidence)
			payload, err := json.Marshal(refreshSB06Payload{Selection: fixture.selection, NextBundle: next, NextEvidence: evidence})
			if err != nil {
				t.Fatal(err)
			}
			payloadPath := filepath.Join(fixture.load.dir, "refresh-journal-payload.json")
			if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
				t.Fatal(err)
			}
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
			cmd := exec.Command(os.Args[0], "-test.run=^TestRefreshJournalCrashChild$")
			cmd.Env = append(os.Environ(), refreshJournalChildEnv+"=1", "TPLAITER_REFRESH_JOURNAL_PAYLOAD="+payloadPath)
			cmd.ExtraFiles = []*os.File{eventW, ackR}
			if err := cmd.Start(); err != nil {
				eventR.Close()
				eventW.Close()
				ackR.Close()
				ackW.Close()
				t.Fatal(err)
			}
			killIssued, reaped := false, false
			var killErr, waitErr error
			killAndReap := func() {
				if !killIssued {
					killErr = cmd.Process.Kill()
					killIssued = true
				}
				if !reaped {
					waitErr = cmd.Wait()
					reaped = true
				}
			}
			defer killAndReap()
			eventW.Close()
			ackR.Close()
			defer eventR.Close()
			defer ackW.Close()
			decoder := json.NewDecoder(eventR)
			var selectedOK bool
			journal := filepath.Join(fixture.loaded.Install.OSS.StorePath, storeDBName+"-journal")
			for {
				if err := eventR.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
					t.Fatal(err)
				}
				var event refreshJournalEvent
				if err := decoder.Decode(&event); err != nil {
					t.Fatalf("class %s event: %v", class, err)
				}
				snapshot := refreshJournalSnapshot(t, journal)
				if refreshJournalClassMatches(class, snapshot, event) {
					selectedOK = true
					break
				}
				if _, err := ackW.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
			}
			if !selectedOK {
				t.Fatalf("class %s had no matching real journal event", class)
			}
			pre := refreshJournalSnapshot(t, journal)
			if !pre.Present {
				t.Fatalf("class %s candidate had no journal", class)
			}
			killAndReap()
			if killErr != nil {
				t.Fatal(killErr)
			}
			if waitErr == nil || cmd.ProcessState == nil {
				t.Fatalf("class %s child was not reaped after SIGKILL", class)
			}
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() {
				t.Fatalf("class %s wait status=%v", class, cmd.ProcessState.Sys())
			}
			beforeReader := refreshJournalSnapshot(t, journal)
			if _, err := OpenReadOnly(context.Background(), fixture.selection); err == nil {
				t.Fatalf("class %s ordinary reader accepted pending journal", class)
			}
			afterReader := refreshJournalSnapshot(t, journal)
			if !reflect.DeepEqual(beforeReader, afterReader) {
				t.Fatalf("class %s ordinary reader changed journal sidecar", class)
			}
			if err := RecoverState(context.Background(), fixture.selection, refreshSB06Factory); err != nil {
				t.Fatalf("class %s recover: %v", class, err)
			}
			allowed := map[string]bool{"old": true, "new": true}
			assertRefreshSB06RecoveredHead(t, fixture, old, nextHead, allowed)
		})
	}
}

func TestRefreshJournalCrashChild(t *testing.T) {
	if os.Getenv(refreshJournalChildEnv) != "1" {
		t.Skip("child")
	}
	event := os.NewFile(uintptr(3), "refresh-journal-events")
	ack := os.NewFile(uintptr(4), "refresh-journal-acks")
	if event == nil || ack == nil {
		t.Fatal("missing inherited journal pipes")
	}
	defer event.Close()
	defer ack.Close()
	raw, err := os.ReadFile(os.Getenv("TPLAITER_REFRESH_JOURNAL_PAYLOAD"))
	if err != nil {
		t.Fatal(err)
	}
	var payload refreshSB06Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	observer := &storeProofObserver{}
	observer.traceHook = func(trace storeTraceEvent) {
		if trace.Kind != storeFileJournal || (trace.Op != storeTraceOpen && trace.Op != storeTraceWrite && trace.Op != storeTraceFileSync) {
			return
		}
		if err := json.NewEncoder(event).Encode(refreshJournalEvent{Op: trace.Op, Kind: trace.Kind, Offset: trace.Offset, Requested: trace.Requested, Completed: trace.Completed}); err != nil {
			os.Exit(2)
		}
		var b [1]byte
		if _, err := io.ReadFull(ack, b[:]); err != nil || b[0] != 1 {
			os.Exit(2)
		}
	}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
	if _, err := Refresh(ctx, payload.Selection, refreshSB06Factory, payload.NextBundle, payload.NextEvidence); err == nil {
		t.Fatal("child refresh returned before parent kill")
	}
}

type refreshJournalSidecar struct {
	Present   bool   `json:"present"`
	Dev       uint64 `json:"dev,omitempty"`
	Ino       uint64 `json:"ino,omitempty"`
	Mode      uint32 `json:"mode,omitempty"`
	UID       uint32 `json:"uid,omitempty"`
	Nlink     uint64 `json:"nlink,omitempty"`
	Size      int64  `json:"size,omitempty"`
	MTimeSec  int64  `json:"mtimeSec,omitempty"`
	MTimeNsec int64  `json:"mtimeNsec,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Bytes     []byte `json:"bytes,omitempty"`
}

func refreshJournalClassMatches(class string, snapshot refreshJournalSidecar, event refreshJournalEvent) bool {
	if !snapshot.Present {
		return false
	}
	size := snapshot.Size
	first := -1
	if len(snapshot.Bytes) > 0 {
		first = int(snapshot.Bytes[0])
	}
	switch class {
	case "empty":
		return event.Op == storeTraceOpen && size == 0
	case "cold":
		return event.Op == storeTraceWrite && size > 0 && first == 0
	case "hot":
		return event.Op == storeTraceFileSync && size > 0 && first != 0
	default:
		return false
	}
}

func refreshJournalSnapshot(t *testing.T, path string) refreshJournalSidecar {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return refreshJournalSidecar{}
	}
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	mtimeSec, mtimeNsec := int64(0), int64(0)
	v := reflect.ValueOf(&st).Elem()
	ts := v.FieldByName("Mtim")
	if !ts.IsValid() {
		ts = v.FieldByName("Mtimespec")
	}
	if ts.IsValid() {
		sec, nsec := ts.FieldByName("Sec"), ts.FieldByName("Nsec")
		if sec.IsValid() && nsec.IsValid() {
			mtimeSec, mtimeNsec = sec.Int(), nsec.Int()
		}
	}
	digest := sha256.Sum256(raw)
	return refreshJournalSidecar{Present: true, Dev: uint64(st.Dev), Ino: uint64(st.Ino), Mode: uint32(st.Mode), UID: st.Uid, Nlink: uint64(st.Nlink), Size: st.Size, MTimeSec: mtimeSec, MTimeNsec: mtimeNsec, SHA256: "sha256:" + hex.EncodeToString(digest[:]), Bytes: bytes.Clone(raw)}
}
