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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

const refreshSB06ChildEnv = "TPLAITER_SB06_CHILD"

type refreshSB06Payload struct {
	Selection    LaunchSelection   `json:"selection"`
	NextBundle   []byte            `json:"nextBundle"`
	NextEvidence map[string][]byte `json:"nextEvidence"`
}

type refreshSB06Transition struct {
	NextStateSHA256     string
	PreviousStateSHA256 string
	PreviousBundleJSON  []byte
	NextBundleJSON      []byte
	EvidenceDigestsJSON []byte
}

type refreshSB06Head struct {
	InstallationCount  int
	InstallationID     string
	DescriptorSHA256   string
	ProvisioningSHA256 string
	InitialStateSHA256 string
	StateJSON          []byte
	StateSHA256        string
	BundleJSON         []byte
	Generation         int64
	TransitionCount    int
	Blobs              map[string][]byte
	Transition         refreshSB06Transition
}

func TestRefreshSB06InterruptChild(t *testing.T) {
	if os.Getenv(refreshSB06ChildEnv) != "1" {
		t.Skip("child")
	}
	event := os.NewFile(uintptr(3), "refresh-sb06-events")
	ack := os.NewFile(uintptr(4), "refresh-sb06-acks")
	if event == nil || ack == nil {
		t.Fatal("missing inherited refresh pipes")
	}
	defer event.Close()
	defer ack.Close()
	raw, err := os.ReadFile(os.Getenv("TPLAITER_SB06_PAYLOAD"))
	if err != nil {
		t.Fatal(err)
	}
	var payload refreshSB06Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	storeRefreshPhaseHook = func(stage string) {
		if err := json.NewEncoder(event).Encode(stage); err != nil {
			os.Exit(2)
		}
		var b [1]byte
		if _, err := io.ReadFull(ack, b[:]); err != nil || b[0] != 1 {
			os.Exit(2)
		}
	}
	if _, err := Refresh(context.Background(), payload.Selection, refreshSB06Factory, payload.NextBundle, payload.NextEvidence); err == nil {
		t.Fatal("child refresh returned before parent kill")
	}
}

func TestRefreshSB06ActualInterruptCuts(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, phase := range []string{"begin", "write", "commit-before", "commit"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
				t.Fatal(err)
			}
			next, evidence := rotateBundle(t, fixture)
			old, nextHead := deriveRefreshSB06Heads(t, fixture, next, evidence)
			payloadRaw, err := json.Marshal(refreshSB06Payload{Selection: fixture.selection, NextBundle: next, NextEvidence: evidence})
			if err != nil {
				t.Fatal(err)
			}
			payloadPath := filepath.Join(fixture.load.dir, "refresh-sb06-payload.json")
			if err := os.WriteFile(payloadPath, payloadRaw, 0o600); err != nil {
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
			cmd := exec.Command(os.Args[0], "-test.run=^TestRefreshSB06InterruptChild$")
			cmd.Env = append(os.Environ(), refreshSB06ChildEnv+"=1", "TPLAITER_SB06_PAYLOAD="+payloadPath)
			cmd.ExtraFiles = []*os.File{eventW, ackR}
			if err := cmd.Start(); err != nil {
				eventR.Close()
				eventW.Close()
				ackR.Close()
				ackW.Close()
				t.Fatal(err)
			}
			killIssued, reaped := false, false
			var killErr, childWaitErr error
			killAndReap := func() {
				if !killIssued {
					killErr = cmd.Process.Kill()
					killIssued = true
				}
				if !reaped {
					childWaitErr = cmd.Wait()
					reaped = true
				}
			}
			defer killAndReap()
			eventW.Close()
			ackR.Close()
			defer eventR.Close()
			defer ackW.Close()
			decoder := json.NewDecoder(eventR)
			for _, want := range []string{"begin", "write", "commit-before", "commit"} {
				if err := eventR.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
					killAndReap()
					t.Fatal(err)
				}
				var stage string
				if err := decoder.Decode(&stage); err != nil {
					killAndReap()
					t.Fatalf("cut %s event: %v", phase, err)
				}
				if stage != want {
					killAndReap()
					t.Fatalf("cut %s phase=%q want=%q", phase, stage, want)
				}
				if stage == phase {
					break
				}
				if _, err := ackW.Write([]byte{1}); err != nil {
					killAndReap()
					t.Fatal(err)
				}
			}
			killAndReap()
			if killErr != nil {
				t.Fatal(killErr)
			}
			if childWaitErr == nil || cmd.ProcessState == nil {
				t.Fatalf("cut %s child did not report SIGKILL", phase)
			}
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() {
				t.Fatalf("cut %s wait status=%v", phase, cmd.ProcessState.Sys())
			}
			if err := RecoverState(context.Background(), fixture.selection, refreshSB06Factory); err != nil {
				t.Fatalf("cut %s recover: %v", phase, err)
			}
			allowed := map[string]bool{"old": true}
			if phase == "commit" {
				allowed = map[string]bool{"new": true}
			} else {
				allowed["new"] = true
			}
			assertRefreshSB06RecoveredHead(t, fixture, old, nextHead, allowed)
		})
	}
}

func refreshSB06Factory(reader evidencecas.Reader) (*bootstrap.Verifier, error) {
	return bootstrap.NewVerifier(reader, bootstrap.ClockFunc(func() time.Time {
		return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	}), nil, 0)
}

func deriveRefreshSB06Heads(t *testing.T, fixture bootstrapFixture, nextRaw []byte, evidence map[string][]byte) (refreshSB06Head, refreshSB06Head) {
	t.Helper()
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	old := readRefreshSB06Head(t, store)
	proj, err := projectInstallation(fixture.loaded)
	if err != nil {
		t.Fatal(err)
	}
	old.InstallationCount = 1
	old.InstallationID = proj.installationID
	old.DescriptorSHA256 = proj.descriptorSHA256
	old.ProvisioningSHA256 = proj.provisioningSHA256
	old.InitialStateSHA256 = proj.initialStateSHA256
	ext, err := bootstrap.LoadExternal(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	stored, currentRaw, err := store.currentBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current, err := bundleFromStored(context.Background(), store, stored)
	if err != nil {
		t.Fatal(err)
	}
	nextStored, err := DecodeStoredBundle(nextRaw)
	if err != nil {
		t.Fatal(err)
	}
	overlay := overlayEvidence{base: store, add: cloneEvidence(evidence)}
	next, err := bundleFromStored(context.Background(), overlay, *nextStored)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := refreshSB06Factory(overlay)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := verifier.PrepareOSSRefresh(context.Background(), ext, current, next)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := canonicalRefs(nextStored.references())
	if err != nil {
		t.Fatal(err)
	}
	newHead := old
	newHead.StateJSON = proposal.NextStateJSON()
	newHead.StateSHA256 = stateDigest(newHead.StateJSON)
	newHead.BundleJSON = append([]byte(nil), nextRaw...)
	newHead.Blobs = make(map[string][]byte, len(old.Blobs)+len(evidence))
	for ref, raw := range old.Blobs {
		newHead.Blobs[ref] = clone(raw)
	}
	newHead.Generation++
	newHead.TransitionCount++
	newHead.Transition = refreshSB06Transition{NextStateSHA256: newHead.StateSHA256, PreviousStateSHA256: old.StateSHA256, PreviousBundleJSON: currentRaw, NextBundleJSON: nextRaw, EvidenceDigestsJSON: refs}
	for ref, raw := range evidence {
		newHead.Blobs[ref] = clone(raw)
	}
	return old, newHead
}

func readRefreshSB06Head(t *testing.T, store *Store) refreshSB06Head {
	t.Helper()
	var h refreshSB06Head
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM installation`).Scan(&h.InstallationCount); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), `SELECT installationID,descriptorSHA256,provisioningSHA256,initialStateSHA256 FROM installation WHERE singleton=1`).Scan(&h.InstallationID, &h.DescriptorSHA256, &h.ProvisioningSHA256, &h.InitialStateSHA256); err != nil {
		t.Fatal(err)
	}
	var stateSHA string
	if err := store.db.QueryRowContext(context.Background(), `SELECT stateSHA256,stateJSON,bundleJSON,generation FROM accepted WHERE singleton=1`).Scan(&stateSHA, &h.StateJSON, &h.BundleJSON, &h.Generation); err != nil {
		t.Fatal(err)
	}
	h.StateSHA256 = stateSHA
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM transitions`).Scan(&h.TransitionCount); err != nil {
		t.Fatal(err)
	}
	h.Blobs = map[string][]byte{}
	rows, err := store.db.QueryContext(context.Background(), `SELECT digest,bytes FROM blobs ORDER BY digest`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ref string
		var raw []byte
		if err := rows.Scan(&ref, &raw); err != nil {
			t.Fatal(err)
		}
		h.Blobs[ref] = raw
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if h.TransitionCount > 0 {
		if err := store.db.QueryRowContext(context.Background(), `SELECT nextStateSHA256,previousStateSHA256,previousBundleJSON,nextBundleJSON,evidenceDigestsJSON FROM transitions ORDER BY nextStateSHA256 LIMIT 1`).Scan(&h.Transition.NextStateSHA256, &h.Transition.PreviousStateSHA256, &h.Transition.PreviousBundleJSON, &h.Transition.NextBundleJSON, &h.Transition.EvidenceDigestsJSON); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func assertRefreshSB06RecoveredHead(t *testing.T, fixture bootstrapFixture, old, next refreshSB06Head, allowed map[string]bool) string {
	t.Helper()
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatalf("fresh Store.Load: %v", err)
	}
	if _, err := verifyCurrent(context.Background(), store, refreshSB06Factory); err != nil {
		t.Fatalf("fresh LoadExternal/VerifyOSS: %v", err)
	}
	var integrity string
	if err := store.db.QueryRowContext(context.Background(), `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity_check=%q err=%v", integrity, err)
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Stat(filepath.Join(fixture.loaded.Install.OSS.StorePath, storeDBName+suffix)); !os.IsNotExist(err) {
			t.Fatalf("retained sidecar %s: %v", suffix, err)
		}
	}
	got := readRefreshSB06Head(t, store)
	for label, want := range map[string]refreshSB06Head{"old": old, "new": next} {
		if !allowed[label] {
			continue
		}
		if refreshSB06HeadsEqual(got, want) {
			return label
		}
	}
	t.Fatalf("recovered mixed or incomplete head: generation=%d transitions=%d state=%s", got.Generation, got.TransitionCount, got.StateSHA256)
	return ""
}

func refreshSB06HeadsEqual(a, b refreshSB06Head) bool {
	if a.InstallationCount != b.InstallationCount || a.InstallationID != b.InstallationID || a.DescriptorSHA256 != b.DescriptorSHA256 || a.ProvisioningSHA256 != b.ProvisioningSHA256 || a.InitialStateSHA256 != b.InitialStateSHA256 || a.StateSHA256 != b.StateSHA256 || !bytes.Equal(a.StateJSON, b.StateJSON) || !bytes.Equal(a.BundleJSON, b.BundleJSON) || a.Generation != b.Generation || a.TransitionCount != b.TransitionCount || len(a.Blobs) != len(b.Blobs) {
		return false
	}
	for ref, raw := range b.Blobs {
		if !bytes.Equal(a.Blobs[ref], raw) {
			return false
		}
	}
	return bytes.Equal(a.Transition.EvidenceDigestsJSON, b.Transition.EvidenceDigestsJSON) && a.Transition.NextStateSHA256 == b.Transition.NextStateSHA256 && a.Transition.PreviousStateSHA256 == b.Transition.PreviousStateSHA256 && bytes.Equal(a.Transition.PreviousBundleJSON, b.Transition.PreviousBundleJSON) && bytes.Equal(a.Transition.NextBundleJSON, b.Transition.NextBundleJSON)
}

func TestEnrollSB05BoundarySequence(t *testing.T) {
	fixture := newBootstrapFixture(t)
	old := storeEnrollmentPhaseHook
	defer func() { storeEnrollmentPhaseHook = old }()
	var got []string
	storeEnrollmentPhaseHook = func(stage string) { got = append(got, stage) }
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	want := []string{"mkdir", "parent-sync", "root-created", "pending-write-before", "pending-write", "pending-filesync", "pending-dirsync", "pending-synced", "sqlite-commit-before", "sqlite-commit", "verification-before", "verification", "rename", "final-dirsync"}
	if len(got) != len(want) {
		t.Fatalf("phase count=%d want=%d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("phase[%d]=%q want=%q", i, got[i], want[i])
		}
	}
}

// TestRefreshSB06ActualPreparedPath proves the normal oracle used after an
// interrupted writer: the production Refresh path builds a signed opaque
// proposal, commits it, and a fresh Store/LoadExternal/VerifyOSS view sees a
// complete retained head. Unsupported WAL/SHM evidence remains fail closed.
func TestRefreshSB06ActualPreparedPath(t *testing.T) {
	fixture := newBootstrapFixture(t)
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	next, evidence := rotateBundle(t, fixture)
	if _, err := Refresh(context.Background(), fixture.selection, fixture.factory, next, evidence); err != nil {
		t.Fatal(err)
	}
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := verifyCurrent(context.Background(), store, fixture.factory); err != nil {
		t.Fatalf("fresh VerifyOSS: %v", err)
	}
	var generation, transitions int
	if err := store.db.QueryRowContext(context.Background(), `SELECT generation FROM accepted WHERE singleton=1`).Scan(&generation); err != nil || generation != 2 {
		t.Fatalf("generation=%d err=%v", generation, err)
	}
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM transitions`).Scan(&transitions); err != nil || transitions != 1 {
		t.Fatalf("transitions=%d err=%v", transitions, err)
	}
	if err := os.WriteFile(filepath.Join(fixture.loaded.Install.OSS.StorePath, storeDBName+"-wal"), []byte("hostile"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverState(context.Background(), fixture.selection, fixture.factory); err == nil {
		t.Fatal("WAL recovery accepted")
	}
}

func TestOrdinaryReaderNeverInitializesOrRecovers(t *testing.T) {
	fixture := newBootstrapFixture(t)
	root := fixture.loaded.Install.OSS.StorePath
	if _, err := OpenReadOnly(context.Background(), fixture.selection); !errors.Is(err, ErrAnchorMissing) {
		t.Fatalf("missing store read = %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("ordinary read initialized installation directory")
	}
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(root, storeDBName+"-journal")
	if err := os.WriteFile(journal, []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReadOnly(context.Background(), fixture.selection); !errors.Is(err, ErrPending) {
		t.Fatalf("hot journal read = %v", err)
	}
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenReadOnly(context.Background(), fixture.selection); err != nil {
		t.Fatal(err)
	} else {
		_ = store.Close()
	}
}

func TestConcurrentRefreshHasOneCASWinner(t *testing.T) {
	fixture := newBootstrapFixture(t)
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	nextBundle, nextEvidence := rotateBundle(t, fixture)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := Refresh(context.Background(), fixture.selection, fixture.factory, nextBundle, nextEvidence)
			results <- err
		}()
	}
	group.Wait()
	close(results)
	var success, failure int
	for err := range results {
		if err == nil {
			success++
		} else {
			failure++
		}
	}
	if success != 1 || failure != 1 {
		t.Fatalf("refresh successes=%d failures=%d", success, failure)
	}
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var generation, transitions int
	if err := store.db.QueryRowContext(context.Background(), `SELECT generation FROM accepted WHERE singleton=1`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM transitions`).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if generation != 2 || transitions != 1 {
		t.Fatalf("generation=%d transitions=%d", generation, transitions)
	}
}
