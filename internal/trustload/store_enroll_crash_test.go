//go:build darwin || linux

package trustload

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

const enrollCrashChildEnv = "TPLAITER_ENROLL_CRASH_CHILD"

var enrollCrashPhases = []string{
	"mkdir", "parent-sync", "root-created", "pending-write-before", "pending-write", "pending-filesync", "pending-dirsync", "pending-synced",
	"sqlite-commit-before", "sqlite-commit", "verification-before", "verification", "rename", "final-dirsync",
}

type enrollCrashPayload struct {
	Selection LaunchSelection   `json:"selection"`
	State     []byte            `json:"state"`
	Bundle    []byte            `json:"bundle"`
	Evidence  map[string][]byte `json:"evidence"`
}

// TestStoreEnrollCrashSB05 kills a separate real enrollment process after
// each observed lifecycle boundary. SIGKILL is process-death coverage only;
// it is deliberately not described as a power-loss simulation.
func TestStoreEnrollCrashSB05(t *testing.T) {
	if os.Getenv(enrollCrashChildEnv) == "1" {
		runEnrollCrashChild(t)
		return
	}
	for _, cut := range enrollCrashPhases {
		t.Run(cut, func(t *testing.T) { runEnrollCrashCut(t, cut) })
	}
}

func runEnrollCrashChild(t *testing.T) {
	event := os.NewFile(uintptr(3), "enroll-crash-events")
	ack := os.NewFile(uintptr(4), "enroll-crash-acks")
	if event == nil || ack == nil {
		t.Fatal("missing inherited crash pipes")
	}
	defer event.Close()
	defer ack.Close()
	payloadPath := os.Getenv("TPLAITER_ENROLL_CRASH_PAYLOAD")
	raw, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	var payload enrollCrashPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	storeEnrollmentPhaseHook = func(stage string) {
		if err := json.NewEncoder(event).Encode(stage); err != nil {
			os.Exit(2)
		}
		var b [1]byte
		if _, err := io.ReadFull(ack, b[:]); err != nil || b[0] != 1 {
			os.Exit(2)
		}
	}
	if err := Enroll(context.Background(), payload.Selection, enrollCrashFactory, payload.State, payload.Bundle, payload.Evidence); err != nil {
		t.Fatalf("child Enroll: %v", err)
	}
}

func runEnrollCrashCut(t *testing.T, cut string) {
	t.Helper()
	fixture := newBootstrapFixture(t)
	payload := enrollCrashPayload{Selection: fixture.selection, State: fixture.stateJSON, Bundle: fixture.bundleJSON, Evidence: fixture.evidence}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(fixture.load.dir, "enroll-crash-payload.json")
	if err := os.WriteFile(payloadPath, raw, 0o600); err != nil {
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
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreEnrollCrashSB05$")
	cmd.Env = append(os.Environ(), enrollCrashChildEnv+"=1", "TPLAITER_ENROLL_CRASH_PAYLOAD="+payloadPath)
	cmd.ExtraFiles = []*os.File{eventW, ackR}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reaped, killIssued := false, false
	defer func() {
		if !reaped {
			if !killIssued {
				killIssued = true
				_ = cmd.Process.Kill()
			}
			_ = cmd.Wait()
			reaped = true
		}
	}()
	_ = eventW.Close()
	_ = ackR.Close()
	defer eventR.Close()
	defer ackW.Close()
	decoder := json.NewDecoder(eventR)
	for _, want := range enrollCrashPhases {
		if err := eventR.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := decoder.Decode(&got); err != nil {
			t.Fatalf("cut %s event: %v", cut, err)
		}
		if got != want {
			t.Fatalf("cut %s phase=%q want=%q", cut, got, want)
		}
		if got == cut {
			break
		}
		if _, err := ackW.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	killIssued = true
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	stateErr := cmd.Wait()
	reaped = true
	if stateErr == nil || cmd.ProcessState == nil {
		t.Fatalf("cut %s child did not report SIGKILL", cut)
	} else if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !status.Signaled() {
		t.Fatalf("cut %s child wait status=%v", cut, cmd.ProcessState.Sys())
	}
	assertEnrollCrashOutcome(t, fixture, cut)
}

func assertEnrollCrashOutcome(t *testing.T, fixture bootstrapFixture, cut string) {
	t.Helper()
	store, readErr := OpenReadOnly(context.Background(), fixture.selection)
	completePending := cut == "sqlite-commit" || cut == "verification-before" || cut == "verification"
	postActivation := cut == "rename" || cut == "final-dirsync"
	if !completePending && !postActivation {
		if store != nil {
			_ = store.Close()
			t.Fatalf("ordinary reader accepted incomplete cut %s", cut)
		}
		if readErr == nil {
			t.Fatalf("ordinary reader accepted incomplete cut %s", cut)
		}
		if err := RecoverState(context.Background(), fixture.selection, enrollCrashFactory); err == nil {
			t.Fatalf("recovery activated incomplete cut %s", cut)
		}
		return
	}
	if completePending {
		if store != nil {
			_ = store.Close()
			t.Fatalf("ordinary reader accepted pending cut %s", cut)
		}
		if readErr == nil {
			t.Fatalf("ordinary reader accepted pending cut %s", cut)
		}
		if err := RecoverState(context.Background(), fixture.selection, enrollCrashFactory); err != nil {
			t.Fatalf("recover exact pending %s: %v", cut, err)
		}
	} else if readErr != nil {
		t.Fatalf("ordinary reader after active cut %s: %v", cut, readErr)
	} else {
		_ = store.Close()
	}
	assertEnrollCrashInitialAuthority(t, fixture)
	if err := Enroll(context.Background(), fixture.selection, enrollCrashFactory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err == nil {
		t.Fatalf("cut %s allowed re-enrollment/overwrite", cut)
	}
}

func assertEnrollCrashInitialAuthority(t *testing.T, fixture bootstrapFixture) {
	t.Helper()
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ext, err := bootstrap.LoadExternal(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ExpectedOSSStateSHA256 != fixture.loaded.Install.OSS.InitialStateSHA256 {
		t.Fatalf("state=%s want initial=%s", snapshot.ExpectedOSSStateSHA256, fixture.loaded.Install.OSS.InitialStateSHA256)
	}
	proj, err := projectInstallation(fixture.loaded)
	if err != nil {
		t.Fatal(err)
	}
	var installationID, descriptor, provisioning, initial string
	if err := store.db.QueryRowContext(context.Background(), `SELECT installationID,descriptorSHA256,provisioningSHA256,initialStateSHA256 FROM installation WHERE singleton=1`).Scan(&installationID, &descriptor, &provisioning, &initial); err != nil {
		t.Fatal(err)
	}
	if installationID != proj.installationID || descriptor != proj.descriptorSHA256 || provisioning != proj.provisioningSHA256 || initial != proj.initialStateSHA256 {
		t.Fatalf("installation tuple=%q/%q/%q/%q", installationID, descriptor, provisioning, initial)
	}
	var stateDigest string
	var stateRaw, bundleRaw []byte
	var generation int64
	if err := store.db.QueryRowContext(context.Background(), `SELECT stateSHA256,stateJSON,bundleJSON,generation FROM accepted WHERE singleton=1`).Scan(&stateDigest, &stateRaw, &bundleRaw, &generation); err != nil {
		t.Fatal(err)
	}
	if stateDigest != proj.initialStateSHA256 || !bytes.Equal(stateRaw, fixture.stateJSON) || !bytes.Equal(bundleRaw, fixture.bundleJSON) || generation != 1 {
		t.Fatalf("accepted tuple digest=%q generation=%d stateMatch=%v bundleMatch=%v", stateDigest, generation, bytes.Equal(stateRaw, fixture.stateJSON), bytes.Equal(bundleRaw, fixture.bundleJSON))
	}
	var transitions, blobCount int
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM transitions`).Scan(&transitions); err != nil || transitions != 0 {
		t.Fatalf("transitions=%d err=%v", transitions, err)
	}
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM blobs`).Scan(&blobCount); err != nil || blobCount != len(fixture.evidence) {
		t.Fatalf("blob count=%d want=%d err=%v", blobCount, len(fixture.evidence), err)
	}
	for digest, want := range fixture.evidence {
		var got []byte
		if err := store.db.QueryRowContext(context.Background(), `SELECT bytes FROM blobs WHERE digest=?`, digest).Scan(&got); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("blob %s match=%v err=%v", digest, bytes.Equal(got, want), err)
		}
	}
	stored, _, err := store.currentBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := bundleFromStored(context.Background(), store, stored)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := enrollCrashFactory(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyOSS(context.Background(), ext, bundle); err != nil {
		t.Fatalf("fresh VerifyOSS: %v", err)
	}
}

func enrollCrashFactory(reader evidencecas.Reader) (*bootstrap.Verifier, error) {
	return bootstrap.NewVerifier(reader, bootstrap.ClockFunc(func() time.Time {
		return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	}), nil, 0)
}
