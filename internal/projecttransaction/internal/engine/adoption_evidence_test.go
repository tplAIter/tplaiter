//go:build darwin || linux

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/receiptevidence"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestPlausiblePolicyCannotSubstituteUpdateReceiptForOrigin(t *testing.T) {
	tx, _, r, home := signedUpdateEngine(t)
	defer tx.Release()
	root, e := provenance.DecodeRootTemplateLock(tx.plan.Material.Before[".tplaiter/root-template.lock.json"].Data)
	if e != nil {
		t.Fatal(e)
	}
	policy, e := adoptionpolicy.New(adoptionpolicy.Origin{ProjectID: tx.plan.Material.ProjectID, Binding: r.TrustRuntime().Binding(), SourceRootLockSHA256: root.RootLockSHA256, SourceCommit: root.Root.Commit, RendererVersion: root.Renderer.Version, RenderInputsSHA256: evidencecas.Digest(nil), DecisionAt: "2026-06-01T00:00:00Z", Exclusions: []adoptionpolicy.Exclusion{{Path: "ordinary.txt", SourceSHA256: evidencecas.Digest([]byte("signed")), SourceMode: 0o644, InitialState: "modified", Observed: adoptionpolicy.Observation{Exists: true, Mode: 0o640, Device: 1, Inode: 2, SHA256: evidencecas.Digest([]byte("ours"))}}}})
	if e != nil {
		t.Fatal(e)
	}
	name := filepath.Join(tx.dir, "state.json")
	before, e := os.ReadFile(name)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ReadAdoptionOrigin(context.Background(), r, home, policy); e == nil {
		t.Fatal("other signed operation became adoption origin")
	}
	after, e := os.ReadFile(name)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("origin verifier mutated receipt", e)
	}
	j, e := receiptevidence.Read(context.Background(), r, home, tx.ID())
	if e != nil {
		t.Fatalf("shared receipt reader refused engine journal: %v", e)
	}
	defer j.Close()
	if j.Kind() != NativeUpdateKind {
		t.Fatalf("receipt kind = %q, want %q", j.Kind(), NativeUpdateKind)
	}
	if _, e = j.Record(context.Background(), r, "state.json"); e != nil {
		t.Fatalf("shared receipt reader refused state record: %v", e)
	}
}

// Every positive phase below is produced by the actual engine owner. No test
// assigns a committed phase or reconstructs a MAC from a caller-supplied key.
func TestCorrectiveReceiptUpdateColdEpochLifetimeAndWire(t *testing.T) {
	ctx := context.Background()
	tx, _, r, home := signedUpdateEngine(t)
	id := tx.ID()
	if err := tx.Commit(ctx); err != nil {
		tx.Release()
		t.Fatal(err)
	}
	tx.Release()
	cold := coldSignedUpdate(t, r, home, id)
	defer cold.Release()
	if err := cold.Commit(ctx); err != nil {
		t.Fatal("actual cold terminal confirmation", err)
	}
	j, err := receiptevidence.Read(ctx, r, home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.RecheckFor(ctx, r); err != nil {
		t.Fatal("retained same-runtime observation", err)
	}
	record, err := j.Record(ctx, r, "plan.json")
	info, statErr := os.Stat(filepath.Join(cold.dir, "plan.json"))
	if err != nil || statErr != nil || (Identity{record.Device(), record.Inode()}) != fileID(info) {
		t.Fatal("actual platform identity", err, statErr)
	}
	if err := j.RecheckFor(ctx, nil); err == nil {
		t.Fatal("foreign owner accepted")
	}
	// Unknown/duplicate/integer-byte counterchecks use the complete actual
	// owner-produced plan, with malformed bytes signed by that existing owner.
	original, err := os.ReadFile(filepath.Join(cold.dir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	raw, _ := canonicaljson.Canonical(cold.plan)
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = json.RawMessage(`1`)
	if err := cold.writeSigned("plan.json", object, false); err != nil {
		t.Fatal(err)
	}
	if _, err := receiptevidence.ReadProjectRecord(ctx, r, home, id, "plan.json"); err == nil {
		t.Fatal("unknown complete payload field accepted")
	}
	if err := os.WriteFile(filepath.Join(cold.dir, "plan.json"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(r.ScratchRoot(), "project-transaction-authority", "seal.key")
	saved := keyPath + ".retained"
	if err := os.Rename(keyPath, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x5c}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Record(ctx, r, "state.json"); err == nil {
		t.Fatal("retained key epoch changed silently")
	}
	// The original writer remains bound to its retained authority, even when
	// the current on-disk key can authenticate an independently produced state.
	other := &Transaction{runtime: r, key: bytes.Repeat([]byte{0x5c}, 32), dir: cold.dir, plan: cold.plan}
	if err := other.writeSigned("state.json", cold.state, false); err != nil {
		t.Fatal(err)
	}
	var state progress
	if err := cold.readProjectSigned(context.Background(), "state.json", &state); !errors.Is(err, ErrAuthentication) {
		t.Fatal("held writer rebound to replacement key", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := cold.writeSigned("state.json", cold.state, false); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Record(ctx, r, "state.json"); err == nil {
		t.Fatal("closed borrowed runtime accepted")
	}
}

func TestCorrectiveReceiptFirstMarkerCold(t *testing.T) {
	ctx := context.Background()
	r, home, root := nativeSignedProject(t)
	// The signed New owner already rendered these enrolled metadata bytes. Turn
	// its finite test root into a genuine existing unmarked project; first-marker
	// Acquire/Seal/Commit below owns all receipt phases and physical publication.
	before, err := WorkspaceSnapshot(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	after := map[string]File{}
	for name, file := range before {
		if strings.HasPrefix(name, ".tplaiter/") && !file.Directory {
			file.Device = 0
			file.Inode = 0
			after[name] = file
		}
	}
	if err = os.RemoveAll(filepath.Join(root, ".tplaiter")); err != nil {
		t.Fatal(err)
	}
	before, err = WorkspaceSnapshot(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	registryInfo, err := os.Stat(filepath.Join(home, "projects.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ri := fileID(registryInfo)
	m := Material{Root: root, Home: home, ProjectID: r.ProjectContext().ProjectID, Binding: r.TrustRuntime().Binding(), Before: before, After: after, ReadOnlyPaths: []string{}, Fingerprint: evidencecas.Digest([]byte("actual-first-marker-transport-control")), Intent: json.RawMessage(`{"operation":"first-marker-transport-control"}`), Registry: &RegistryPair{Before: File{Data: registry, Mode: uint32(registryInfo.Mode().Perm()), Device: ri.Device, Inode: ri.Inode}, After: File{Data: registry, Mode: uint32(registryInfo.Mode().Perm())}}}
	f, err := AcquireFirstMarker(ctx, r, m, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Seal(ctx, m, []string{}); err != nil {
		f.Release()
		t.Fatal(err)
	}
	id := f.ID()
	f.Release()
	cold, err := OpenFirstMarker(ctx, r, home, id)
	if err != nil {
		t.Fatal("actual prepared cold first-marker", err)
	}
	if err = cold.Commit(ctx); err != nil {
		cold.Release()
		t.Fatal(err)
	}
	cold.Release()
	cold, err = OpenFirstMarker(ctx, r, home, id)
	if err != nil {
		t.Fatal("actual committed cold first-marker", err)
	}
	if err = cold.Commit(ctx); err != nil {
		cold.Release()
		t.Fatal(err)
	}
	cold.Release()
	j, err := receiptevidence.Read(ctx, r, home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if j.Kind() != NativeLinkKind || j.RecheckFor(ctx, r) != nil {
		t.Fatal("first-marker source owner/lifetime mismatch")
	}
	plan, err := j.Record(ctx, r, "plan.json")
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Record(ctx, r, "state.json")
	if err != nil {
		t.Fatal(err)
	}
	var decoded firstMarkerState
	if canonicaljson.DecodeStrict(state.Payload(), &decoded) != nil || decoded.Phase != "committed" || decoded.Plan != (Identity{plan.Device(), plan.Inode()}) {
		t.Fatal("cold actual first-marker wire/identity mismatch")
	}
}

// This context observes only the real production leaf's payload read boundary.
// It does not mutate files or add a callback to the reader/engine API.
type receiptPayloadCancellation struct {
	context.Context
	cancel      context.CancelFunc
	chunkChecks int
	canceled    bool
}

func (c *receiptPayloadCancellation) Err() error {
	if c.canceled {
		return c.Context.Err()
	}
	var pcs [64]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	read, record, keyCheck := false, false, false
	for {
		frame, more := frames.Next()
		read = read || strings.Contains(frame.Function, "receiptevidence.(*directoryHandle).read")
		record = record || strings.Contains(frame.Function, "receiptevidence.(*Journal).record")
		keyCheck = keyCheck || strings.Contains(frame.Function, "receiptevidence.(*Journal).check")
		if !more {
			break
		}
	}
	if read && record && !keyCheck {
		c.chunkChecks++
		// The first two checks precede open; the third is the actual chunk read.
		if c.chunkChecks == 3 {
			c.cancel()
			c.canceled = true
			return c.Context.Err()
		}
	}
	return c.Context.Err()
}
func TestCorrectiveReceiptProductionCallerCancellation(t *testing.T) {
	tx, _, r, home := signedUpdateEngine(t)
	defer tx.Release()
	id := tx.ID()
	check := func(t *testing.T, call func(context.Context) error) {
		t.Helper()
		base, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx := &receiptPayloadCancellation{Context: base, cancel: cancel}
		err := call(ctx)
		select {
		case <-ctx.Done():
		default:
			t.Fatal("real caller Done was not canceled")
		}
		if !ctx.canceled || !errors.Is(err, context.Canceled) {
			t.Fatalf("actual caller did not cancel the production payload read: triggered=%v err=%v", ctx.canceled, err)
		}
	}
	t.Run("project-adapter", func(t *testing.T) {
		check(t, func(ctx context.Context) error {
			var plan immutable
			return tx.readProjectSigned(ctx, "plan.json", &plan)
		})
	})
	t.Run("cold-open", func(t *testing.T) {
		check(t, func(ctx context.Context) error {
			opened, err := Open(ctx, r, NativeUpdateKind, home, id)
			if opened != nil {
				opened.Release()
			}
			return err
		})
	})
	t.Run("historical-fence", func(t *testing.T) { check(t, tx.rejectActiveJournals) })
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal("actual engine commit", err)
	}
	t.Run("terminal-confirmation", func(t *testing.T) { check(t, tx.Commit) })
	// This authentic terminal receipt is generated by Commit, not assigned data.
	if err := tx.rejectActiveJournals(context.Background()); err != nil {
		t.Fatal("actual retained terminal fence", err)
	}
}

// Cancellation is injected by the caller context at an actual confined raw
// observation, never by a production hook or a forged phase/receipt fixture.
type receiptObservationCancellation struct {
	context.Context
	cancel                       context.CancelFunc
	material                     bool
	checks                       int
	pass, desiredPass, entryLine int
	triggered                    bool
}

func (c *receiptObservationCancellation) Err() error {
	if c.triggered {
		return c.Context.Err()
	}
	var pcs [64]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	read, observation, material, inspection := false, false, false, false
	observationLine := 0
	for {
		f, more := frames.Next()
		read = read || strings.Contains(f.Function, "receiptevidence.(*directoryHandle).read")
		if strings.Contains(f.Function, "receiptevidence.ObserveProjectReceipt") {
			observation = true
			observationLine = f.Line
		}
		material = material || strings.Contains(f.Function, "engine.(*CommittedUpdate).MaterialFor")
		inspection = inspection || strings.Contains(f.Function, "engine.InspectJournal")
		if !more {
			break
		}
	}
	selected := inspection
	if c.material {
		selected = material && !inspection
	}
	if observation && selected && !read {
		if c.entryLine == 0 {
			c.entryLine = observationLine
		}
		if observationLine == c.entryLine {
			c.pass++
			c.checks = 0
		}
	}
	if read && observation && selected && c.pass == c.desiredPass {
		c.checks++
		if c.checks == 3 {
			c.triggered = true
			c.cancel()
		}
	}
	return c.Context.Err()
}
func TestCorrectiveReceiptProductionObservationCancellation(t *testing.T) {
	ctx := context.Background()
	tx, fixture, r, home := signedUpdateEngine(t)
	defer tx.Release()
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("actual owner Commit", err)
	}
	// Materialize only the actual enrolled fixture source CAS in its configured
	// lifecycle reader. Production inspection has no bootstrap-store fallback.
	store, err := trustload.OpenReadOnly(ctx, fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := inspectionReferences(tx.plan.Material)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		raw, err := store.Read(ctx, ref)
		if err != nil || evidencecas.Digest(raw) != ref {
			t.Fatal("actual fixture source CAS", err)
		}
		leaf := strings.TrimPrefix(ref, "sha256:")
		name := filepath.Join(fixture.evidence, "sha256", leaf[:2], leaf[2:])
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err := ReadCommittedUpdate(ctx, r, home, tx.ID())
	if err != nil {
		t.Fatal("actual committed owner inspection", err)
	}
	if _, err := owner.MaterialFor(ctx, r); err != nil {
		t.Fatal("actual owner MaterialFor", err)
	}
	for _, test := range []struct {
		name     string
		material bool
		pass     int
	}{
		{"inspection-kind-plan", false, 1},
		{"inspection-plan", false, 2},
		{"inspection-state", false, 3},
		{"material-before-plan", true, 1},
		{"material-before-state", true, 2},
		{"material-after-plan", true, 3},
		{"material-after-state", true, 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			base, cancel := context.WithCancel(ctx)
			defer cancel()
			caller := &receiptObservationCancellation{Context: base, cancel: cancel, material: test.material, desiredPass: test.pass}
			var err error
			if test.material {
				_, err = owner.MaterialFor(caller, r)
			} else {
				_, err = InspectJournal(caller, r, home, tx.ID())
			}
			if !caller.triggered || !errors.Is(err, context.Canceled) {
				t.Fatalf("production raw pass did not preserve cancellation: target=%d seen=%d triggered=%v err=%v", test.pass, caller.pass, caller.triggered, err)
			}
			select {
			case <-caller.Done():
			default:
				t.Fatal("real caller Done remains open")
			}
		})
	}
	// Keep the plan/state diagnostic split: a damaged plan is not authenticated
	// merely because a separate valid current-layout state can identify tampering.
	planPath := filepath.Join(tx.dir, "plan.json")
	raw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var record envelope
	if err := canonicaljson.DecodeStrict(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.MAC = strings.Repeat("0", 64)
	damaged, err := canonicaljson.Canonical(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := InspectJournal(ctx, r, home, tx.ID())
	if !errors.Is(err, ErrAuthentication) || errors.Is(err, ErrInspectionUncovered) || got.Sealed() || got.Terminal() {
		t.Fatalf("independent signed state lost tamper classification: %+v %v", got, err)
	}
	if err := os.WriteFile(planPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.MaterialFor(ctx, r); err != nil {
		t.Fatal("restored actual owner", err)
	}
}

// The real owner has already authenticated its terminal receipt before this
// context cancels a chosen exact-byte confirmation pass through the held fd.
type rollbackReceiptCancellation struct {
	context.Context
	cancel     context.CancelFunc
	callsites  map[int]int
	wantedPass int
	triggered  bool
}

func (c *rollbackReceiptCancellation) Err() error {
	if c.triggered {
		return c.Context.Err()
	}
	var pcs [64]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	match, confirm, callerLine := false, false, 0
	for {
		f, more := frames.Next()
		match = match || strings.Contains(f.Function, "engine.matchReceiptContext")
		confirm = confirm || strings.Contains(f.Function, "engine.(*Transaction).confirmRollback")
		if strings.Contains(f.Function, "engine.syncReceiptExact") {
			callerLine = f.Line
		}
		if !more {
			break
		}
	}
	if match && confirm && callerLine != 0 {
		pass, found := c.callsites[callerLine]
		if !found {
			pass = len(c.callsites) + 1
			c.callsites[callerLine] = pass
		}
		if pass == c.wantedPass {
			c.triggered = true
			c.cancel()
		}
	}
	return c.Context.Err()
}
func TestCorrectiveReceiptRollbackConfirmationCancellation(t *testing.T) {
	ctx := context.Background()
	tx, _, r, home := signedUpdateEngine(t)
	if err := tx.Apply(ctx); err != nil {
		tx.Release()
		t.Fatal("actual owner apply", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		tx.Release()
		t.Fatal("actual owner rollback", err)
	}
	id := tx.ID()
	tx.Release()
	// Cold admission reconstructs the actual retained original signed material.
	cold := coldSignedUpdate(t, r, home, id)
	defer cold.Release()
	if err := cold.Rollback(ctx); err != nil {
		t.Fatal("genuine cold terminal confirmation", err)
	}
	path := filepath.Join(cold.dir, "state.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, pass := range []int{1, 2} {
		t.Run(map[int]string{1: "before-fsync", 2: "after-fsync"}[pass], func(t *testing.T) {
			base, cancel := context.WithCancel(ctx)
			defer cancel()
			caller := &rollbackReceiptCancellation{Context: base, cancel: cancel, callsites: map[int]int{}, wantedPass: pass}
			err := cold.Rollback(caller)
			if !caller.triggered || !errors.Is(err, context.Canceled) {
				t.Fatalf("real rollback confirmation did not cancel pass%d: triggered=%v err=%v", pass, caller.triggered, err)
			}
			select {
			case <-caller.Done():
			default:
				t.Fatal("actual caller Done remains open")
			}
			current, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(current, original) {
				t.Fatal("canceled confirmation rewrote terminal receipt", err)
			}
			if err := cold.Rollback(ctx); err != nil {
				t.Fatal("authentic terminal retry after cancellation", err)
			}
		})
	}
}
