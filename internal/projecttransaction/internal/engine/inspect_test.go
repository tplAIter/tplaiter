//go:build darwin || linux

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

type inspectMetadata struct{ info os.FileInfo }

func inspectionMetadata(t *testing.T, roots ...string) map[string]inspectMetadata {
	t.Helper()
	out := map[string]inspectMetadata{}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(name string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := os.Lstat(name)
			if err != nil {
				return err
			}
			out[name] = inspectMetadata{info: info}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func assertInspectionUnchanged(t *testing.T, before map[string]inspectMetadata, roots ...string) {
	t.Helper()
	after := inspectionMetadata(t, roots...)
	if len(after) != len(before) {
		t.Fatal("inspector created/removed evidence")
	}
	for name, old := range before {
		fresh, ok := after[name]
		if !ok || !os.SameFile(old.info, fresh.info) || old.info.Mode() != fresh.info.Mode() || old.info.Size() != fresh.info.Size() || !old.info.ModTime().Equal(fresh.info.ModTime()) {
			t.Fatal("inspector mutated observed evidence")
		}
	}
}

func assertInspected(t *testing.T, r *trustload.Runtime, home string, tx *Transaction, status InspectionStatus, terminal bool) JournalInspection {
	t.Helper()
	before := inspectionMetadata(t, tx.plan.Material.Root, home, r.ScratchRoot())
	got, err := InspectJournal(context.Background(), r, home, tx.ID())
	if err != nil || got.Status() != status || got.Terminal() != terminal || !got.Sealed() || got.Phase() != tx.state.Phase || got.SourceReferences() == 0 || got.PlanDigest() == "" || got.ReceiptDigest() == "" {
		t.Fatalf("inspection status=%s phase=%s sealed=%v terminal=%v refs=%d err=%v", got.Status(), got.Phase(), got.Sealed(), got.Terminal(), got.SourceReferences(), err)
	}
	assertInspectionUnchanged(t, before, tx.plan.Material.Root, home, r.ScratchRoot())
	return got
}

func TestSignedInspectionProgressAndHistoricalTerminal(t *testing.T) {
	r, home, root := nativeSignedProject(t)
	tx, err := beginSignedNative(context.Background(), nativePlan(t, r, home))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	assertInspected(t, r, home, tx, InspectionActive, false) // inspect while real leases are held
	if err := tx.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertInspected(t, r, home, tx, InspectionActive, false)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := assertInspected(t, r, home, tx, InspectionCommitted, true)
	historicalDigest := got.ReceiptDigest()
	tx.Release()
	// A second genuine runtime-bound transaction publishes the same generator
	// intent idempotently while retaining the old journal and old owned slots.
	nextPlan, err := gen.PlanNative(context.Background(), r, home, []gen.NativeOperation{{Kind: "entity", Name: "Gadget"}})
	if err != nil {
		t.Fatal(err)
	}
	next, err := beginSignedNative(context.Background(), nextPlan)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Commit(context.Background()); err != nil {
		next.Release()
		t.Fatal(err)
	}
	next.Release()
	assertInspected(t, r, home, tx, InspectionCommitted, true)
	// A later ordinary project edit must not reinterpret sealed terminal history
	// as unfinished just because its old current target no longer matches.
	anchor := filepath.Join(root, "cmd/service/main.go")
	raw, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchor, append(raw, []byte("\n// later legitimate owner edit\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	got = assertInspected(t, r, home, tx, InspectionCommitted, true)
	if got.ReceiptDigest() != historicalDigest {
		t.Fatal("historical receipt was rewritten")
	}
}

func TestSignedInspectionRollbackAndImageDiagnostics(t *testing.T) {
	r, home, _ := nativeSignedProject(t)
	tx, err := beginSignedNative(context.Background(), nativePlan(t, r, home))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := tx.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertInspected(t, r, home, tx, InspectionRolledBack, true)
	saved := tx.images + ".saved"
	if err := os.Rename(tx.images, saved); err != nil {
		t.Fatal(err)
	}
	got := assertInspected(t, r, home, tx, InspectionMissingImages, false)
	if len(got.Issues()) != 1 || got.Issues()[0] != InspectionMissingImages {
		t.Fatal("missing slots not distinguished")
	}
	if err := os.Rename(saved, tx.images); err != nil {
		t.Fatal(err)
	}
	slot := filepath.Join(tx.images, tx.state.Steps[0].Slot)
	if err := os.Chmod(slot, 0o640); err != nil {
		t.Fatal(err)
	}
	assertInspected(t, r, home, tx, InspectionUnsafe, false)
}

func rewriteInspectionPlan(t *testing.T, tx *Transaction, change func(map[string]json.RawMessage)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(tx.dir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var outer envelope
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(outer.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	change(payload)
	outer.Payload, err = canonicaljson.Canonical(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = canonicaljson.Canonical(outer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tx.dir, "plan.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSignedInspectionRefusalsNeverInitializeAuthority(t *testing.T) {
	r, home, _ := nativeSignedProject(t)
	tx, err := beginSignedNative(context.Background(), nativePlan(t, r, home))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	original, err := os.ReadFile(filepath.Join(tx.dir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, value string
		want        InspectionStatus
	}{{"apiVersion", `"tplaiter.dev/project-transaction/v99"`, InspectionFuture}, {"kind", `"ForeignTransaction"`, InspectionUnsupportedKind}} {
		rewriteInspectionPlan(t, tx, func(payload map[string]json.RawMessage) { payload[tc.name] = json.RawMessage(tc.value) })
		before := inspectionMetadata(t, tx.dir, r.ScratchRoot())
		got, err := InspectJournal(context.Background(), r, home, tx.ID())
		if err != nil || got.Status() != tc.want || got.Sealed() || got.Terminal() || got.Phase() != "" {
			t.Fatalf("unknown layout trusted: %s %v", got.Status(), err)
		}
		assertInspectionUnchanged(t, before, tx.dir, r.ScratchRoot())
		if err := os.WriteFile(filepath.Join(tx.dir, "plan.json"), original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	corrupted := append([]byte(nil), original...)
	corrupted[len(corrupted)-2] ^= 1
	if err := os.WriteFile(filepath.Join(tx.dir, "plan.json"), corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := InspectJournal(context.Background(), r, home, tx.ID()); err == nil || got.Terminal() || got.Sealed() {
		t.Fatal("tampered receipt admitted")
	}
	if err := os.WriteFile(filepath.Join(tx.dir, "plan.json"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	authority := filepath.Join(r.ScratchRoot(), "project-transaction-authority")
	saved := authority + ".saved"
	if err := os.Rename(authority, saved); err != nil {
		t.Fatal(err)
	}
	before := inspectionMetadata(t, r.ScratchRoot(), tx.dir)
	if got, err := InspectJournal(context.Background(), r, home, tx.ID()); !errors.Is(err, ErrAuthentication) || got.Sealed() {
		t.Fatal("missing authority admitted")
	}
	if _, err := os.Lstat(authority); !os.IsNotExist(err) {
		t.Fatal("authority initialized")
	}
	assertInspectionUnchanged(t, before, r.ScratchRoot(), tx.dir)
	if err := os.Rename(saved, authority); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectJournal(ctx, r, home, tx.ID()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := InspectJournal(context.Background(), r, filepath.Join(home, ".."), tx.ID()); !errors.Is(err, ErrAuthentication) {
		t.Fatal("foreign target root accepted")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := InspectJournal(context.Background(), r, home, tx.ID()); !errors.Is(err, ErrAuthentication) || got.Sealed() {
		t.Fatal("closed runtime admitted")
	}
}

func TestSignedInspectionSourceCASIsDistinctFromImages(t *testing.T) {
	r, home, _ := nativeSignedProject(t)
	tx, err := beginSignedNative(context.Background(), nativePlan(t, r, home))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	rootLock, err := provenance.DecodeRootTemplateLock(tx.plan.Material.Before[".tplaiter/root-template.lock.json"].Data)
	if err != nil {
		t.Fatal(err)
	}
	// Locate only the actual fixture installation's enrolled evidence object.
	selectionRaw, err := os.ReadFile(filepath.Join(home, "fixture-launch.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selection trustload.LaunchSelection
	if err := json.Unmarshal(selectionRaw, &selection); err != nil {
		t.Fatal(err)
	}
	loaded, err := trustload.Load(context.Background(), selection)
	if err != nil {
		t.Fatal(err)
	}
	digest := rootLock.Root.StatementCAS
	leaf := digest[len("sha256:"):]
	object := filepath.Join(loaded.Install.EvidenceRoot, "sha256", leaf[:2], leaf[2:])
	// The real CAS layout is fixed by evidencecas, never selected by journal data.
	raw, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(object); err != nil {
		t.Fatal(err)
	}
	got := assertInspected(t, r, home, tx, InspectionCommitted, true)
	if len(got.Issues()) != 1 || got.Issues()[0] != InspectionMissingCAS {
		t.Fatal("historical missing CAS not separately diagnosed")
	}
	if err := os.WriteFile(object, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got = assertInspected(t, r, home, tx, InspectionCommitted, true)
	if len(got.Issues()) != 0 {
		t.Fatal("restored real CAS not read")
	}
	// Byte corruption of a present CAS object is unsafe evidence, not missing CAS.
	if err := os.WriteFile(object, bytes.Repeat([]byte("!"), len(raw)), 0o600); err != nil {
		t.Fatal(err)
	}
	assertInspected(t, r, home, tx, InspectionUnsafe, false)
}

func TestSignedInspectionFutureProgress(t *testing.T) {
	r, home, _ := nativeSignedProject(t)
	tx, err := beginSignedNative(context.Background(), nativePlan(t, r, home))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	name := filepath.Join(tx.dir, "state.json")
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var record envelope
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(record.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	payload["apiVersion"] = "tplaiter.dev/project-transaction/v99"
	record.Payload, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := InspectJournal(context.Background(), r, home, tx.ID())
	if err != nil || got.Status() != InspectionFuture || got.Sealed() || got.Terminal() || got.Phase() != "" {
		t.Fatalf("future progress: %s %v", got.Status(), err)
	}
}

func TestSignedInspectionVisibleTerminalIsNotDurabilityConfirmation(t *testing.T) {
	for _, phase := range []string{"committed", "rolled-back"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			r, home, root := nativeSignedProject(t)
			tx, err := beginSignedNative(ctx, nativePlan(t, r, home))
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Release()
			if phase == "committed" {
				tx.commitFault = commitWriteAfterPublish
				if err := tx.Commit(ctx); !errors.Is(err, errCommitWriteFault) {
					t.Fatalf("expected publication uncertainty: %v", err)
				}
				if tx.state.Phase == "committed" {
					t.Fatal("fixture cached success")
				}
			} else {
				if err := tx.Apply(ctx); err != nil {
					t.Fatal(err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				// Publish the actual signed rollback receipt through the storage primitive
				// with a deterministic error after rename, before directory sync. No private
				// signing material is read or constructed by this fault fixture.
				name := filepath.Join(tx.dir, "state.json")
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := durableReplace(name, raw, commitWriteAfterPublish); !errors.Is(err, errCommitWriteFault) {
					t.Fatalf("expected rollback receipt publication uncertainty: %v", err)
				}
			}
			before := inspectionMetadata(t, root, home, r.ScratchRoot())
			got, err := InspectJournal(ctx, r, home, tx.ID())
			if err != nil || !got.Sealed() || !got.Terminal() || got.Phase() != phase || got.Durability() != ReceiptDurabilityNotObserved {
				t.Fatalf("visible terminal: phase=%s status=%s durability=%s err=%v", got.Phase(), got.Status(), got.Durability(), err)
			}
			assertInspectionUnchanged(t, before, root, home, r.ScratchRoot())
			// Cached mutator state cannot grant any additional observation certainty.
			tx.state.Phase = "untrusted-cache-value"
			fresh, err := InspectJournal(ctx, r, home, tx.ID())
			if err != nil || fresh.Phase() != phase || fresh.ReceiptDigest() != got.ReceiptDigest() || fresh.Durability() != ReceiptDurabilityNotObserved {
				t.Fatal("inspection used mutator cache", err)
			}
			assertInspectionUnchanged(t, before, root, home, r.ScratchRoot())
		})
	}
}

func TestPublishedPriorGuardWithSignedInspection(t *testing.T) {
	for _, phase := range []string{"prepared", "applying", "committed"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			r, home, root := nativeSignedProject(t)
			first, err := beginSignedNative(ctx, nativePlan(t, r, home))
			if err != nil {
				t.Fatal(err)
			}
			if phase == "applying" {
				err = first.Apply(ctx)
			}
			if phase == "committed" {
				err = first.Commit(ctx)
			}
			if err != nil {
				first.Release()
				t.Fatal(err)
			}
			first.Release()
			receipt := filepath.Join(first.dir, "state.json")
			old, err := os.ReadFile(receipt)
			if err != nil {
				t.Fatal(err)
			}
			nextPlan, err := gen.PlanNative(ctx, r, home, []gen.NativeOperation{{Kind: "entity", Name: "Gadget"}})
			if err != nil {
				t.Fatal(err)
			}
			next, err := beginSignedNative(ctx, nextPlan)
			if phase != "committed" {
				if next != nil {
					next.Release()
				}
				if !errors.Is(err, ErrActive) {
					t.Fatalf("published guard refusal: %v", err)
				}
				for _, name := range nextPlan.Result().CreatedFiles {
					if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
						t.Fatal("second output published")
					}
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := next.Commit(ctx); err != nil {
					next.Release()
					t.Fatal(err)
				}
				next.Release()
			}
			fresh, err := os.ReadFile(receipt)
			if err != nil || !bytes.Equal(old, fresh) {
				t.Fatal("first receipt changed")
			}
			got, err := InspectJournal(ctx, r, home, first.ID())
			if err != nil || !got.Sealed() || got.Terminal() != (phase == "committed") {
				t.Fatal("published guard inspection", err)
			}
		})
	}
}

func TestSignedUpdateInspectionPublishedSlotSchema(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "rolled-back"}[rollback], func(t *testing.T) {
			ctx := context.Background()
			tx, fixture, r, home := signedUpdateEngine(t)
			defer tx.Release()
			if err := inspectionMaterial(tx.plan.Material); err != nil {
				t.Fatal("published update material inspection schema", err)
			}
			if err := tx.validateSteps(); err != nil {
				t.Fatal("published update step schema", err)
			}
			// Published Update fixtures enroll source evidence in the bootstrap
			// store, but leave the runtime's separate FS CAS empty. Observe this
			// real gap before explicitly materializing those exact fixture CAS
			// objects. Production inspection never falls back to that store.
			missing, err := InspectJournal(ctx, r, home, tx.ID())
			if err != nil || missing.Status() != InspectionMissingCAS || !missing.Sealed() || missing.Terminal() {
				t.Fatal("unpopulated concrete CAS must refuse active readiness", err)
			}
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
				if err != nil {
					t.Fatal(err)
				}
				if evidencecas.Digest(raw) != ref {
					t.Fatal("fixture source CAS digest")
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
			assertInspected(t, r, home, tx, InspectionActive, false)
			deleted, registry := false, false
			for _, step := range tx.state.Steps {
				deleted = deleted || step.Delete
				registry = registry || step.Registry
			}
			if !deleted || !registry {
				t.Fatal("fixture lacks actual deletion/registry pair")
			}
			if err := tx.Apply(ctx); err != nil {
				t.Fatal(err)
			}
			assertInspected(t, r, home, tx, InspectionActive, false)
			if rollback {
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
			status := InspectionCommitted
			if rollback {
				status = InspectionRolledBack
			}
			assertInspected(t, r, home, tx, status, true)
			var registrySlot string
			for _, step := range tx.state.Steps {
				if step.Registry {
					registrySlot = tx.slotPath(step)
				}
			}
			// Retain the exact inode outside both inspected private namespaces.
			held := filepath.Join(filepath.Dir(home), "retained-registry-slot")
			if err := os.Rename(registrySlot, held); err != nil {
				t.Fatal(err)
			}
			got, err := InspectJournal(ctx, r, home, tx.ID())
			if err != nil || got.Status() != InspectionMissingImages || got.Terminal() {
				t.Fatalf("missing registry slot: %s %v", got.Status(), err)
			}
			if err := os.Rename(held, registrySlot); err != nil {
				t.Fatal(err)
			}
			assertInspected(t, r, home, tx, status, true)
			// Remove an actual target-source object from the runtime-held CAS;
			// the old source alone must not make the after closure look complete.
			digest := fixture.targetRefs.StatementCAS
			hex := strings.TrimPrefix(digest, "sha256:")
			casPath := filepath.Join(fixture.evidence, "sha256", hex[:2], hex[2:])
			raw, err := os.ReadFile(casPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(casPath); err != nil {
				t.Fatal(err)
			}
			missing, err = InspectJournal(ctx, r, home, tx.ID())
			if err != nil || !missing.Terminal() || !slices.Contains(missing.Issues(), InspectionMissingCAS) {
				t.Fatalf("actual target CAS: %v %v", missing.Issues(), err)
			}
			if err := os.WriteFile(casPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			assertInspected(t, r, home, tx, status, true)
		})
	}
}

func TestSignedInspectionCurrentMarkerAndUncoveredAuthority(t *testing.T) {
	ctx := context.Background()
	r, home, root := nativeSignedProject(t)
	tx, err := beginSignedNative(ctx, nativePlan(t, r, home))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		tx.Release()
		t.Fatal(err)
	}
	tx.Release()
	markerPath := filepath.Join(root, ".tplaiter/project.yaml")
	original, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(original, &marker); err != nil {
		t.Fatal(err)
	}
	// Legitimate current metadata can change without rewriting the historical
	// journal or requiring a whole old-target/old-marker afterimage match.
	marker.Project["inspection-note"] = "later legitimate metadata"
	later, err := yaml.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, later, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := InspectJournal(ctx, r, home, tx.ID())
	if err != nil || !got.Sealed() || !got.Terminal() {
		t.Fatal("legitimate current metadata refused", err)
	}
	marker.ID = "foreign-project"
	foreignMarker, err := yaml.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, foreignMarker, 0o644); err != nil {
		t.Fatal(err)
	}
	before := inspectionMetadata(t, root, home, r.ScratchRoot())
	got, err = InspectJournal(ctx, r, home, tx.ID())
	if err == nil || got.Sealed() || got.Terminal() || got.Phase() != "" {
		t.Fatal("foreign CURRENT marker accepted")
	}
	assertInspectionUnchanged(t, before, root, home, r.ScratchRoot())
	if err := os.WriteFile(markerPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	heldMarker := filepath.Join(filepath.Dir(root), "retained-marker")
	if err := os.Rename(markerPath, heldMarker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(heldMarker, markerPath); err != nil {
		t.Fatal(err)
	}
	got, err = InspectJournal(ctx, r, home, tx.ID())
	if err == nil || got.Sealed() || got.Terminal() {
		t.Fatal("marker symlink followed")
	}
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(heldMarker, markerPath); err != nil {
		t.Fatal(err)
	}
	// An unsigned root label cannot convert proven same-authority plan damage
	// into trusted foreign ownership or grant terminal status.
	planPath := filepath.Join(tx.dir, "plan.json")
	raw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var record envelope
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	var plan immutable
	if err := json.Unmarshal(record.Payload, &plan); err != nil {
		t.Fatal(err)
	}
	plan.Material.Root = filepath.Join(filepath.Dir(root), "caller-claimed-other-root")
	record.Payload, err = json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = InspectJournal(ctx, r, home, tx.ID())
	if err == nil || got.Status() != InspectionUnsafe || got.Sealed() || got.Terminal() {
		t.Fatal("unsigned ownership label trusted")
	}
	if err := os.WriteFile(planPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	other, otherHome, otherRoot := nativeSignedProject(t)
	otherTx, err := beginSignedNative(ctx, nativePlan(t, other, otherHome))
	if err != nil {
		t.Fatal(err)
	}
	if err := otherTx.Commit(ctx); err != nil {
		otherTx.Release()
		t.Fatal(err)
	}
	otherTx.Release()
	before = inspectionMetadata(t, root, home, r.ScratchRoot(), otherRoot, otherHome, other.ScratchRoot())
	got, err = InspectJournal(ctx, r, otherHome, otherTx.ID())
	if !errors.Is(err, ErrInspectionUncovered) || got.Status() != InspectionUnresolved || got.Sealed() || got.Terminal() || got.Phase() != "" {
		t.Fatalf("uncovered actual runtime: %s %v", got.Status(), err)
	}
	assertInspectionUnchanged(t, before, root, home, r.ScratchRoot(), otherRoot, otherHome, other.ScratchRoot())
	// The very same genuine receipt is terminal when observed through its
	// actual installed runtime; the first runtime never declares it corrupt.
	got, err = InspectJournal(ctx, other, otherHome, otherTx.ID())
	if err != nil || !got.Sealed() || !got.Terminal() || got.Status() != InspectionCommitted {
		t.Fatal("own installed runtime refused genuine receipt", err)
	}
	assertInspectionUnchanged(t, before, root, home, r.ScratchRoot(), otherRoot, otherHome, other.ScratchRoot())
}
