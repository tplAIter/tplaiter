package stateledger

import (
	"context"
	"errors"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
)

// Legacy profile-only authorities do not prove installed project identity.
type profileOnlyAuthority struct{ a fakeAuthority }

func (a profileOnlyAuthority) Binding() bootstrap.ProfileBinding { return a.a.Binding() }
func (a profileOnlyAuthority) CheckBinding(b bootstrap.ProfileBinding) error {
	return a.a.CheckBinding(b)
}

func TestVerifyStableRequiresProjectIdentityProof(t *testing.T) {
	root := stableProject(t)
	if _, err := VerifyStable(context.Background(), root, profileOnlyAuthority{fakeAuthority{fixtureProfile()}}, StableVerifyOptions{CAS: fullCAS()}); !errors.Is(err, ErrProjectIdentity) {
		t.Fatalf("profile-only fallback: %v", err)
	}
	if _, err := VerifyStable(nil, root, fakeAuthority{fixtureProfile()}, StableVerifyOptions{}); !errors.Is(err, ErrUnsafe) { //nolint:staticcheck // Deliberately exercise nil-context denial.
		t.Fatalf("nil context: %v", err)
	}
}

// Verification must also fail when cancellation occurs at its final fresh check.
type cancelFinalAuthority struct {
	fakeAuthority
	cancel context.CancelFunc
	checks int
}

func (a *cancelFinalAuthority) CheckProjectIdentity(ctx context.Context, root, id string) error {
	a.checks++
	if a.checks == 2 {
		a.cancel()
	}
	return a.fakeAuthority.CheckProjectIdentity(ctx, root, id)
}

func TestVerifyStableRechecksProjectIdentityBeforeReturning(t *testing.T) {
	root := stableProject(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &cancelFinalAuthority{fakeAuthority: fakeAuthority{fixtureProfile()}, cancel: cancel}
	if snapshot, err := VerifyStable(ctx, root, a, StableVerifyOptions{CAS: fullCAS()}); !errors.Is(err, context.Canceled) || snapshot != nil || a.checks != 2 {
		t.Fatalf("late cancellation: snapshot=%v error=%v checks=%d", snapshot, err, a.checks)
	}
}

func TestMarkerInventoryRequiresCoherentBytesTypeAndMode(t *testing.T) {
	raw := []byte("checked marker bytes")
	valid := Entry{Scope: "project", Path: StateDir + "/project.yaml", Kind: "file", Mode: 0o600, SHA256: sha(raw), Exists: true}
	if err := checkMarkerInventory(&Snapshot{Entries: []Entry{valid}}, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Entry){
		"foreign bytes": func(e *Entry) { e.SHA256 = sha([]byte("foreign marker")) },
		"mode":          func(e *Entry) { e.Mode = 0o644 },
		"type":          func(e *Entry) { e.Kind = "symlink"; e.Target = "foreign" },
		"nonexistent":   func(e *Entry) { e.Exists = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := valid
			mutate(&e)
			if err := checkMarkerInventory(&Snapshot{Entries: []Entry{e}}, raw, 0o600); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("incoherent marker: %v", err)
			}
		})
	}
	for _, entries := range [][]Entry{nil, {valid, valid}} {
		if err := checkMarkerInventory(&Snapshot{Entries: entries}, raw, 0o600); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("missing/duplicate marker: %v", err)
		}
	}
}
