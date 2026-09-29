//go:build darwin || linux

package trustload

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

func TestRefreshSB07PostCommitNoAuthority(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name     string
		arm      func(t *testing.T, fixture bootstrapFixture, cancel context.CancelFunc, observer *storeProofObserver) VerifierFactory
		expected []error
	}{
		{"writer-close", armRefreshSB07Close, []error{ErrProvenanceUnavailable}},
		{"reopen-factory", armRefreshSB07FactoryFail, []error{ErrProvenanceUnavailable}},
		{"expired-verify", armRefreshSB07Expired, []error{ErrProvenanceUnavailable}},
		{"cancel", armRefreshSB07Cancel, []error{context.Canceled, ErrAnchorMissing}},
		{"root-swap", armRefreshSB07RootSwap, []error{ErrAnchorMissing}},
		{"reopen-driver-open", armRefreshSB07ReopenDriverOpen, []error{ErrProvenanceUnavailable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, next, evidence, old, wantNew := refreshBoundaryFixture(t)
			observer := &storeProofObserver{}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), storeProofObserverKey{}, observer))
			defer cancel()
			factory := tc.arm(t, fixture, cancel, observer)
			authority, err := Refresh(ctx, fixture.selection, factory, next, evidence)
			if authority != nil || err == nil {
				t.Fatalf("postcommit %s authority=%v err=%v", tc.name, authority, err)
			}
			assertRefreshExpectedError(t, err, tc.expected...)
			if tc.name == "root-swap" {
				restoreRefreshSB07Root(t, fixture)
			}
			assertRefreshBoundaryHead(t, fixture, old, wantNew, true)
		})
	}
}

func armRefreshSB07Close(t *testing.T, _ bootstrapFixture, _ context.CancelFunc, _ *storeProofObserver) VerifierFactory {
	old := storePhysicalClose
	armed, hits := false, 0
	storeRefreshPhaseHook = func(stage string) {
		if stage == "commit" {
			armed = true
		}
	}
	storePhysicalClose = func(conn *sql.Conn) error {
		err := old(conn)
		if armed {
			hits++
			return errors.New("post-commit close")
		}
		return err
	}
	t.Cleanup(func() {
		storePhysicalClose = old
		storeRefreshPhaseHook = nil
		if hits == 0 {
			t.Errorf("postcommit close seam not hit")
		}
	})
	return refreshSB06Factory
}

func armRefreshSB07FactoryFail(t *testing.T, _ bootstrapFixture, _ context.CancelFunc, _ *storeProofObserver) VerifierFactory {
	calls := 0
	return func(reader evidencecas.Reader) (*bootstrap.Verifier, error) {
		calls++
		if calls == 3 {
			return nil, errors.New("post-commit factory")
		}
		return refreshSB06Factory(reader)
	}
}

func armRefreshSB07Expired(t *testing.T, _ bootstrapFixture, _ context.CancelFunc, _ *storeProofObserver) VerifierFactory {
	calls := 0
	return func(reader evidencecas.Reader) (*bootstrap.Verifier, error) {
		calls++
		if calls != 3 {
			return refreshSB06Factory(reader)
		}
		return bootstrap.NewVerifier(reader, bootstrap.ClockFunc(func() time.Time { return time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC) }), nil, 0)
	}
}

func armRefreshSB07Cancel(t *testing.T, _ bootstrapFixture, cancel context.CancelFunc, _ *storeProofObserver) VerifierFactory {
	old := storeRefreshPhaseHook
	hit := false
	storeRefreshPhaseHook = func(stage string) {
		if stage == "commit" {
			hit = true
			cancel()
		}
	}
	t.Cleanup(func() {
		storeRefreshPhaseHook = old
		if !hit {
			t.Errorf("postcommit cancel seam not hit")
		}
	})
	return refreshSB06Factory
}

func armRefreshSB07RootSwap(t *testing.T, fixture bootstrapFixture, _ context.CancelFunc, _ *storeProofObserver) VerifierFactory {
	root, oldRoot := fixture.loaded.Install.OSS.StorePath, fixture.loaded.Install.OSS.StorePath+"-sb07-old"
	old := storeRefreshPhaseHook
	hit := false
	storeRefreshPhaseHook = func(stage string) {
		if stage != "commit" {
			return
		}
		hit = true
		if err := os.Rename(root, oldRoot); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		storeRefreshPhaseHook = old
		if !hit {
			t.Errorf("postcommit root swap seam not hit")
			return
		}
		if _, err := os.Lstat(oldRoot); os.IsNotExist(err) {
			return
		}
		if err := os.Remove(root); err != nil {
			t.Error(err)
			return
		}
		if err := os.Rename(oldRoot, root); err != nil {
			t.Error(err)
		}
	})
	return refreshSB06Factory
}

func restoreRefreshSB07Root(t *testing.T, fixture bootstrapFixture) {
	t.Helper()
	root, oldRoot := fixture.loaded.Install.OSS.StorePath, fixture.loaded.Install.OSS.StorePath+"-sb07-old"
	if _, err := os.Lstat(oldRoot); os.IsNotExist(err) {
		return
	} else if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(oldRoot, root); err != nil {
		t.Fatal(err)
	}
}

func armRefreshSB07ReopenDriverOpen(t *testing.T, _ bootstrapFixture, _ context.CancelFunc, observer *storeProofObserver) VerifierFactory {
	old := storeRefreshPhaseHook
	hit := false
	storeRefreshPhaseHook = func(stage string) {
		if stage != "commit" {
			return
		}
		hit = true
		observer.mu.Lock()
		observer.failPhase = "driver.open"
		observer.mu.Unlock()
	}
	t.Cleanup(func() {
		storeRefreshPhaseHook = old
		if !hit {
			t.Errorf("postcommit driver-open seam not hit")
		}
	})
	return refreshSB06Factory
}
