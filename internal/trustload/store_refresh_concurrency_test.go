//go:build darwin || linux

package trustload

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
)

type refreshConcurrencyResult struct {
	authority *bootstrap.Authority
	err       error
	observer  *storeProofObserver
}

func TestRefreshSB03PreparedConcurrency(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	fixture := newBootstrapFixture(t)
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	next, evidence := rotateBundle(t, fixture)
	old, wantNew := deriveRefreshSB06Heads(t, fixture, next, evidence)

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	previousClose := storePhysicalClose
	var closeCalls atomic.Int32
	storePhysicalClose = func(conn *sql.Conn) error {
		if closeCalls.Add(1) <= 2 {
			entered <- struct{}{}
			<-release
		}
		return previousClose(conn)
	}
	released := false
	results := make(chan refreshConcurrencyResult, 2)
	var group sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if !released {
			close(release)
			released = true
		}
		cancel()
		group.Wait()
		storePhysicalClose = previousClose
	}()
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			observer := &storeProofObserver{}
			callCtx := context.WithValue(ctx, storeProofObserverKey{}, observer)
			authority, err := Refresh(callCtx, fixture.selection, fixture.factory, next, evidence)
			results <- refreshConcurrencyResult{authority: authority, err: err, observer: observer}
		}()
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-deadline.C:
			t.Fatal("both Refresh calls did not reach post-Prepare close")
		}
	}
	close(release)
	released = true
	if !waitRefreshConcurrency(&group) {
		t.Fatal("Refresh goroutines did not reap")
	}
	close(results)
	winners, losers := 0, 0
	for result := range results {
		if result.authority != nil && result.err == nil {
			assertSB03ObserverBalance(t, result.observer, 3, 3)
			winners++
			continue
		}
		if result.authority == nil && errors.Is(result.err, ErrRefreshConflict) {
			assertSB03ObserverBalance(t, result.observer, 1, 1)
			losers++
			continue
		}
		t.Fatalf("unexpected concurrent result authority=%v err=%v", result.authority, result.err)
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("winners=%d losers=%d", winners, losers)
	}
	assertRefreshSB06RecoveredHead(t, fixture, old, wantNew, map[string]bool{"new": true})
}

func assertSB03ObserverBalance(t *testing.T, observer *storeProofObserver, opens, closes int) {
	t.Helper()
	if observer == nil {
		t.Fatal("missing contender observer")
	}
	observer.mu.Lock()
	gotOpens, gotCloses := observer.physicalOpens, observer.physicalCloses
	observer.mu.Unlock()
	if gotOpens != opens || gotCloses != closes {
		t.Fatalf("contender physical connections opens/closes=%d/%d want=%d/%d", gotOpens, gotCloses, opens, closes)
	}
}

func waitRefreshConcurrency(group *sync.WaitGroup) bool {
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(15 * time.Second):
		return false
	}
}

func TestRefreshSB03ReadStoreBlocksMaintenance(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	fixture := newBootstrapFixture(t)
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	next, evidence := rotateBundle(t, fixture)
	old, _ := deriveRefreshSB06Heads(t, fixture, next, evidence)
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCurrent(context.Background(), store, fixture.factory); err != nil {
		t.Fatal(err)
	}
	if got := readRefreshSB06Head(t, store); !refreshSB06HeadsEqual(got, old) {
		t.Fatal("retained SH reader did not observe complete old head")
	}
	if lease, err := openRootLease(context.Background(), fixture.loaded.Install.OSS.StorePath, storeRefresh); lease != nil || !errors.Is(err, ErrRefreshConflict) {
		if lease != nil {
			lease.Close()
		}
		t.Fatalf("maintenance EX while SH held: lease=%v err=%v", lease, err)
	}
	assertRefreshSB06RecoveredHead(t, fixture, old, old, map[string]bool{"old": true})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if lease, err := openRootLease(context.Background(), fixture.loaded.Install.OSS.StorePath, storeRefresh); err != nil {
		t.Fatalf("maintenance EX after SH close: %v", err)
	} else {
		lease.Close()
	}
}

var _ = sync.WaitGroup{}
