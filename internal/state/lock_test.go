//go:build unix

package state

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// TestWithLock_SerializesConcurrentReadModifyWrite starts N goroutines, each
// reading projects.yaml, adding its record, and saving it—the classic
// read-modify-write that loses data without serialization. Without WithLock it
// is a lost-update test (the last writer wins); with it all N records must reach
// the file. Run with -race in the implementation's DoD.
func TestWithLock_SerializesConcurrentReadModifyWrite(t *testing.T) {
	home := t.TempDir()
	const n = 10

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = WithLock(home, func() error {
				p, err := LoadProjects(home)
				if err != nil {
					return err
				}
				p.Upsert(ProjectRef{ID: fmt.Sprintf("proj-%d", i), Path: fmt.Sprintf("/p/%d", i)})
				return SaveProjects(home, p)
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: WithLock() error = %v", i, err)
		}
	}

	got, err := LoadProjects(home)
	if err != nil {
		t.Fatalf("LoadProjects() error = %v", err)
	}
	if len(got.Items) != n {
		t.Fatalf("LoadProjects() has %d items after %d concurrent upserts, want %d (lost update)", len(got.Items), n, n)
	}
	seen := make(map[string]bool, n)
	for _, item := range got.Items {
		seen[item.ID] = true
	}
	if len(seen) != n {
		t.Errorf("LoadProjects() distinct IDs = %d, want %d: %+v", len(seen), n, got.Items)
	}
}

// TestWithLock_RunsFnAndPropagatesError checks the basic contract: fn is called
// exactly once and its error is returned to the caller.
func TestWithLock_RunsFnAndPropagatesError(t *testing.T) {
	home := t.TempDir()
	calls := 0

	err := WithLock(home, func() error {
		calls++
		return errors.New("boom")
	})
	if err == nil || err.Error() != "boom" {
		t.Errorf("WithLock() error = %v, want \"boom\"", err)
	}
	if calls != 1 {
		t.Errorf("WithLock() called fn %d times, want 1", calls)
	}
}

// TestWithLock_HomeMustExist documents that WithLock does not create home; the
// caller must call EnsureHome first (see WithLock's package comment). Here home
// exists (t.TempDir) but contains no files beforehand; flock must still create
// .lock and work.
func TestWithLock_HomeMustExist(t *testing.T) {
	home := t.TempDir()

	called := false
	if err := WithLock(home, func() error { called = true; return nil }); err != nil {
		t.Fatalf("WithLock() error = %v", err)
	}
	if !called {
		t.Error("WithLock() did not call fn")
	}
}
