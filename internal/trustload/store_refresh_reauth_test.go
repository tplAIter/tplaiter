//go:build darwin || linux

package trustload

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SB04 mutates one independently pinned input at each reauthentication
// boundary. The mutation is held through Refresh's result, then restored only
// so the same persisted root can be inspected with ordinary APIs.
func TestRefreshSB04ReauthBoundaries(t *testing.T) {
	for _, boundary := range []string{"proposal-sh-close-before-ex", "ex-post-lock", "commit-before", "commit"} {
		for _, target := range []string{"root", "active-marker", "descriptor", "provisioning", "policy"} {
			t.Run(boundary+"/"+target, func(t *testing.T) {
				fixture, next, evidence, old, wantNew := refreshBoundaryFixture(t)
				restore := armRefreshSB04Mutation(t, fixture, boundary, target)
				authority, err := Refresh(context.Background(), fixture.selection, fixture.factory, next, evidence)
				if authority != nil || err == nil {
					t.Fatalf("mutated %s/%s authority=%v err=%v", boundary, target, authority, err)
				}
				assertRefreshExpectedError(t, err, refreshSB04ExpectedError(boundary, target))
				restore()
				allowNew := boundary == "commit" || (boundary == "commit-before" && (target == "descriptor" || target == "provisioning" || target == "policy" || target == "root" || target == "active-marker"))
				assertRefreshBoundaryHead(t, fixture, old, wantNew, allowNew)
			})
		}
	}
}

func refreshSB04ExpectedError(boundary, target string) error {
	switch target {
	case "root":
		if boundary == "commit-before" || boundary == "commit" {
			return ErrAnchorMissing
		}
		return ErrProvenanceUnavailable
	case "active-marker":
		return ErrProvenanceUnavailable
	case "descriptor", "provisioning", "policy":
		if boundary == "commit-before" || boundary == "commit" {
			return ErrProvenanceUnavailable
		}
		return ErrPinMismatch
	default:
		panic("unknown SB04 target")
	}
}

// assertRefreshExpectedError accepts only a declared public error family. It
// intentionally does not print a lower-level error, which could disclose a
// database diagnostic or a local filesystem path.
func assertRefreshExpectedError(t *testing.T, err error, allowed ...error) {
	t.Helper()
	for _, want := range allowed {
		if errors.Is(err, want) {
			assertRefreshSafeErrorText(t, err)
			return
		}
	}
	t.Fatalf("Refresh returned undeclared public error family %s", refreshErrorFamily(err))
}

func assertRefreshSafeErrorText(t *testing.T, err error) {
	t.Helper()
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "sqlite") || strings.ContainsAny(text, "/\\") {
		t.Fatal("Refresh returned unsafe public error text")
	}
}

func refreshErrorFamily(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "context.Canceled"
	case errors.Is(err, ErrProvenanceUnavailable):
		return "ErrProvenanceUnavailable"
	case errors.Is(err, ErrPinMismatch):
		return "ErrPinMismatch"
	case errors.Is(err, ErrRefreshConflict):
		return "ErrRefreshConflict"
	case errors.Is(err, ErrPending):
		return "ErrPending"
	case errors.Is(err, ErrAnchorMissing):
		return "ErrAnchorMissing"
	case errors.Is(err, ErrConfigInvalid):
		return "ErrConfigInvalid"
	default:
		return "unknown"
	}
}

func refreshBoundaryFixture(t *testing.T) (bootstrapFixture, []byte, map[string][]byte, refreshSB06Head, refreshSB06Head) {
	t.Helper()
	fixture := newBootstrapFixture(t)
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	next, evidence := rotateBundle(t, fixture)
	old, wantNew := deriveRefreshSB06Heads(t, fixture, next, evidence)
	return fixture, next, evidence, old, wantNew
}

func armRefreshSB04Mutation(t *testing.T, fixture bootstrapFixture, boundary, target string) func() {
	t.Helper()
	mutate, restore := refreshSB04TargetMutation(t, fixture, target)
	var hit bool
	switch boundary {
	case "proposal-sh-close-before-ex":
		old := storePhysicalClose
		calls := 0
		storePhysicalClose = func(conn *sql.Conn) error {
			err := old(conn)
			calls++
			if calls == 1 {
				mutate()
				hit = true
			}
			return err
		}
		t.Cleanup(func() {
			storePhysicalClose = old
			if !hit {
				t.Errorf("missing %s seam", boundary)
			}
		})
	case "ex-post-lock":
		old := storeRootLeaseHook
		locks := 0
		storeRootLeaseHook = func(stage string) {
			if stage == "post-lock-pre-return" {
				locks++
				if locks == 2 {
					mutate()
					hit = true
				}
			}
		}
		t.Cleanup(func() {
			storeRootLeaseHook = old
			if !hit {
				t.Errorf("missing %s seam locks=%d", boundary, locks)
			}
		})
	case "commit-before", "commit":
		old := storeRefreshPhaseHook
		storeRefreshPhaseHook = func(stage string) {
			if stage == boundary {
				mutate()
				hit = true
			}
		}
		t.Cleanup(func() {
			storeRefreshPhaseHook = old
			if !hit {
				t.Errorf("missing %s seam", boundary)
			}
		})
	default:
		t.Fatal("unknown boundary")
	}
	return restore
}

func refreshSB04TargetMutation(t *testing.T, fixture bootstrapFixture, target string) (func(), func()) {
	t.Helper()
	path := ""
	switch target {
	case "descriptor":
		path = fixture.loaded.Install.Descriptor.Path
	case "provisioning":
		path = fixture.loaded.Install.Provisioning.Path
	case "policy":
		path = fixture.loaded.Install.ExecutionPolicy.Path
	case "active-marker":
		path = filepath.Join(fixture.loaded.Install.OSS.StorePath, activeMarkerName)
	case "root":
		root, old := fixture.loaded.Install.OSS.StorePath, fixture.loaded.Install.OSS.StorePath+"-sb04-old"
		return func() {
				if err := os.Rename(root, old); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
			}, func() {
				if err := os.Remove(root); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(old, root); err != nil {
					t.Fatal(err)
				}
			}
	default:
		t.Fatal("unknown target")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := path + "-sb04-old"
	replacement := append([]byte(nil), raw...)
	if target != "active-marker" {
		replacement = append(replacement, '\n')
	}
	return func() {
			if err := os.Rename(path, old); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, replacement, 0o600); err != nil {
				t.Fatal(err)
			}
		}, func() {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(old, path); err != nil {
				t.Fatal(err)
			}
		}
}

func assertRefreshBoundaryHead(t *testing.T, fixture bootstrapFixture, old, wantNew refreshSB06Head, allowNew bool) {
	t.Helper()
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := verifyCurrent(context.Background(), store, fixture.factory); err != nil {
		t.Fatal(err)
	}
	got := readRefreshSB06Head(t, store)
	if refreshSB06HeadsEqual(got, old) {
		return
	}
	if allowNew && refreshSB06HeadsEqual(got, wantNew) {
		return
	}
	t.Fatalf("durable head old=%v newAllowed=%v got=%+v", refreshSB06HeadsEqual(got, old), allowNew, got)
}
