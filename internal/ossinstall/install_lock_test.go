package ossinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInstallLocksUseStableSiblingFiles(t *testing.T) {
	base := canonicalTempDir(t)
	root := filepath.Join(base, "prefix", "lib", "tplaiter", "trust")
	destination := filepath.Join(base, "prefix", "bin", "tplaiter")
	locks, err := AcquireInstallLocks(context.Background(), root, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := locks.Close(); err != nil {
		t.Fatal(err)
	}
	rootLock := filepath.Join(filepath.Dir(root), ".trust.tplaiter-install.lock")
	destinationLock := filepath.Join(filepath.Dir(destination), ".tplaiter.tplaiter-destination.lock")
	for _, path := range []string{rootLock, destinationLock} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
			t.Fatalf("invalid lock file %s: %+v", path, info)
		}
	}
	second, err := AcquireInstallLocks(context.Background(), root, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for _, path := range []string{rootLock, destinationLock} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInstallLocksRejectSymlinkAncestor(t *testing.T) {
	base := canonicalTempDir(t)
	outside := canonicalTempDir(t)
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	_, err := AcquireInstallLocks(context.Background(), filepath.Join(base, "link", "trust"), "")
	if err == nil {
		t.Fatal("symlink ancestor accepted")
	}
}

func TestInstallLocksAllowOrdinaryDirectoryLinkCounts(t *testing.T) {
	base := canonicalTempDir(t)
	if err := os.MkdirAll(filepath.Join(base, "existing", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	locks, err := AcquireInstallLocks(context.Background(), filepath.Join(base, "existing", "nested", "trust"), filepath.Join(base, "existing", "nested", "bin", "tplaiter"))
	if err != nil {
		t.Fatal(err)
	}
	if err := locks.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInstallLocksRejectOverlappingResourcesBeforeMutation(t *testing.T) {
	base := canonicalTempDir(t)
	root := filepath.Join(base, "foreign", "trust")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "nested", "bin", "tplaiter")
	if _, err := AcquireInstallLocks(context.Background(), root, destination); err == nil {
		t.Fatal("overlapping resources accepted")
	}
	if _, err := os.Stat(filepath.Dir(destination)); !os.IsNotExist(err) {
		t.Fatalf("overlap refusal created destination parents: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), ".trust.tplaiter-install.lock")); !os.IsNotExist(err) {
		t.Fatalf("overlap refusal created root lock: %v", err)
	}
}

func TestInstallLocksRejectDirectoryDestination(t *testing.T) {
	base := canonicalTempDir(t)
	root := filepath.Join(base, "trust")
	destination := filepath.Join(base, "bin", "tplaiter")
	if err := os.MkdirAll(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireInstallLocks(context.Background(), root, destination); err == nil {
		t.Fatal("directory destination accepted")
	}
}

func TestLockFileCloseIsIdempotent(t *testing.T) {
	base := canonicalTempDir(t)
	locks, err := AcquireInstallLocks(context.Background(), filepath.Join(base, "trust"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := locks.Close(); err != nil {
		t.Fatal(err)
	}
	if err := locks.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishExecutableRefusesAliasAndPreservesOldBytes(t *testing.T) {
	base := canonicalTempDir(t)
	source := filepath.Join(base, "build")
	destination := filepath.Join(base, "bin", "tplaiter")
	alias := filepath.Join(base, "foreign")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(destination, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishExecutable(source, destination); err == nil {
		t.Fatal("hard-linked destination accepted")
	}
	for _, path := range []string{destination, alias} {
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != "old executable" {
			t.Fatalf("pre-publication failure changed %s: %v %q", path, err, raw)
		}
	}
	if _, err := PublishExecutable(filepath.Dir(source), destination); err == nil {
		t.Fatal("non-regular build output accepted")
	}
	raw, err := os.ReadFile(destination)
	if err != nil || string(raw) != "old executable" {
		t.Fatalf("invalid source changed destination: %v %q", err, raw)
	}
}

func TestPublishExecutableRefusesObservedSubstitution(t *testing.T) {
	base := canonicalTempDir(t)
	source := filepath.Join(base, "build")
	destination := filepath.Join(base, "bin", "tplaiter")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	publicationPhaseHook = func(phase publicationPhase, path string) error {
		if phase == publicationBeforeRename {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.WriteFile(path, []byte("substituted executable"), 0o755)
		}
		return nil
	}
	defer func() { publicationPhaseHook = nil }()
	result, err := PublishExecutable(source, destination)
	if result.Committed || err == nil {
		t.Fatalf("observed substitution was published: committed=%v err=%v", result.Committed, err)
	}
	raw, readErr := os.ReadFile(destination)
	if readErr != nil || string(raw) != "substituted executable" {
		t.Fatalf("substitution result changed unexpectedly: %v %q", readErr, raw)
	}
}

func TestPublishExecutableReportsPostRenameFailureAsCommitted(t *testing.T) {
	base := canonicalTempDir(t)
	source := filepath.Join(base, "build")
	destination := filepath.Join(base, "bin", "tplaiter")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("simulated post-rename durability failure")
	publicationPhaseHook = func(phase publicationPhase, path string) error {
		if phase == publicationAfterRename {
			return failure
		}
		return nil
	}
	defer func() { publicationPhaseHook = nil }()
	result, err := PublishExecutable(source, destination)
	if !result.Committed || !errors.Is(err, failure) {
		t.Fatalf("post-rename failure classification: committed=%v err=%v", result.Committed, err)
	}
	raw, readErr := os.ReadFile(destination)
	if readErr != nil || string(raw) != "new executable" {
		t.Fatalf("committed bytes missing: %v %q", readErr, raw)
	}
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
