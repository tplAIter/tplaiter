//go:build linux || darwin

package ossinstall

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPublicationPreservesConcurrentEmptyDestination(t *testing.T) {
	parent := filepath.Dir(tempRoot(t))
	stage := filepath.Join(parent, "stage")
	root := filepath.Join(parent, "destination")
	writeTestFile(t, filepath.Join(stage, RegistrationFile), "verified candidate")
	var before os.FileInfo
	installationPublicationHook = func() {
		if err := os.Mkdir(root, 0o750); err != nil {
			t.Fatal(err)
		}
		// Fix the mode independently of the process umask.
		if err := os.Chmod(root, 0o750); err != nil {
			t.Fatal(err)
		}
		var err error
		before, err = os.Lstat(root)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { installationPublicationHook = nil })
	if err := publishInstallation(stage, root); !errors.Is(err, ErrInstallRootForeign) {
		t.Fatalf("concurrent empty destination: %v", err)
	}
	after, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if before == nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatal("foreign destination inode or mode replaced")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("foreign empty root changed: %v", err)
	}
	assertTestFile(t, filepath.Join(stage, RegistrationFile), "verified candidate")
}

func TestPublicationRefusesPreexistingEmptyDestination(t *testing.T) {
	parent := filepath.Dir(tempRoot(t))
	stage := filepath.Join(parent, "stage")
	root := filepath.Join(parent, "destination")
	writeTestFile(t, filepath.Join(stage, RegistrationFile), "candidate")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishInstallation(stage, root); !errors.Is(err, ErrInstallRootForeign) {
		t.Fatalf("existing empty destination: %v", err)
	}
	after, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatal("preexisting empty inode or mode replaced")
	}
}

func TestPublicationUnsupportedNativeRenameIsTypedRefusal(t *testing.T) {
	for _, err := range []error{unix.ENOSYS, unix.EINVAL, unix.ENOTSUP, unix.EOPNOTSUPP} {
		got := classifyPublicationRenameError(err)
		if !errors.Is(got, ErrPublicationUnsupported) || !errors.Is(got, err) {
			t.Fatalf("unsupported rename %v: %v", err, got)
		}
	}
	if got := classifyPublicationRenameError(unix.EACCES); !errors.Is(got, unix.EACCES) || errors.Is(got, ErrPublicationUnsupported) {
		t.Fatalf("ordinary I/O error changed: %v", got)
	}
}
