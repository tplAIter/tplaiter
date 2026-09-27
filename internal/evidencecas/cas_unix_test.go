//go:build darwin || linux

package evidencecas

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixRootRejectsSymlinkComponent(t *testing.T) {
	base := t.TempDir()
	physical := filepath.Join(base, "physical")
	if err := os.MkdirAll(physical, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(physical, alias); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := NewFSReader(alias); err == nil {
		t.Fatal("accepted symlink root")
	}
}
