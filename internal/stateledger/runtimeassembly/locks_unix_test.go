//go:build darwin || linux

package runtimeassembly

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/stateledger"
)

func TestWriterLockBindingAndContention(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, stateledger.StateDir), 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := holdWriters(context.Background(), root, home)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	if second, err := holdWriters(context.Background(), root, home); err == nil {
		second.close()
		t.Fatal("busy writer admitted")
	}
	lock := filepath.Join(home, ".lock")
	old := lock + ".saved"
	if err := os.Rename(lock, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.check(context.Background()); !errors.Is(err, stateledger.ErrUnsafe) {
		t.Fatal(err)
	}
	first.close()
	first.locks = nil
	foreign, err := os.ReadFile(lock)
	if err != nil || string(foreign) != "foreign" {
		t.Fatal("foreign lock modified")
	}
}
