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

func TestReadCoordinationNoCreationBindingAndContention(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	state := filepath.Join(root, stateledger.StateDir)
	for _, dir := range []string{home, state} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	readers, err := holdReaders(context.Background(), root, home)
	if err != nil {
		t.Fatal(err)
	}
	if readers.complete() {
		t.Fatal("missing lock treated as held")
	}
	for _, lock := range []string{filepath.Join(state, "update.lock"), filepath.Join(home, ".lock")} {
		if _, err := os.Lstat(lock); !os.IsNotExist(err) {
			t.Fatal("readonly lock created")
		}
	}
	writers, err := holdWriters(context.Background(), root, home)
	if err != nil {
		t.Fatal(err)
	}
	if err := readers.check(context.Background()); !errors.Is(err, ErrJournal) {
		t.Fatal("new writer inode missed", err)
	}
	readers.close()
	if blocked, err := holdReaders(context.Background(), root, home); err == nil {
		blocked.close()
		t.Fatal("live writer admitted")
	}
	writers.close()
	readers, err = holdReaders(context.Background(), root, home)
	if err != nil {
		t.Fatal(err)
	}
	defer readers.close()
	if !readers.complete() {
		t.Fatal("existing writer inodes not retained")
	}
	if blocked, err := holdWriters(context.Background(), root, home); err == nil {
		blocked.close()
		t.Fatal("writer ran under reader")
	}
	lock := filepath.Join(home, ".lock")
	if err := os.Rename(lock, lock+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := readers.check(context.Background()); !errors.Is(err, stateledger.ErrUnsafe) {
		t.Fatal("replacement missed", err)
	}
}
