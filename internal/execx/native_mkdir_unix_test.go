//go:build darwin || linux

package execx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeMkdirHeldParentAndRefusals(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "parent")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	expected, err := parent.Stat()
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "held")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := MkdirAtParent(context.Background(), parent, foreign, "refused"); err == nil {
		t.Fatal("mismatched parent accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := MkdirAtParent(ctx, parent, expected, "cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled mkdir: %v", err)
	}
	if err := MkdirAtParent(context.Background(), parent, expected, "../escape"); err == nil {
		t.Fatal("invalid basename accepted")
	}
	if err := MkdirAtParent(context.Background(), parent, expected, "output"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(moved, "output"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("held directory mode: %v %v", info, err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("foreign parent changed: %v %v", entries, err)
	}
	for _, name := range []string{"refused", "cancelled"} {
		if _, err := os.Stat(filepath.Join(moved, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refusal created %s: %v", name, err)
		}
	}
}
