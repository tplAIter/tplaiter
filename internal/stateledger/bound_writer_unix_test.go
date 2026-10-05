//go:build darwin || linux

package stateledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBoundMigrationWriterConfinesRenameAndPreservesReplacement(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, StateDir)
	home := filepath.Join(root, "home")
	for _, dir := range []string{state, home} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"project.yaml", DependencyLockFile} {
		if err := os.WriteFile(filepath.Join(state, name), []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files := []*os.File{}
	open := func(path string, flags int) *os.File {
		f, err := os.OpenFile(path, flags, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		return f
	}
	projectFD, stateFD, homeFD := open(root, os.O_RDONLY), open(state, os.O_RDONLY), open(home, os.O_RDONLY)
	projectLock, homeLock := open(filepath.Join(state, "update.lock"), os.O_CREATE|os.O_RDWR), open(filepath.Join(home, ".lock"), os.O_CREATE|os.O_RDWR)
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	bound, err := BindMigrationWriter(context.Background(), root, projectFD, stateFD, homeFD, projectLock, homeLock)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	retained := filepath.Join(root, "retained")
	var foreign os.FileInfo
	original, err := os.Stat(filepath.Join(state, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFailpoint = func(stage, name string) error {
		if stage != "before-rename" || name != "project.yaml" {
			return nil
		}
		if err := os.Rename(state, retained); err != nil {
			return err
		}
		if err := os.Mkdir(state, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(state, name), []byte("foreign"), 0o640); err != nil {
			return err
		}
		var err error
		foreign, err = os.Stat(filepath.Join(state, name))
		return err
	}
	t.Cleanup(func() { writeFailpoint = nil })
	if err := bound.write(context.Background(), "project.yaml", []byte("migrated")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("replacement refusal: %v", err)
	}
	after, err := os.Stat(filepath.Join(state, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(state, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(foreign, after) || after.Mode().Perm() != 0o640 || string(raw) != "foreign" {
		t.Fatal("foreign publication changed")
	}
	old, err := os.Stat(filepath.Join(retained, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(retained, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(original, old) || original.Mode() != old.Mode() || string(raw) != "original" {
		t.Fatal("retained original changed")
	}
	entries, err := os.ReadDir(retained)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatal("owned temporary was not removed")
	}
}
