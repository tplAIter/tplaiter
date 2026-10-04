package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestUnadmittedEngineCannotMutate(t *testing.T) {
	tx := &Transaction{}
	if tx.ID() != "" {
		t.Fatal("undurable transaction exposed identity")
	}
	for _, action := range []func(context.Context) error{tx.Apply, tx.Commit, tx.Rollback} {
		if err := action(context.Background()); !errors.Is(err, ErrActive) {
			t.Fatalf("unadmitted mutation: %v", err)
		}
	}
	if err := tx.Seal(context.Background(), Material{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("raw zero material admitted: %v", err)
	}
	if err := tx.Admit(context.Background()); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("zero runtime admitted: %v", err)
	}
}

func TestStorageConfinement(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(base, "held")
	foreign := filepath.Join(base, "foreign")
	for _, name := range []string{parent, foreign} {
		if err := os.Mkdir(name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	name := filepath.Join(parent, "receipt")
	if err := durableExclusive(name, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	data, err := privateRead(name, 8)
	if err != nil || string(data) != "original" {
		t.Fatalf("read: %q %v", data, err)
	}
	if _, err := privateRead(name, 7); !errors.Is(err, ErrAuthentication) {
		t.Fatal("oversize accepted", err)
	}
	if err := durableExclusive(name, []byte("replacement"), 0o600); !os.IsExist(err) {
		t.Fatal("exclusive overwrite", err)
	}
	for _, bad := range []string{"relative/receipt", parent + "/../held/receipt"} {
		if _, err := privateRead(bad, 32); !errors.Is(err, ErrAuthentication) {
			t.Fatal("noncanonical read", err)
		}
		if err := durableExclusive(bad, nil, 0o600); !errors.Is(err, ErrAuthentication) {
			t.Fatal("noncanonical write", err)
		}
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := privateRead(link, 32); !errors.Is(err, ErrAuthentication) {
		t.Fatal("symlink read", err)
	}
	hard := filepath.Join(parent, "hard")
	if err := os.Link(name, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := privateRead(name, 32); !errors.Is(err, ErrAuthentication) {
		t.Fatal("hardlink read", err)
	}
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := privateRead(name, 32); !errors.Is(err, ErrAuthentication) {
		t.Fatal("wrong mode read", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		t.Fatal(err)
	}
	held, leaf, err := confinedParent(name)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := os.WriteFile(filepath.Join(foreign, "receipt"), []byte("foreign"), 0o640); err != nil {
		t.Fatal(err)
	}
	foreignInfo, err := os.Stat(filepath.Join(foreign, "receipt"))
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "moved")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, parent); err != nil {
		t.Fatal(err)
	}
	if err := checkStorageParent(held, name); !errors.Is(err, ErrAuthentication) {
		t.Fatal("swapped binding accepted", err)
	}
	if _, err := privateRead(name, 32); !errors.Is(err, ErrAuthentication) {
		t.Fatal("symlink parent read", err)
	}
	if err := durableExclusive(filepath.Join(parent, "new"), nil, 0o600); !errors.Is(err, ErrAuthentication) {
		t.Fatal("symlink parent write", err)
	}
	if err := durableReplace(name, []byte("overwrite"), commitWriteOK); !errors.Is(err, ErrAuthentication) {
		t.Fatal("symlink parent replace", err)
	}
	f, err := held.OpenFile(leaf, readNoFollow(), 0)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := f.Stat()
	f.Close()
	if err != nil || !os.SameFile(original, opened) {
		t.Fatal("held original inode lost")
	}
	after, err := os.Stat(filepath.Join(foreign, "receipt"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(foreign, "receipt"))
	if err != nil || string(raw) != "foreign" || !os.SameFile(foreignInfo, after) || after.Mode().Perm() != 0o640 {
		t.Fatal("foreign changed")
	}
	if _, err := os.Stat(filepath.Join(foreign, "new")); !os.IsNotExist(err) {
		t.Fatal("foreign new file")
	}
	// A real directory replacement also fails the held binding, not just symlinks.
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkStorageParent(held, name); !errors.Is(err, ErrAuthentication) {
		t.Fatal("foreign directory accepted", err)
	}
}

type identityInfo struct {
	os.FileInfo
	stat any
}

func (i identityInfo) Sys() any { return i.stat }
func TestDeviceIdentity(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stat := reflect.New(reflect.TypeOf(info.Sys()).Elem())
	dev := stat.Elem().FieldByName("Dev")
	stat.Elem().FieldByName("Ino").SetUint(99)
	values := []uint64{0, 1}
	if dev.Kind() == reflect.Int32 {
		values = append(values, 0x7fffffff, 0xffffffff80000000, 0xffffffffffffffff)
	} else {
		values = append(values, 1<<40, 1<<63, 0xffffffffffffffff)
	}
	for _, want := range values {
		if dev.Kind() == reflect.Int32 {
			if want <= 0x7fffffff {
				dev.SetInt(int64(want))
			} else {
				dev.SetInt(-1 - int64(^want))
			}
		} else {
			dev.SetUint(want)
		}
		fake := identityInfo{FileInfo: info, stat: stat.Interface()}
		got := fileID(fake)
		if got.Device != want || got.Inode != 99 {
			t.Fatalf("device identity lost bits: %x", want)
		}
	}
}
