package newcmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/newtransaction"
)

func TestLiveNewRestrictiveUmask(t *testing.T) {
	const child = "TPLAITER_TEST_LIVE_UMASK_CHILD"
	if os.Getenv(child) != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// Change umask only in a separate process, never in this test runner.
		cmd := exec.Command("/bin/sh", "-c", `umask 077; exec "$1" -test.run='^TestLiveNewRestrictiveUmask$' -test.v`, "live-new-umask", binary)
		cmd.Env = append(os.Environ(), child+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("restrictive umask child: %v\n%s", err, output)
		}
		return
	}
	f, opts, d := liveFixture(t)
	before, err := os.Stat(f.project)
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), opts, d); err != nil {
		t.Fatal(err)
	}
	assertLiveProject(t, f, d)
	after, err := os.Stat(f.project)
	if err != nil || !os.SameFile(before, after) || before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf("caller root changed: %v", err)
	}
	assertLiveMode(t, filepath.Join(f.project, "hello.txt"), 0o644)
	assertLiveMode(t, filepath.Join(f.project, ".tplaiter"), 0o700)
	assertLiveMode(t, filepath.Join(f.project, ".tplaiter/root-template.lock.json"), 0o644)
	items, err := newtransaction.Inventory(d.Home)
	if err != nil || len(items) != 0 {
		t.Fatalf("normal new left uncertain journal: %+v %v", items, err)
	}
	// Exercise nested output directories, which the minimal signed fixture
	// does not contain, under the same child-only restrictive umask.
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".tplaiter"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeLiveTree(root, map[string][]byte{"nested/deeper/output.txt": []byte("owned")}); err != nil {
		t.Fatal(err)
	}
	assertLiveMode(t, root, 0o700)
	assertLiveMode(t, filepath.Join(root, "nested"), 0o755)
	assertLiveMode(t, filepath.Join(root, "nested/deeper"), 0o755)
	assertLiveMode(t, filepath.Join(root, "nested/deeper/output.txt"), 0o644)
	// The native mkdir children must not change their invoking process's 077
	// umask. These unrelated creations still receive restrictive permissions.
	if err := os.WriteFile(filepath.Join(root, "umask-probe"), []byte("probe"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "umask-dir-probe"), 0o777); err != nil {
		t.Fatal(err)
	}
	assertLiveMode(t, filepath.Join(root, "umask-probe"), 0o600)
	assertLiveMode(t, filepath.Join(root, "umask-dir-probe"), 0o700)
}

func assertLiveMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != mode {
		t.Fatalf("mode %s: want %o; info %v, error %v", path, mode, info, err)
	}
}

func TestLiveModeDoesNotChmodForeignDirectory(t *testing.T) {
	root := t.TempDir()
	before, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".tplaiter", "foreign"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeLiveTree(root, map[string][]byte{"foreign/output.txt": []byte("owned")}); !errors.Is(err, newtransaction.ErrOwnershipUncertain) {
		t.Fatalf("unowned directory accepted: %v", err)
	}
	assertLiveMode(t, filepath.Join(root, "foreign"), 0o700)
	assertLiveMode(t, root, before.Mode().Perm())
	if _, err := os.Stat(filepath.Join(root, "foreign/output.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrote into unowned directory: %v", err)
	}
}

func TestLiveDirectoryReplacementBeforeFirstObservation(t *testing.T) {
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	parent, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	info, err := parent.Stat()
	if err != nil {
		t.Fatal(err)
	}
	parent.Close()
	observed := map[string]os.FileInfo{".": info}
	called := false
	err = mkdirLiveParentsWith(root, "output", observed, func(root *os.Root, name string, parent os.FileInfo) error {
		if err := mkdirLiveDirectory(root, name, parent); err != nil {
			return err
		}
		// Deterministic reviewer interleaving: move A and install B before
		// the caller's very first Lstat/Open, not after descriptor retention.
		if err := root.Rename(name, "moved-A"); err != nil {
			return err
		}
		if err := root.Mkdir(name, 0o700); err != nil {
			return err
		}
		called = true
		return nil
	})
	if !called || !errors.Is(err, newtransaction.ErrOwnershipUncertain) {
		t.Fatalf("first-observation replacement accepted: called=%v err=%v", called, err)
	}
	assertLiveMode(t, filepath.Join(rootPath, "output"), 0o700)
	assertLiveMode(t, filepath.Join(rootPath, "moved-A"), 0o755)
	if _, accepted := observed["output"]; accepted {
		t.Fatal("foreign directory added to observed output parents")
	}
	entries, err := os.ReadDir(filepath.Join(rootPath, "output"))
	if err != nil || len(entries) != 0 {
		t.Fatal("foreign directory content changed")
	}
}

func TestLiveModeUsesRetainedDescriptorAfterPathReplacement(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			root := t.TempDir()
			name := filepath.Join(root, "owned")
			if directory {
				if err := os.Mkdir(name, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(name, []byte("owned"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			moved := filepath.Join(root, "retained")
			if err := os.Rename(name, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0o644)
			if directory {
				mode = 0o755
			}
			if err := chmodSyncLive(file, mode); err != nil {
				t.Fatal(err)
			}
			assertLiveMode(t, moved, mode)
			assertLiveMode(t, name, 0o600)
			if raw, err := os.ReadFile(name); err != nil || string(raw) != "foreign" {
				t.Fatal("foreign replacement changed")
			}
		})
	}
}
