package readonlysnapshot

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// fsImage is a byte-exact image (paths, modes, mtimes, contents) of a tree.
func fsImage(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		line := path + " " + info.Mode().String() + " " + info.ModTime().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			line += " " + digest(b)
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestSnapshotWritesNothingAndIsReproducible(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for rel, content := range map[string]string{
		".tplaiter/project.yaml":    "id: project-1\n",
		".tplaiter/ownership.json":  "{\"version\":1}\n",
		".tplaiter/migrations.json": "{\"version\":1,\"applied\":[]}\n",
		"main.go":                   "package main\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, root, "init", "--quiet")
	runGit(t, root, "add", ".")
	if err := os.WriteFile(filepath.Join(root, "scratch.txt"), []byte("untracked"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := fsImage(t, root)
	first, err := Project(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Project(root)
	if err != nil {
		t.Fatal(err)
	}
	if after := fsImage(t, root); after != before {
		t.Fatalf("snapshot wrote to the project:\nbefore=%s\nafter=%s", before, after)
	}
	a, err := first.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := second.SHA256()
	if a != b {
		t.Fatal("snapshot digest is not reproducible")
	}
	if len(first.Ledgers) != 3 || first.IndexSHA256 == "" || len(first.Untracked) != 1 || len(first.Tracked) != 4 {
		t.Fatalf("snapshot components=%+v", first)
	}
}

func TestSnapshotIsolatesGitFromUserConfiguration(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".tplaiter"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".tplaiter", "project.yaml"), []byte("id: p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	var envs [][]string
	runner := recordingGit{fn: func(args []string, opts execx.Options) {
		calls = append(calls, args)
		envs = append(envs, opts.Env)
	}}
	if _, err := ProjectWith(context.Background(), root, Options{Runner: runner}); err != nil {
		t.Fatal(err)
	}
	if len(calls) == 0 {
		t.Fatal("git was not consulted")
	}
	for i, args := range calls {
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--no-optional-locks") || !strings.Contains(joined, "credential.helper=") {
			t.Fatalf("git call %d is not isolated: %s", i, joined)
		}
		env := strings.Join(envs[i], " ")
		for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0"} {
			if !strings.Contains(env, want) {
				t.Fatalf("git call %d misses %s: %s", i, want, env)
			}
		}
	}
}

// recordingGit fails every git call, as outside a work tree, and records it.
type recordingGit struct {
	fn func([]string, execx.Options)
}

func (r recordingGit) Run(_ context.Context, _ string, args []string, opts execx.Options) (execx.Result, error) {
	r.fn(args, opts)
	return execx.Result{ExitCode: 128}, &execx.ExitError{Name: "git", Args: args, ExitCode: 128}
}

func (recordingGit) LookPath(name string) (string, error) { return name, nil }
