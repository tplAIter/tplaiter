package renderref

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"
)

func templateFixture(t *testing.T) fs.FS {
	t.Helper()
	return os.DirFS(filepath.Join("..", "..", "testdata", "fixtures", "single-basic"))
}

func TestRenderInScratchMatchesExistingEngineAndCleansOwnedDirectory(t *testing.T) {
	scratch := t.TempDir()
	if err := os.Chmod(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	src := templateFixture(t)
	plain, err := Render(context.Background(), src, Input{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	preview, err := RenderInScratch(context.Background(), src, Input{}, scratch)
	if err != nil {
		t.Fatalf("RenderInScratch: %v", err)
	}
	if len(preview.Files) != len(plain.Files) {
		t.Fatalf("files = %d, want %d", len(preview.Files), len(plain.Files))
	}
	for path, want := range plain.Files {
		if got := string(preview.Files[path]); got != string(want) {
			t.Fatalf("%s differs", path)
		}
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("scratch retained %d entries", len(entries))
	}
}

func TestRenderInScratchRejectsCancelledAndUnsafeRoots(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderInScratch(ctx, templateFixture(t), Input{}, private); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled render = %v", err)
	}
	if _, err := RenderInScratch(context.Background(), templateFixture(t), Input{}, "relative"); err == nil {
		t.Fatal("relative root accepted")
	}
	link := filepath.Join(t.TempDir(), "scratch-link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := RenderInScratch(context.Background(), templateFixture(t), Input{}, link); err == nil {
		t.Fatal("symlink root accepted")
	}
}

func TestRenderInScratchJoinsPrimaryAndCleanupFailure(t *testing.T) {
	scratch := t.TempDir()
	if err := os.Chmod(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	cleanupFailure := errors.New("cleanup failure")
	original := closeScratch
	closeScratch = func(dir *scratchDirectory) error { return errors.Join(dir.Close(), cleanupFailure) }
	t.Cleanup(func() { closeScratch = original })
	result, err := RenderInScratch(context.Background(), fstest.MapFS{}, Input{}, scratch)
	if result != nil || !errors.Is(err, fs.ErrNotExist) || !errors.Is(err, cleanupFailure) {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	entries, readErr := os.ReadDir(scratch)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("cleanup entries=%v err=%v", entries, readErr)
	}
}

func TestRenderInScratchDiscardsBoundedOutputAndCleansUp(t *testing.T) {
	for _, tc := range []struct {
		name, wantErr string
		count, bytes  int
	}{
		{name: "entry limit", wantErr: "renderref: preview output entry limit", count: 4097, bytes: 1},
		{name: "byte limit", wantErr: "renderref: preview output byte limit", count: 2, bytes: 32 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			scratch := filepath.Join(parent, "scratch")
			if err := os.Mkdir(scratch, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(scratch, 0o700); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(parent, "outside.txt")
			const sentinelData = "must remain untouched"
			if err := os.WriteFile(sentinel, []byte(sentinelData), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := testContext(t)
			defer cancel()
			src := boundedFixture(tc.count, tc.bytes)
			if tc.name == "byte limit" {
				src = boundedFixtureWithSizes(32<<20, 32<<20+1)
			}
			result, err := RenderInScratch(ctx, src, Input{}, scratch)
			if result != nil || err == nil || err.Error() != tc.wantErr {
				t.Fatalf("bounded preview result=%#v err=%q want exact %q", result, err, tc.wantErr)
			}
			entries, readErr := os.ReadDir(scratch)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("scratch entries=%v err=%v", entries, readErr)
			}
			gotSentinel, readErr := os.ReadFile(sentinel)
			if readErr != nil || string(gotSentinel) != sentinelData {
				t.Fatalf("external sentinel=%q err=%v", gotSentinel, readErr)
			}
		})
	}
}

func boundedFixture(count, size int) fs.FS {
	sizes := make([]int, count)
	for i := range sizes {
		sizes[i] = size
	}
	return boundedFixtureWithSizes(sizes...)
}

func boundedFixtureWithSizes(sizes ...int) fs.FS {
	files := fstest.MapFS{"template.manifest.yaml": {Data: []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: bounded\n  version: 1.0.0\n  description: bounded fixture\nengine:\n  type: gotemplate\n  root: files\n")}}
	for i, size := range sizes {
		data := make([]byte, size)
		for j := range data {
			data[j] = 'x'
		}
		files[fmt.Sprintf("files/f%04d.txt.tmpl", i)] = &fstest.MapFile{Data: data}
	}
	return files
}

// testContext bounds a render by the test binary's own deadline (go test
// -timeout) rather than a fixed wall-clock budget, so the limit tests assert
// the entry/byte bound and not how fast a loaded machine renders 4097 files.
// A small margin leaves time to report the failure before the binary panics.
func testContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	deadline, ok := t.Deadline()
	if !ok {
		return context.WithCancel(context.Background())
	}
	return context.WithDeadline(context.Background(), deadline.Add(-10*time.Second))
}
