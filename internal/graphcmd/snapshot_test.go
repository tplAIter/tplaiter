//go:build darwin || linux

package graphcmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func graphTree(t *testing.T) string {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "service.go"), []byte("package service\nfunc Hello() {}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	return root
}
func TestConfinedImagesStaleSymlinkAndCancellation(t *testing.T) {
	root := graphTree(t)
	s, e := captureFiles(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if e = s.recheck(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "service.go"), []byte("package service\nfunc Changed() {}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = s.recheck(context.Background()); Code(e) != "GRAPH_SOURCE_STALE" {
		t.Fatal("missed source change", e)
	}
	if e = os.Symlink("service.go", filepath.Join(root, "alias.go")); e != nil {
		t.Fatal(e)
	}
	if _, e = captureFiles(context.Background(), root); Code(e) != "GRAPH_INPUT_TOPOLOGY" {
		t.Fatal("accepted symlink", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = captureFiles(ctx, graphTree(t)); e == nil {
		t.Fatal("accepted cancellation")
	}
}
