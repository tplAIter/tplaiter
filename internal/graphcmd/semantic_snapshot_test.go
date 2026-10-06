package graphcmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
)

func TestSemanticCaptureRequiresActualInstalledRuntime(t *testing.T) {
	if _, e := CaptureSemanticFiles(context.Background(), nil, runtimeassembly.Options{}); e == nil {
		t.Fatal("nil runtime admitted")
	}
	var s SemanticFiles
	if _, _, _, e := s.Images(context.Background()); e == nil {
		t.Fatal("zero snapshot admitted")
	}
	if e := s.Recheck(context.Background()); e == nil {
		t.Fatal("zero snapshot fresh")
	}
	s.Close()
}
func TestSemanticSharedCaptureConfinedBytesAndStale(t *testing.T) {
	// This exercises the shared byte kernel, not authenticated installed admission.
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(root, "service.go")
	raw := []byte("package service\nfunc Value() int { return 1 }\n")
	if e = os.WriteFile(p, raw, 0644); e != nil {
		t.Fatal(e)
	}
	s, e := captureFiles(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if len(s.files) != 1 || string(s.files[0].Bytes) != string(raw) || s.facts[0].Mode != 0644 {
		t.Fatal("capture lost bytes/mode")
	}
	if e = os.WriteFile(p, []byte("package service\nfunc Value() int { return 2 }\n"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = s.recheck(context.Background()); e == nil {
		t.Fatal("changed byte image stayed fresh")
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("/outside/not-read", p); e != nil {
		t.Fatal(e)
	}
	if _, e = captureFiles(context.Background(), root); e == nil {
		t.Fatal("symlink followed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = captureFiles(ctx, root); !errors.Is(e, context.Canceled) {
		t.Fatal("ignored cancellation", e)
	}
}
