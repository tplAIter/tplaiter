//go:build darwin || linux

package graphcmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitCachePublicationAndCorruptCounter(t *testing.T) {
	ctx := context.Background()
	root := graphTree(t)
	if e := os.Mkdir(filepath.Join(root, ".tplaiter"), 0700); e != nil {
		t.Fatal(e)
	}
	s, e := captureFiles(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	g, state, e := analyze(ctx, s, root, "read")
	if e != nil || state != "missing" {
		t.Fatal(state, e)
	}
	if _, e = os.Stat(filepath.Join(root, ".tplaiter", "graph-cache")); !os.IsNotExist(e) {
		t.Fatal("readonly created cache")
	}
	if e = publishCache(ctx, root, s, g); e != nil {
		t.Fatal(e)
	}
	hit, state, e := inspectCache(ctx, root, s)
	if e != nil || state != "hit" || hit.Digest != g.Digest {
		t.Fatal(state, e)
	}
	if e = os.WriteFile(filepath.Join(root, "service.go"), []byte("package service\nfunc Different() {}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	changed, e := captureFiles(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	defer changed.close()
	fresh, state, e := analyze(ctx, changed, root, "read")
	if e != nil || state != "stale" || fresh.Digest == g.Digest {
		t.Fatal("cached outdated facts", state, e)
	}
	if e = os.WriteFile(filepath.Join(root, ".tplaiter", "graph-cache", cacheName(cacheKey(s))), []byte(`{"apiVersion":"bad"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, state, e = inspectCache(ctx, root, s); e == nil || state != "corrupt" {
		t.Fatal("accepted corrupt cache", state, e)
	}
}
