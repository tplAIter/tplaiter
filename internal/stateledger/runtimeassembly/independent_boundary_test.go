//go:build darwin || linux

package runtimeassembly_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
)

type replacedDuringReplan struct {
	context.Context
	t     *testing.T
	home  string
	root  string
	fired bool
}

func (c *replacedDuringReplan) Err() error {
	b := make([]byte, 16384)
	n := runtime.Stack(b, false)
	if !c.fired && strings.Contains(string(b[:n]), "internal/stateledger.ApplyPlanContext(") {
		c.fired = true
		name := filepath.Join(c.root, stateledger.StateDir)
		if err := os.Rename(name, c.root+".retained-state"); err != nil {
			c.t.Fatal(err)
		}
		if err := os.CopyFS(name, os.DirFS(c.root+".retained-state")); err != nil {
			c.t.Fatal(err)
		}
		if err := filepath.WalkDir(c.root+".retained-state", func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			i, e := d.Info()
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(c.root+".retained-state", p)
			if e != nil {
				return e
			}
			return os.Chmod(filepath.Join(name, rel), i.Mode().Perm())
		}); err != nil {
			c.t.Fatal(err)
		}
	}
	return c.Context.Err()
}

func TestIndependentReplacedWriterDuringReplan(t *testing.T) {
	ctx := context.Background()
	r, home, root := nativeSignedProject(t)
	marker := filepath.Join(root, stateledger.StateDir, "project.yaml")
	legacy := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Project\nid: project-local-go\ntemplate:\n  repo: https://github.com/tplAIter/template-go\n  name: go\n  version: " + publicGoCommit + "\nproject: {}\nsettings: {}\nruntime: {}\n")
	if err := os.WriteFile(marker, legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	// Establish the same persistent coordination inode before the reviewed plan;
	// the adapter refuses a stale digest if a previously absent lock changes it.
	if err := os.WriteFile(filepath.Join(root, stateledger.StateDir, "update.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := runtimeassembly.Options{Home: home, SecretProvider: publicHome{}}
	planned, err := runtimeassembly.Plan(ctx, r, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(planned.Mutations) != 1 || planned.From != stateledger.ProjectV1 {
		t.Fatal("not a real marker migration")
	}
	boundary := &replacedDuringReplan{Context: ctx, t: t, home: home, root: root}
	_, err = runtimeassembly.ApplyPlan(boundary, r, opts, planned.PlanSHA256)
	after, readErr := os.ReadFile(marker)
	if readErr != nil {
		t.Fatal(readErr)
	}
	t.Logf("interleave=%v error=%v markerChanged=%v", boundary.fired, err, !bytes.Equal(legacy, after))
	if !boundary.fired {
		t.Fatal("boundary not reached")
	}
	if !errors.Is(err, stateledger.ErrUnsafe) {
		t.Fatalf("expected replaced binding refusal: %v", err)
	}
	if !bytes.Equal(legacy, after) {
		t.Fatal("replaced writer binding refused only AFTER publishing marker")
	}
}
