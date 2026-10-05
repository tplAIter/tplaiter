//go:build darwin || linux

package runtimeassembly_test

import (
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

type replaceBindingContext struct {
	context.Context
	t                *testing.T
	root, home, kind string
	fired            bool
	before           map[string]image
	preserve         []string
}

func (c *replaceBindingContext) Err() error {
	stack := make([]byte, 16384)
	n := runtime.Stack(stack, false)
	if !c.fired && strings.Contains(string(stack[:n]), "internal/stateledger.ApplyPlanContext(") {
		c.fired = true
		if c.kind == "state" {
			state := filepath.Join(c.root, stateledger.StateDir)
			retained := c.root + ".retained-state"
			if err := os.Rename(state, retained); err != nil {
				c.t.Fatal(err)
			}
			if err := os.CopyFS(state, os.DirFS(retained)); err != nil {
				c.t.Fatal(err)
			}
			if err := filepath.WalkDir(retained, func(path string, _ fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				info, err := os.Lstat(path)
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(retained, path)
				if err != nil {
					return err
				}
				return os.Chmod(filepath.Join(state, rel), info.Mode().Perm())
			}); err != nil {
				c.t.Fatal(err)
			}
			c.preserve = []string{state, retained, c.home}
		} else {
			lock := filepath.Join(c.home, ".lock")
			retained := c.home + ".retained-lock"
			before, err := os.ReadFile(lock)
			if err != nil {
				c.t.Fatal(err)
			}
			if err := os.Rename(lock, retained); err != nil {
				c.t.Fatal(err)
			}
			if err := os.WriteFile(lock, before, 0o600); err != nil {
				c.t.Fatal(err)
			}
			c.preserve = []string{c.root, c.home, retained}
		}
		c.before = capture(c.t, c.preserve...)
	}
	return c.Context.Err()
}

func TestConcreteMigrationReplanBindingPreservesForeign(t *testing.T) {
	for _, kind := range []string{"state", "home-lock"} {
		t.Run(kind, func(t *testing.T) {
			r, home, root := nativeSignedProject(t)
			marker := filepath.Join(root, stateledger.StateDir, "project.yaml")
			legacy := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Project\nid: project-local-go\ntemplate:\n  repo: https://github.com/tplAIter/template-go\n  name: go\n  version: " + publicGoCommit + "\nproject: {}\nsettings: {}\nruntime: {}\n")
			if err := os.WriteFile(marker, legacy, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, stateledger.StateDir, "update.lock"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			options := runtimeassembly.Options{Home: home, SecretProvider: publicHome{}}
			planned, err := runtimeassembly.Plan(context.Background(), r, options)
			if err != nil {
				t.Fatal(err)
			}
			boundary := &replaceBindingContext{Context: context.Background(), t: t, root: root, home: home, kind: kind}
			_, err = runtimeassembly.ApplyPlan(boundary, r, options, planned.PlanSHA256)
			if !boundary.fired || !errors.Is(err, stateledger.ErrUnsafe) {
				t.Fatalf("interleave=%v refusal=%v", boundary.fired, err)
			}
			unchanged(t, boundary.before, boundary.preserve...)
			// Failed adapter released the original writer locks, so the same actual
			// runtime can re-plan and migrate a freshly reviewed unchanged binding.
			next, err := runtimeassembly.Plan(context.Background(), r, options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtimeassembly.ApplyPlan(context.Background(), r, options, next.PlanSHA256); err != nil {
				t.Fatal(err)
			}
		})
	}
}
