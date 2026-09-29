package newcmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// TestPostCreateHookInterruptKillsHookGroup interrupts tplaiter (the test
// process) while an optional postCreate hook runs in its own process group.
// The hook group must be stopped, not orphaned, and the interrupt must abort
// the hook sequence instead of being downgraded to an optional-hook warning.
func TestPostCreateHookInterruptKillsHookGroup(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	target := t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "pids")
	marker := filepath.Join(target, "second-hook-ran")
	tpl := &manifest.Template{}
	tpl.Hooks.PostCreate = []manifest.Hook{
		{Run: `sleep 300 & echo "$$ $!" > "` + pidFile + `.tmp" && mv "` + pidFile + `.tmp" "` + pidFile + `"; wait`, Optional: true},
		{Run: `touch "` + marker + `"`},
	}
	var out, errOut bytes.Buffer
	r := &run{d: Deps{Runner: execx.Exec{}, Out: &out, Err: &errOut}}

	done := make(chan error, 1)
	go func() {
		done <- r.runHooks(context.Background(), target, tpl, settings.Resolved{}, manifest.ProjectInfo{})
	}()
	pgid, grandchild := readHookPids(t, pidFile)
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	err := <-done
	if !errors.Is(err, execx.ErrInterrupted) {
		t.Fatalf("runHooks err = %v; want ErrInterrupted", err)
	}
	if strings.Contains(errOut.String(), "skipped (optional)") {
		t.Fatalf("interrupt was downgraded to an optional-hook warning: %q", errOut.String())
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("the hook after the interrupted one still ran")
	}
	waitHookGone(t, -pgid, "hook process group")
	waitHookGone(t, grandchild, "hook grandchild")
}

func readHookPids(t *testing.T, path string) (pgid, grandchild int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if data, err := os.ReadFile(path); err == nil {
			f := strings.Fields(string(data))
			if len(f) == 2 {
				a, errA := strconv.Atoi(f[0])
				b, errB := strconv.Atoi(f[1])
				if errA == nil && errB == nil {
					return a, b
				}
			}
			t.Fatalf("malformed pid file %q", data)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not written", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitHookGone polls until kill(target, 0) reports ESRCH.
func waitHookGone(t *testing.T, target int, what string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := syscall.Kill(target, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (%d) still exists after the interrupt: kill(0)=%v", what, target, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
