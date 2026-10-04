//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Execute flag handling in a child so a regression to blocking os.Open cannot
// strand the test runner. There is never a writer attached to the FIFO.
func TestPublicInputFlagsRejectFIFOWithoutWriter(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--publishers", "--source-packages", "--project-contexts"} {
		t.Run(flag, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			fifo := filepath.Join(dir, "public-input")
			root := filepath.Join(dir, "install")
			if err := unix.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "-test.run=^TestPublicInputFIFOHelper$")
			command.Env = append(os.Environ(), "TPLAITER_TEST_FIFO_FLAG="+flag, "TPLAITER_TEST_FIFO_PATH="+fifo, "TPLAITER_TEST_FIFO_ROOT="+root)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("FIFO public input blocked past deadline: %v", ctx.Err())
			}
			if err != nil {
				t.Fatalf("FIFO rejection helper: %v\n%s", err, output)
			}
			if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("FIFO input published installation: %v", err)
			}
		})
	}
}

func TestPublicInputFIFOHelper(t *testing.T) {
	flag := os.Getenv("TPLAITER_TEST_FIFO_FLAG")
	if flag == "" {
		return
	}
	var out bytes.Buffer
	root := os.Getenv("TPLAITER_TEST_FIFO_ROOT")
	if err := run([]string{"--root", root, flag, os.Getenv("TPLAITER_TEST_FIFO_PATH")}, &out); err == nil {
		t.Fatal("FIFO accepted")
	}
	if out.Len() != 0 {
		t.Fatal("FIFO emitted install pins")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FIFO rejection created install: %v", err)
	}
}
