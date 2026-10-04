package execx

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func capturedGitSnapshot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"objects", "refs"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("[core]\nrepositoryformatversion=0\nbare=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "HEAD"), []byte("ref: refs/heads/capture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCapturedGitBatchFixedOfflineStreamingOwnership(t *testing.T) {
	snapshot := capturedGitSnapshot(t)
	t.Setenv("GIT_OBJECT_DIRECTORY", "/unapproved")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "include.path")
	t.Setenv("GIT_CONFIG_VALUE_0", "/unapproved")
	child, err := StartCapturedGitBatch(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	id := strings.Repeat("a", 40)
	if _, err := io.WriteString(child, id+"\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReaderSize(child, 128).ReadSlice('\n')
	if err != nil || string(line) != id+" missing\n" {
		t.Fatal("offline fixed child did not stream missing-object reply")
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if child.cmd.ProcessState == nil {
		t.Fatal("owned child was not waited")
	}
}

func TestCapturedGitBatchCancellationKillsAndWaits(t *testing.T) {
	snapshot := capturedGitSnapshot(t)
	ctx, cancel := context.WithCancel(context.Background())
	child, err := StartCapturedGitBatch(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	var b [1]byte
	if _, err := child.Read(b[:]); err == nil {
		t.Fatal("cancelled child remained readable")
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if child.cmd.ProcessState == nil {
		t.Fatal("cancelled child was not waited")
	}
	if _, err := StartCapturedGitBatch(ctx, snapshot); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancelled child started")
	}
}
