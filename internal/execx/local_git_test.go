package execx

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestLocalGitCommitSanitizedEnvironmentAndCancellation(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{{"init", "-q", root}, {"-C", root, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com", "commit", "--allow-empty", "-qm", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture Git: %v %s", err, out)
		}
	}
	t.Setenv("GIT_DIR", "/nonexistent/poison")
	t.Setenv("GIT_CONFIG_COUNT", "invalid")
	got, err := LocalGitCommit(context.Background(), root, "HEAD")
	if err != nil || len(got) != 40 || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("local commit: %q %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LocalGitCommit(ctx, root, "HEAD"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolution: %v", err)
	}
	for _, ref := range []string{"", "--help", "HEAD\nother", "HEAD\x00other"} {
		if _, err := LocalGitCommit(context.Background(), root, ref); err == nil {
			t.Fatalf("invalid ref accepted: %q", ref)
		}
	}
}
