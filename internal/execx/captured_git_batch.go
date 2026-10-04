package execx

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"sync"
)

// CapturedGitBatch owns a single offline cat-file child over a caller-owned,
// sanitized bare snapshot. It streams pipes without retaining output; callers
// must bound and validate frames before allocation, and Close on every path.
// It is deliberately separate from Runner's inherited environment/buffering.
type CapturedGitBatch struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output io.ReadCloser
	once   sync.Once
}

// StartCapturedGitBatch starts only the fixed Git batch reader. Snapshot must be
// a private sanitized bare directory, never an original source repository. There
// is no executable, argv, config, environment or diagnostic-output override.
func StartCapturedGitBatch(ctx context.Context, snapshot string) (*CapturedGitBatch, error) {
	if ctx == nil || !filepath.IsAbs(snapshot) || filepath.Clean(snapshot) != snapshot {
		return nil, errors.New("execx: invalid captured Git snapshot")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Use a fixed relative gitdir in the owned snapshot; source paths never reach
	// argv. All Git/config/object/proxy/credential injection variables are absent.
	cmd := exec.CommandContext(ctx, "/usr/bin/git", "--git-dir=.", "cat-file", "--batch")
	cmd.Dir = snapshot
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + snapshot, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_COUNT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL="}
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, errors.New("execx: cannot start captured Git reader")
	}
	return &CapturedGitBatch{cmd: cmd, input: input, output: output}, nil
}

func (p *CapturedGitBatch) Read(b []byte) (int, error)  { return p.output.Read(b) }
func (p *CapturedGitBatch) Write(b []byte) (int, error) { return p.input.Write(b) }

// Close kills and waits exactly once, including cancelled/truncated/limit failure
// paths. Deliberate shutdown diagnostics are discarded rather than accumulated.
func (p *CapturedGitBatch) Close() error {
	p.once.Do(func() { _ = p.input.Close(); _ = p.output.Close(); _ = p.cmd.Process.Kill(); _ = p.cmd.Wait() })
	return nil
}
