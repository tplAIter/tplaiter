package execx

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// LocalGitCommit resolves one local reference without checkout, inherited Git
// configuration, credentials, replacement objects, or partial-clone fetching.
// Its executable, arguments and environment are fixed here, not caller supplied.
func LocalGitCommit(ctx context.Context, clone, ref string) (string, error) {
	if ctx == nil || ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "\x00\r\n") {
		return "", errors.New("invalid local Git reference")
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return "", err
	}
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, git, "--no-optional-locks", "-C", clone, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1"}
	out, err := cmd.Output()
	if err != nil {
		return "", errors.Join(err, childCtx.Err())
	}
	return strings.TrimSpace(string(out)), nil
}
