package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// ImportFromTool obtains a token from the `bin` CLI tool (`glab`/`gh`) using
// `<bin> auth token [--hostname <host>]` through runner and stores it under
// tool `tool` for host `host`. Returns the ID of the saved record.
//
// This is a reusable function called by both the `tplater auth
// import-glab|import-gh` command and the interactive `repo add` auth flow.
// All external calls go through [execx.Runner], so the logic can be mocked in
// unit tests without real glab/gh binaries.
//
// A missing binary in PATH is a meaningful actionable error (not a panic): the
// caller can show it to the user and suggest installation.
func ImportFromTool(ctx context.Context, s *Store, runner execx.Runner, bin, tool, host string) (int64, error) {
	if _, err := runner.LookPath(bin); err != nil {
		return 0, fmt.Errorf("auth: %s not found in PATH — install it and retry (%s auth login)", bin, bin)
	}

	runArgs := []string{"auth", "token"}
	if host != "" {
		runArgs = append(runArgs, "--hostname", host)
	}
	res, err := runner.Run(ctx, bin, runArgs, execx.Options{})
	if err != nil {
		return 0, fmt.Errorf("auth: %s auth token: %w", bin, err)
	}
	token := strings.TrimSpace(res.Stdout)
	if token == "" {
		return 0, fmt.Errorf("auth: %s returned empty token (run `%s auth login`)", bin, bin)
	}

	return s.Put(Credential{
		Host:  host,
		Tool:  tool,
		Token: token,
		Note:  "imported from " + bin,
	})
}
