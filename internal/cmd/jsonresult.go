package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// resultOperationAnnotation names the result/v1 operation a command reports
// with --json. [withResult] sets it; [runMain] reads it to emit a failure
// envelope when the command fails before producing its own.
const resultOperationAnnotation = "tplaiter.dev/result-operation"

// jsonFlagUsage is the help text of every --json flag.
const jsonFlagUsage = "print a result/v1 JSON envelope on stdout (see docs/exit-codes.md)"

// withResult declares that c reports op with --json and adds the flag (a
// command that already defines --json keeps its own definition). Commands
// call it from their constructor: `return withResult(c, op)`.
func withResult(c *cobra.Command, op resultdto.Operation) *cobra.Command {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[resultOperationAnnotation] = string(op)
	if c.Flags().Lookup("json") == nil {
		c.Flags().Bool("json", false, jsonFlagUsage)
	}
	return c
}

// setResultOperation records the operation a command whose operation depends
// on its flags (update) actually reports, so that a later failure envelope
// names the same operation.
func setResultOperation(c *cobra.Command, op resultdto.Operation) {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[resultOperationAnnotation] = string(op)
}

// resultOperation returns the operation c reports with --json, or "".
func resultOperation(c *cobra.Command) resultdto.Operation {
	if c == nil {
		return ""
	}
	return resultdto.Operation(c.Annotations[resultOperationAnnotation])
}

// jsonMode reports whether --json was given to cmd.
func jsonMode(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	v, err := cmd.Flags().GetBool("json")
	return err == nil && v
}

// emittedResult records that the current invocation already printed its
// envelope, so [runMain] does not print a second one for the same failure.
var emittedResult bool

// errResultReported is the stderr message of a command that already
// reported its non-zero outcome in the envelope.
var errResultReported = errors.New("see the result/v1 envelope on stdout")

// newResult returns an envelope for op stamped with this binary's version.
func newResult(op resultdto.Operation) resultdto.Result {
	return resultdto.New(op, resolveVersion())
}

// emitResult prints env on cmd's stdout as canonical result/v1 JSON and
// returns the error that makes the process exit with exit. exit must agree
// with env.Status (see resultdto.ValidateStatusExit); a violation is an
// internal contract bug and is reported as such without printing.
func emitResult(cmd *cobra.Command, env resultdto.Result, exit resultdto.ExitCode, cause error) error {
	if err := env.ValidateExit(exit); err != nil {
		return fmt.Errorf("cmd: result/v1 contract: %w", err)
	}
	raw, err := resultdto.MarshalCanonical(env)
	if err != nil {
		return fmt.Errorf("cmd: result/v1 contract: %w", err)
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n", raw); err != nil {
		return err
	}
	emittedResult = true
	if exit == resultdto.ExitSuccess {
		return nil
	}
	if cause == nil {
		cause = errResultReported
	}
	return &resultExitError{code: exit, err: cause}
}

// resultExitError carries the registry exit code of a command that already
// printed its envelope.
type resultExitError struct {
	code resultdto.ExitCode
	err  error
}

func (e *resultExitError) Error() string                { return e.err.Error() }
func (e *resultExitError) Unwrap() error                { return e.err }
func (e *resultExitError) ExitCode() resultdto.ExitCode { return e.code }

// emitData is emitResult for a successful envelope whose only payload is
// data.
func emitData(cmd *cobra.Command, op resultdto.Operation, proj *resultdto.Project, data any) error {
	env := newResult(op)
	env.Project = proj
	if err := env.SetData(data); err != nil {
		return err
	}
	return emitResult(cmd, env, resultdto.ExitSuccess, nil)
}

// projectAt identifies the project containing dir for a result envelope, or
// nil when dir is not inside a readable project. The project id comes from
// .tplaiter/project.yaml; markers written before ids existed fall back to
// the slug and then to the directory name, which are stable for the same
// checkout.
func projectAt(dir string) *resultdto.Project {
	root, proj, err := project.FindRoot(dir)
	if err != nil || proj == nil {
		return nil
	}
	id := proj.ID
	if id == "" {
		id = proj.Project.Slug
	}
	if id == "" {
		id = filepath.Base(root)
	}
	return &resultdto.Project{ID: id, Root: root}
}

// currentProject is projectAt for the working directory.
func currentProject() *resultdto.Project {
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}
	return projectAt(cwd)
}

// humanOut returns where a command prints human-readable progress and
// tables: stdout normally, nowhere in --json mode, where stdout carries only
// the envelope (whose data holds the same information) and stderr keeps
// warnings and errors. Discarding keeps MCP children well inside the
// transport's stderr bound.
func humanOut(cmd *cobra.Command) io.Writer {
	if jsonMode(cmd) {
		return io.Discard
	}
	return cmd.OutOrStdout()
}

// rfc3339 formats t for data payloads; the zero time is omitted.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// nonNil returns s, or an empty slice for nil, so that data arrays are
// never null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
