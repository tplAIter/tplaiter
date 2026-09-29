package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/ui"
	"github.com/tplAIter/tplaiter/internal/update"
)

// Main runs the CLI and returns the process exit status. It is the only
// place that maps errors to exit codes (docs/exit-codes.md):
//
//	0   success
//	1   findings (conflict markers found, lint failures, a diff)
//	2   usage (unknown command or flag, wrong number of arguments)
//	3   operational failure (the default for an untyped error)
//	4   conflicts left for manual resolution
//	5   refused by the trust policy
//	6   transaction failure
//	7   incompatible version or state
//	8   unavailable in this build (TRUST_*_UNAVAILABLE / _UNSUPPORTED)
//	9   internal error
//	10  a child process run on the user's behalf failed (--json mode)
//
// With --json, a command that fails before printing its own result/v1
// envelope gets a failure envelope on stdout; stderr keeps the human
// message.
func Main() int {
	return runMain(rootCmd, os.Args[1:], os.Stderr)
}

func runMain(root *cobra.Command, args []string, stderr io.Writer) int {
	emittedResult = false
	instrumentUsage(root)
	root.SetArgs(args)
	c, err := root.ExecuteC()
	if err == nil {
		return int(resultdto.ExitSuccess)
	}
	code := exitCodeFor(err)
	if !emittedResult && jsonRequested(c, args) {
		if op := resultOperation(c); op != "" {
			if raw, encErr := resultdto.MarshalCanonical(failureResult(op, err, code)); encErr == nil {
				_, _ = fmt.Fprintf(c.OutOrStdout(), "%s\n", raw)
			}
		}
	}
	if !errors.Is(err, errResultReported) {
		_, _ = fmt.Fprintln(stderr, ui.ErrorPrefix(ui.Default()), err)
	}
	return code.Int()
}

// usageError marks command-line usage mistakes (exit 2).
type usageError struct{ err error }

func (e *usageError) Error() string                { return e.err.Error() }
func (e *usageError) Unwrap() error                { return e.err }
func (e *usageError) ExitCode() resultdto.ExitCode { return resultdto.ExitUsage }

// usageArgsAnnotation marks a command whose Args validator is already
// wrapped by instrumentUsage.
const usageArgsAnnotation = "tplaiter.dev/usage-args"

// instrumentUsage types every command-line usage error as [usageError]:
// flag parsing errors (FlagErrorFunc, inherited by every subcommand),
// positional argument validation, and unknown subcommands of the root.
// It is idempotent.
func instrumentUsage(root *cobra.Command) {
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &usageError{err: err} })
	if root.Args == nil {
		// Without a validator cobra's legacy check reports unknown
		// subcommands as an untyped error; NoArgs reports the same message.
		root.Args = cobra.NoArgs
	}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Args != nil && c.Annotations[usageArgsAnnotation] == "" {
			validate := c.Args
			c.Args = func(cmd *cobra.Command, args []string) error {
				if err := validate(cmd, args); err != nil {
					return &usageError{err: err}
				}
				return nil
			}
			if c.Annotations == nil {
				c.Annotations = map[string]string{}
			}
			c.Annotations[usageArgsAnnotation] = "wrapped"
		}
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
}

// jsonRequested reports whether the invocation asked for --json. The flag
// value is used when cobra parsed it; otherwise (a usage error, or a command
// with DisableFlagParsing) the raw arguments before `--` are scanned.
func jsonRequested(c *cobra.Command, args []string) bool {
	if jsonMode(c) {
		return true
	}
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--json" || arg == "--json=true" {
			return true
		}
	}
	return false
}

// trustCodePattern matches the fixed code tokens that trust sentinel errors
// carry as their entire message, optionally prefixed by the owning package
// (for example "trustload: TRUST_ANCHOR_MISSING").
var trustCodePattern = regexp.MustCompile(`^(?:(?:trustload|bootstrap|trustverify|provenance|operationtrust|evidencecas): )?((?:TRUST|MCP)_[A-Z0-9_]+)$`)

// errorCodes returns the fixed trust/transport codes in err's chain, sorted
// and deduplicated. Only a whole leaf message that is exactly a code token
// counts; free text is never parsed for codes.
func errorCodes(err error) []string {
	var codes []string
	walkErrorChain(err, func(e error) {
		if hasUnwrap(e) {
			return
		}
		if m := trustCodePattern.FindStringSubmatch(e.Error()); m != nil {
			codes = append(codes, m[1])
		}
	})
	slices.Sort(codes)
	return slices.Compact(codes)
}

func hasUnwrap(e error) bool {
	switch e.(type) { //nolint:errorlint // inspects this node itself; the caller walks the chain
	case interface{ Unwrap() error }, interface{ Unwrap() []error }:
		return true
	}
	return false
}

func walkErrorChain(err error, visit func(error)) {
	var walk func(error, int)
	walk = func(e error, depth int) {
		if e == nil || depth > 64 {
			return
		}
		visit(e)
		if many, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				walk(child, depth+1)
			}
			return
		}
		walk(errors.Unwrap(e), depth+1)
	}
	walk(err, 0)
}

// codeExit maps one trust/transport code to its exit category.
func codeExit(code string) resultdto.ExitCode {
	if strings.HasSuffix(code, "_UNAVAILABLE") || strings.HasSuffix(code, "_UNSUPPORTED") {
		return resultdto.ExitUnavailable
	}
	if strings.HasPrefix(code, "MCP_") {
		return resultdto.ExitUnavailable
	}
	return resultdto.ExitTrust
}

// exitCodeFor is the exit-code registry. Typed errors choose their code;
// legacy exit statuses of update/settings/lint are mapped onto the registry;
// trust codes map by category; anything else is an operational failure.
func exitCodeFor(err error) resultdto.ExitCode {
	if err == nil {
		return resultdto.ExitSuccess
	}
	best := resultdto.ExitCode(-1)
	consider := func(code resultdto.ExitCode) {
		if code.Valid() && code > best {
			best = code
		}
	}
	walkErrorChain(err, func(e error) {
		if typed, ok := e.(resultdto.ExitCoder); ok {
			consider(typed.ExitCode())
		}
	})
	if best >= 0 {
		return best
	}
	var updateErr *update.ExitCodeError
	if errors.As(err, &updateErr) {
		return updateExit(updateErr.Code)
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		// ExitError carries an explicit status: 1 for findings (lint, doctor,
		// update --check) or a child's own status that `run`/`env setup`
		// propagate in text mode. It is passed through unchanged.
		return resultdto.ExitCode(exitErr.Code)
	}
	for _, code := range errorCodes(err) {
		consider(codeExit(code))
	}
	if best >= 0 {
		return best
	}
	return resultdto.ExitOperational
}

// updateExit maps the statuses of internal/update (update.ExitCodeError),
// which predate the registry: 1 meant "conflict markers found" (a finding)
// and 2 meant "conflicts remain for manual resolution".
func updateExit(code int) resultdto.ExitCode {
	switch code {
	case 0:
		return resultdto.ExitSuccess
	case 1:
		return resultdto.ExitFinding
	case 2:
		return resultdto.ExitConflict
	default:
		return resultdto.ExitOperational
	}
}

// failureResult is the envelope printed for a --json command that failed
// before printing its own. It never carries raw error text: only typed
// diagnostics, fixed trust codes, or a generic code.
func failureResult(op resultdto.Operation, err error, code resultdto.ExitCode) resultdto.Result {
	env := newResult(op)
	switch code {
	case resultdto.ExitTrust, resultdto.ExitTransaction, resultdto.ExitIncompatible, resultdto.ExitUnavailable:
		env.Status = resultdto.StatusBlocked
	case resultdto.ExitConflict:
		env.Status = resultdto.StatusConflicted
	case resultdto.ExitFinding:
		env.Status = resultdto.StatusChanges
	default:
		env.Status = resultdto.StatusFailed
	}
	if !code.Valid() {
		env.Status = resultdto.StatusFailed
	}
	env.Diagnostics = resultdto.ProjectDiagnostics(err)
	for _, c := range errorCodes(err) {
		env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: c, Severity: "error", Message: codeMessage(c), Details: map[string]any{}})
	}
	if errors.Is(err, project.ErrNotInProject) {
		env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "TPL-E-PROJECT-NOT-FOUND", Severity: "error", Message: "the working directory is not inside a tplaiter project", Details: map[string]any{}})
	}
	var usage *usageError
	if errors.As(err, &usage) {
		env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "CLI_USAGE", Severity: "error", Message: "invalid command-line usage; see --help", Details: map[string]any{}})
	}
	if len(env.Diagnostics) == 0 {
		env.Diagnostics = []resultdto.Diagnostic{{Code: "CLI_OPERATION_FAILED", Severity: "error", Message: "the command failed; run it without --json for the human-readable error", Details: map[string]any{"exitCode": code.Int()}}}
	}
	return env
}

func codeMessage(code string) string {
	if codeExit(code) == resultdto.ExitUnavailable {
		return "the operation is unavailable in this build or configuration"
	}
	return "the operation was refused by the trust policy"
}
