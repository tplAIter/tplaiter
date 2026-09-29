package resultdto

import (
	"errors"
	"fmt"
)

// ExitCoder is implemented by typed errors that choose their exit code.
// Classification uses types and interfaces, never error text.
type ExitCoder interface{ ExitCode() ExitCode }

// Diagnosticer exposes a structured diagnostic. Projection never inspects an
// error's text, so wrapped and joined errors remain safe to classify.
type Diagnosticer interface{ Diagnostic() Diagnostic }

// DiagnosticError is a typed error that carries its public diagnostic.
type DiagnosticError struct {
	Value Diagnostic
	Exit  ExitCode
	Err   error
}

func (e *DiagnosticError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Value.Code + ": " + e.Err.Error()
	}
	return e.Value.Message
}

func (e *DiagnosticError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ExitCode implements [ExitCoder].
func (e *DiagnosticError) ExitCode() ExitCode {
	if e == nil {
		return ExitInternal
	}
	return e.Exit
}

// Diagnostic implements [Diagnosticer].
func (e *DiagnosticError) Diagnostic() Diagnostic {
	if e == nil {
		return Diagnostic{}
	}
	return e.Value
}

// NewDiagnosticError returns a typed error with a public diagnostic.
func NewDiagnosticError(diagnostic Diagnostic, exit ExitCode, err error) *DiagnosticError {
	if diagnostic.Details == nil {
		diagnostic.Details = map[string]any{}
	}
	return &DiagnosticError{Value: diagnostic, Exit: exit, Err: err}
}

// LifecycleError is a typed error whose public projection is only its code.
type LifecycleError struct {
	Code string
	Exit ExitCode
	Err  error
}

func (e *LifecycleError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}
	return e.Code
}

func (e *LifecycleError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ExitCode implements [ExitCoder].
func (e *LifecycleError) ExitCode() ExitCode {
	if e == nil {
		return ExitInternal
	}
	return e.Exit
}

// Diagnostic implements [Diagnosticer].
func (e *LifecycleError) Diagnostic() Diagnostic {
	if e == nil {
		return Diagnostic{}
	}
	// Err is retained for human logs and error chaining, but it may contain
	// answers, credentials or paths outside the public project identity. The
	// automation envelope exposes only a deterministic safe message.
	return Diagnostic{Code: e.Code, Severity: "error", Message: "lifecycle operation failed", Details: map[string]any{}}
}

// NewError returns a [LifecycleError].
func NewError(code string, exit ExitCode, err error) *LifecycleError {
	return &LifecycleError{Code: code, Exit: exit, Err: err}
}

// Classify returns the exit code chosen by the typed errors in err's chain.
// The highest code wins when several typed errors are joined. An error
// without a typed member is [ExitInternal]; callers that own a wider mapping
// (the CLI exit registry) apply it first.
func Classify(err error) ExitCode {
	if err == nil {
		return ExitSuccess
	}
	best := ExitCode(-1)
	walkErrors(err, func(current error) {
		c, ok := current.(ExitCoder)
		if ok && c.ExitCode().Valid() && c.ExitCode() > best {
			best = c.ExitCode()
		}
	})
	if best < 0 {
		return ExitInternal
	}
	return best
}

// ProjectDiagnostics deterministically flattens typed diagnostics from both
// errors.Join and ordinary wrapping. Unstructured errors are intentionally
// omitted; their text is not a protocol contract.
func ProjectDiagnostics(err error) []Diagnostic {
	var out []Diagnostic
	walkErrors(err, func(current error) {
		if d, ok := current.(Diagnosticer); ok {
			out = append(out, d.Diagnostic())
		}
	})
	r := Result{Diagnostics: out}
	return deduplicateDiagnostics(r.Canonical().Diagnostics)
}

// walkErrors visits every node of err's chain, including errors.Join
// branches, up to a fixed depth.
func walkErrors(err error, visit func(error)) {
	var walk func(error, int)
	walk = func(current error, depth int) {
		if current == nil || depth > 64 {
			return
		}
		visit(current)
		if many, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				walk(child, depth+1)
			}
			return
		}
		walk(errors.Unwrap(current), depth+1)
	}
	walk(err, 0)
}

func deduplicateDiagnostics(in []Diagnostic) []Diagnostic {
	out := make([]Diagnostic, 0, len(in))
	seen := map[string]struct{}{}
	for _, d := range in {
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", d.Code, d.Severity, d.Path, d.BlockID, d.Message)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}

// ClassifyChildExit maps the exit status of a tplaiter child process that
// did not produce a result/v1 envelope. Registered codes (1..10) are
// reported as [ExitChild] so a caller cannot confuse them with its own
// registry; signal exits (128+) are preserved.
func ClassifyChildExit(code int) int {
	if code == 0 {
		return int(ExitSuccess)
	}
	if code > int(ExitSuccess) && code <= int(ExitChild) {
		return int(ExitChild)
	}
	return code
}
