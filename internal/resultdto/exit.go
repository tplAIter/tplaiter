package resultdto

import "fmt"

// ExitCode is the process-level contract shared by every tplaiter command.
// It is documented in docs/exit-codes.md; the numeric values are stable.
//
//	0  success
//	1  findings (diff present, check found drift or conflict markers, lint failures)
//	2  usage (unknown command or flag, wrong arguments)
//	≥3 typed failures
type ExitCode int

const (
	ExitSuccess      ExitCode = 0
	ExitFinding      ExitCode = 1
	ExitUsage        ExitCode = 2
	ExitOperational  ExitCode = 3
	ExitConflict     ExitCode = 4
	ExitTrust        ExitCode = 5
	ExitTransaction  ExitCode = 6
	ExitIncompatible ExitCode = 7
	ExitUnavailable  ExitCode = 8
	ExitInternal     ExitCode = 9
	// ExitChild is reported in --json mode when a child process that a
	// command runs on the user's behalf (a manifest command, a playbook)
	// exits non-zero; data carries the child's own exit status.
	ExitChild ExitCode = 10
)

// Valid reports whether e is one of the registered exit codes.
func (e ExitCode) Valid() bool { return e >= ExitSuccess && e <= ExitChild }

// Int returns e as a process exit status.
func (e ExitCode) Int() int { return int(e) }

// String returns the registry name of e.
func (e ExitCode) String() string {
	switch e {
	case ExitSuccess:
		return "success"
	case ExitFinding:
		return "finding"
	case ExitUsage:
		return "usage"
	case ExitOperational:
		return "operational"
	case ExitConflict:
		return "conflict"
	case ExitTrust:
		return "trust"
	case ExitTransaction:
		return "transaction"
	case ExitIncompatible:
		return "incompatible"
	case ExitUnavailable:
		return "unavailable"
	case ExitInternal:
		return "internal"
	case ExitChild:
		return "child"
	default:
		return fmt.Sprintf("exit(%d)", int(e))
	}
}

// StatusForExit returns the canonical envelope status for a process outcome.
// Producers may refine a successful operation to changes/not-applicable when
// they have domain evidence; failures must not guess from error text.
func StatusForExit(code ExitCode) Status {
	switch code {
	case ExitSuccess:
		return StatusOK
	case ExitFinding:
		return StatusChanges
	case ExitConflict:
		return StatusConflicted
	case ExitOperational, ExitTrust, ExitTransaction, ExitIncompatible, ExitUnavailable:
		return StatusBlocked
	default:
		return StatusFailed
	}
}

// statusExitMatrix lists the statuses allowed for each exit code.
var statusExitMatrix = map[ExitCode]map[Status]bool{
	ExitSuccess:      {StatusOK: true, StatusChanges: true, StatusNotApplicable: true},
	ExitFinding:      {StatusChanges: true, StatusConflicted: true, StatusFailed: true, StatusNotApplicable: true},
	ExitUsage:        {StatusFailed: true},
	ExitOperational:  {StatusFailed: true, StatusBlocked: true},
	ExitConflict:     {StatusConflicted: true},
	ExitTrust:        {StatusFailed: true, StatusBlocked: true},
	ExitTransaction:  {StatusFailed: true, StatusBlocked: true},
	ExitIncompatible: {StatusFailed: true, StatusBlocked: true},
	ExitUnavailable:  {StatusFailed: true, StatusBlocked: true},
	ExitInternal:     {StatusFailed: true},
	ExitChild:        {StatusFailed: true},
}

// ValidateStatusExit checks that status is allowed for exit code.
func ValidateStatusExit(status Status, code ExitCode) error {
	if !code.Valid() {
		return fmt.Errorf("invalid exit code %d", code)
	}
	if !validStatus(status) {
		return fmt.Errorf("unsupported result status %q", status)
	}
	if !statusExitMatrix[code][status] {
		return fmt.Errorf("status %q is incompatible with exit code %d (%s)", status, code, code)
	}
	return nil
}
