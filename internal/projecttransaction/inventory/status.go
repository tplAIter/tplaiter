// Package inventory observes existing-tree transaction evidence. Observations
// are not mutation capabilities and are never parsed as generic new/v1 journals.
package inventory

// Status distinguishes journal progress from unavailable evidence. A string
// reported by a caller or an unsigned journal never establishes terminal state.
type Status string

const (
	StatusUnverified      Status = "unverified"
	StatusActive          Status = "active"
	StatusCommitted       Status = "committed"
	StatusRolledBack      Status = "rolled-back"
	StatusFuture          Status = "future"
	StatusUnsupportedKind Status = "unsupported-kind"
	StatusUnsafe          Status = "unsafe"
	StatusMissingCAS      Status = "missing-cas"
	StatusMissingImages   Status = "missing-images"
	StatusUnresolved      Status = "unresolved"
)

// Record is a read-only result. Private fields prevent external construction of
// a verified terminal observation. It has no authority/material/key setter.
type Record struct {
	id            string
	kind          string
	phase         string
	status        Status
	issues        []Status
	planDigest    string
	receiptDigest string
	sealed        bool
	terminal      bool
}

// ID is the observed engine transaction ID.
func (r Record) ID() string { return r.id }

// Kind preserves the native-generator/native-update distinction.
func (r Record) Kind() string { return r.kind }

// Phase is the authenticated receipt phase, when one has been verified.
func (r Record) Phase() string { return r.phase }

// Status is unverified for a zero record; it cannot default to terminal success.
func (r Record) Status() Status {
	if r.status == "" {
		return StatusUnverified
	}
	return r.status
}

// Issues returns detached evidence classifications. Missing source CAS differs
// from missing physical image slots even when both apply to one receipt.
func (r Record) Issues() []Status { return append([]Status(nil), r.issues...) }

// PlanDigest identifies the authenticated immutable receipt, not a caller plan.
func (r Record) PlanDigest() string { return r.planDigest }

// ReceiptDigest identifies the verified progress receipt bytes.
func (r Record) ReceiptDigest() string { return r.receiptDigest }

// Sealed reports actual current-layout receipt authentication, not caller trust.
func (r Record) Sealed() bool { return r.sealed }

// Terminal is historical receipt evidence, never migration or mutation admission.
func (r Record) Terminal() bool { return r.terminal }

// ReceiptDurability is observation evidence, never a writer confirmation.
type ReceiptDurability string

const (
	ReceiptDurabilityUnverified  ReceiptDurability = "unverified"
	ReceiptDurabilityNotObserved ReceiptDurability = "not-observable-readonly"
)

// Durability describes receipt observation, not a mutator's terminal-confirmation
// result. Read-only inspection cannot establish that a prior fsync completed.
func (r Record) Durability() ReceiptDurability {
	if r.sealed {
		return ReceiptDurabilityNotObserved
	}
	return ReceiptDurabilityUnverified
}
