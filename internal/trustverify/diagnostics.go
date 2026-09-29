package trustverify

import (
	"context"
	"errors"
)

// ErrorCode is safe to expose: it intentionally contains no reader text or bytes.
type ErrorCode string

const (
	TrustRuntimeInvalid         ErrorCode = "TRUST_RUNTIME_INVALID"
	TrustEvidenceMissing        ErrorCode = "TRUST_EVIDENCE_MISSING"
	TrustEvidenceTampered       ErrorCode = "TRUST_EVIDENCE_TAMPERED"
	TrustSubjectInvalid         ErrorCode = "TRUST_SUBJECT_INVALID"
	TrustProofUnsupported       ErrorCode = "TRUST_PROOF_UNSUPPORTED"
	TrustExecutionPolicyInvalid ErrorCode = "TRUST_EXECUTION_POLICY_INVALID"
	TrustRequestInvalid         ErrorCode = "TRUST_REQUEST_INVALID"
	TrustApprovalRequired       ErrorCode = "TRUST_APPROVAL_REQUIRED"
	TrustApprovalMismatch       ErrorCode = "TRUST_APPROVAL_MISMATCH"
	TrustLegacyUnbound          ErrorCode = "TRUST_LEGACY_UNBOUND"
)

type Diagnostic struct { //nolint:errname // public diagnostic type; the name is part of the verifier API
	code ErrorCode
}

func (e *Diagnostic) Error() string { return string(e.code) }
func (e *Diagnostic) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

func diagnostic(code ErrorCode, err error) error {
	if err == nil {
		return &Diagnostic{code: code}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	// Adapter and verifier errors can contain paths, opaque backend details, or
	// other untrusted text. Stable callers receive only this safe category.
	return &Diagnostic{code: code}
}
