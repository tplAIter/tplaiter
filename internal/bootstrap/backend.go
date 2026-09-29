package bootstrap

import (
	"context"
	"errors"
)

var (
	ErrProtectionUnavailable = errors.New("bootstrap: TRUST_PROTECTION_UNAVAILABLE")
	ErrPending               = errors.New("bootstrap: TRUST_PENDING")
)

// ProtectedReader is read-only. Production platform adapters are intentionally supplied by a later packet.
type ProtectedReader interface {
	CheckProtection(context.Context) error
	Snapshot(context.Context) (ProtectedSnapshot, error)
}
type ProtectedSnapshot struct {
	Envelope      []byte
	Receipt       []byte
	Transparency  TransparencyEvidence
	Pending       bool
	BackendID     string
	EvidenceClass EvidenceClass
}

func (s ProtectedSnapshot) copy() ProtectedSnapshot {
	s.Envelope = append([]byte(nil), s.Envelope...)
	s.Receipt = append([]byte(nil), s.Receipt...)
	return s
}

func protectedSnapshot(ctx context.Context, b ProtectedReader) (ProtectedSnapshot, error) {
	if b == nil {
		return ProtectedSnapshot{}, ErrProtectionUnavailable
	}
	if e := b.CheckProtection(ctx); e != nil {
		return ProtectedSnapshot{}, ErrProtectionUnavailable
	}
	s, e := b.Snapshot(ctx)
	if e != nil {
		return ProtectedSnapshot{}, ErrProtectionUnavailable
	}
	if s.Pending {
		return ProtectedSnapshot{}, ErrPending
	}
	if s.BackendID == "" || s.EvidenceClass != EvidenceProduction {
		return ProtectedSnapshot{}, ErrProtectionUnavailable
	}
	return s.copy(), nil
}
