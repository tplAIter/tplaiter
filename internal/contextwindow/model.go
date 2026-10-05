// Package contextwindow plans complete host envelopes and serializes reservations.
// The public host starts unknown: caller data cannot establish model capacity.
package contextwindow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	Invalid   = "CONTEXT_WINDOW_INVALID"
	Unknown   = "CONTEXT_WINDOW_UNKNOWN"
	Stale     = "CONTEXT_WINDOW_STALE"
	Overflow  = "CONTEXT_WINDOW_OVERFLOW"
	Conflict  = "CONTEXT_WINDOW_CONFLICT"
	Revoked   = "CONTEXT_WINDOW_REVOKED"
	Busy      = "CONTEXT_WINDOW_BUSY"
	HardBytes = 1 << 20
)

type Error struct{ Code, Field string }

func (e *Error) Error() string      { return e.Code + ": " + e.Field }
func fail(code, field string) error { return &Error{Code: code, Field: field} }

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Guard struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

// Envelope is host-recorded data, not a claim about tokens or model authority.
// Every field is included in the canonical request wire counted by the planner.
type Envelope struct {
	System         []string          `json:"system"`
	ToolSchemas    []json.RawMessage `json:"toolSchemas"`
	History        []Message         `json:"history"`
	PriorResponses []string          `json:"priorResponses"`
	Guards         []Guard           `json:"guards"`
}
type Scope struct {
	Session string `json:"session"`
	Model   string `json:"model"`
}
type Optional struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}
type Omission struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}
type Request struct {
	// OutputByteReserve applies only to the bounded-byte adapter, never model tokens.
	OutputByteReserve int

	ID               string
	Selection        *Selection
	Optional         []Optional
	MaxBytes         int
	ReasoningReserve int64
	OutputReserve    int64
}
type payload struct {
	QuerySHA256 string          `json:"querySHA256"`
	Required    json.RawMessage `json:"required"`
	Optional    []Optional      `json:"optional"`
	Omitted     []Omission      `json:"omitted"`
}
type pending struct {
	ID      string          `json:"id"`
	Context json.RawMessage `json:"context"`
}
type wireEnvelope struct {
	Scope    Scope             `json:"scope"`
	Base     Envelope          `json:"base"`
	Retained []json.RawMessage `json:"retained"`
	Parallel []pending         `json:"parallel"`
}

// Plan describes the exact canonical model request envelope, not its transport
// wrapper or a certified provider response. Estimate is always bytes/4.
type Plan struct {
	CapacityAccounting string `json:"capacityAccounting"`
	OutputByteReserve  int64  `json:"outputByteReserve"`

	Envelope         json.RawMessage `json:"envelope"`
	Bytes            int             `json:"bytes"`
	EnvelopeBytes    int             `json:"envelopeBytes"`
	TokenEstimate    int             `json:"tokenEstimate"`
	Accounting       string          `json:"accounting"`
	CountedTokens    int64           `json:"countedTokens"`
	ReasoningReserve int64           `json:"reasoningReserve"`
	OutputReserve    int64           `json:"outputReserve"`
	Omitted          []Omission      `json:"omitted"`
	Epoch            uint64          `json:"epoch"`
	SnapshotSHA256   string          `json:"snapshotSHA256"`
	QuerySHA256      string          `json:"querySHA256"`
	ProfilePin       string          `json:"profilePin"`
}
type Spending struct {
	InputBytes  int64 `json:"inputBytes"`
	OutputBytes int64 `json:"outputBytes"`

	Accounting          string `json:"accounting"`
	InputTokens         int64  `json:"inputTokens"`
	OutputTokens        int64  `json:"outputTokens"`
	ReasoningAccounting string `json:"reasoningAccounting"`
}

func digest(raw []byte) string { s := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(s[:]) }

func encode(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, fmt.Errorf("encode context: %w", e)
	}
	return b, nil
}

func copyJSON[T any](v T) (T, error) {
	var result T
	b, e := encode(v)
	if e == nil {
		e = json.Unmarshal(b, &result)
	}
	return result, e
}

func label(s string) bool {
	return len(s) > 0 && len(s) <= 256 && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}

func validateEnvelope(v Envelope) error {
	if len(v.System) > 128 || len(v.ToolSchemas) > 128 || len(v.History) > 1024 || len(v.PriorResponses) > 1024 || len(v.Guards) > 128 {
		return fail(Invalid, "envelope count")
	}
	// Reject raw oversized values before serializing or cloning caller data.
	bytes := 0
	for _, s := range v.System {
		bytes += len(s)
		if bytes > HardBytes {
			return fail(Overflow, "envelope bytes")
		}
	}
	for _, s := range v.PriorResponses {
		bytes += len(s)
		if bytes > HardBytes {
			return fail(Overflow, "envelope bytes")
		}
	}
	for _, m := range v.History {
		bytes += len(m.Role) + len(m.Content)
		if bytes > HardBytes {
			return fail(Overflow, "envelope bytes")
		}
	}
	for _, g := range v.Guards {
		bytes += len(g.ID) + len(g.Content)
		if bytes > HardBytes {
			return fail(Overflow, "envelope bytes")
		}
	}
	for _, s := range v.ToolSchemas {
		bytes += len(s)
		if bytes > HardBytes {
			return fail(Overflow, "envelope bytes")
		}
	}
	for _, s := range append(append([]string(nil), v.System...), v.PriorResponses...) {
		if !utf8.ValidString(s) {
			return fail(Invalid, "text")
		}
	}
	for _, m := range v.History {
		if !label(m.Role) || !utf8.ValidString(m.Content) {
			return fail(Invalid, "history")
		}
	}
	guards := map[string]bool{}
	for _, g := range v.Guards {
		if !label(g.ID) || guards[g.ID] || !utf8.ValidString(g.Content) {
			return fail(Invalid, "guards")
		}
		guards[g.ID] = true
	}
	for _, tool := range v.ToolSchemas {
		if !json.Valid(tool) || !utf8.Valid(tool) {
			return fail(Invalid, "tools")
		}
	}
	b, e := encode(v)
	if e != nil {
		return e
	}
	if len(b) > HardBytes {
		return fail(Overflow, "host envelope bytes")
	}
	return nil
}
