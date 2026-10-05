package contextwindow

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"unicode/utf8"
)

// profile is an instrumentation-only seam. There is no production registered
// model/tokenizer or public constructor accepting counts, capacity, or callbacks.
// Package tests bind a pinned synthetic host counter, never a real model claim.
type profile struct {
	pin        string
	accounting string
	window     int64
	count      func([]byte) (int64, error)
	byteOnly   bool
}

// ResponseObservation is issued only at the private trusted host transport
// instrumentation boundary. Raw caller response/usage data cannot finish work.
type (
	ResponseObservation struct{ *responseRecord }
	responseRecord      struct {
		owner                            *hostState
		reservation                      *entry
		wireDigest, profilePin, response string
		input, output                    int64
	}
)

// CompactionObservation records an actual host compaction, not a caller's claim
// that its context became smaller. Its next envelope is owned by this receipt.
type (
	CompactionObservation struct{ *compactionRecord }
	compactionRecord      struct {
		owner       *hostState
		observation *snapshotRecord
		next        Envelope
	}
)

// recordResponse is the concrete host instrumentation seam, with no shell or
// caller capacity callback. The bounded-byte adapter and synthetic fixture host
// use this seam to observe the exact delivered request wire.
func (h *Host) recordResponse(ctx context.Context, r *Reservation, delivered []byte, response string) (*ResponseObservation, error) {
	if e := checkContext(ctx); e != nil {
		return nil, e
	}
	if h == nil || h.hostState == nil || r == nil || r.entry == nil || r.host != h.hostState {
		return nil, fail(Invalid, "host response")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, fail(Revoked, "host")
	}
	if h.profile == nil {
		return nil, fail(Unknown, "host instrumentation")
	}
	if h.reservations[r.id] != r.entry || digest(delivered) != digest(r.wire) || h.profile.pin != r.plan.ProfilePin {
		return nil, fail(Stale, "delivered request/profile")
	}
	if h.profile.window != r.window || h.profile.accounting != r.accounting {
		return nil, fail(Stale, "response instrumentation profile")
	}
	if r.receipt != nil {
		if r.receipt.response != response {
			return nil, fail(Conflict, "different response for observed request")
		}
		return &ResponseObservation{responseRecord: r.receipt}, nil
	}
	if !utf8.ValidString(response) || len(response) > HardBytes {
		return nil, fail(Invalid, "response bytes")
	}
	input, e := h.profile.count(delivered)
	if e != nil {
		return nil, fmt.Errorf("observed input: %w", e)
	}
	output, e := h.profile.count([]byte(response))
	if e != nil {
		return nil, fmt.Errorf("observed output: %w", e)
	}
	if input < 0 || input > 1e9 || output < 0 || output > 1e9 {
		return nil, fail(Invalid, "observed usage")
	}
	if e := checkContext(ctx); e != nil {
		return nil, e
	}
	r.receipt = &responseRecord{owner: h.hostState, reservation: r.entry, wireDigest: digest(delivered), profilePin: h.profile.pin, response: response, input: input, output: output}
	// Host usage happened even when later source/window publication refuses.
	h.spend.Accounting = h.profile.accounting
	if h.profile.byteOnly {
		h.spend.InputBytes += input
		h.spend.OutputBytes += output
	} else {
		h.spend.InputTokens += input
		h.spend.OutputTokens += output
	}
	if output > r.output {
		h.closed = true
		h.epoch++
	}
	return &ResponseObservation{responseRecord: r.receipt}, nil
}

func (h *Host) recordCompaction(ctx context.Context, o *Observation, next Envelope) (*CompactionObservation, error) {
	if e := checkContext(ctx); e != nil {
		return nil, e
	}
	if h == nil || h.hostState == nil {
		return nil, fail(Invalid, "host")
	}
	if e := validateEnvelope(next); e != nil {
		return nil, e
	}
	owned, e := copyJSON(next)
	if e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.validate(o); e != nil {
		return nil, e
	}
	if h.profile == nil {
		return nil, fail(Unknown, "host compaction instrumentation")
	}
	return &CompactionObservation{compactionRecord: &compactionRecord{owner: h.hostState, observation: o.snapshotRecord, next: owned}}, nil
}

// Host owns observations and the single reservation ledger for its session.
// NewHost records an envelope but cannot certify a model window from caller data.
type Host struct{ *hostState }

type hostState struct {
	mu           sync.Mutex
	scope        Scope
	base         Envelope
	epoch        uint64
	closed       bool
	profile      *profile
	retained     []json.RawMessage
	reservations map[string]*entry
	terminal     map[string]bool
	spend        Spending
}

// Observation is opaque and instance/epoch/snapshot/profile bound. Its zero
// value or a report copied from another host cannot admit a reservation.
type (
	Observation    struct{ *snapshotRecord }
	snapshotRecord struct {
		owner    *hostState
		epoch    uint64
		snapshot string
		pin      string
	}
)

func NewHost(scope Scope, base Envelope) (*Host, error) {
	if !label(scope.Session) || !label(scope.Model) {
		return nil, fail(Invalid, "scope")
	}
	if e := validateEnvelope(base); e != nil {
		return nil, e
	}
	owned, e := copyJSON(base)
	if e != nil {
		return nil, e
	}
	return &Host{hostState: &hostState{scope: scope, base: owned, epoch: 1, retained: []json.RawMessage{}, reservations: map[string]*entry{}, terminal: map[string]bool{}, spend: Spending{Accounting: "unknown", ReasoningAccounting: "unknown"}}}, nil
}

func (h *Host) Observe(ctx context.Context) (*Observation, error) {
	if e := checkContext(ctx); e != nil {
		return nil, e
	}
	if h == nil || h.hostState == nil {
		return nil, fail(Invalid, "host")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := checkContext(ctx); e != nil {
		return nil, e
	}
	if h.closed {
		return nil, fail(Revoked, "host")
	}
	snapshot, e := h.snapshot()
	if e != nil {
		return nil, e
	}
	pin := ""
	if h.profile != nil {
		pin = h.profile.pin
	}
	return &Observation{snapshotRecord: &snapshotRecord{owner: h.hostState, epoch: h.epoch, snapshot: snapshot, pin: pin}}, nil
}

func (h *Host) snapshot() (string, error) {
	pin, accounting, window := "", "unknown", int64(0)
	if h.profile != nil {
		pin, accounting, window = h.profile.pin, h.profile.accounting, h.profile.window
	}
	b, e := encode(struct {
		Envelope               wireEnvelope
		ProfilePin, Accounting string
		Window                 int64
	}{wireEnvelope{Scope: h.scope, Base: h.base, Retained: h.retained}, pin, accounting, window})
	if e != nil {
		return "", e
	}
	return digest(b), nil
}

func (h *Host) validate(o *Observation) error {
	if h.closed {
		return fail(Revoked, "host")
	}
	if o == nil || o.snapshotRecord == nil || o.owner != h.hostState || o.epoch != h.epoch {
		return fail(Stale, "host observation")
	}
	snapshot, e := h.snapshot()
	if e != nil {
		return e
	}
	pin := ""
	if h.profile != nil {
		pin = h.profile.pin
	}
	if o.snapshot != snapshot || o.pin != pin {
		return fail(Stale, "host snapshot/profile")
	}
	return nil
}

func (h *Host) wire(extra *Reservation, omitID string) ([]byte, error) {
	p := make([]pending, 0, len(h.reservations)+1)
	for id, r := range h.reservations {
		if id != omitID {
			p = append(p, pending{ID: id, Context: r.payload})
		}
	}
	if extra != nil {
		p = append(p, pending{ID: extra.id, Context: extra.payload})
	}
	sort.Slice(p, func(a, b int) bool { return p[a].ID < p[b].ID })
	return encode(wireEnvelope{Scope: h.scope, Base: h.base, Retained: h.retained, Parallel: p})
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return fail(Invalid, "context")
	}
	return ctx.Err()
}

// Revoke invalidates all observations/reservations. It cannot increase capacity.
func (h *Host) Revoke() {
	if h == nil || h.hostState == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	h.epoch++
}

// Compact replaces only host history/prior responses. System/tools/guards and
// every committed C03 packet/pin/floor are retained exactly. Active reservations
// must finish or release first. A new epoch invalidates previous observations.
func (h *Host) Compact(ctx context.Context, observed *CompactionObservation) error {
	if e := checkContext(ctx); e != nil {
		return e
	}
	if h == nil || h.hostState == nil {
		return fail(Invalid, "host")
	}
	if observed == nil || observed.compactionRecord == nil || observed.owner != h.hostState {
		return fail(Invalid, "compaction observation")
	}
	o, next := &Observation{snapshotRecord: observed.observation}, observed.next
	if e := validateEnvelope(next); e != nil {
		return e
	}
	owned, e := copyJSON(next)
	if e != nil {
		return e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e = h.validate(o); e != nil {
		return e
	}
	if len(h.reservations) > 0 {
		return fail(Busy, "parallel reservations")
	}
	before, e := encode(struct {
		System []string
		Tools  []json.RawMessage
		Guards []Guard
	}{h.base.System, h.base.ToolSchemas, h.base.Guards})
	if e != nil {
		return e
	}
	after, e := encode(struct {
		System []string
		Tools  []json.RawMessage
		Guards []Guard
	}{owned.System, owned.ToolSchemas, owned.Guards})
	if e != nil {
		return e
	}
	if digest(before) != digest(after) {
		return fail(Conflict, "compaction mandatory guards/system/tools")
	}
	old := h.base
	h.base = owned
	wire, e := h.wire(nil, "")
	if e != nil {
		h.base = old
		return e
	}
	if len(wire) > HardBytes {
		h.base = old
		return fail(Overflow, "compaction bytes")
	}
	if h.profile != nil {
		count, err := h.profile.count(wire)
		if err != nil {
			h.base = old
			return err
		}
		if count < 0 || count > h.profile.window {
			h.base = old
			return fail(Overflow, "compaction window")
		}
	}
	if e := checkContext(ctx); e != nil {
		h.base = old
		return e
	}
	h.epoch++
	return nil
}

// Spending is cumulative instrumented usage, never subtracted from capacity.
func (h *Host) Spending() Spending {
	if h == nil || h.hostState == nil {
		return Spending{Accounting: "unknown", ReasoningAccounting: "unknown"}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.spend
}
