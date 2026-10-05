package contextwindow

import (
	"context"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// Reservation is an opaque ledger entry. Copying a report cannot recreate it.
type (
	Reservation struct{ *entry }
	entry       struct {
		host              *hostState
		id                string
		fingerprint       string
		selection         *selectionRecord
		payload           json.RawMessage
		wire              []byte
		plan              Plan
		maxBytes          int
		reasoning, output int64
		window            int64
		accounting        string
		receipt           *responseRecord
		delivering        bool
	}
)

func (h *Host) awaitingResponse() bool {
	for _, r := range h.reservations {
		if r.receipt != nil || r.delivering {
			return true
		}
	}
	return false
}

// Preview is a bounded estimate when remaining window is unknown. It never
// creates a reservation or reports unknown capacity as available tokens.
func (h *Host) Preview(ctx context.Context, o *Observation, req Request) (Plan, error) {
	if e := checkContext(ctx); e != nil {
		return Plan{}, e
	}
	if h == nil || h.hostState == nil {
		return Plan{}, fail(Invalid, "host")
	}
	if len(req.Optional) > 64 {
		return Plan{}, fail(Invalid, "optional count")
	}
	if req.Selection != nil {
		req.Selection = &Selection{selectionRecord: req.Selection.selectionRecord}
	}
	req.Optional = append([]Optional(nil), req.Optional...)
	if e := selectionFresh(ctx, req.Selection); e != nil {
		return Plan{}, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.validate(o); e != nil {
		return Plan{}, e
	}
	if h.awaitingResponse() {
		return Plan{}, fail(Busy, "observed response awaiting window reconciliation")
	}
	r, e := h.build(ctx, o, req)
	if e != nil {
		return Plan{}, e
	}
	if e := checkContext(ctx); e != nil {
		return Plan{}, e
	}
	return copyJSON(r.plan)
}

// Reserve counts the complete envelope under the host's real mutex, including
// every outstanding parallel payload and reasoning/output reservation.
func (h *Host) Reserve(ctx context.Context, o *Observation, req Request) (*Reservation, Plan, error) {
	if e := checkContext(ctx); e != nil {
		return nil, Plan{}, e
	}
	if h == nil || h.hostState == nil {
		return nil, Plan{}, fail(Invalid, "host")
	}
	if len(req.Optional) > 64 {
		return nil, Plan{}, fail(Invalid, "optional count")
	}
	if req.Selection != nil {
		req.Selection = &Selection{selectionRecord: req.Selection.selectionRecord}
	}
	req.Optional = append([]Optional(nil), req.Optional...)
	if e := selectionFresh(ctx, req.Selection); e != nil {
		return nil, Plan{}, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := checkContext(ctx); e != nil {
		return nil, Plan{}, e
	}
	if e := h.validate(o); e != nil {
		return nil, Plan{}, e
	}
	if h.profile == nil {
		return nil, Plan{}, fail(Unknown, "remaining model window")
	}
	if h.awaitingResponse() {
		return nil, Plan{}, fail(Busy, "observed response awaiting window reconciliation")
	}
	r, e := h.build(ctx, o, req)
	if e != nil {
		return nil, Plan{}, e
	}
	if h.terminal[r.id] {
		return nil, Plan{}, fail(Conflict, "terminal request replay")
	}
	if old, ok := h.reservations[r.id]; ok {
		if old.selection != req.Selection.selectionRecord || old.fingerprint != r.fingerprint {
			return nil, Plan{}, fail(Conflict, "request ID reused")
		}
		if old.plan.Epoch != o.epoch || old.plan.SnapshotSHA256 != o.snapshot {
			return nil, Plan{}, fail(Stale, "reservation belongs to previous host snapshot; finish or release")
		}
		p, e := copyJSON(old.plan)
		return &Reservation{entry: old}, p, e
	}
	if len(h.reservations) >= 64 || len(h.terminal) >= 1024 {
		return nil, Plan{}, fail(Overflow, "ledger entry count")
	}
	p, e := copyJSON(r.plan)
	if e != nil {
		return nil, Plan{}, e
	}
	if e := checkContext(ctx); e != nil {
		return nil, Plan{}, e
	}
	h.reservations[r.id] = r.entry
	return r, p, nil
}

func (h *Host) build(ctx context.Context, o *Observation, req Request) (*Reservation, error) {
	if e := checkContext(ctx); e != nil {
		return nil, e
	}
	if req.OutputByteReserve < 0 || req.OutputByteReserve > HardBytes {
		return nil, fail(Invalid, "output byte reserve")
	}
	if h.profile != nil && h.profile.byteOnly {
		if req.ReasoningReserve != 0 || req.OutputReserve != 0 {
			return nil, fail(Unknown, "model token reserves")
		}
	} else if req.OutputByteReserve != 0 {
		return nil, fail(Invalid, "byte reserve requires byte adapter")
	}
	if !label(req.ID) || req.Selection == nil || req.Selection.selectionRecord == nil || len(req.Optional) > 64 || req.ReasoningReserve < 0 || req.ReasoningReserve > 1e9 || req.OutputReserve < 0 || req.OutputReserve > 1e9 {
		return nil, fail(Invalid, "request")
	}
	maxBytes := req.MaxBytes
	if maxBytes == 0 {
		maxBytes = 65536
	}
	if maxBytes < 1 || maxBytes > HardBytes {
		return nil, fail(Invalid, "byte bound")
	}
	seen := map[string]bool{}
	totalOptional := 0
	for _, v := range req.Optional {
		if !label(v.ID) || seen[v.ID] || !utf8.ValidString(v.Content) || len(v.Content) > HardBytes {
			return nil, fail(Invalid, "optional")
		}
		seen[v.ID] = true
		totalOptional += len(v.Content)
		if totalOptional > HardBytes {
			return nil, fail(Invalid, "optional total bytes")
		}
	}
	fingerprint, e := encode(struct {
		Query, Selection  string
		Optional          []Optional
		MaxBytes          int
		Reasoning, Output int64
		OutputBytes       int
	}{req.Selection.query, digest(req.Selection.raw), req.Optional, maxBytes, req.ReasoningReserve, req.OutputReserve, req.OutputByteReserve})
	if e != nil {
		return nil, e
	}
	if req.Selection.projection != "" {
		fingerprint, e = encode(struct{ Legacy, Projection, Wire string }{digest(fingerprint), req.Selection.projection, digest(req.Selection.deliveryBytes())})
		if e != nil {
			return nil, e
		}
	}
	r := &Reservation{entry: &entry{host: h.hostState, id: req.ID, fingerprint: digest(fingerprint), selection: req.Selection.selectionRecord, maxBytes: maxBytes, reasoning: req.ReasoningReserve, output: req.OutputReserve}}
	if h.profile != nil && h.profile.byteOnly {
		r.output = int64(req.OutputByteReserve)
	}
	if h.profile != nil {
		r.window = h.profile.window
		r.accounting = h.profile.accounting
	}
	p := payload{QuerySHA256: req.Selection.query, Required: req.Selection.deliveryBytes(), Optional: append([]Optional{}, req.Optional...), Omitted: []Omission{}}
	bound := maxBytes
	reserve := r.reasoning + r.output
	for id, old := range h.reservations {
		if id != r.id {
			reserve += old.reasoning + old.output
			if old.maxBytes < bound {
				bound = old.maxBytes
			}
		}
	}
	for {
		if e := checkContext(ctx); e != nil {
			return nil, e
		}
		raw, e := encode(p)
		if e != nil {
			return nil, e
		}
		r.payload = raw
		wire, e := h.wire(r, r.id)
		if e != nil {
			return nil, e
		}
		counted := int64(0)
		accounting := "bytes/4-estimate; remaining-unknown"
		if h.profile != nil {
			if h.profile.count == nil || h.profile.pin == "" || h.profile.window < 1 || h.profile.window > 1e9 {
				return nil, fail(Invalid, "instrumentation profile")
			}
			counted, e = h.profile.count(wire)
			if e != nil {
				return nil, fmt.Errorf("host token instrumentation: %w", e)
			}
			if counted < 0 || counted > 1e9 {
				return nil, fail(Invalid, "instrumented count")
			}
			accounting = h.profile.accounting
		}
		reason := ""
		if len(wire) > bound || (h.profile != nil && h.profile.byteOnly && int64(len(wire))+reserve > int64(bound)) {
			reason = "whole-envelope-bytes"
		} else if h.profile != nil && counted+reserve > h.profile.window {
			reason = "whole-envelope-window"
		}
		if reason == "" {
			r.wire = wire
			r.plan = Plan{Envelope: wire, EnvelopeBytes: len(wire), TokenEstimate: (len(wire) + 3) / 4, Accounting: accounting, CountedTokens: counted, Omitted: p.Omitted, Epoch: o.epoch, SnapshotSHA256: o.snapshot, QuerySHA256: p.QuerySHA256, ProfilePin: o.pin}
			r.plan.CapacityAccounting = "model-window-unknown"
			if h.profile != nil && !h.profile.byteOnly {
				r.plan.CapacityAccounting = "instrumented-profile"
			}
			if h.profile != nil && h.profile.byteOnly {
				r.plan.CountedTokens = 0
			}
			// Reserve fields in the report include ALL outstanding demands, separately.
			r.plan.ReasoningReserve = 0
			r.plan.OutputReserve = 0
			for id, old := range h.reservations {
				if id != r.id {
					r.plan.ReasoningReserve += old.reasoning
					r.plan.OutputReserve += old.output
				}
			}
			r.plan.ReasoningReserve += r.reasoning
			r.plan.OutputReserve += r.output
			if h.profile != nil && h.profile.byteOnly {
				r.plan.OutputByteReserve = r.plan.OutputReserve
				r.plan.OutputReserve = 0
			}
			if fitPlan(&r.plan, bound) {
				return r, nil
			}
			reason = "planner-response-bytes"
		}
		if len(p.Optional) == 0 {
			return nil, fail(Overflow, reason+" mandatory floor")
		}
		n := len(p.Optional) - 1
		p.Omitted = append(p.Omitted, Omission{ID: p.Optional[n].ID, Reason: reason})
		p.Optional = p.Optional[:n]
	}
}

// Release is idempotent for this exact opaque entry; a reused ID cannot reacquire
// a released reservation. It records no spending and does not enlarge capacity.
func (h *Host) Release(ctx context.Context, r *Reservation) error {
	if e := checkContext(ctx); e != nil {
		return e
	}
	if h == nil || h.hostState == nil || r == nil || r.entry == nil || r.host != h.hostState {
		return fail(Invalid, "reservation")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	old, ok := h.reservations[r.id]
	if !ok {
		if h.terminal[r.id] {
			return nil
		}
		return fail(Stale, "reservation")
	}
	if old != r.entry {
		return fail(Stale, "reservation")
	}
	if (r.receipt != nil || r.delivering) && !h.closed {
		return fail(Busy, "observed response must finish or revoke")
	}
	delete(h.reservations, r.id)
	h.terminal[r.id] = true
	return nil
}

// Finish is the host response instrumentation boundary, not a provider call.
// The public unknown host cannot create a reservation, so caller response data
// cannot manufacture trustworthy usage. Hidden reasoning spending stays unknown.
func (h *Host) Finish(ctx context.Context, r *Reservation, observed *ResponseObservation) error {
	if e := checkContext(ctx); e != nil {
		return e
	}
	if h == nil || h.hostState == nil || r == nil || r.entry == nil || r.host != h.hostState {
		return fail(Invalid, "response/reservation")
	}
	if observed == nil || observed.responseRecord == nil || observed.owner != h.hostState || observed.reservation != r.entry || observed.wireDigest != digest(r.wire) || observed.profilePin != r.plan.ProfilePin {
		return fail(Invalid, "response observation")
	}
	response := observed.response
	if !utf8.ValidString(response) || len(response) > HardBytes {
		return fail(Invalid, "response bytes")
	}
	if e := r.selection.fresh(ctx); e != nil {
		return e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := checkContext(ctx); e != nil {
		return e
	}
	if h.closed {
		if observed.output > r.output {
			return fail(Overflow, "observed output reserve")
		}
		return fail(Revoked, "host")
	}
	if h.reservations[r.id] != r.entry || h.profile == nil {
		return fail(Stale, "reservation")
	}
	if r.receipt != observed.responseRecord || h.profile.window != r.window || h.profile.accounting != r.accounting || h.profile.pin != observed.profilePin {
		return fail(Stale, "response receipt/profile")
	}
	if e := checkContext(ctx); e != nil {
		return e
	}
	next := append(append([]json.RawMessage{}, h.retained...), r.payload)
	base, e := copyJSON(h.base)
	if e != nil {
		return e
	}
	base.PriorResponses = append(base.PriorResponses, response)
	// Rebuild all remaining parallel obligations against actual returned bytes.
	oldBase, oldRetained := h.base, h.retained
	h.base, h.retained = base, next
	wire, e := h.wire(nil, r.id)
	if e != nil {
		h.base, h.retained = oldBase, oldRetained
		return e
	}
	tokens, e := h.profile.count(wire)
	if e != nil {
		h.base, h.retained = oldBase, oldRetained
		return fmt.Errorf("response window instrumentation: %w", e)
	}
	bound := r.maxBytes
	reserve := int64(0)
	for id, old := range h.reservations {
		if id != r.id {
			reserve += old.reasoning + old.output
			if old.maxBytes < bound {
				bound = old.maxBytes
			}
		}
	}
	if tokens < 0 || tokens > 1e9 || len(wire) > bound || (h.profile.byteOnly && int64(len(wire))+reserve > int64(bound)) || tokens+reserve > h.profile.window {
		h.base, h.retained = oldBase, oldRetained
		h.closed = true
		h.epoch++
		return fail(Overflow, "observed whole envelope")
	}
	if e := checkContext(ctx); e != nil {
		h.base, h.retained = oldBase, oldRetained
		return e
	}
	delete(h.reservations, r.id)
	h.terminal[r.id] = true
	h.epoch++
	return nil
}

func fitPlan(p *Plan, bound int) bool {
	for range 32 {
		raw, err := encode(p)
		if err != nil {
			return false
		}
		if p.Bytes == len(raw) {
			return p.Bytes <= bound
		}
		p.Bytes = len(raw)
	}
	return false
}
