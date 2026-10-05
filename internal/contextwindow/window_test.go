package contextwindow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/contextindex"
)

// This counter defines a synthetic local host alphabet, not a model tokenizer.
// The private profile is intentionally unavailable to production callers.
func syntheticCount(raw []byte) (int64, error) { return int64(utf8.RuneCount(raw)) + 3, nil }

func TestOpaqueWrapperReplacementCannotChangeOwnedEntries(t *testing.T) {
	ctx := context.Background()
	s := selection(t)
	h := syntheticHost(t, baseEnvelope(), 1000000)
	o := observation(t, h)
	p, e := h.Preview(ctx, o, Request{ID: "one", Selection: s, OutputReserve: 512})
	if e != nil {
		t.Fatal(e)
	}
	h.profile.window = p.CountedTokens + 512
	o = observation(t, h)
	r, _, e := h.Reserve(ctx, o, Request{ID: "one", Selection: s, OutputReserve: 512})
	if e != nil {
		t.Fatal(e)
	}
	original := *r
	other := syntheticHost(t, baseEnvelope(), 1000000)
	otherSelection := selection(t)
	foreign, _, e := other.Reserve(ctx, observation(t, other), Request{ID: "foreign", Selection: otherSelection, OutputReserve: 512})
	if e != nil {
		t.Fatal(e)
	}
	*r = *foreign // Replacing a public wrapper must not rewrite the owned entry.
	*s = *otherSelection
	_, _, e = h.Reserve(ctx, o, Request{ID: "two", Selection: s})
	code(t, e, Overflow)
	received := syntheticResponse(t, h, &original, "ok")
	foreignReceived := syntheticResponse(t, other, foreign, "ok")
	*received = *foreignReceived
	e = h.Finish(ctx, &original, received)
	code(t, e, Invalid)
	received = syntheticResponse(t, h, &original, "ok")
	if e = h.Finish(ctx, &original, received); e != nil {
		t.Fatal(e)
	}
	if len(h.retained) != 1 || len(h.reservations) != 0 {
		t.Fatal("wrapper replacement changed owned source selection/ledger")
	}
}

func TestOpaqueHostEventsDeliveryBindingAndExactlyOnceUsage(t *testing.T) {
	h := syntheticHost(t, baseEnvelope(), 1000000)
	s := selection(t)
	o := observation(t, h)
	r, _, e := h.Reserve(context.Background(), o, Request{ID: "one", Selection: s, OutputReserve: 100})
	if e != nil {
		t.Fatal(e)
	}
	e = h.Finish(context.Background(), r, &ResponseObservation{})
	code(t, e, Invalid)
	e = h.Compact(context.Background(), &CompactionObservation{})
	code(t, e, Invalid)
	_, e = h.recordResponse(context.Background(), r, []byte("different delivery"), "answer")
	code(t, e, Stale)
	if h.Spending().InputTokens != 0 {
		t.Fatal("substituted delivery minted spending")
	}
	received := syntheticResponse(t, h, r, "answer")
	spent := h.Spending()
	repeated := syntheticResponse(t, h, r, "answer")
	if repeated.responseRecord != received.responseRecord || spent != h.Spending() || spent.InputTokens != received.input {
		t.Fatal("repeated observation double spent")
	}
	_, _, e = h.Reserve(context.Background(), o, Request{ID: "pending", Selection: s})
	code(t, e, Busy)
	if e = h.Finish(context.Background(), r, received); e != nil {
		t.Fatal(e)
	}
	if h.Spending() != spent {
		t.Fatal("window publication counted spending twice")
	}
	e = h.Finish(context.Background(), r, received)
	code(t, e, Stale)
}

func syntheticResponse(t *testing.T, h *Host, r *Reservation, text string) *ResponseObservation {
	t.Helper()
	receipt, e := h.recordResponse(context.Background(), r, r.wire, text)
	if e != nil {
		t.Fatal(e)
	}
	return receipt
}

func syntheticCompaction(t *testing.T, h *Host, o *Observation, next Envelope) *CompactionObservation {
	t.Helper()
	receipt, e := h.recordCompaction(context.Background(), o, next)
	if e != nil {
		t.Fatal(e)
	}
	return receipt
}

func TestResponseOverrunRevokesAndNoForeignCompletion(t *testing.T) {
	h := syntheticHost(t, baseEnvelope(), 1000000)
	s := selection(t)
	o := observation(t, h)
	r, _, e := h.Reserve(context.Background(), o, Request{ID: "one", Selection: s, OutputReserve: 5})
	if e != nil {
		t.Fatal(e)
	}
	foreign := syntheticHost(t, baseEnvelope(), 1000000)
	received := syntheticResponse(t, h, r, "overflow response")
	e = foreign.Finish(context.Background(), r, received)
	code(t, e, Invalid)
	e = h.Finish(context.Background(), r, received)
	code(t, e, Overflow)
	if len(h.retained) != 0 || h.Spending().InputTokens == 0 {
		t.Fatal("overrun published a false safe window or hid observed usage")
	}
	_, _, e = h.Reserve(context.Background(), o, Request{ID: "replay", Selection: s})
	code(t, e, Revoked)
	if e = h.Release(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	_, e = h.Observe(context.Background())
	code(t, e, Revoked)
}

func TestHostCopyCannotForkCapacityAndProfileDriftRefuses(t *testing.T) {
	h := syntheticHost(t, baseEnvelope(), 1000000)
	s := selection(t)
	o := observation(t, h)
	preview, e := h.Preview(context.Background(), o, Request{ID: "one", Selection: s, OutputReserve: 100})
	if e != nil {
		t.Fatal(e)
	}
	h.profile.window = preview.CountedTokens + 100
	_, _, e = h.Reserve(context.Background(), o, Request{ID: "old", Selection: s})
	code(t, e, Stale)
	o = observation(t, h)
	r, _, e := h.Reserve(context.Background(), o, Request{ID: "one", Selection: s, OutputReserve: 100})
	if e != nil {
		t.Fatal(e)
	}
	copied := *h // only the opaque state pointer is copied; mutex and ledger shared.
	_, _, e = copied.Reserve(context.Background(), o, Request{ID: "two", Selection: s})
	code(t, e, Overflow)
	if e = copied.Release(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	if len(h.reservations) != 0 {
		t.Fatal("copy forked ledger")
	}
	copied.Revoke()
	_, e = h.Observe(context.Background())
	code(t, e, Revoked)
}

func syntheticHost(t *testing.T, base Envelope, window int64) *Host {
	t.Helper()
	h, e := NewHost(Scope{Session: "synthetic", Model: "synthetic-unicode/v1"}, base)
	if e != nil {
		t.Fatal(e)
	}
	h.profile = &profile{pin: digest([]byte("synthetic-unicode/v1: utf8-runes + 3 framing; fixture only")), accounting: "synthetic-host-count; not model tokens", window: window, count: syntheticCount}
	return h
}

func baseEnvelope() Envelope {
	return Envelope{System: []string{"mandatory system"}, ToolSchemas: []json.RawMessage{json.RawMessage(`{"type":"object","properties":{"value":{"type":"string"}}}`)}, History: []Message{{Role: "user", Content: "История 🚀"}}, PriorResponses: []string{"previous answer"}, Guards: []Guard{{ID: "required-review", Content: "never omit the review floor"}}}
}

func selection(t *testing.T) *Selection {
	t.Helper()
	raw, e := os.ReadFile("../../testdata/knowledge/catalog.json")
	if e != nil {
		t.Fatal(e)
	}
	i, e := contextindex.New(raw, nil)
	if e != nil {
		t.Fatal(e)
	}
	s, e := Select(context.Background(), i, contextindex.Request{Query: contextindex.Query{Kind: "skill", One: true}, MaxBytes: 32768}, nil)
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func observation(t *testing.T, h *Host) *Observation {
	t.Helper()
	o, e := h.Observe(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return o
}

func code(t *testing.T, e error, want string) {
	t.Helper()
	var d *Error
	if !errors.As(e, &d) || d.Code != want {
		t.Fatalf("want %s: %v", want, e)
	}
}

func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, e := encode(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestUnknownDefaultWholeEnvelopeAndNoCallerGrant(t *testing.T) {
	base := baseEnvelope()
	base.ToolSchemas = append(base.ToolSchemas, json.RawMessage(`{"description":"`+strings.Repeat("Огромная schema 😀", 600)+`"}`))
	h, e := NewHost(Scope{Session: "test", Model: "caller-claims-256k"}, base)
	if e != nil {
		t.Fatal(e)
	}
	s := selection(t)
	req := Request{ID: "query", Selection: s, ReasoningReserve: 100, OutputReserve: 300}
	o := observation(t, h)
	p, e := h.Preview(context.Background(), o, req)
	if e != nil {
		t.Fatal(e)
	}
	if p.Bytes != len(encoded(t, p)) || p.EnvelopeBytes != len(p.Envelope) || p.TokenEstimate != (p.EnvelopeBytes+3)/4 || p.CountedTokens != 0 || !strings.Contains(p.Accounting, "remaining-unknown") {
		t.Fatal("invented exact tokens/window")
	}
	var full wireEnvelope
	if e = json.Unmarshal(p.Envelope, &full); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(full.Base, base) || len(full.Parallel) != 1 {
		t.Fatal("system/tools/history/priorresponses/guards missing")
	}
	var contextPayload payload
	if e = json.Unmarshal(full.Parallel[0].Context, &contextPayload); e != nil {
		t.Fatal(e)
	}
	if string(contextPayload.Required) != string(s.raw) {
		t.Fatal("C03 mandatory floor/pins changed")
	}
	_, _, e = h.Reserve(context.Background(), o, req)
	code(t, e, Unknown)
	_, _, e = h.Reserve(context.Background(), &Observation{}, req)
	code(t, e, Stale)
	_, e = h.Preview(context.Background(), o, Request{ID: "raw", Selection: &Selection{}})
	code(t, e, Invalid)
	other := syntheticHost(t, base, 1000000)
	_, _, e = other.Reserve(context.Background(), o, req)
	code(t, e, Stale)
	if h.Spending().Accounting != "unknown" || len(h.reservations) != 0 {
		t.Fatal("caller data minted usage or reservation")
	}
}

func TestOptionalOmissionAndMandatoryOverflow(t *testing.T) {
	h := syntheticHost(t, baseEnvelope(), 1000000)
	o := observation(t, h)
	s := selection(t)
	req := Request{ID: "one", Selection: s, ReasoningReserve: 50, OutputReserve: 100}
	required, e := h.Preview(context.Background(), o, req)
	if e != nil {
		t.Fatal(e)
	}
	req.MaxBytes = required.Bytes + 400
	req.Optional = []Optional{{ID: "a", Content: strings.Repeat("optional", 300)}, {ID: "b", Content: strings.Repeat("extra", 300)}}
	p, e := h.Preview(context.Background(), o, req)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Omitted) != 2 || p.Omitted[0].ID != "b" || p.Omitted[1].ID != "a" || p.Bytes > req.MaxBytes {
		t.Fatal("optional omissions unexplained or nondeterministic")
	}
	for _, omit := range p.Omitted {
		if omit.Reason != "whole-envelope-bytes" && omit.Reason != "planner-response-bytes" {
			t.Fatal(omit)
		}
	}
	var full wireEnvelope
	var selected payload
	if e = json.Unmarshal(p.Envelope, &full); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(full.Parallel[0].Context, &selected); e != nil {
		t.Fatal(e)
	}
	if string(selected.Required) != string(s.raw) {
		t.Fatal("required floor silently pruned")
	}
	req.Optional = nil
	req.MaxBytes = required.Bytes - 1
	_, e = h.Preview(context.Background(), o, req)
	code(t, e, Overflow)
	req.MaxBytes = 0
	h.profile.window = required.CountedTokens + 149
	o = observation(t, h)
	_, _, e = h.Reserve(context.Background(), o, req)
	code(t, e, Overflow)
	h.profile.window = required.CountedTokens + 150
	o = observation(t, h)
	r, plan, e := h.Reserve(context.Background(), o, req)
	if e != nil {
		t.Fatal(e)
	}
	if plan.CountedTokens == int64(plan.TokenEstimate) || plan.ReasoningReserve != 50 || plan.OutputReserve != 100 {
		t.Fatal("estimate treated as exact or reserve missing")
	}
	again, _, e := h.Reserve(context.Background(), o, req)
	if e != nil || again.entry != r.entry || len(h.reservations) != 1 {
		t.Fatalf("repeat double reservation: %v", e)
	}
	req.OutputReserve++
	_, _, e = h.Reserve(context.Background(), o, req)
	if e == nil {
		t.Fatal("ID reused with changed request")
	}
	if e = h.Release(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	if e = h.Release(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	req.OutputReserve--
	_, _, e = h.Reserve(context.Background(), o, req)
	code(t, e, Conflict)
}

func TestConcurrentReservationsSpendAndCompactionFloor(t *testing.T) {
	ctx := context.Background()
	s := selection(t)
	base := baseEnvelope()
	probe := syntheticHost(t, base, 1000000)
	po := observation(t, probe)
	_, _, e := probe.Reserve(ctx, po, Request{ID: "q000", Selection: s, OutputReserve: 512, ReasoningReserve: 256})
	if e != nil {
		t.Fatal(e)
	}
	_, pair, e := probe.Reserve(ctx, po, Request{ID: "q001", Selection: s, OutputReserve: 512, ReasoningReserve: 256})
	if e != nil {
		t.Fatal(e)
	}
	h := syntheticHost(t, base, pair.CountedTokens+1536)
	o := observation(t, h)
	var mu sync.Mutex
	var held []*Reservation
	var wg sync.WaitGroup
	for n := range 16 {
		wg.Go(func() {
			r, _, err := h.Reserve(ctx, o, Request{ID: fmt.Sprintf("q%03d", n), Selection: s, OutputReserve: 512, ReasoningReserve: 256})
			if err != nil {
				var d *Error
				if !errors.As(err, &d) || d.Code != Overflow {
					t.Errorf("parallel: %v", err)
				}
				return
			}
			mu.Lock()
			held = append(held, r)
			mu.Unlock()
		})
	}
	wg.Wait()
	if len(held) != 2 {
		t.Fatalf("expected exactly two slots: %d", len(held))
	}
	e = h.Compact(ctx, syntheticCompaction(t, h, o, base))
	code(t, e, Busy)
	for n, r := range held {
		if e = h.Finish(ctx, r, syntheticResponse(t, h, r, "done")); e != nil {
			t.Fatal(e)
		}
		if n == 0 {
			fresh := observation(t, h)
			_, _, err := h.Reserve(ctx, fresh, Request{ID: held[1].id, Selection: s, OutputReserve: 512, ReasoningReserve: 256})
			code(t, err, Stale)
		}
	}
	spend := h.Spending()
	if spend.InputTokens <= 0 || spend.OutputTokens <= 0 || spend.ReasoningAccounting != "unknown" {
		t.Fatal("spending fabricated/missing")
	}
	// Spend is cumulative and separate; it may exceed one window over time.
	if spend.InputTokens <= h.profile.window {
		t.Fatal("fixture did not demonstrate cumulative spend > window")
	}
	_, _, e = h.Reserve(ctx, o, Request{ID: "later", Selection: s})
	code(t, e, Stale)
	next := observation(t, h)
	before := string(encoded(t, h.retained))
	pins := string(s.raw)
	bad := base
	bad.Guards = nil
	e = h.Compact(ctx, syntheticCompaction(t, h, next, bad))
	code(t, e, Conflict)
	compact := base
	compact.History = []Message{{Role: "summary", Content: "host compacted history"}}
	compact.PriorResponses = nil
	if e = h.Compact(ctx, syntheticCompaction(t, h, next, compact)); e != nil {
		t.Fatal(e)
	}
	if string(encoded(t, h.retained)) != before || !strings.Contains(string(encoded(t, h.retained)), "requiredFloor") || !strings.Contains(pins, "statementCAS") {
		t.Fatal("compaction lost source pins/mandatory floor")
	}
	_, e = h.Preview(ctx, next, Request{ID: "stale", Selection: s})
	code(t, e, Stale)
	newObservation := observation(t, h)
	_, e = h.Preview(ctx, newObservation, Request{ID: "new", Selection: s})
	code(t, e, Overflow) // Retained floors still occupy the window after compaction.
	if newObservation.pin != h.profile.pin || newObservation.epoch != h.epoch {
		t.Fatal("profile/snapshot not pinned")
	}
	h.Revoke()
	_, e = h.Observe(ctx)
	code(t, e, Revoked)
	_, _, e = h.Reserve(ctx, newObservation, Request{ID: "revoked", Selection: s})
	code(t, e, Revoked)
}

func TestCancellationAndDefensiveCopies(t *testing.T) {
	base := baseEnvelope()
	h := syntheticHost(t, base, 1000000)
	s := selection(t)
	o := observation(t, h)
	base.System[0] = "caller mutation"
	req := Request{ID: "one", Selection: s, Optional: []Optional{{ID: "optional", Content: "immutable"}}, OutputReserve: 100}
	r, p, e := h.Reserve(context.Background(), o, req)
	if e != nil {
		t.Fatal(e)
	}
	req.Optional[0].Content = "mutated"
	p.Envelope[0] = 0
	p.Omitted = append(p.Omitted, Omission{ID: "fake"})
	if !json.Valid(r.wire) || strings.Contains(string(r.wire), "mutated") || strings.Contains(string(r.wire), "caller mutation") {
		t.Fatal("caller mutated opaque state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e = h.Finish(ctx, r, syntheticResponse(t, h, r, "answer"))
	if !errors.Is(e, context.Canceled) || len(h.retained) != 0 {
		t.Fatal("cancelled completion published")
	}
	e = h.Release(context.Background(), r)
	code(t, e, Busy)
	_, _, e = h.Reserve(context.Background(), o, Request{ID: "before-reconcile", Selection: s})
	code(t, e, Busy)
	h.Revoke()
	h = syntheticHost(t, baseEnvelope(), 1000000)
	o = observation(t, h)
	ctx, cancel = context.WithCancel(context.Background())
	h.profile.count = func(raw []byte) (int64, error) { cancel(); return syntheticCount(raw) }
	_, _, e = h.Reserve(ctx, o, Request{ID: "cancelled-count", Selection: s})
	if !errors.Is(e, context.Canceled) || len(h.reservations) != 0 {
		t.Fatal("cancellation during count reserved")
	}
}
