package contextwindow

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type exchangeFunc func(context.Context, []byte, int) ([]byte, error)

func (f exchangeFunc) Exchange(c context.Context, b []byte, n int) ([]byte, error) { return f(c, b, n) }

func byteAdapter(t *testing.T) (*Adapter, *Host, *Selection) {
	t.Helper()
	a, e := NewByteAdapter(Scope{Session: "production-bytes", Model: "unknown-model"}, baseEnvelope())
	if e != nil {
		t.Fatal(e)
	}
	return a, a.Host(), selection(t)
}

func TestByteAdapterDeliveryAccountingReplayAndCompaction(t *testing.T) {
	a, h, s := byteAdapter(t)
	ctx := context.Background()
	o := observation(t, h)
	profile := a.Profile()
	if profile.ModelCapacity != "unknown" || profile.ByteCeiling != HardBytes || profile.Pin == "" {
		t.Fatal(profile)
	}
	req := Request{ID: "production", Selection: s, OutputByteReserve: 512, Optional: []Optional{{ID: "large", Content: strings.Repeat("optional", 10000)}}}
	p, e := h.Preview(ctx, o, Request{ID: req.ID, Selection: s, OutputByteReserve: 512})
	if e != nil {
		t.Fatal(e)
	}
	req.MaxBytes = p.Bytes + 500
	held, p, e := h.Reserve(ctx, o, req)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Omitted) != 1 || p.CountedTokens != 0 || p.OutputReserve != 0 || p.OutputByteReserve != 512 || p.CapacityAccounting != "model-window-unknown" || p.TokenEstimate != (p.EnvelopeBytes+3)/4 {
		t.Fatal(p.Accounting, p.CapacityAccounting, p.Omitted)
	}
	calls := 0
	transport := exchangeFunc(func(ctx context.Context, b []byte, ceiling int) ([]byte, error) {
		calls++
		if !bytes.Equal(b, p.Envelope) || ceiling != 512 {
			t.Fatal("wrong delivered wire/response ceiling")
		}
		b[0] = 0
		return []byte("actual transport answer 🚀"), nil
	})
	receipt, e := a.Deliver(ctx, held, transport)
	if e != nil {
		t.Fatal(e)
	}
	again, e := a.Deliver(ctx, held, transport)
	if e != nil || again.responseRecord != receipt.responseRecord || calls != 1 {
		t.Fatal("delivery repeated", e, calls)
	}
	spend := h.Spending()
	if spend.InputBytes != int64(p.EnvelopeBytes) || spend.OutputBytes != int64(len("actual transport answer 🚀")) || spend.InputTokens != 0 || spend.OutputTokens != 0 || spend.ReasoningAccounting != "unknown" {
		t.Fatal(spend)
	}
	_, _, e = h.Reserve(ctx, o, Request{ID: "pending", Selection: s})
	code(t, e, Busy)
	e = h.Release(ctx, held)
	code(t, e, Busy)
	if e = h.Finish(ctx, held, receipt); e != nil {
		t.Fatal(e)
	}
	if h.Spending() != spend {
		t.Fatal("finish double spent")
	}
	_, e = a.Deliver(ctx, held, transport)
	code(t, e, Stale)
	old := string(encoded(t, h.retained))
	fresh := observation(t, h)
	next := baseEnvelope()
	next.History = nil
	next.PriorResponses = nil
	compact, e := a.ObserveCompaction(ctx, fresh, next)
	if e != nil {
		t.Fatal(e)
	}
	next.System[0] = "caller mutation"
	if e = h.Compact(ctx, compact); e != nil {
		t.Fatal(e)
	}
	if string(encoded(t, h.retained)) != old {
		t.Fatal("compaction dropped mandatory packets")
	}
	_, e = h.Preview(ctx, fresh, Request{ID: "stale", Selection: s})
	code(t, e, Stale)
	_, _, e = h.Reserve(ctx, observation(t, h), Request{ID: "token-claim", Selection: s, OutputReserve: 1})
	code(t, e, Unknown)
}

func TestByteAdapterOverrunAndAmbiguousDeliveryRevoke(t *testing.T) {
	for _, kind := range []string{"overrun", "error", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			a, h, s := byteAdapter(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			held, _, e := h.Reserve(ctx, observation(t, h), Request{ID: kind, Selection: s, OutputByteReserve: 2})
			if e != nil {
				t.Fatal(e)
			}
			receipt, e := a.Deliver(ctx, held, exchangeFunc(func(context.Context, []byte, int) ([]byte, error) {
				switch kind {
				case "error":
					return nil, errors.New("transport interrupted")
				case "cancel":
					cancel()
					return []byte("ok"), nil
				default:
					return []byte("too long"), nil
				}
			}))
			if kind == "overrun" {
				if e != nil {
					t.Fatal(e)
				}
				e = h.Finish(context.Background(), held, receipt)
				code(t, e, Overflow)
				if h.Spending().OutputBytes != 8 {
					t.Fatal("overrun usage hidden")
				}
			} else if e == nil {
				t.Fatal("ambiguous delivery accepted")
			}
			_, e = h.Observe(context.Background())
			code(t, e, Revoked)
			if len(h.retained) != 0 {
				t.Fatal("failed delivery published")
			}
		})
	}
}

func TestByteAdapterConcurrentDeliveryAndBounds(t *testing.T) {
	a, h, s := byteAdapter(t)
	ctx := context.Background()
	o := observation(t, h)
	req := Request{ID: "one", Selection: s, OutputByteReserve: 128}
	p, e := h.Preview(ctx, o, req)
	if e != nil {
		t.Fatal(e)
	}
	req.MaxBytes = p.EnvelopeBytes + 127
	_, _, e = h.Reserve(ctx, o, req)
	code(t, e, Overflow)
	req.MaxBytes = 0
	r, _, e := h.Reserve(ctx, o, req)
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		receipt, err := a.Deliver(ctx, r, exchangeFunc(func(context.Context, []byte, int) ([]byte, error) {
			close(entered)
			<-release
			return []byte("ok"), nil
		}))
		if err != nil {
			t.Error(err)
			return
		}
		if err = h.Finish(ctx, r, receipt); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	_, e = a.Deliver(ctx, r, exchangeFunc(func(context.Context, []byte, int) ([]byte, error) {
		t.Error("duplicate transport called")
		return nil, nil
	}))
	code(t, e, Busy)
	_, _, e = h.Reserve(ctx, o, Request{ID: "parallel", Selection: s})
	code(t, e, Busy)
	e = h.Release(ctx, r)
	code(t, e, Busy)
	close(release)
	wg.Wait()
	if len(h.retained) != 1 || h.Spending().OutputBytes != 2 {
		t.Fatal("concurrent delivery publication")
	}
}

func TestByteAdapterParallelReservationsKeepAllPayloads(t *testing.T) {
	_, h, s := byteAdapter(t)
	ctx := context.Background()
	o := observation(t, h)
	r, first, e := h.Reserve(ctx, o, Request{ID: "one", Selection: s, OutputByteReserve: 50})
	if e != nil {
		t.Fatal(e)
	}
	_, second, e := h.Reserve(ctx, o, Request{ID: "two", Selection: s, OutputByteReserve: 70})
	if e != nil {
		t.Fatal(e)
	}
	if second.OutputByteReserve != 120 || second.EnvelopeBytes <= first.EnvelopeBytes || !bytes.Contains(second.Envelope, []byte(`"id":"one"`)) || !bytes.Contains(second.Envelope, []byte(`"id":"two"`)) {
		t.Fatal("parallel obligations lost")
	}
	repeated, _, e := h.Reserve(ctx, o, Request{ID: "one", Selection: s, OutputByteReserve: 50})
	if e != nil || repeated.entry != r.entry {
		t.Fatal("repeat duplicated", e)
	}
}
