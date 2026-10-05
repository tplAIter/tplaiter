package contextwindow

import "context"

// Adapter provides useful admission for a fixed local byte ceiling. It does not
// certify a model window or tokenizer. No caller capacity or counter is accepted.
type Adapter struct{ host *Host }

// Transport is the host integration boundary. Exchange receives an owned copy
// of the exact planned wire and a byte response ceiling. It must honor context.
// The adapter measures bytes itself; transport never supplies trusted token usage.
type Transport interface {
	Exchange(context.Context, []byte, int) ([]byte, error)
}

type Profile struct {
	Accounting    string `json:"accounting"`
	ModelCapacity string `json:"modelCapacity"`
	ByteCeiling   int    `json:"byteCeiling"`
	Pin           string `json:"pin"`
}

func NewByteAdapter(scope Scope, base Envelope) (*Adapter, error) {
	h, e := NewHost(scope, base)
	if e != nil {
		return nil, e
	}
	h.profile = &profile{pin: digest([]byte("bounded-local-wire-bytes/v1; ceiling=1048576; model-capacity=unknown")), accounting: "measured-wire-bytes; model-tokens-unknown", window: HardBytes, byteOnly: true, count: func(b []byte) (int64, error) { return int64(len(b)), nil }}
	return &Adapter{host: h}, nil
}

func (a *Adapter) Host() *Host {
	if a == nil || a.host == nil {
		return nil
	}
	return &Host{hostState: a.host.hostState}
}

func (a *Adapter) Profile() Profile {
	if a == nil || a.host == nil {
		return Profile{Accounting: "unknown", ModelCapacity: "unknown"}
	}
	return Profile{Accounting: a.host.profile.accounting, ModelCapacity: "unknown", ByteCeiling: HardBytes, Pin: a.host.profile.pin}
}

// Deliver issues an opaque receipt after actual transport delivery. Failures are
// ambiguous about delivery, so revoke rather than freeing potentially used space.
// A repeated successful delivery returns its receipt without calling transport.
func (a *Adapter) Deliver(ctx context.Context, r *Reservation, t Transport) (*ResponseObservation, error) {
	if e := checkContext(ctx); e != nil {
		return nil, e
	}
	if a == nil || a.host == nil || r == nil || r.entry == nil || r.host != a.host.hostState || t == nil {
		return nil, fail(Invalid, "adapter delivery")
	}
	h := a.host
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, fail(Revoked, "host")
	}
	if h.reservations[r.id] != r.entry {
		h.mu.Unlock()
		return nil, fail(Stale, "reservation")
	}
	if r.receipt != nil {
		receipt := r.receipt
		h.mu.Unlock()
		return &ResponseObservation{responseRecord: receipt}, nil
	}
	if r.delivering {
		h.mu.Unlock()
		return nil, fail(Busy, "delivery in progress")
	}
	r.delivering = true
	wire := append([]byte(nil), r.wire...)
	bound := int(r.output)
	h.mu.Unlock()
	response, e := t.Exchange(ctx, append([]byte(nil), wire...), bound)
	if e == nil {
		e = checkContext(ctx)
	}
	if e != nil {
		h.Revoke()
		return nil, e
	}
	// An overrun cannot be represented as safe admission or silently discarded.
	if len(response) > HardBytes {
		h.Revoke()
		return nil, fail(Overflow, "transport response bytes")
	}
	receipt, e := h.recordResponse(ctx, r, wire, string(response))
	if e != nil {
		h.Revoke()
		return nil, e
	}
	return receipt, nil
}

// ObserveCompaction records replacement history for the local byte ledger only.
// It never makes a claim about remaining model tokens. Mandatory state is checked
// again by Host.Compact, and retained C03 packets are preserved by that operation.
func (a *Adapter) ObserveCompaction(ctx context.Context, o *Observation, next Envelope) (*CompactionObservation, error) {
	if a == nil || a.host == nil {
		return nil, fail(Invalid, "adapter")
	}
	return a.host.recordCompaction(ctx, o, next)
}
