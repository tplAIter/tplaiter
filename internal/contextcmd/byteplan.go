package contextcmd

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/contextwindow"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

// localContextTransport delivers the required C03 packet from the exact C04
// planned wire. It performs no provider calls, accepts no caller response or
// capacity claim and never reads a mutable filesystem catalog.
type localContextTransport struct {
	expected string
	packet   contextindex.Packet
}

func (t *localContextTransport) Exchange(ctx context.Context, wire []byte, responseByteCeiling int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var envelope struct {
		Parallel []struct {
			Context struct {
				Required json.RawMessage `json:"required"`
			} `json:"context"`
		} `json:"parallel"`
	}
	if err := json.Unmarshal(wire, &envelope); err != nil {
		return nil, fail(Invalid)
	}
	if len(envelope.Parallel) != 1 {
		return nil, fail(Stale)
	}
	raw := envelope.Parallel[0].Context.Required
	if evidencecas.Digest(raw) != t.expected {
		return nil, fail(Stale)
	}
	if len(raw) > responseByteCeiling {
		return nil, fail(Budget)
	}
	if err := json.Unmarshal(raw, &t.packet); err != nil {
		return nil, fail(Invalid)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]byte(nil), raw...), nil
}

func deliverLocalContext(ctx context.Context, idx *contextindex.Index, coreReq contextindex.Request, binding contextindex.Binding, req Request, snapshot string, packet contextindex.Packet) (contextindex.Packet, contextwindow.Plan, contextwindow.Profile, contextwindow.Spending, error) {
	empty := contextindex.Packet{}
	var noPlan contextwindow.Plan
	var noProfile contextwindow.Profile
	var noSpend contextwindow.Spending
	selected, err := contextwindow.Select(ctx, idx, coreReq, []contextindex.Binding{binding})
	if err != nil {
		return empty, noPlan, noProfile, noSpend, err
	}
	raw, err := json.Marshal(packet)
	if err != nil {
		return empty, noPlan, noProfile, noSpend, err
	}
	selectors, err := json.Marshal(req)
	if err != nil {
		return empty, noPlan, noProfile, noSpend, err
	}
	// This envelope is the actual local C05 retrieval invocation, not an invented
	// provider/system/history envelope for the external agent using CLI or MCP.
	adapter, err := contextwindow.NewByteAdapter(contextwindow.Scope{Session: snapshot, Model: "local-retrieval;model-window-unknown"}, contextwindow.Envelope{
		System:         []string{"Deliver only the authenticated installed C03 selection; local byte transport, no model-window admission."},
		ToolSchemas:    []json.RawMessage{},
		History:        []contextwindow.Message{{Role: "request", Content: string(selectors)}},
		PriorResponses: []string{},
		Guards:         []contextwindow.Guard{{ID: "installed-snapshot", Content: snapshot}, {ID: "mandatory-context", Content: "Retain every C03 required floor and authenticated source pin."}},
	})
	if err != nil {
		return empty, noPlan, noProfile, noSpend, err
	}
	host := adapter.Host()
	defer host.Revoke()
	observation, err := host.Observe(ctx)
	if err != nil {
		return empty, noPlan, noProfile, noSpend, err
	}
	reservation, plan, err := host.Reserve(ctx, observation, contextwindow.Request{ID: "context-retrieval", Selection: selected, MaxBytes: req.MaxBytes, OutputByteReserve: len(raw)})
	if err != nil {
		return empty, noPlan, noProfile, noSpend, err
	}
	transport := &localContextTransport{expected: evidencecas.Digest(raw)}
	receipt, err := adapter.Deliver(ctx, reservation, transport)
	if err != nil {
		return empty, noPlan, noProfile, noSpend, err
	}
	if err = host.Finish(ctx, reservation, receipt); err != nil {
		return empty, noPlan, noProfile, noSpend, err
	}
	return transport.packet, plan, adapter.Profile(), host.Spending(), nil
}

// The public C04 model host lacks trusted capacity instrumentation. Its actual
// reservation result supplies the typed unknown plan outcome; local byte
// admission above cannot promote itself into model-window authority.
func missingModelWindow(ctx context.Context, idx *contextindex.Index, req contextindex.Request, binding contextindex.Binding, maxBytes int, snapshot string) (string, error) {
	selection, err := contextwindow.Select(ctx, idx, req, []contextindex.Binding{binding})
	if err != nil {
		return "", err
	}
	host, err := contextwindow.NewHost(contextwindow.Scope{Session: snapshot, Model: "unadmitted-model-profile"}, contextwindow.Envelope{Guards: []contextwindow.Guard{{ID: "installed-snapshot", Content: snapshot}}})
	if err != nil {
		return "", err
	}
	defer host.Revoke()
	observation, err := host.Observe(ctx)
	if err != nil {
		return "", err
	}
	_, _, err = host.Reserve(ctx, observation, contextwindow.Request{ID: "model-context-plan", Selection: selection, MaxBytes: maxBytes})
	var window *contextwindow.Error
	if errors.As(err, &window) && window.Code == contextwindow.Unknown {
		return window.Code, nil
	}
	if err != nil {
		return "", err
	}
	return "", fail(Invalid)
}
