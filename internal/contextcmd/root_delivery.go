package contextcmd

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/contextwindow"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// rootContextTransport consumes the actual planned bytes. Neither an excerpt
// packet nor a caller count can stand in for the complete materialized body.
type rootContextTransport struct {
	bodyDigest, guardDigest, packetDigest string
	delivered                             []byte
	assembled                             []byte
}

func (t *rootContextTransport) Exchange(ctx context.Context, wire []byte, ceiling int) ([]byte, error) {
	if ctx == nil {
		return nil, fail(Invalid)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var e struct {
		Base struct {
			Guards []contextwindow.Guard `json:"guards"`
		} `json:"base"`
		Parallel []struct {
			Context struct {
				Required json.RawMessage `json:"required"`
			} `json:"context"`
		} `json:"parallel"`
	}
	if err := json.Unmarshal(wire, &e); err != nil {
		return nil, fail(Invalid)
	}
	if len(e.Parallel) != 1 || evidencecas.Digest(e.Parallel[0].Context.Required) != t.packetDigest {
		return nil, fail(Stale)
	}
	var body []byte
	count := 0
	for _, guard := range e.Base.Guards {
		if guard.ID == "root-context-body" {
			count++
			body = []byte(guard.Content)
		}
	}
	if count != 1 || evidencecas.Digest(body) != t.guardDigest {
		return nil, fail(Stale)
	}

	var parsed resultdto.RootContextBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fail(Invalid)
	}
	// The required packet occurs once in the actual invocation, in C04's
	// authenticated selection. The guard carries images and other metadata.
	if raw, _ := json.Marshal(parsed.Packet); string(raw) != string(mustEmptyRootPacket()) {
		return nil, fail(Stale)
	}
	if err := json.Unmarshal(e.Parallel[0].Context.Required, &parsed.Packet); err != nil {
		return nil, fail(Invalid)
	}
	body, err := json.Marshal(parsed)
	if err != nil || evidencecas.Digest(body) != t.bodyDigest {
		return nil, fail(Stale)
	}
	if len(rootGuardBody(parsed)) > ceiling {
		return nil, fail(Budget)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	t.assembled = append([]byte(nil), body...)
	t.delivered = rootGuardBody(parsed)
	return append([]byte(nil), t.delivered...), nil
}

func deliverRootContext(ctx context.Context, idx *contextindex.Index, coreReq contextindex.Request, binding contextindex.Binding, req RootSelectionRequest, body resultdto.RootContextBody) (resultdto.ContextRootSelectionData, error) {
	empty := resultdto.ContextRootSelectionData{}
	selected, err := contextwindow.Select(ctx, idx, coreReq, []contextindex.Binding{binding})
	if err != nil {
		return empty, err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return empty, err
	}
	packet, err := json.Marshal(body.Packet)
	if err != nil {
		return empty, err
	}
	request, err := json.Marshal(req)
	if err != nil {
		return empty, err
	}
	adapter, err := contextwindow.NewByteAdapter(contextwindow.Scope{Session: body.Snapshot, Model: "local-root-selection;model-window-unknown"}, contextwindow.Envelope{
		System: []string{"Deliver the complete authenticated ROOT selection; no model-window authority."}, ToolSchemas: []json.RawMessage{}, History: []contextwindow.Message{{Role: "request", Content: string(request)}}, PriorResponses: []string{}, Guards: []contextwindow.Guard{{ID: "installed-snapshot", Content: body.Snapshot}, {ID: "root-context-body", Content: string(rootGuardBody(body))}},
	})
	if err != nil {
		return empty, err
	}
	host := adapter.Host()
	defer host.Revoke()
	observation, err := host.Observe(ctx)
	if err != nil {
		return empty, err
	}
	reservation, plan, err := host.Reserve(ctx, observation, contextwindow.Request{ID: "root-context-selection", Selection: selected, MaxBytes: req.MaxBytes, OutputByteReserve: len(rootGuardBody(body))})
	if err != nil {
		return empty, rootDeliveryError(err)
	}
	transport := &rootContextTransport{bodyDigest: evidencecas.Digest(raw), guardDigest: evidencecas.Digest(rootGuardBody(body)), packetDigest: evidencecas.Digest(packet)}
	receipt, err := adapter.Deliver(ctx, reservation, transport)
	if err != nil {
		return empty, rootDeliveryError(err)
	}
	if err = host.Finish(ctx, reservation, receipt); err != nil {
		return empty, rootDeliveryError(err)
	}
	if evidencecas.Digest(transport.delivered) != transport.guardDigest || evidencecas.Digest(transport.assembled) != transport.bodyDigest {
		return empty, fail(Stale)
	}
	var deliveredBody resultdto.RootContextBody
	if err = json.Unmarshal(transport.assembled, &deliveredBody); err != nil {
		return empty, err
	}
	out := resultdto.ContextRootSelectionData{Body: deliveredBody, Delivery: resultdto.RootByteDelivery{State: "local-byte-delivery-finished", EnvelopeSHA256: evidencecas.Digest(plan.Envelope), BodySHA256: transport.bodyDigest, ResponseSHA256: transport.guardDigest, EnvelopeBytes: plan.EnvelopeBytes, OutputByteReserve: plan.OutputByteReserve, Profile: adapter.Profile(), Spending: host.Spending()}}
	if !fitRootResult(&out, req.MaxBytes) {
		return empty, fail(Budget)
	}
	return out, nil
}

func rootDeliveryError(err error) error {
	var e *contextwindow.Error
	if errors.As(err, &e) && e.Code == contextwindow.Overflow {
		return fail(Budget)
	}
	return err
}

func fitRootResult(out *resultdto.ContextRootSelectionData, maxBytes int) bool {
	for range 32 {
		raw, err := json.Marshal(out)
		if err != nil || len(raw) > maxBytes {
			return false
		}
		if out.Bytes == len(raw) {
			return true
		}
		out.Bytes = len(raw)
	}
	return false
}

// Omit the duplicate packet from the guard, never from the complete response or
// the actual required selection. Both pieces are digest-bound in the transport.
func rootGuardBody(body resultdto.RootContextBody) []byte {
	body.Packet = contextindex.Packet{}
	raw, _ := json.Marshal(body)
	return raw
}
func mustEmptyRootPacket() []byte { raw, _ := json.Marshal(contextindex.Packet{}); return raw }
