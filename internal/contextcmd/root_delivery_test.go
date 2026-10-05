package contextcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/contextwindow"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func TestRootSelectionCompleteByteFloor(t *testing.T) {
	f := normalRootFixture(t, "")
	req := rootRequest("base.skill.review")
	s, err := BeginRootSelection(context.Background(), f.runtime, req)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	out := s.Result()
	raw := rootJSON(t, resultdto.RootDeliveryReceiptV2{APIVersion: resultdto.RootReceiptV2, BodySHA256: out.Delivery.BodySHA256, PacketSHA256: evidencecas.Digest(rootJSON(t, out.Body.Packet)), GuardSHA256: evidencecas.Digest(mustRootV2Guard(t, out.Body)), ImagesSHA256: evidencecas.Digest(rootJSON(t, out.Body.Files)), FileCount: len(out.Body.Files)})
	if out.Delivery.Spending.InputBytes != int64(out.Delivery.EnvelopeBytes) || out.Delivery.Spending.OutputBytes != int64(len(raw)) || out.Delivery.OutputByteReserve != int64(len(raw)) || out.Delivery.ResponseSHA256 != evidencecas.Digest(raw) || out.Delivery.Profile.ModelCapacity != "unknown" || out.Delivery.Spending.InputTokens != 0 || out.Delivery.Spending.OutputTokens != 0 || out.Bytes != len(rootJSON(t, out)) {
		t.Fatal("not actual full-image byte delivery")
	}
	// Include the actual Finish-retained response, whose JSON escaping can
	// exceed the initial raw output reservation. Find the boundary using the
	// real consumer rather than assuming envelope+reserve is its final floor.
	low, high := 1, 32768
	for low < high {
		mid := (low + high) / 2
		req.MaxBytes = mid
		candidate, e := BeginRootSelection(context.Background(), f.runtime, req)
		if e == nil {
			candidate.Close()
			high = mid
		} else {
			if candidate != nil {
				t.Fatal("partial budget result")
			}
			low = mid + 1
		}
	}
	minimum := low
	req.MaxBytes = minimum
	exact, e := BeginRootSelection(context.Background(), f.runtime, req)
	if e != nil {
		t.Fatal("exact complete consumer floor", e)
	}
	exact.Close()
	req.MaxBytes--
	if bad, e := BeginRootSelection(context.Background(), f.runtime, req); e == nil || bad != nil {
		t.Fatal("complete floor minus one returned partial context")
	}
	t.Logf("actual complete floor=%d includes Finish-retained output; DTO=%d; one-byte-short whole refusal", minimum, out.Bytes)
	large := normalRootFixture(t, "large-image")
	largeReq := rootRequest("base.skill.review")
	largeReq.MaxBytes = minimum
	if bad, err := BeginRootSelection(context.Background(), large.runtime, largeReq); err == nil || bad != nil {
		t.Fatal("large full images replaced with excerpts or omitted")
	}
}

func TestRootDeliveryRejectsMissingFloorAndChangedImage(t *testing.T) {
	f := normalRootFixture(t, "")
	s, err := BeginRootSelection(context.Background(), f.runtime, rootRequest("base.skill.review"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := s.admitted
	out := s.Result()
	out.Body.APIVersion = "tplaiter.dev/context-root-selection/v1" // Exercise the unchanged legacy transport wire.
	body := rootJSON(t, out.Body)
	packet := rootJSON(t, out.Body.Packet)
	idx, err := contextindex.New(a.knowledge, nil)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{}
	for _, r := range out.Body.Packet.Records {
		required = append(required, r.ID)
	}
	selection, err := contextwindow.Select(context.Background(), idx, contextindex.Request{Query: contextindex.Query{ID: required[0], One: true}, Limit: 1, MaxRecords: 256, MaxBytes: 32768, Required: required, IncludeExcerpts: true, MaxExcerptBytes: 2048}, []contextindex.Binding{{SourceID: a.sourceID, Runtime: a.runtime.TrustRuntime(), Resolution: a.resolution}})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := contextwindow.NewByteAdapter(contextwindow.Scope{Session: out.Body.Snapshot, Model: "local-test;model-window-unknown"}, contextwindow.Envelope{System: []string{}, ToolSchemas: []json.RawMessage{}, History: []contextwindow.Message{}, PriorResponses: []string{}, Guards: []contextwindow.Guard{{ID: "root-context-body", Content: string(rootGuardBody(out.Body))}}})
	if err != nil {
		t.Fatal(err)
	}
	host := adapter.Host()
	defer host.Revoke()
	observation, err := host.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := host.Preview(context.Background(), observation, contextwindow.Request{ID: "root-proof", Selection: selection, MaxBytes: 32768, OutputByteReserve: len(rootGuardBody(out.Body))})
	if err != nil {
		t.Fatal(err)
	}
	transport := func() *rootContextTransport {
		return &rootContextTransport{bodyDigest: evidencecas.Digest(body), guardDigest: evidencecas.Digest(rootGuardBody(out.Body)), packetDigest: evidencecas.Digest(packet)}
	}
	if raw, err := transport().Exchange(context.Background(), plan.Envelope, len(rootGuardBody(out.Body))); err != nil || string(raw) != string(rootGuardBody(out.Body)) {
		t.Fatal("actual frozen wire positive failed", err)
	}
	for _, name := range []string{"floor", "image", "duplicate-body", "ceiling", "cancel"} {
		t.Run(name, func(t *testing.T) {
			var wire map[string]json.RawMessage
			if err = json.Unmarshal(plan.Envelope, &wire); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			ceiling := len(rootGuardBody(out.Body))
			want := Stale
			switch name {
			case "floor":
				var parallel []map[string]json.RawMessage
				if err = json.Unmarshal(wire["parallel"], &parallel); err != nil {
					t.Fatal(err)
				}
				var payload map[string]json.RawMessage
				if err = json.Unmarshal(parallel[0]["context"], &payload); err != nil {
					t.Fatal(err)
				}
				var packet contextindex.Packet
				if err = json.Unmarshal(payload["required"], &packet); err != nil {
					t.Fatal(err)
				}
				packet.RequiredFloor = []string{}
				payload["required"] = rootJSON(t, packet)
				parallel[0]["context"] = rootJSON(t, payload)
				wire["parallel"] = rootJSON(t, parallel)
			case "image", "duplicate-body":
				var base map[string]json.RawMessage
				if err = json.Unmarshal(wire["base"], &base); err != nil {
					t.Fatal(err)
				}
				var guards []contextwindow.Guard
				if err = json.Unmarshal(base["guards"], &guards); err != nil {
					t.Fatal(err)
				}
				if name == "image" {
					guards[0].Content += " "
				} else {
					guards = append(guards, guards[0])
				}
				base["guards"] = rootJSON(t, guards)
				wire["base"] = rootJSON(t, base)
			case "ceiling":
				ceiling--
				want = Budget
			case "cancel":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
				want = "CONTEXT_CANCELLED"
			}
			tr := transport()
			raw, err := tr.Exchange(ctx, rootJSON(t, wire), ceiling)
			if err == nil || Code(err) != want || raw != nil || tr.delivered != nil {
				t.Fatal("bad frozen wire delivered partial content")
			}
		})
	}
}

func mustRootV2Guard(t *testing.T, b resultdto.RootContextBody) []byte {
	t.Helper()
	raw, e := resultdto.RootGuardV2(b)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestRootV2TransportCompleteReceiptAndTamper(t *testing.T) {
	f := normalRootFixture(t, "")
	s, e := BeginRootSelection(context.Background(), f.runtime, rootRequest("base.skill.review"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	out := s.Result()
	body := out.Body
	idx, e := contextindex.New(s.admitted.knowledge, nil)
	if e != nil {
		t.Fatal(e)
	}
	required := []string{}
	for _, r := range body.Packet.Records {
		required = append(required, r.ID)
	}
	req := contextindex.Request{Query: contextindex.Query{ID: required[0], One: true}, Limit: 1, MaxRecords: 256, MaxBytes: 32768, Required: required, IncludeExcerpts: true, MaxExcerptBytes: 2048}
	bound := contextindex.Binding{SourceID: s.admitted.sourceID, Runtime: s.admitted.runtime.TrustRuntime(), Resolution: s.admitted.resolution}
	selected, e := contextwindow.Select(context.Background(), idx, req, []contextindex.Binding{bound})
	if e != nil {
		t.Fatal(e)
	}
	selected, e = contextwindow.FactorRootSelectionV2(context.Background(), selected)
	if e != nil {
		t.Fatal(e)
	}
	guard := mustRootV2Guard(t, body)
	adapter, e := contextwindow.NewByteAdapter(contextwindow.Scope{Session: body.Snapshot, Model: "local-byte-test"}, contextwindow.Envelope{System: []string{}, ToolSchemas: []json.RawMessage{}, History: []contextwindow.Message{}, PriorResponses: []string{}, Guards: []contextwindow.Guard{{ID: "root-context-body", Content: string(guard)}}})
	if e != nil {
		t.Fatal(e)
	}
	host := adapter.Host()
	defer host.Revoke()
	observation, e := host.Observe(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	facts, e := contextindex.EncodeRootFactsV2(body.Packet)
	if e != nil {
		t.Fatal(e)
	}
	projection := rootJSON(t, facts)
	packet := rootJSON(t, body.Packet)
	bodyRaw := rootJSON(t, body)
	receipt := rootJSON(t, resultdto.RootDeliveryReceiptV2{APIVersion: resultdto.RootReceiptV2, BodySHA256: evidencecas.Digest(bodyRaw), PacketSHA256: evidencecas.Digest(packet), GuardSHA256: evidencecas.Digest(guard), ImagesSHA256: evidencecas.Digest(rootJSON(t, body.Files)), FileCount: len(body.Files)})
	plan, e := host.Preview(context.Background(), observation, contextwindow.Request{ID: "complete-root", Selection: selected, MaxBytes: 32768, OutputByteReserve: len(receipt)})
	if e != nil {
		t.Fatal(e)
	}
	makeTransport := func() *rootContextTransport {
		return &rootContextTransport{bodyDigest: evidencecas.Digest(bodyRaw), packetDigest: evidencecas.Digest(packet), guardDigest: evidencecas.Digest(guard), projectionDigest: evidencecas.Digest(projection), v2: true}
	}
	positive := makeTransport()
	response, e := positive.Exchange(context.Background(), plan.Envelope, len(receipt))
	if e != nil || !bytes.Equal(response, receipt) || !bytes.Equal(positive.assembled, bodyRaw) {
		t.Fatal("complete body not actually consumed", e)
	}
	for _, name := range []string{"missing-image", "missing-floor", "source-pin", "image-count", "packet-hash", "receipt-ceiling", "cancel"} {
		t.Run(name, func(t *testing.T) {
			tr := makeTransport()
			wire := append([]byte(nil), plan.Envelope...)
			ctx := context.Background()
			ceiling := len(receipt)
			switch name {
			case "missing-image":
				wire = bytes.Replace(wire, []byte("root-context-body"), []byte("missing-context-body"), 1)
			case "missing-floor":
				wire = bytes.Replace(wire, []byte("requiredFloor"), []byte("missingFloor"), 1)
			case "source-pin":
				wire = bytes.Replace(wire, []byte(body.Packet.Sources[0].Anchor.Commit), []byte("different-source"), 1)
			case "image-count":
				tr.bodyDigest = evidencecas.Digest([]byte("body without required images"))
			case "packet-hash":
				tr.packetDigest = evidencecas.Digest([]byte("packet missing required record"))
			case "receipt-ceiling":
				ceiling--
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if got, e := tr.Exchange(ctx, wire, ceiling); e == nil || got != nil || len(tr.assembled) != 0 || len(tr.delivered) != 0 {
				t.Fatal("partial delivery escaped", name, e)
			}
		})
	}
	t.Logf("actual complete packet/images consumed before %d-byte receipt; all altered facts/source/body and short-output cases refused before delivery", len(receipt))
}
