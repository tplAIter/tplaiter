package providerclient

import (
	"context"
	"encoding/json"
	"strconv"
)

// OperationReceipt retains a bounded observation on the original connection.
// It is data, never source authentication, an execution permit or organization admission.
type OperationReceipt struct {
	session   *Session
	operation string
	raw       []byte
	binding   Binding
}

func (r *OperationReceipt) Operation() string {
	if r == nil {
		return ""
	}
	return r.operation
}
func (r *OperationReceipt) Bytes() []byte {
	if r == nil {
		return nil
	}
	return copyRaw(r.raw)
}
func (r *OperationReceipt) Binding() Binding {
	if r == nil {
		return Binding{}
	}
	return cloneBinding(r.binding)
}

// Describe observes the negotiated description again without creating a new scope.
func (s *Session) Describe(ctx context.Context) (*OperationReceipt, error) {
	return s.observeOperation(ctx, "describe", "", "")
}

// Inspect observes a captured source, or a captured asset within that source.
func (s *Session) Inspect(ctx context.Context, sourceID, assetID string) (*OperationReceipt, error) {
	return s.observeOperation(ctx, "inspect", sourceID, assetID)
}

// Resolve preserves the captured immutable pin. It cannot resolve floating refs.
func (s *Session) Resolve(ctx context.Context, sourceID, assetID string) (*OperationReceipt, error) {
	return s.observeOperation(ctx, "resolve", sourceID, assetID)
}

// Graph observes complete source containment only. Other layers remain unresolved data.
func (s *Session) Graph(ctx context.Context) (*OperationReceipt, error) {
	return s.observeOperation(ctx, "graph", "", "")
}

func (s *Session) observeOperation(ctx context.Context, op, sourceID, assetID string) (receipt *OperationReceipt, err error) {
	if s == nil || ctx == nil || s.conn == nil || s.closed.Load() || !s.dynamic {
		return nil, failure("SESSION_LIFETIME", nil)
	}
	if !s.busy.CompareAndSwap(false, true) {
		return nil, failure("SESSION_BUSY", nil)
	}
	defer s.busy.Store(false)
	// Unsupported optional operations do not consume or invalidate catalog/read sessions.
	if !includes(s.hello.Provider.Operations, op) {
		return nil, failure("SESSION_OPERATION_UNSUPPORTED", nil)
	}
	var expected []byte
	q := request{Version: APIVersion, Op: op, Budget: &s.query.Budget, DeadlineMS: s.query.DeadlineMS}
	if op == "inspect" || op == "resolve" {
		src, ok := s.source(sourceID)
		if !ok || src.State != "available-static" || (s.query.SourceID != "" && sourceID != s.query.SourceID) {
			return nil, failure("SESSION_SCOPE", nil)
		}
		q.SourceID, q.AssetID, q.Pin = sourceID, assetID, src.Revision
		expected, _ = json.Marshal(src)
		if assetID != "" {
			found := false
			for _, asset := range src.Assets {
				if asset.ID == assetID {
					expected, _ = json.Marshal(asset)
					found = true
				}
			}
			if !found {
				return nil, failure("SESSION_SCOPE", nil)
			}
		}
	}
	// The current graph operation has no narrowing selector. Never broaden a selected-source session.
	if op == "graph" && s.query.SourceID != "" {
		return nil, failure("SESSION_SCOPE", nil)
	}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	finish, err := s.deadline(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	s.sequence++
	q.ID = op + "-" + strconv.Itoa(s.sequence)
	response, err := s.exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	switch op {
	case "describe":
		var got Description
		if strict(response.Result, &got) != nil {
			return nil, failure("SESSION_WIRE", nil)
		}
		actual, _ := json.Marshal(got)
		original, _ := json.Marshal(s.hello)
		if !jsonEqual(actual, original) {
			return nil, failure("SESSION_SCOPE", nil)
		}
	case "inspect", "resolve":
		// Decode into the captured shape, rejecting unknown keys before identity comparison.
		if assetID == "" {
			var got SourceDescriptor
			if strict(response.Result, &got) != nil {
				return nil, failure("SESSION_WIRE", nil)
			}
		} else {
			var got AssetDescriptor
			if strict(response.Result, &got) != nil {
				return nil, failure("SESSION_WIRE", nil)
			}
		}
		if !jsonEqual(response.Result, expected) {
			return nil, failure("SESSION_SCOPE", nil)
		}
	case "graph":
		if err := s.checkContainment(response.Result); err != nil {
			return nil, err
		}
	default:
		return nil, failure("SESSION_OPERATION_UNSUPPORTED", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &OperationReceipt{session: s, operation: op, raw: copyRaw(response.Result), binding: cloneBinding(s.binding)}, nil
}

func (s *Session) checkContainment(raw []byte) error {
	var graph struct {
		Edges []struct {
			Layer      string          `json:"layer"`
			Type       string          `json:"type"`
			From       string          `json:"from"`
			To         string          `json:"to"`
			Anchor     json.RawMessage `json:"anchor"`
			Confidence string          `json:"confidence"`
		} `json:"edges"`
		Unresolved []string `json:"unresolved"`
	}
	if strictOpaque(raw, &graph) != nil || !required(raw, "edges", "unresolved") || graph.Edges == nil || graph.Unresolved == nil || len(graph.Unresolved) > 32 {
		return failure("SESSION_WIRE", nil)
	}
	expected := map[string]AssetDescriptor{}
	for _, src := range s.discovered {
		for _, asset := range src.Assets {
			expected[src.ID+"\x00"+asset.ID] = asset
		}
	}
	if len(graph.Edges) != len(expected) {
		return failure("SESSION_SCOPE", nil)
	}
	seen := map[string]bool{}
	for _, edge := range graph.Edges {
		key := edge.From + "\x00" + edge.To
		asset, ok := expected[key]
		anchor, _ := json.Marshal(asset.Anchor)
		if !ok || seen[key] || edge.Layer != "source" || edge.Type != "contains-curated-asset" || edge.Confidence != "exact-pinned-blob" || !jsonEqual(edge.Anchor, anchor) {
			return failure("SESSION_SCOPE", nil)
		}
		seen[key] = true
	}
	return nil
}
