package providerclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This peer is freshly authored neutral data, not an installed provider proof.
func optionalPeer(t *testing.T, mode string) (*Session, *atomic.Int32) {
	t.Helper()
	var hello Description
	hello.Provider.ID = "example-provider"
	hello.Provider.Operations = []string{"describe", "catalog", "read", "knowledge", "inspect", "resolve", "graph"}
	if mode == "unsupported" {
		hello.Provider.Operations = hello.Provider.Operations[:4]
	}
	hello.Provider.Capabilities = []string{"local-curated-read"}
	hello.Provider.SnapshotDigest = "sha256:example-snapshot:" + strings.Repeat("1", 64)
	hello.Provider.Evidence = "pinned-raw-git-objects"
	hello.Provider.Qualification = LocalPrototype
	hello.SchemaVersion = DescriptorVersion
	hello.Limits.DeadlineMS = 2000
	hello.Limits.FrameBytes = 4096
	hello.Limits.Frames = 256
	hello.Limits.MetadataBytes = 16384
	hello.Limits.ResponseBytes = 32768
	hello.Limits.SourceBytes = 8192
	hello.SideEffectClasses = []string{"read-only-local"}
	hello.UnsupportedCapabilities = []string{}
	src := SourceDescriptor{ID: "example:source:docs", Revision: strings.Repeat("2", 40), GitTreeOID: strings.Repeat("3", 40), State: "available-static", Assets: []AssetDescriptor{}, Capabilities: []string{}, Unresolved: []string{}}
	asset := AssetDescriptor{ID: "example:asset:readme", Kind: "static-document", Bytes: 4, DescriptorDigest: Digest{Algorithm: "sha256", Domain: "example-descriptor", Hex: strings.Repeat("4", 64)}}
	asset.Anchor.SourceID, asset.Anchor.Revision, asset.Anchor.Path = src.ID, src.Revision, "README.md"
	asset.Anchor.BlobDigest = Digest{Algorithm: "sha256", Domain: "content-bytes", Hex: digest([]byte("data"))[7:]}
	src.Assets = append(src.Assets, asset)
	client, server := net.Pipe()
	calls := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(3 * time.Second))
		rd := bufio.NewReader(server)
		for {
			raw, err := rd.ReadBytes('\n')
			if err != nil {
				return
			}
			var q request
			if json.Unmarshal(raw, &q) != nil {
				return
			}
			var result any
			switch q.Op {
			case "handshake":
				// Open must not newly require optional operations.
				for _, op := range q.RequiredOperations {
					if op == "inspect" || op == "resolve" || op == "graph" {
						t.Error("optional op required globally")
					}
				}
				result = hello
			case "catalog":
				result = []SourceDescriptor{src}
			case "describe":
				calls.Add(1)
				d := copyJSON(hello)
				if mode == "describe-drift" {
					d.Provider.ID = "example-other"
				}
				result = d
			case "inspect", "resolve":
				calls.Add(1)
				if q.SourceID != src.ID || q.Pin != src.Revision || q.Path != "" {
					t.Error("captured pin/selector not sent")
				}
				if q.AssetID == "" {
					result = src
				} else {
					a := asset
					if mode == "descriptor-drift" {
						a.Anchor.Revision = strings.Repeat("5", 40)
					}
					result = a
				}
			case "graph":
				calls.Add(1)
				from := src.ID
				if mode == "foreign-edge" {
					from = "example:source:foreign"
				}
				edge := map[string]any{"layer": "source", "type": "contains-curated-asset", "from": from, "to": asset.ID, "anchor": asset.Anchor, "confidence": "exact-pinned-blob"}
				edges := []any{edge}
				if mode == "duplicate-edge" {
					edges = append(edges, edge)
				}
				result = map[string]any{"edges": edges, "unresolved": []string{"semantic layer unavailable"}}
			default:
				t.Errorf("unexpected operation %s", q.Op)
				return
			}
			packet, _ := json.Marshal(map[string]any{"version": APIVersion, "id": q.ID, "status": "ok", "result": result, "usage": map[string]any{}})
			if _, err = server.Write(append(packet, '\n')); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { client.Close(); <-done })
	s, err := Open(context.Background(), client, Query{PageSources: 1}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return s, calls
}

func TestOptionalOperationIdentityAndRefusal(t *testing.T) {
	t.Run("captured-identity", func(t *testing.T) {
		s, calls := optionalPeer(t, "")
		defer s.Close()
		src := s.Sources()[0]
		asset := src.Assets[0]
		receipts := []*OperationReceipt{}
		d, e := s.Describe(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		receipts = append(receipts, d)
		i, e := s.Inspect(context.Background(), src.ID, "")
		if e != nil {
			t.Fatal(e)
		}
		receipts = append(receipts, i)
		r, e := s.Resolve(context.Background(), src.ID, asset.ID)
		if e != nil {
			t.Fatal(e)
		}
		receipts = append(receipts, r)
		g, e := s.Graph(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		receipts = append(receipts, g)
		for _, receipt := range receipts {
			before := receipt.Bytes()
			copy := receipt.Bytes()
			copy[0] = '!'
			if !jsonEqual(before, receipt.Bytes()) || receipt.Operation() == "" || receipt.Binding().HandshakeResultSHA256 == "" {
				t.Fatal("mutable or unbound receipt")
			}
		}
		if calls.Load() != 4 {
			t.Fatal("unexpected exchanges")
		}
		if _, e = s.Inspect(context.Background(), "example:source:foreign", ""); e == nil || calls.Load() != 4 {
			t.Fatal("foreign selector dispatched")
		}
		if s.RequireProduction() == nil {
			t.Fatal("observation became production admission")
		}
	})
	t.Run("optional-support", func(t *testing.T) {
		s, calls := optionalPeer(t, "unsupported")
		defer s.Close()
		_, e := s.Inspect(context.Background(), s.Sources()[0].ID, "")
		var fault *Error
		if !errors.As(e, &fault) || fault.Code != "SESSION_OPERATION_UNSUPPORTED" || calls.Load() != 0 || s.closed.Load() {
			t.Fatal("optional refusal consumed session", e)
		}
		if _, e = s.Describe(context.Background()); e != nil {
			t.Fatal(e)
		}
	})
	for _, mode := range []string{"describe-drift", "descriptor-drift", "foreign-edge", "duplicate-edge"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := optionalPeer(t, mode)
			src := s.Sources()[0]
			var err error
			switch mode {
			case "describe-drift":
				_, err = s.Describe(context.Background())
			case "descriptor-drift":
				_, err = s.Resolve(context.Background(), src.ID, src.Assets[0].ID)
			default:
				_, err = s.Graph(context.Background())
			}
			var fault *Error
			if !errors.As(err, &fault) || fault.Code != "SESSION_SCOPE" || !s.closed.Load() {
				t.Fatal("identity mismatch accepted", err)
			}
		})
	}
	t.Run("cancelled", func(t *testing.T) {
		s, calls := optionalPeer(t, "")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, e := s.Graph(ctx); !errors.Is(e, context.Canceled) || calls.Load() != 0 || !s.closed.Load() {
			t.Fatal("cancelled operation dispatched", e)
		}
	})
}
