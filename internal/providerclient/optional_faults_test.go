package providerclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These peers are neutral fault fixtures, never provider or source authority.
func optionalFaultSession(t *testing.T, mode string) (*Session, <-chan struct{}, *atomic.Int32) {
	t.Helper()
	client, peer := net.Pipe()
	seen, done := make(chan struct{}), make(chan struct{})
	calls := new(atomic.Int32)
	var hello Description
	hello.Provider.ID = "neutral-fault-peer"
	hello.Provider.Operations = []string{"describe", "catalog", "read", "knowledge", "graph"}
	if mode == "unavailable" {
		hello.Provider.Operations = hello.Provider.Operations[:4]
	}
	hello.Provider.Capabilities = []string{"local-curated-read"}
	hello.Provider.SnapshotDigest = "sha256:neutral-fixture:" + strings.Repeat("1", 64)
	hello.Provider.Evidence = "neutral-fixture-only"
	hello.Provider.Qualification = LocalPrototype
	hello.SchemaVersion = DescriptorVersion
	hello.Limits.DeadlineMS, hello.Limits.FrameBytes, hello.Limits.Frames = 2000, 4096, 256
	hello.Limits.MetadataBytes, hello.Limits.ResponseBytes, hello.Limits.SourceBytes = 16384, 32768, 8192
	hello.SideEffectClasses, hello.UnsupportedCapabilities = []string{"read-only-local"}, []string{}
	go func() {
		defer close(done)
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(2 * time.Second))
		rd := bufio.NewReader(peer)
		for {
			raw, err := rd.ReadBytes('\n')
			if err != nil {
				return
			}
			var q request
			if err := json.Unmarshal(raw, &q); err != nil {
				t.Error(err)
				return
			}
			response := map[string]any{"version": APIVersion, "id": q.ID, "status": "ok", "usage": map[string]any{}}
			switch q.Op {
			case "handshake":
				for _, op := range q.RequiredOperations {
					if op == "graph" || op == "inspect" || op == "resolve" {
						t.Error("Open newly required optional operation")
					}
				}
				response["result"] = hello
			case "catalog":
				response["result"] = []SourceDescriptor{}
			case "graph":
				calls.Add(1)
				close(seen)
				switch mode {
				case "cancel", "deadline", "blocked-write":
					// Cancellation/timeout must interrupt the consumer; no result is emitted.
					_, _ = io.Copy(io.Discard, rd)
					return
				case "partial":
					_, _ = peer.Write([]byte(`{"version":"local-provider.session/v1","id":`))
					_, _ = io.Copy(io.Discard, rd)
					return
				case "version":
					response["version"] = "local-provider.session/v2"
					response["result"] = map[string]any{"edges": []any{}, "unresolved": []string{}}
				case "refusal":
					response["status"] = "error"
					response["error"] = map[string]any{"code": "OPERATION_UNSUPPORTED", "message": "operation unavailable"}
				default:
					t.Error("unavailable operation reached wire")
					return
				}
			default:
				t.Error("unexpected neutral fixture operation", q.Op)
				return
			}
			out, err := json.Marshal(response)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := peer.Write(append(out, '\n')); err != nil {
				return
			}
			if q.Op == "catalog" && mode == "blocked-write" {
				// Open has completed. Deliberately stop reading the next request.
				close(seen)
				time.Sleep(300 * time.Millisecond)
				return
			}
		}
	}()
	t.Cleanup(func() {
		client.Close()
		peer.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("neutral fault peer leaked")
		}
	})
	s, err := Open(context.Background(), client, Query{PageSources: 1}, Limits{Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return s, seen, calls
}

func TestOptionalSessionFaultControls(t *testing.T) {
	t.Run("active-cancellation", func(t *testing.T) {
		s, seen, calls := optionalFaultSession(t, "cancel")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			select {
			case <-seen:
				cancel()
			case <-ctx.Done():
			}
		}()
		receipt, err := s.Graph(ctx)
		<-finished
		if receipt != nil || !errors.Is(err, context.Canceled) || !s.closed.Load() || calls.Load() != 1 {
			t.Fatal("active cancellation leaked receipt/session", err, calls.Load())
		}
	})
	for _, mode := range []string{"deadline", "partial", "blocked-write", "version", "refusal"} {
		t.Run(mode, func(t *testing.T) {
			s, _, calls := optionalFaultSession(t, mode)
			begin := time.Now()
			receipt, err := s.Graph(context.Background())
			want := "SESSION_DEADLINE"
			if mode == "version" {
				want = "SESSION_VERSION"
			}
			if mode == "refusal" {
				want = "SESSION_REFUSED"
			}
			var fault *Error
			if receipt != nil || !errors.As(err, &fault) || fault.Code != want || !s.closed.Load() {
				t.Fatal("fault leaked receipt or live session", err)
			}
			if mode == "refusal" && fault.PeerCode != "OPERATION_UNSUPPORTED" {
				t.Fatal("peer refusal lost", fault.PeerCode)
			}
			if want == "SESSION_DEADLINE" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline cause lost", err)
			}
			if time.Since(begin) > time.Second {
				t.Fatal("fault unbounded")
			}
			expected := int32(1)
			if mode == "blocked-write" {
				expected = 0
			}
			if calls.Load() != expected {
				t.Fatal("unexpected dispatch count", calls.Load())
			}
		})
	}
	t.Run("unavailable-before-dispatch", func(t *testing.T) {
		s, _, calls := optionalFaultSession(t, "unavailable")
		defer s.Close()
		receipt, err := s.Graph(context.Background())
		var fault *Error
		if receipt != nil || !errors.As(err, &fault) || fault.Code != "SESSION_OPERATION_UNSUPPORTED" || calls.Load() != 0 || s.closed.Load() {
			t.Fatal("unavailable optional op dispatched or closed compatible session", err)
		}
	})
}
