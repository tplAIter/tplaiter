package providerclient

// These synthetic peers test client behavior only. They are NOT existing
// producer compatibility evidence; that gate awaits the approved live handoff.
import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/knowledge"
)

func wire(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func testFixture(t *testing.T) (HostBinding, []page) {
	t.Helper()
	raw, e := os.ReadFile("../../testdata/knowledge/catalog.json")
	if e != nil {
		t.Fatal(e)
	}
	p, e := parts(raw)
	if e != nil {
		t.Fatal(e)
	}
	// A second complete source with distinct public identities and aliases.
	var second map[string]any
	_ = json.Unmarshal(p.Sources[0], &second)
	second["id"] = "example:source:second"
	second["pin"].(map[string]any)["alias"] = "second"
	p.Sources = append(p.Sources, wire(t, second))
	raw = wire(t, p)
	if _, e = knowledge.Decode(raw); e != nil {
		t.Fatal(e)
	}
	hello := json.RawMessage(`{"provider":{"qualification":"local-user-approved-uncertified"},"schemaVersion":"local-provider.descriptor/v1","limits":{},"sideEffectClasses":[],"unsupportedCapabilities":[]}`)
	h := HostBinding{HandshakeResultSHA256: digest(hello), KnowledgeSchemaSHA256: KnowledgeSchemaSHA256, CatalogSHA256: digest(raw), CatalogJSON: raw, CatalogDigest: json.RawMessage(`"test-catalog-pin"`), ScopeDigest: json.RawMessage(`"test-scope-pin"`), QueryDigest: json.RawMessage(`"test-query-pin"`), SuccessStatus: "ok"}
	first := p
	first.Sources = p.Sources[:1]
	last := p
	last.Sources = p.Sources[1:]
	last.Items = []json.RawMessage{}
	last.Edges = []json.RawMessage{}
	pages := []page{{CatalogDigest: h.CatalogDigest, ScopeDigest: h.ScopeDigest, QueryDigest: h.QueryDigest, Offset: 0, TotalSources: 2, ExternalReferences: []string{}, Catalog: wire(t, first), NextCursor: "opaque.synthetic.cursor"}, {CatalogDigest: h.CatalogDigest, ScopeDigest: h.ScopeDigest, QueryDigest: h.QueryDigest, Offset: 1, TotalSources: 2, Complete: true, ExternalReferences: []string{}, Catalog: wire(t, last)}}
	return h, pages
}

func testHello() json.RawMessage {
	return json.RawMessage(`{"provider":{"qualification":"local-user-approved-uncertified"},"schemaVersion":"local-provider.descriptor/v1","limits":{},"sideEffectClasses":[],"unsupportedCapabilities":[]}`)
}

func peer(t *testing.T, pages []page, mutate func(int, *response)) net.Conn {
	t.Helper()
	var copied []page
	_ = json.Unmarshal(wire(t, pages), &copied)
	pages = copied
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer b.Close()
		_ = b.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(b)
		for n := 0; n <= len(pages); n++ {
			raw, e := reader.ReadBytes('\n')
			if e != nil {
				return
			}
			var q request
			if json.Unmarshal(raw, &q) != nil {
				return
			}
			if q.Version != APIVersion {
				t.Error("wrong request version")
			}
			result := testHello()
			if n == 0 {
				if q.Op != "handshake" || !reflect.DeepEqual(q.SchemaVersions, []string{DescriptorVersion}) || !reflect.DeepEqual(q.RequiredOperations, []string{"describe", "knowledge"}) || !reflect.DeepEqual(q.RequiredCapabilities, []string{"local-curated-read"}) {
					t.Error("handshake request")
				}
			} else {
				if q.Op != "knowledge" || q.AssetID != "" || q.Path != "" {
					t.Error("knowledge request")
				}
				want := "page:1"
				if n > 1 {
					want += ":" + pages[n-2].NextCursor
				}
				if q.Projection != want {
					t.Error("cursor was not forwarded")
				}
				result = wire(t, pages[n-1])
			}
			r := response{Version: APIVersion, ID: q.ID, Status: "ok", Result: result, Usage: json.RawMessage(`{}`)}
			if mutate != nil {
				mutate(n, &r)
			}
			packet := append(wire(t, r), '\n')
			for len(packet) > 0 {
				size := 7
				if size > len(packet) {
					size = len(packet)
				}
				n, e := b.Write(packet[:size])
				if e != nil {
					return
				}
				packet = packet[n:]
			}
		}
	}()
	t.Cleanup(func() {
		_ = a.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("peer leaked")
		}
	})
	return a
}

func code(t *testing.T, err error, want string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != want {
		t.Fatalf("got %v, want %s", err, want)
	}
}

func TestExistingDialectAndReconstruction(t *testing.T) {
	h, p := testFixture(t)
	s, e := OpenLocal(context.Background(), peer(t, p, nil), h, Query{PageSources: 1}, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	got, b, e := s.ReadCatalog(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	want, e := knowledge.Decode(h.CatalogJSON)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(got, want) || b.CatalogSHA256 != h.CatalogSHA256 {
		t.Fatal("catalog/pins changed")
	}
	if s.Qualification() != LocalPrototype {
		t.Fatal("qualification")
	}
	code(t, s.RequireProduction(), "SESSION_PRODUCTION_UNQUALIFIED")
	_, _, e = s.ReadCatalog(context.Background())
	code(t, e, "SESSION_LIFETIME")
}

func TestPageRefusals(t *testing.T) {
	cases := []struct {
		name, code string
		mutate     func(int, *response)
	}{
		{"wrong-version", "SESSION_VERSION", func(n int, r *response) {
			if n == 1 {
				r.Version = "future/v2"
			}
		}},
		{"wrong-id", "SESSION_SCOPE", func(n int, r *response) {
			if n == 1 {
				r.ID = "foreign"
			}
		}},
		{"peer-refusal", "SESSION_REFUSED", func(n int, r *response) {
			if n == 1 {
				r.Result = nil
				r.Status = "error"
				r.Error = json.RawMessage(`{"code":"CURSOR_STALE","message":"safe"}`)
			}
		}},
		{"query", "SESSION_SCOPE", func(n int, r *response) {
			if n == 1 {
				var p page
				_ = json.Unmarshal(r.Result, &p)
				p.QueryDigest = json.RawMessage(`"other"`)
				r.Result = wire(t, p)
			}
		}},
		{"scope", "SESSION_SCOPE", func(n int, r *response) {
			if n == 1 {
				var p page
				_ = json.Unmarshal(r.Result, &p)
				p.ScopeDigest = json.RawMessage(`"other"`)
				r.Result = wire(t, p)
			}
		}},
		{"catalog-digest", "SESSION_SCOPE", func(n int, r *response) {
			if n == 1 {
				var p page
				_ = json.Unmarshal(r.Result, &p)
				p.CatalogDigest = json.RawMessage(`"other"`)
				r.Result = wire(t, p)
			}
		}},
		{"offset", "SESSION_CURSOR", func(n int, r *response) {
			if n == 1 {
				var p page
				_ = json.Unmarshal(r.Result, &p)
				p.Offset = 1
				r.Result = wire(t, p)
			}
		}},
		{"premature-complete", "SESSION_PARTIAL", func(n int, r *response) {
			if n == 1 {
				var p page
				_ = json.Unmarshal(r.Result, &p)
				p.Complete = true
				p.NextCursor = ""
				r.Result = wire(t, p)
			}
		}},
		{"cursor-repeat", "SESSION_CURSOR", func(n int, r *response) {
			if n == 2 {
				var p page
				_ = json.Unmarshal(r.Result, &p)
				p.Complete = false
				p.NextCursor = "opaque.synthetic.cursor"
				r.Result = wire(t, p)
			}
		}},
		{"content", "SESSION_CATALOG_PIN", func(n int, r *response) {
			if n == 1 {
				r.Result = json.RawMessage(strings.Replace(string(r.Result), "100644", "120000", 1))
			}
		}},
		{"unknown-page-field", "SESSION_WIRE", func(n int, r *response) {
			if n == 1 {
				r.Result = append(r.Result[:len(r.Result)-1], []byte(`,"grant":true}`)...)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, p := testFixture(t)
			s, e := OpenLocal(context.Background(), peer(t, p, tc.mutate), h, Query{PageSources: 1}, Limits{})
			if e != nil {
				t.Fatal(e)
			}
			got, b, e := s.ReadCatalog(context.Background())
			code(t, e, tc.code)
			if got.ID != "" || b.CatalogSHA256 != "" {
				t.Fatal("partial result")
			}
		})
	}
}

func TestFrozenHostBuffersAndAdmission(t *testing.T) {
	h, p := testFixture(t)
	s, e := OpenLocal(context.Background(), peer(t, p, nil), h, Query{PageSources: 1}, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	for i := range h.CatalogJSON {
		h.CatalogJSON[i] = 'x'
	}
	for i := range h.QueryDigest {
		h.QueryDigest[i] = 'x'
	}
	if _, _, e = s.ReadCatalog(context.Background()); e != nil {
		t.Fatal("host buffers were not frozen", e)
	}
	var zero Session
	_, _, e = zero.ReadCatalog(context.Background())
	code(t, e, "SESSION_LIFETIME")
	code(t, zero.RequireProduction(), "SESSION_PRODUCTION_UNQUALIFIED")
	h, p = testFixture(t)
	h.HandshakeResultSHA256 = digest(nil)
	_, e = OpenLocal(context.Background(), peer(t, p, nil), h, Query{PageSources: 1}, Limits{})
	code(t, e, "SESSION_DESCRIPTOR_PIN")
}

func TestBoundedNDJSONAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{{"partial", []byte(`{"version":`), "SESSION_IO"}, {"oversize", []byte(strings.Repeat("x", 32769)), "SESSION_BOUNDS"}, {"length-prefix", []byte{0, 0, 0, 1, '{', '\n'}, "SESSION_WIRE"}, {"duplicate", []byte("{\"version\":\"local-provider.session/v1\",\"version\":\"x\"}\n"), "SESSION_WIRE"}, {"null", []byte("{\"version\":null}\n"), "SESSION_WIRE"}} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := testFixture(t)
			a, b := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer b.Close()
				_, _ = bufio.NewReader(b).ReadBytes('\n')
				_, _ = b.Write(tc.raw)
			}()
			_, e := OpenLocal(context.Background(), a, h, Query{PageSources: 1}, Limits{})
			code(t, e, tc.want)
			<-done
		})
	}
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "blocked-write-deadline", true: "blocked-write-cancel"}[cancel], func(t *testing.T) {
			h, _ := testFixture(t)
			a, b := net.Pipe()
			defer b.Close()
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			if cancel {
				timer := time.AfterFunc(20*time.Millisecond, stop)
				defer timer.Stop()
			}
			_, e := OpenLocal(ctx, a, h, Query{PageSources: 1}, Limits{Timeout: 100 * time.Millisecond})
			if cancel {
				if !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
			} else {
				code(t, e, "SESSION_DEADLINE")
			}
		})
	}
}

func TestSlowPeerAndPartialPage(t *testing.T) {
	for _, mode := range []string{"silent", "partial", "close"} {
		t.Run(mode, func(t *testing.T) {
			h, _ := testFixture(t)
			a, b := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer b.Close()
				reader := bufio.NewReader(b)
				raw, e := reader.ReadBytes('\n')
				if e != nil {
					return
				}
				var q request
				_ = json.Unmarshal(raw, &q)
				_, _ = b.Write(append(wire(t, response{Version: APIVersion, ID: q.ID, Status: "ok", Result: testHello(), Usage: json.RawMessage(`{}`)}), '\n'))
				_, _ = reader.ReadBytes('\n')
				switch mode {
				case "silent":
					var x [1]byte
					_, _ = b.Read(x[:])
				case "partial":
					_, _ = b.Write([]byte(`{"version":`))
				case "close":
					return
				}
			}()
			s, e := OpenLocal(context.Background(), a, h, Query{PageSources: 1}, Limits{Timeout: 100 * time.Millisecond})
			if e != nil {
				t.Fatal(e)
			}
			got, binding, e := s.ReadCatalog(context.Background())
			if mode == "silent" {
				code(t, e, "SESSION_DEADLINE")
			} else {
				code(t, e, "SESSION_IO")
			}
			if got.ID != "" || binding.CatalogSHA256 != "" {
				t.Fatal("partial")
			}
			<-done
		})
	}
}

func TestLimitsAndStrictTokens(t *testing.T) {
	h, p := testFixture(t)
	s, e := OpenLocal(context.Background(), peer(t, p, nil), h, Query{PageSources: 1}, Limits{Pages: 1})
	if e != nil {
		t.Fatal(e)
	}
	_, _, e = s.ReadCatalog(context.Background())
	code(t, e, "SESSION_BOUNDS")
	for _, q := range []Query{{PageSources: 0}, {PageSources: 129}, {PageSources: 1, DeadlineMS: 2001}, {PageSources: 1, Budget: Budget{StrictTokens: true}}} {
		a, b := net.Pipe()
		_ = b.Close()
		_, e = OpenLocal(context.Background(), a, h, q, Limits{})
		code(t, e, "SESSION_HOST_BINDING")
	}
	for _, l := range []Limits{{FrameBytes: 32769}, {TotalBytes: 3 << 20}, {Pages: 129}, {Timeout: 3 * time.Second}} {
		a, b := net.Pipe()
		_ = b.Close()
		_, e = OpenLocal(context.Background(), a, h, Query{PageSources: 1}, l)
		code(t, e, "SESSION_LIMITS")
	}
}

func TestNullableCatalogIsNotEnvelopeNull(t *testing.T) {
	h, p := testFixture(t)
	if !strings.Contains(string(h.CatalogJSON), `"default":null`) {
		t.Fatal("missing nullable C01 fixture")
	}
	s, e := OpenLocal(context.Background(), peer(t, p, nil), h, Query{PageSources: 1}, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.ReadCatalog(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestSourceCompletenessAndHostBudget(t *testing.T) {
	h, p := testFixture(t)
	var first catalogParts
	_ = json.Unmarshal(p[0].Catalog, &first)
	first.Items = []json.RawMessage{}
	p[0].Catalog = wire(t, first)
	s, e := OpenLocal(context.Background(), peer(t, p, nil), h, Query{PageSources: 1}, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	_, _, e = s.ReadCatalog(context.Background())
	code(t, e, "SESSION_PARTIAL")
	h, p = testFixture(t)
	s, e = OpenLocal(context.Background(), peer(t, p, nil), h, Query{PageSources: 1, Budget: Budget{ResponseBytes: 512}}, Limits{})
	if e == nil {
		_, _, e = s.ReadCatalog(context.Background())
	}
	code(t, e, "SESSION_BOUNDS")
	h, p = testFixture(t)
	p[0].ExternalReferences = []string{"foreign:source:other"}
	s, e = OpenLocal(context.Background(), peer(t, p, nil), h, Query{PageSources: 1}, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	_, _, e = s.ReadCatalog(context.Background())
	code(t, e, "SESSION_PARTIAL")
}

func TestCatalogCancelAndTotalWireBounds(t *testing.T) {
	h, p := testFixture(t)
	limited, e := OpenLocal(context.Background(), peer(t, p, nil), h, Query{PageSources: 1}, Limits{FrameBytes: 512, TotalBytes: 512})
	if e == nil {
		_, _, e = limited.ReadCatalog(context.Background())
	}
	code(t, e, "SESSION_BOUNDS")
	h, _ = testFixture(t)
	a, b := net.Pipe()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer b.Close()
		reader := bufio.NewReader(b)
		raw, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var q request
		_ = json.Unmarshal(raw, &q)
		_, _ = b.Write(append(wire(t, response{Version: APIVersion, ID: q.ID, Status: "ok", Result: testHello(), Usage: json.RawMessage(`{}`)}), '\n'))
		_, _ = reader.ReadBytes('\n')
		stop()
		var x [1]byte
		_, _ = b.Read(x[:])
	}()
	s, e := OpenLocal(ctx, a, h, Query{PageSources: 1}, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	got, binding, e := s.ReadCatalog(ctx)
	if !errors.Is(e, context.Canceled) || got.ID != "" || binding.CatalogSHA256 != "" {
		t.Fatal("catalog cancellation", e)
	}
	<-done
}
