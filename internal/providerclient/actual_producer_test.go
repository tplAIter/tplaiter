//go:build providerclient_live

package providerclient

// The host supplies an approved actual producer outside public Git. This test
// never discovers commands, reads private implementation, or launches a process.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type pipeAddress struct{}

func (pipeAddress) Network() string { return "owned-pipe" }
func (pipeAddress) String() string  { return "owned-pipe" }

type pipeConn struct{ read, write *os.File }

func (p *pipeConn) Read(b []byte) (int, error)  { return p.read.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error) { return p.write.Write(b) }
func (p *pipeConn) Close() error {
	a := p.read.Close()
	b := p.write.Close()
	if a != nil {
		return a
	}
	return b
}
func (p *pipeConn) LocalAddr() net.Addr  { return pipeAddress{} }
func (p *pipeConn) RemoteAddr() net.Addr { return pipeAddress{} }
func (p *pipeConn) SetDeadline(t time.Time) error {
	if e := p.read.SetReadDeadline(t); e != nil {
		return e
	}
	return p.write.SetWriteDeadline(t)
}
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return p.read.SetReadDeadline(t) }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return p.write.SetWriteDeadline(t) }

type tracedConn struct {
	net.Conn
	input, output bytes.Buffer
}

func (c *tracedConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	_, _ = c.output.Write(b[:n])
	return n, e
}

func (c *tracedConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	_, _ = c.input.Write(b[:n])
	return n, e
}

func proofConn(t *testing.T, index int) *tracedConn {
	t.Helper()
	suffix := strconv.Itoa(index)
	var conn net.Conn
	if os.Getenv("PROVIDERCLIENT_PROOF_MODE") == "socket" {
		c, e := net.DialTimeout("unix", os.Getenv("PROVIDERCLIENT_PROOF_SOCKET_"+suffix), time.Second)
		if e != nil {
			t.Fatal("approved socket unavailable")
		}
		conn = c
	} else {
		r, e := strconv.Atoi(os.Getenv("PROVIDERCLIENT_PROOF_READ_" + suffix))
		if e != nil {
			t.Fatal("read descriptor missing")
		}
		w, e := strconv.Atoi(os.Getenv("PROVIDERCLIENT_PROOF_WRITE_" + suffix))
		if e != nil {
			t.Fatal("write descriptor missing")
		}
		if unix.SetNonblock(r, true) != nil || unix.SetNonblock(w, true) != nil {
			t.Fatal("pollable descriptors unavailable")
		}
		conn = &pipeConn{read: os.NewFile(uintptr(r), "owned-read"), write: os.NewFile(uintptr(w), "owned-write")}
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &tracedConn{Conn: conn}
}

func transcript(c *tracedConn) []map[string]json.RawMessage {
	reads := bufio.NewScanner(bytes.NewReader(c.output.Bytes()))
	writes := bufio.NewScanner(bytes.NewReader(c.input.Bytes()))
	reads.Buffer(make([]byte, 4096), 32768)
	writes.Buffer(make([]byte, 4096), 4096)
	result := []map[string]json.RawMessage{}
	for writes.Scan() && reads.Scan() {
		result = append(result, map[string]json.RawMessage{"request": copyRaw(writes.Bytes()), "response": copyRaw(reads.Bytes())})
	}
	return result
}

func TestActualProducer(t *testing.T) {
	ctx := context.Background()
	first := proofConn(t, 1)
	s, e := Open(ctx, first, Query{PageSources: 1}, Limits{})
	if e != nil {
		t.Fatal("actual handshake/catalog", e)
	}
	defer s.Close()
	got, returnedBinding, e := s.ReadCatalog(ctx)
	if e != nil || got.ID == "" || len(got.Sources) != 2 || returnedBinding.CatalogSHA256 == "" {
		t.Fatal("corrected counterpart must pass actual C01 admission", e)
	}
	binding := copyJSON(s.binding)
	var cursor string
	pageCount := 0
	var reconstructed catalogParts
	for _, entry := range transcript(first) {
		var req request
		_ = json.Unmarshal(entry["request"], &req)
		if req.Op == "knowledge" {
			pageCount++
			var r response
			_ = json.Unmarshal(entry["response"], &r)
			var p page
			_ = json.Unmarshal(r.Result, &p)
			part, e := parts(p.Catalog)
			if e != nil {
				t.Fatal(e)
			}
			if pageCount == 1 {
				reconstructed = part
			} else {
				reconstructed.Sources = append(reconstructed.Sources, part.Sources...)
				reconstructed.Items = append(reconstructed.Items, part.Items...)
				reconstructed.Edges = append(reconstructed.Edges, part.Edges...)
			}
			if p.NextCursor != "" {
				cursor = p.NextCursor
			}
		}
	}
	rawCatalog := wire(t, reconstructed)
	if pageCount != 2 || cursor == "" || len(reconstructed.Sources) != 2 || len(reconstructed.Items) != 4 || digest(rawCatalog) != binding.CatalogSHA256 {
		t.Fatal("actual two-page reconstruction/digest")
	}
	second := proofConn(t, 2)
	other, e := Open(ctx, second, Query{PageSources: 1}, Limits{})
	if e != nil {
		t.Fatal("second actual session", e)
	}
	defer other.Close()
	code(t, other.RequireProduction(), "SESSION_PRODUCTION_UNQUALIFIED")
	readCount := 0
	for _, source := range other.Sources() {
		for _, asset := range source.Assets {
			data, e := other.ReadAsset(ctx, source.ID, asset.ID)
			if e != nil || digest(data) != "sha256:"+asset.Anchor.BlobDigest.Hex {
				t.Fatal("actual asset read mismatch")
			}
			readCount++
		}
	}
	if readCount != 4 {
		t.Fatal("four actual asset reads required")
	}
	finish, e := other.deadline(ctx)
	if e != nil {
		t.Fatal(e)
	}
	full, e := other.exchange(ctx, request{Version: APIVersion, ID: "full", Op: "knowledge", Projection: "page:128", Budget: &Budget{}})
	finish()
	if e != nil {
		t.Fatal("actual full catalog", e)
	}
	var fullPage page
	var fullPin string
	if json.Unmarshal(full.Result, &fullPage) != nil || !fullPage.Complete || json.Unmarshal(fullPage.CatalogDigest, &fullPin) != nil || digest(fullPage.Catalog) != fullPin {
		t.Fatal("full exact digest")
	}
	finish, e = other.deadline(ctx)
	if e != nil {
		t.Fatal(e)
	}
	pageOne, e := other.exchange(ctx, request{Version: APIVersion, ID: "page-one", Op: "knowledge", Projection: "page:1", Budget: &Budget{}})
	finish()
	if e != nil {
		t.Fatal("actual second-instance page", e)
	}
	var currentPage page
	_ = json.Unmarshal(pageOne.Result, &currentPage)
	currentCursor := currentPage.NextCursor
	if currentCursor == "" {
		t.Fatal("current cursor absent")
	}
	src := other.Sources()[0]
	asset := src.Assets[0]
	negatives := []struct {
		q    request
		want string
	}{
		{request{Version: APIVersion, ID: "wrong-pin", Op: "read", SourceID: src.ID, AssetID: asset.ID, Pin: strings.Repeat("0", 40)}, "PIN_MISMATCH"},
		{request{Version: APIVersion, ID: "query-change", Op: "knowledge", Projection: "page:2:" + currentCursor}, "CURSOR_STALE"},
		{request{Version: APIVersion, ID: "scope-change", Op: "knowledge", SourceID: src.ID, Projection: "page:1:" + currentCursor}, "CURSOR_STALE"},
		{request{Version: APIVersion, ID: "budget-change", Op: "knowledge", Projection: "page:1:" + currentCursor, Budget: &Budget{ResponseBytes: 10000}}, "CURSOR_STALE"},
		{request{Version: "local-provider.session/v2", ID: "wrong-version", Op: "describe"}, "SCHEMA_VERSION_UNSUPPORTED"},
	}
	refusals := map[string]string{}
	for _, tc := range negatives {
		finish, e = other.deadline(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, e = other.exchange(ctx, tc.q)
		finish()
		var refusal *Error
		if !errors.As(e, &refusal) || refusal.Code != "SESSION_REFUSED" || refusal.PeerCode != tc.want {
			t.Fatal("actual refusal mismatch", tc.q.ID)
		}
		refusals[tc.q.ID] = refusal.PeerCode
	}
	third := proofConn(t, 3)
	raw := &Session{conn: third, reader: bufio.NewReaderSize(third, 4096), limits: Limits{FrameBytes: 32768, TotalBytes: 2 << 20, Pages: 128, Timeout: 2 * time.Second}, host: HostBinding{SuccessStatus: "ok"}}
	defer raw.Close()
	var refusal *Error
	for _, tc := range []struct {
		id           string
		schema, caps []string
		want         string
	}{{"bad-schema", []string{"unsupported/v9"}, []string{"local-curated-read"}, "SCHEMA_VERSION_UNSUPPORTED"}, {"bad-capability", []string{DescriptorVersion}, []string{"execute"}, "CAPABILITY_REQUIRED"}} {
		finish, e = raw.deadline(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, e = raw.exchange(ctx, request{Version: APIVersion, ID: tc.id, Op: "handshake", SchemaVersions: tc.schema, RequiredCapabilities: tc.caps})
		finish()
		if !errors.As(e, &refusal) || refusal.PeerCode != tc.want {
			t.Fatal("negotiation refusal mismatch", tc.id)
		}
		refusals[tc.id] = refusal.PeerCode
	}
	foreign, e := Open(ctx, third, Query{PageSources: 1}, Limits{})
	if e != nil {
		t.Fatal("actual corrected negotiation", e)
	}
	defer foreign.Close()
	finish, e = foreign.deadline(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = foreign.exchange(ctx, request{Version: APIVersion, ID: "foreign-cursor", Op: "knowledge", Projection: "page:1:" + currentCursor})
	finish()
	if !errors.As(e, &refusal) || refusal.PeerCode != "CURSOR_STALE" {
		t.Fatal("foreign cursor was admitted")
	}
	refusals["foreign-cursor"] = refusal.PeerCode
	receipt := map[string]any{"transport": os.Getenv("PROVIDERCLIENT_PROOF_MODE"), "wireVersion": APIVersion, "qualification": LocalPrototype, "organizationCertified": false, "c01Admission": true, "sources": 2, "assetsRead": readCount, "knowledgePages": pageCount, "binding": binding, "refusals": refusals, "sessions": [][]map[string]json.RawMessage{transcript(first), transcript(second), transcript(third)}}
	output, e := json.MarshalIndent(receipt, "", "  ")
	if e != nil {
		t.Fatal("receipt encoding")
	}
	if e = os.WriteFile(os.Getenv("PROVIDERCLIENT_PROOF_OUTPUT"), append(output, '\n'), 0o600); e != nil {
		t.Fatal("receipt persistence")
	}
}
