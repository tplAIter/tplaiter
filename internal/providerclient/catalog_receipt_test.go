package providerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/tplAIter/tplaiter/internal/knowledge"
)

func TestCatalogReceiptFrozenExactAndCopies(t *testing.T) {
	host, pages := testFixture(t)
	s, err := OpenLocal(context.Background(), peer(t, pages, nil), host, Query{PageSources: 1}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.ReadCatalogReceipt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Bytes(), host.CatalogJSON) || r.Binding().CatalogSHA256 != digest(r.Bytes()) {
		t.Fatal("exact observed bytes lost")
	}
	if len(r.Sources()) != 2 || len(r.Items()) != 3 || len(r.Descriptors()) != 0 {
		t.Fatal("capture scope")
	}
	raw := r.Bytes()
	raw[0] = '!'
	sources := r.Sources()
	sources[0][0] = '!'
	items := r.Items()
	items[0][0] = '!'
	b := r.Binding()
	b.CatalogDigest[0] = '!'
	if !bytes.Equal(r.Bytes(), host.CatalogJSON) || r.Sources()[0][0] != '{' || r.Items()[0][0] != '{' || r.Binding().CatalogDigest[0] == '!' {
		t.Fatal("mutable receipt")
	}
	if err := s.RequireProduction(); err == nil {
		t.Fatal("receipt manufactured production authority")
	}
	_, err = s.ReadCatalogReceipt(context.Background())
	code(t, err, "SESSION_LIFETIME")
}

func TestCatalogReceiptFailureNoPartial(t *testing.T) {
	for _, mode := range []string{"eof", "digest", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			host, pages := testFixture(t)
			if mode == "eof" {
				pages = pages[:1]
			}
			if mode == "digest" {
				var p catalogParts
				_ = json.Unmarshal(pages[0].Catalog, &p)
				p.Items[0] = bytes.Replace(p.Items[0], []byte(`"id":`), []byte(`"id" :`), 1)
				pages[0].Catalog = wire(t, p)
				// Reorder complete source pages, retaining the same semantic catalog.
				pages[0].Catalog, pages[1].Catalog = pages[1].Catalog, pages[0].Catalog
			}
			s, err := OpenLocal(context.Background(), peer(t, pages, nil), host, Query{PageSources: 1}, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			r, err := s.ReadCatalogReceipt(ctx)
			if err == nil || r != nil {
				t.Fatal("partial receipt escaped", err)
			}
			if !s.closed.Load() {
				t.Fatal("failed observation left connection open")
			}
		})
	}
}

func TestCatalogReceiptLexicalAndBounds(t *testing.T) {
	_, pages := testFixture(t)
	c := &catalogCapture{}
	for _, p := range pages {
		if err := c.observe(wire(t, p)); err != nil {
			t.Fatal(err)
		}
	}
	// A JSON spelling difference must not be normalized into a pinned receipt.
	c.sources[0] = bytes.Replace(c.sources[0], []byte(`"id":`), []byte(`"id" :`), 1)
	h, _ := testFixture(t)
	r, err := c.finish(&Session{}, Binding{CatalogSHA256: h.CatalogSHA256})
	if err != nil || !bytes.Equal(r.Bytes(), h.CatalogJSON) {
		t.Fatal("wire whitespace compaction", err)
	}
	c.sources[0] = bytes.Replace(c.sources[0], []byte("example"), []byte(`\u0065xample`), 1)
	r, err = c.finish(&Session{}, Binding{CatalogSHA256: h.CatalogSHA256})
	if r != nil {
		t.Fatal("lexical normalization masked digest")
	}
	code(t, err, "SESSION_CATALOG_BINDING")
	c = &catalogCapture{bytes: knowledge.MaxBytes}
	code(t, c.observe(wire(t, pages[0])), "SESSION_BOUNDS")
	c = &catalogCapture{pages: 128}
	code(t, c.observe(wire(t, pages[0])), "SESSION_BOUNDS")
}

func TestCatalogReceiptDynamicContentSameConnection(t *testing.T) {
	sources, results := regressionLiveFixture(t)
	body := []byte("public synthetic body\n")
	full := catalogParts{}
	for i := 2; i < len(results); i++ {
		var p page
		_ = json.Unmarshal(results[i], &p)
		part, _ := parts(p.Catalog)
		if i == 2 {
			full = part
			full.Sources = nil
			full.Items = nil
			full.Edges = nil
		}
		for j := range part.Items {
			var item knowledge.Item
			_ = json.Unmarshal(part.Items[j], &item)
			item.ContentSHA256 = digest(body)
			part.Items[j] = wire(t, item)
		}
		full.Sources = append(full.Sources, part.Sources...)
		full.Items = append(full.Items, part.Items...)
		p.Catalog = wire(t, part)
		results[i] = wire(t, p)
	}
	for i := range sources {
		for j := range sources[i].Assets {
			sources[i].Assets[j].Bytes = len(body)
			sources[i].Assets[j].Anchor.BlobDigest.Hex = digest(body)[7:]
		}
	}
	results[1] = wire(t, sources)
	full.Edges = []json.RawMessage{}
	for i := 2; i < len(results); i++ {
		var p page
		_ = json.Unmarshal(results[i], &p)
		p.CatalogDigest = jsonString(digest(wire(t, full)))
		results[i] = wire(t, p)
	}
	asset := sources[0].Assets[0]
	results = append(results, wire(t, struct {
		Asset   AssetDescriptor `json:"asset"`
		Content string          `json:"content"`
		Trust   string          `json:"trust"`
	}{asset, string(body), "untrusted-content-not-policy"}))
	s, err := Open(context.Background(), regressionPeer(t, results), Query{PageSources: 1}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.ReadCatalogReceipt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Bytes(), wire(t, full)) || len(r.Descriptors()) != 2 {
		t.Fatal("complete dynamic capture")
	}
	copied := r.Descriptors()
	copied[0].Assets[0].ID = "changed"
	copied[0].Capabilities = append(copied[0].Capabilities, "changed")
	if r.Descriptors()[0].Assets[0].ID != asset.ID {
		t.Fatal("descriptor alias")
	}
	for _, foreign := range []*CatalogReceipt{nil, {}, {session: &Session{}, raw: r.Bytes()}} {
		cr, e := s.ReadAssetReceipt(context.Background(), foreign, sources[0].ID, asset.ID)
		if cr != nil {
			t.Fatal("foreign body receipt")
		}
		code(t, e, "SESSION_SCOPE")
	}
	var manufactured CatalogReceipt
	if json.Unmarshal([]byte(`{"raw":"anything","session":{},"descriptors":[]}`), &manufactured) != nil {
		t.Fatal("fixture")
	}
	_, err = s.ReadAssetReceipt(context.Background(), &manufactured, sources[0].ID, asset.ID)
	code(t, err, "SESSION_SCOPE")
	cr, err := s.ReadAssetReceipt(context.Background(), r, sources[0].ID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Catalog() != r || cr.Asset() != asset || !bytes.Equal(cr.Bytes(), body) {
		t.Fatal("body observation binding")
	}
	copyBody := cr.Bytes()
	copyBody[0] = '!'
	if !bytes.Equal(cr.Bytes(), body) {
		t.Fatal("body alias")
	}
}
