package providerclient

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/knowledge"
)

// This synthetic peer preserves the actual wire envelope. It is a regression
// test, not a producer interoperability certificate.
func regressionLiveFixture(t *testing.T) ([]SourceDescriptor, []json.RawMessage) {
	t.Helper()
	host, _ := testFixture(t)
	cat, err := parts(host.CatalogJSON)
	if err != nil {
		t.Fatal(err)
	}
	var template knowledge.Item
	if json.Unmarshal(cat.Items[2], &template) != nil || template.Kind != "resource" {
		t.Fatal("resource fixture")
	}
	cat.Items = []json.RawMessage{}
	cat.Edges = []json.RawMessage{}
	sources := []SourceDescriptor{}
	for i, rawSource := range cat.Sources {
		var source knowledge.Source
		if json.Unmarshal(rawSource, &source) != nil {
			t.Fatal("source fixture")
		}
		descriptor := SourceDescriptor{ID: source.ID, Revision: source.Pin.Commit, GitTreeOID: strings.Repeat("a", 40), State: "available-static", Assets: []AssetDescriptor{}, Capabilities: []string{}, Unresolved: []string{}}
		for j, path := range []string{"README.md", "guide.md"} {
			item := template
			item.ID = "example:resource:item" + strconv.Itoa(i) + "-" + strconv.Itoa(j)
			item.SourceID = source.ID
			item.SourcePath = path
			cat.Items = append(cat.Items, wire(t, item))
			asset := AssetDescriptor{ID: "example:asset:" + strconv.Itoa(i) + "-" + strconv.Itoa(j), Kind: "static-document", Bytes: 0, DescriptorDigest: Digest{Algorithm: "sha256", Domain: "asset-descriptor", Hex: strings.Repeat("b", 64)}}
			asset.Anchor.SourceID = source.ID
			asset.Anchor.Revision = source.Pin.Commit
			asset.Anchor.Path = path
			asset.Anchor.BlobDigest = Digest{Algorithm: "sha256", Domain: "content-bytes", Hex: strings.TrimPrefix(item.ContentSHA256, "sha256:")}
			descriptor.Assets = append(descriptor.Assets, asset)
		}
		sources = append(sources, descriptor)
	}
	full := wire(t, cat)
	if _, err := knowledge.Decode(full); err != nil {
		t.Fatal("valid C01 regression catalog", err)
	}
	var hello Description
	hello.Provider.ID = "synthetic-provider"
	hello.Provider.Operations = []string{"describe", "catalog", "read", "knowledge"}
	hello.Provider.Capabilities = []string{"local-curated-read"}
	hello.Provider.SnapshotDigest = "sha256:synthetic-scope:" + strings.Repeat("c", 64)
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
	results := []json.RawMessage{wire(t, hello), wire(t, sources)}
	for i, source := range sources {
		part := cat
		part.Sources = cat.Sources[i : i+1]
		part.Items = []json.RawMessage{}
		for _, raw := range cat.Items {
			if objectString(raw, "sourceId") == source.ID {
				part.Items = append(part.Items, raw)
			}
		}
		p := page{Catalog: wire(t, part), CatalogDigest: jsonString(digest(full)), ScopeDigest: jsonString(hello.Provider.SnapshotDigest), QueryDigest: jsonString("sha256:" + strings.Repeat("d", 64)), Offset: i, TotalSources: 2, Complete: i == 1, ExternalReferences: []string{}}
		if i == 0 {
			p.NextCursor = "synthetic-cursor"
		}
		results = append(results, wire(t, p))
	}
	return sources, results
}

func regressionPeer(t *testing.T, results []json.RawMessage) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(server)
		for _, result := range results {
			raw, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var req request
			if json.Unmarshal(raw, &req) != nil {
				return
			}
			reply := response{Version: APIVersion, ID: req.ID, Status: "ok", Result: result, Usage: json.RawMessage(`{}`)}
			if _, err = server.Write(append(wire(t, reply), '\n')); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("regression peer did not close")
		}
	})
	return client
}

func TestLiveRejectsDistinctAssetIDsSharingSourcePath(t *testing.T) {
	sources, results := regressionLiveFixture(t)
	extra := sources[0].Assets[0]
	extra.ID = "example:asset:shadow"
	sources[0].Assets = append(sources[0].Assets, extra)
	results[1] = wire(t, sources)
	s, err := Open(context.Background(), regressionPeer(t, results), Query{PageSources: 1}, Limits{})
	if err == nil {
		defer s.Close()
		captured := 0
		for _, src := range s.Sources() {
			captured += len(src.Assets)
		}
		cat, binding, readErr := s.ReadCatalog(context.Background())
		t.Fatalf("ambiguous descriptors admitted: captured=%d items=%d binding=%t error=%v", captured, len(cat.Items), binding.CatalogSHA256 != "", readErr)
	}
	code(t, err, "SESSION_ASSET_AMBIGUITY")
	if s != nil {
		t.Fatal("ambiguous session returned")
	}
}

func TestLivePreservesSamePathsAcrossDistinctSources(t *testing.T) {
	_, results := regressionLiveFixture(t)
	s, err := Open(context.Background(), regressionPeer(t, results), Query{PageSources: 1}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	captured := 0
	for _, src := range s.Sources() {
		captured += len(src.Assets)
	}
	cat, binding, err := s.ReadCatalog(context.Background())
	if err != nil || captured != 4 || len(cat.Items) != captured || binding.CatalogSHA256 == "" {
		t.Fatal("cross-source paths lost", err)
	}
}

func TestOpenLocalRejectsReorderedCompletePages(t *testing.T) {
	host, pages := testFixture(t)
	host.CatalogDigest = jsonString(host.CatalogSHA256)
	for i := range pages {
		pages[i].CatalogDigest = host.CatalogDigest
	}
	pages[0].Catalog, pages[1].Catalog = pages[1].Catalog, pages[0].Catalog
	s, err := OpenLocal(context.Background(), peer(t, pages, nil), host, Query{PageSources: 1}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cat, binding, err := s.ReadCatalog(context.Background())
	code(t, err, "SESSION_CATALOG_BINDING")
	if cat.ID != "" || binding.CatalogSHA256 != "" || !s.closed.Load() {
		t.Fatal("partial catalog/binding or live connection returned")
	}
}

func TestOpenLocalRejectsEquivalentObjectWithDifferentWireBytes(t *testing.T) {
	host, pages := testFixture(t)
	part, err := parts(pages[0].Catalog)
	if err != nil {
		t.Fatal(err)
	}
	original := part.Sources[0]
	var equivalent map[string]json.RawMessage
	if json.Unmarshal(original, &equivalent) != nil {
		t.Fatal("source")
	}
	part.Sources[0] = wire(t, equivalent)
	if string(original) == string(part.Sources[0]) || !jsonEqual(original, part.Sources[0]) {
		t.Fatal("counter must differ only in object byte order")
	}
	pages[0].Catalog = wire(t, part)
	s, err := OpenLocal(context.Background(), peer(t, pages, nil), host, Query{PageSources: 1}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cat, binding, err := s.ReadCatalog(context.Background())
	code(t, err, "SESSION_CATALOG_BINDING")
	if cat.ID != "" || binding.CatalogSHA256 != "" {
		t.Fatal("binding returned for changed compact bytes")
	}
}
