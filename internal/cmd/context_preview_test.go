package cmd

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/providerclient"
)

type previewSynthetic struct {
	fault   atomic.Int32
	socket  string
	catalog []byte
	sources []providerclient.SourceDescriptor
	bodies  map[string]string
	hello   json.RawMessage
}

func previewJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func previewDigest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Independent public synthetic counterpart, not private producer source.
func startPreviewSynthetic(t *testing.T, sourceCount int) *previewSynthetic {
	t.Helper()
	parent, e := os.MkdirTemp("/private/tmp", "lp-syn-")
	if e != nil {
		t.Fatal(e)
	}
	f := &previewSynthetic{socket: filepath.Join(parent, "s.sock"), bodies: map[string]string{}}
	raw, e := os.ReadFile("../../testdata/knowledge/catalog.json")
	if e != nil {
		t.Fatal(e)
	}
	var catalog struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		ID         string            `json:"id"`
		Version    string            `json:"version"`
		Sources    []json.RawMessage `json:"sources"`
		Items      []json.RawMessage `json:"items"`
		Edges      []json.RawMessage `json:"edges"`
	}
	if e = json.Unmarshal(raw, &catalog); e != nil {
		t.Fatal(e)
	}
	originalSource := catalog.Sources[0]
	resourceTemplate := catalog.Items[2]
	catalog.Sources = []json.RawMessage{}
	catalog.Items = []json.RawMessage{}
	catalog.Edges = []json.RawMessage{}
	for sourceIndex := range sourceCount {
		alias := fmt.Sprintf("preview-%02d", sourceIndex)
		var source map[string]any
		_ = json.Unmarshal(originalSource, &source)
		source["id"] = "example:source:" + alias
		source["pin"].(map[string]any)["alias"] = alias
		catalog.Sources = append(catalog.Sources, previewJSON(t, source))
		for _, name := range []string{"readme", "guide"} {
			var item map[string]any
			_ = json.Unmarshal(resourceTemplate, &item)
			item["id"] = "example:resource:" + alias + "-" + name
			item["sourceId"] = source["id"]
			item["sourcePath"] = name + ".md"
			item["requires"] = []string{}
			item["produces"] = []string{}
			item["inputs"].(map[string]any)["contextFloor"] = []string{}
			catalog.Items = append(catalog.Items, previewJSON(t, item))
		}
	}
	for _, sourceRaw := range catalog.Sources {
		var source knowledge.Source
		if e = json.Unmarshal(sourceRaw, &source); e != nil {
			t.Fatal(e)
		}
		descriptor := providerclient.SourceDescriptor{ID: source.ID, Revision: source.Pin.Commit, GitTreeOID: strings.Repeat("a", 40), State: "available-static", Capabilities: []string{}, Assets: []providerclient.AssetDescriptor{}, Unresolved: []string{}}
		for i, itemRaw := range catalog.Items {
			var item map[string]json.RawMessage
			if e = json.Unmarshal(itemRaw, &item); e != nil {
				t.Fatal(e)
			}
			var id, path, sid string
			_ = json.Unmarshal(item["id"], &id)
			_ = json.Unmarshal(item["sourcePath"], &path)
			_ = json.Unmarshal(item["sourceId"], &sid)
			if sid != source.ID {
				continue
			}
			body := "Public synthetic preview: " + id + "\n"
			sum := previewDigest([]byte(body))
			item["contentSHA256"] = previewJSON(t, sum)
			catalog.Items[i] = previewJSON(t, item)
			asset := providerclient.AssetDescriptor{ID: "synthetic:asset:preview-" + strings.ReplaceAll(id, ":", "-"), Kind: "static-document", Bytes: len(body), DescriptorDigest: providerclient.Digest{Algorithm: "sha256", Domain: "asset-descriptor", Hex: strings.Repeat("b", 64)}}
			asset.Anchor.SourceID = source.ID
			asset.Anchor.Path = path
			asset.Anchor.Revision = source.Pin.Commit
			asset.Anchor.BlobDigest = providerclient.Digest{Algorithm: "sha256", Domain: "content-bytes", Hex: sum[7:]}
			descriptor.Assets = append(descriptor.Assets, asset)
			f.bodies[asset.ID] = body
		}
		f.sources = append(f.sources, descriptor)
	}
	f.catalog = previewJSON(t, catalog)
	if _, e = knowledge.Decode(f.catalog); e != nil {
		t.Fatal(e)
	}
	transcript, e := os.ReadFile("../providerclient/testdata/synthetic/receipt.ndjson")
	if e != nil {
		t.Fatal(e)
	}
	var first struct {
		Response struct {
			Result json.RawMessage `json:"result"`
		} `json:"response"`
	}
	if e = json.Unmarshal(bytes.Split(transcript, []byte("\n"))[0], &first); e != nil {
		t.Fatal(e)
	}
	f.hello = first.Response.Result
	// Use the same scope digest in negotiation and knowledge pages.
	var hello map[string]json.RawMessage
	_ = json.Unmarshal(f.hello, &hello)
	var provider map[string]any
	_ = json.Unmarshal(hello["provider"], &provider)
	provider["snapshotDigest"] = "sha256:synthetic-scope:" + strings.Repeat("c", 64)
	hello["provider"] = previewJSON(t, provider)
	f.hello = previewJSON(t, hello)
	listener, e := net.Listen("unix", f.socket)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(c)
				for {
					line, e := reader.ReadBytes('\n')
					if e != nil {
						return
					}
					var req struct {
						Version    string `json:"version"`
						ID         string `json:"id"`
						Op         string `json:"op"`
						Projection string `json:"projection"`
						AssetID    string `json:"assetId"`
					}
					if json.Unmarshal(line, &req) != nil {
						return
					}
					if req.Op == "handshake" {
						switch f.fault.Load() {
						case 1:
							time.Sleep(2500 * time.Millisecond)
							return
						case 2:
							_, _ = c.Write([]byte(`{"version":"local-provider.session/v1"`))
							return
						}
					}
					var result any
					switch req.Op {
					case "handshake", "describe":
						result = f.hello
					case "catalog":
						result = f.sources
					case "knowledge":
						page := catalog
						offset := 0
						if req.Projection != "page:1" {
							if !strings.HasPrefix(req.Projection, "page:1:synthetic-next-") {
								return
							}
							offset, e = strconv.Atoi(strings.TrimPrefix(req.Projection, "page:1:synthetic-next-"))
							if e != nil || offset < 1 || offset >= len(f.sources) {
								return
							}
						}
						page.Sources = catalog.Sources[offset : offset+1]
						page.Items = []json.RawMessage{}
						page.Edges = []json.RawMessage{}
						for _, raw := range catalog.Items {
							var item knowledge.Item
							_ = json.Unmarshal(raw, &item)
							if item.SourceID == f.sources[offset].ID {
								page.Items = append(page.Items, raw)
							}
						}
						for _, rawEdge := range catalog.Edges {
							var edge knowledge.Edge
							_ = json.Unmarshal(rawEdge, &edge)
							if edge.To == f.sources[offset].ID {
								page.Edges = append(page.Edges, rawEdge)
							}
						}
						result = map[string]any{"catalog": json.RawMessage(previewJSON(t, page)), "catalogDigest": previewDigest(f.catalog), "scopeDigest": "sha256:synthetic-scope:" + strings.Repeat("c", 64), "queryDigest": "sha256:" + strings.Repeat("d", 64), "offset": offset, "totalSources": len(f.sources), "complete": offset == len(f.sources)-1, "externalReferences": []string{}}
						if offset < len(f.sources)-1 {
							result.(map[string]any)["nextCursor"] = fmt.Sprintf("synthetic-next-%d", offset+1)
						}
					case "read":
						for _, source := range f.sources {
							for _, asset := range source.Assets {
								if asset.ID == req.AssetID {
									result = map[string]any{"asset": asset, "content": f.bodies[asset.ID], "trust": "untrusted-content-not-policy"}
								}
							}
						}
					default:
						return
					}
					packet := previewJSON(t, map[string]any{"version": providerclient.APIVersion, "id": req.ID, "status": "ok", "result": result, "usage": map[string]any{}})
					if _, e = c.Write(append(packet, '\n')); e != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; wg.Wait(); _ = os.RemoveAll(parent) })
	return f
}
