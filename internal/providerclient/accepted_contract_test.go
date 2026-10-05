package providerclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/knowledge"
)

func TestNeutralFixtureHashesAndSchema(t *testing.T) {
	raw, e := os.ReadFile("testdata/synthetic/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var manifest struct {
		Artifacts []struct {
			File   string `json:"file"`
			SHA256 string `json:"sha256"`
		} `json:"allowedArtifacts"`
	}
	if e = json.Unmarshal(raw, &manifest); e != nil || len(manifest.Artifacts) != 5 {
		t.Fatal("neutral fixture manifest")
	}
	for _, f := range manifest.Artifacts {
		raw, e = os.ReadFile("testdata/synthetic/" + f.File)
		if e != nil {
			t.Fatal(e)
		}
		if digest(raw) != "sha256:"+f.SHA256 {
			t.Fatal("neutral fixture artifact changed")
		}
	}
	schema, e := jsonschema.NewCompiler().Compile("testdata/synthetic/knowledge.v1.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	raw, e = os.ReadFile("testdata/synthetic/full-catalog.json")
	if e != nil {
		t.Fatal(e)
	}
	var value any
	if e = json.Unmarshal(raw, &value); e != nil {
		t.Fatal(e)
	}
	if e = schema.Validate(value); e != nil {
		t.Fatal("neutral fixture full schema", e)
	}
	receipts, e := os.ReadFile("testdata/synthetic/receipt.ndjson")
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range splitLines(receipts) {
		var entry struct {
			Response response `json:"response"`
		}
		if json.Unmarshal(line, &entry) != nil {
			t.Fatal("receipt")
		}
		var p page
		if json.Unmarshal(entry.Response.Result, &p) == nil && len(p.Catalog) > 0 {
			if e = json.Unmarshal(p.Catalog, &value); e != nil {
				t.Fatal(e)
			}
			if e = schema.Validate(value); e != nil {
				t.Fatal("neutral fixture page schema", e)
			}
		}
	}
}

func splitLines(raw []byte) [][]byte {
	var result [][]byte
	start := 0
	for i, b := range raw {
		if b == '\n' {
			if i > start {
				result = append(result, raw[start:i])
			}
			start = i + 1
		}
	}
	if start < len(raw) {
		result = append(result, raw[start:])
	}
	return result
}

func TestNeutralFixtureC01SemanticBlocker(t *testing.T) {
	raw, e := os.ReadFile("testdata/synthetic/full-catalog.json")
	if e != nil {
		t.Fatal(e)
	}
	_, e = knowledge.Decode(raw)
	var failure *knowledge.Error
	if !errors.As(e, &failure) || failure.Code != knowledge.IncompletePin {
		t.Fatal("expected existing public C01 semantic refusal")
	}
	var catalog knowledge.Catalog
	if e = json.Unmarshal(raw, &catalog); e != nil {
		t.Fatal(e)
	}
	for _, src := range catalog.Sources {
		pinBytes, e := json.Marshal(src.Pin)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = deps.DecodePinnedSource(pinBytes); e == nil {
			t.Fatal("synthetic invalid provider label unexpectedly admitted")
		}
		// Diagnostic copies only: no runtime normalization and no changed fixture.
		copyPin := src.Pin
		copyPin.ProviderID = "synthetic-provider"
		pinBytes, e = json.Marshal(copyPin)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = deps.DecodePinnedSource(pinBytes); e == nil {
			t.Fatal("synthetic invalid origin unexpectedly admitted")
		}
		copyPin.Origin = "https://example.test/" + copyPin.Alias + ".git"
		pinBytes, e = json.Marshal(copyPin)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = deps.DecodePinnedSource(pinBytes); e != nil {
			t.Fatal("additional pinned source incompatibility", e)
		}
	}
}

// This checks an exact synthetic derivative, not live producer authentication.
func TestNeutralFixturePagesAndDigest(t *testing.T) {
	raw, err := os.ReadFile("testdata/synthetic/full-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.TrimSpace(raw)
	receipts, err := os.ReadFile("testdata/synthetic/receipt.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	var joined catalogParts
	pages := 0
	var previousCursor string
	for _, line := range splitLines(receipts) {
		var entry struct {
			Request  request  `json:"request"`
			Response response `json:"response"`
		}
		if json.Unmarshal(line, &entry) != nil {
			t.Fatal("fixture envelope")
		}
		if entry.Request.Version != APIVersion || entry.Response.Version != APIVersion || entry.Request.ID != entry.Response.ID {
			t.Fatal("wire version or ID")
		}
		if entry.Request.Op != "knowledge" || entry.Request.Projection == "page:128" {
			continue
		}
		var p page
		if json.Unmarshal(entry.Response.Result, &p) != nil {
			t.Fatal("page")
		}
		if string(p.CatalogDigest) != `"`+digest(raw)+`"` {
			t.Fatal("catalog digest")
		}
		part, err := parts(p.Catalog)
		if err != nil {
			t.Fatal(err)
		}
		if pages == 0 {
			joined = part
			previousCursor = p.NextCursor
			if p.Offset != 0 || p.Complete || previousCursor != "synthetic-cursor-1" {
				t.Fatal("first page")
			}
		} else {
			if entry.Request.Projection != "page:1:"+previousCursor || p.Offset != 1 || !p.Complete {
				t.Fatal("continuation")
			}
			joined.Sources = append(joined.Sources, part.Sources...)
			joined.Items = append(joined.Items, part.Items...)
			joined.Edges = append(joined.Edges, part.Edges...)
		}
		pages++
	}
	assembled, err := json.Marshal(joined)
	if err != nil || pages != 2 || !bytes.Equal(assembled, raw) {
		t.Fatal("exact two-page reconstruction")
	}
}
