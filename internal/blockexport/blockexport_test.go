package blockexport

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixture(blocks ...Block) BlockExport {
	return BlockExport{APIVersion: APIVersion, Kind: Kind, Metadata: Metadata{ID: "base.security", Version: "1.0.0"}, Compatibility: Compatibility{Tplater: ">=0.3.0", MarkerSchema: MarkerSchema}, MergeStrategy: MergeStrategy, Formatter: Formatter{Adapter: "gofmt", OptionsDigest: "sha256:" + strings.Repeat("0", 64)}, Targets: []Target{{Path: "internal/service/services.go", Blocks: blocks}}}
}
func mk(id string, n int) Block {
	return Block{ID: id, Provider: "base", Layout: "layer_files", Body: "managed/service.tmpl", Order: n}
}
func TestResolveDeterministicAndPermutation(t *testing.T) {
	a, b, c := mk("a", 20), mk("b", 10), mk("c", 10)
	c.Anchor.After = "b"
	for _, in := range [][]Block{{a, b, c}, {c, a, b}, {b, c, a}} {
		r, e := Resolve([]BlockExport{fixture(in...)})
		if e != nil {
			t.Fatal(e)
		}
		for i, w := range []string{"b", "c", "a"} {
			if r[0].Blocks[i].ID != w {
				t.Fatalf("got %v", r[0].Blocks)
			}
		}
	}
}
func TestParseStrictRejectsUnsafeAndMalformed(t *testing.T) {
	valid := `apiVersion: tplater.dev/block-export/v1
kind: BlockExport
metadata: {id: base.security, version: 1.0.0}
compatibility: {tplater: ">=0.3.0", markerSchema: tplater.dev/managed-block/v1}
mergeStrategy: managed-blocks-v1
formatter: {adapter: gofmt, optionsDigest: sha256:0000000000000000000000000000000000000000000000000000000000000000}
targets:
  - path: internal/service/services.go
    blocks:
      - {id: service, provider: base, layout: layer_files, body: managed/service.tmpl, order: 1}
`
	if _, e := Parse([]byte(valid)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(valid, "managed/service.tmpl", "managed/../service.tmpl", 1), strings.Replace(valid, "version: 1.0.0", "version: 01.0.0", 1), valid + "---\napiVersion: ignored\n", strings.Replace(valid, "kind: BlockExport", "Kind: BlockExport", 1)} {
		if _, e := Parse([]byte(bad)); e == nil {
			t.Fatal("accepted malformed")
		}
	}
	if _, e := Parse([]byte(strings.Replace(valid, "order: 1}", "order: 1, anchor: {} }", 1))); e == nil {
		t.Fatal("empty anchor accepted")
	}
}
func TestResolveRejectsCollisionsAnchorsAndReplacements(t *testing.T) {
	a, b := mk("a", 1), mk("b", 2)
	a.Anchor.Before = "missing"
	if _, e := Resolve([]BlockExport{fixture(a, b)}); e == nil {
		t.Fatal("unknown anchor")
	}
	a, b = mk("a", 1), mk("b", 2)
	a.Replaces = []string{"old"}
	b.Replaces = []string{"old"}
	if _, e := Resolve([]BlockExport{fixture(a, b)}); e == nil {
		t.Fatal("ambiguous replacement")
	}
	a, b = mk("a", 1), mk("b", 2)
	a.Anchor.Before = "b"
	b.Anchor.Before = "a"
	if _, e := Resolve([]BlockExport{fixture(a, b)}); e == nil {
		t.Fatal("cycle")
	}
}
func TestValidateBoundsAndAnchors(t *testing.T) {
	e := fixture(mk("a", 1))
	e.Targets = make([]Target, MaxTargets+1)
	if Validate(e) == nil {
		t.Fatal("accepted target bound")
	}
	b := mk("a", 1)
	if Validate(fixture(b)) != nil {
		t.Fatal("valid block rejected")
	}
	b.Anchor = Anchor{Before: "a", After: "a"}
	if Validate(fixture(b)) == nil {
		t.Fatal("conflicting anchor accepted")
	}
}

func TestParseRejectsWireCoercionAndYAMLFeatures(t *testing.T) {
	base := `{"apiVersion":"tplater.dev/block-export/v1","kind":"BlockExport","metadata":{"id":"x","version":"1.0.0"},"compatibility":{"tplater":"x","markerSchema":"tplater.dev/managed-block/v1"},"mergeStrategy":"managed-blocks-v1","formatter":{"adapter":"x","optionsDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"targets":[{"path":"x.go","blocks":[{"id":"x","provider":"p","layout":"layer_files","body":"x.tmpl","order":1}]}]}`
	for _, bad := range []string{strings.Replace(base, `"order":1`, `"order":1.5`, 1), strings.Replace(base, `"id":"x"`, `"id":true`, 1), strings.Replace(base, `"blocks":[{`, `"blocks":[{"anchor":{},`, 1), strings.Replace(base, `"body":"x.tmpl"`, `"body":null`, 1)} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatal("accepted wire type/shape")
		}
	}
	if _, err := Parse([]byte("---\n&root " + base)); err == nil {
		t.Fatal("accepted YAML anchor")
	}
	keyAnchor := strings.Replace(validBlockExportYAML(), "apiVersion:", "&key apiVersion:", 1)
	if _, err := Parse([]byte(keyAnchor)); err == nil {
		t.Fatal("accepted YAML mapping-key anchor")
	}
}

func validBlockExportYAML() string {
	return `apiVersion: tplater.dev/block-export/v1
kind: BlockExport
metadata: {id: base.security, version: 1.0.0}
compatibility: {tplater: ">=0.3.0", markerSchema: tplater.dev/managed-block/v1}
mergeStrategy: managed-blocks-v1
formatter: {adapter: gofmt, optionsDigest: sha256:0000000000000000000000000000000000000000000000000000000000000000}
targets:
  - path: internal/service/services.go
    blocks:
      - {id: service, provider: base, layout: layer_files, body: managed/service.tmpl, order: 1}
`
}

func TestOrderSafeIntegerBounds(t *testing.T) {
	base := `{"apiVersion":"tplater.dev/block-export/v1","kind":"BlockExport","metadata":{"id":"x","version":"1.0.0"},"compatibility":{"tplater":"x","markerSchema":"tplater.dev/managed-block/v1"},"mergeStrategy":"managed-blocks-v1","formatter":{"adapter":"x","optionsDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"targets":[{"path":"x.go","blocks":[{"id":"x","provider":"p","layout":"layer_files","body":"x.tmpl","order":ORDER}]}]}`
	for _, order := range []string{"-9007199254740991", "9007199254740991"} {
		if _, err := Parse([]byte(strings.Replace(base, "ORDER", order, 1))); err != nil {
			t.Fatalf("safe boundary %s rejected: %v", order, err)
		}
	}
	for _, order := range []string{"-9007199254740992", "9007199254740992"} {
		if _, err := Parse([]byte(strings.Replace(base, "ORDER", order, 1))); err == nil {
			t.Fatalf("unsafe order %s accepted", order)
		}
	}
	for _, order := range []string{"-9007199254740991", "9007199254740991"} {
		yaml := strings.Replace(validBlockExportYAML(), "order: 1", "order: "+order, 1)
		if _, err := Parse([]byte(yaml)); err != nil {
			t.Fatalf("YAML safe boundary %s rejected: %v", order, err)
		}
	}
}

func TestAnchorRelationsAndJSONRoundTrip(t *testing.T) {
	e := fixture(mk("a", 1))
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(raw); err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	a, b, c := mk("a", 1), mk("b", 2), mk("c", 3)
	a.Anchor.Before = "c"
	b.Anchor.Before = "c"
	if _, err := Resolve([]BlockExport{fixture(a, b, c)}); err == nil {
		t.Fatal("overlapping incoming anchors accepted")
	}
	a, b = mk("a", 1), mk("b", 2)
	b.Anchor.After = "a"
	a.Anchor.Before = "b"
	if _, err := Resolve([]BlockExport{fixture(a, b)}); err == nil {
		t.Fatal("duplicate anchor relation accepted")
	}
}
