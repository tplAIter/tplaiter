package contextindex

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/tplAIter/tplaiter/internal/knowledge"
)

func catalog(t *testing.T) knowledge.Catalog {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/knowledge/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := knowledge.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func wire(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func index(t *testing.T, d knowledge.Catalog, s ...Symbol) *Index {
	t.Helper()
	i, e := New(wire(t, d), s)
	if e != nil {
		t.Fatal(e)
	}
	return i
}

func outcome(t *testing.T, err error, code string) {
	t.Helper()
	var d *Error
	if !errors.As(err, &d) || d.Code != code {
		t.Fatalf("want %s: %v", code, err)
	}
}

func retrieve(t *testing.T, i *Index, r Request) Packet {
	t.Helper()
	p, e := i.Retrieve(context.Background(), r, nil)
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestDeterministicQueriesAndRequiredFloor(t *testing.T) {
	d := catalog(t)
	symbols := []Symbol{{ID: "example:symbol:review", ItemID: d.Items[1].ID, Name: "Review", Line: 2, State: "static"}, {ID: "example:symbol:missing", ItemID: d.Items[1].ID, Name: "Pending", Line: 3, State: "unresolved"}}
	i := index(t, d, symbols...)
	req := Request{Query: Query{ID: d.Items[1].ID, One: true}, Limit: 1, MaxBytes: 32768}
	p := retrieve(t, i, req)
	if p.TotalMatches != 1 || len(p.Records) != 2 || len(p.Sources) != 1 || len(p.RequiredFloor) != 3 {
		t.Fatalf("floor lost: %+v", p)
	}
	if len(p.Excerpts) != 0 || len(p.SourceEvidence) != 0 {
		t.Fatal("implicit source reads")
	}
	selected := map[string]bool{}
	for _, id := range p.RequiredFloor {
		selected[id] = true
	}
	var wantRelations int
	for _, e := range i.graph.Edges {
		if selected[e.From] || selected[e.To] {
			wantRelations++
		}
	}
	if len(p.Relations) != wantRelations || len(p.ExternalReferences) == 0 {
		t.Fatal("incident dependency/semantic/package edges lost")
	}
	for _, r := range p.Records {
		if r.Kind == "skill" && !reflect.DeepEqual(r.Descriptor.Inputs, d.Items[1].Inputs) {
			t.Fatal("input floor/defaults/constraints lost")
		}
	}
	// Reordered metadata must produce the same result bytes.
	d.Items[0], d.Items[2] = d.Items[2], d.Items[0]
	symbols[0], symbols[1] = symbols[1], symbols[0]
	j := index(t, d, symbols...)
	if string(wire(t, p)) != string(wire(t, retrieve(t, j, req))) {
		t.Fatal("input ordering affected packet")
	}
	for _, q := range []Query{{Kind: "block", One: true}, {Kind: "resource", One: true}, {Kind: "path", Path: "blocks/intro.md", One: true}, {Kind: "symbol", Symbol: "Review", One: true}, {Kind: "symbol", Text: "Pending", One: true}, {Kind: "skill", SourceID: d.Sources[0].ID, One: true}} {
		got := retrieve(t, i, Request{Query: q, MaxBytes: 32768})
		if got.TotalMatches != 1 {
			t.Fatalf("query %+v", q)
		}
	}
	static := retrieve(t, i, Request{Query: Query{Symbol: "Review", One: true}, MaxBytes: 32768})
	unresolved := retrieve(t, i, Request{Query: Query{Symbol: "Pending", One: true}, MaxBytes: 32768})
	if static.Records[len(static.Records)-1].State != "static" || unresolved.Records[len(unresolved.Records)-1].State != "unresolved" {
		t.Fatal("reported evidence state changed")
	}
	_, err := i.Retrieve(context.Background(), Request{Query: Query{Kind: "path", One: true}, Limit: 1}, nil)
	outcome(t, err, Ambiguous)
	_, err = i.Retrieve(context.Background(), Request{Query: Query{ID: "example:block:absent", One: true}}, nil)
	outcome(t, err, Missing)
	_, err = i.Retrieve(context.Background(), Request{Query: Query{Symbol: "review", One: true}}, nil)
	outcome(t, err, Missing)
}

func TestBoundsImmutabilityAndCancellation(t *testing.T) {
	d := catalog(t)
	raw := wire(t, d)
	i, err := New(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	for n := range raw {
		raw[n] = 0
	}
	req := Request{Query: Query{Kind: "skill", One: true}, MaxBytes: 32768}
	p := retrieve(t, i, req)
	want := string(wire(t, p))
	if p.Bytes != len(wire(t, p)) {
		t.Fatal("bytes is not exact serialized JSON")
	}
	for _, r := range []Request{{Query: req.Query, MaxRecords: 2}, {Query: req.Query, MaxBytes: p.Bytes - 1}, {Required: []string{"example:block:absent"}}} {
		result, err := i.Retrieve(context.Background(), r, nil)
		if !reflect.DeepEqual(result, Packet{}) {
			t.Fatal("partial success on refusal")
		}
		if len(r.Required) > 0 {
			outcome(t, err, Missing)
		} else {
			outcome(t, err, Budget)
		}
	}
	exact := retrieve(t, i, Request{Query: req.Query, MaxBytes: p.Bytes})
	if exact.Bytes != p.Bytes {
		t.Fatal("exact budget rejected")
	}
	p.Records[0].Descriptor.Requires = append(p.Records[0].Descriptor.Requires, "tampered")
	p.Sources[0].Pin.Origin = "changed"
	if string(wire(t, retrieve(t, i, req))) != want {
		t.Fatal("result mutation changed index")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = i.Retrieve(ctx, req, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			result, e := i.Retrieve(context.Background(), req, nil)
			if e != nil || string(wire(t, result)) != want {
				t.Errorf("concurrent result: %v", e)
			}
		})
	}
	wg.Wait()
}

func TestAnchorAndSymbolDiagnosticsAndStablePathID(t *testing.T) {
	d := catalog(t)
	i := index(t, d)
	before := retrieve(t, i, Request{Query: Query{Kind: "path", Path: d.Items[0].SourcePath, One: true}, MaxBytes: 32768}).Records
	d.Version = "1.0.1"
	d.Items[0].Version = "1.0.1"
	d.Items[0].Export = nil
	d.Items[0].ContentSHA256 = "sha256:" + strings.Repeat("2", 64)
	after := retrieve(t, index(t, d), Request{Query: Query{Kind: "path", Path: d.Items[0].SourcePath, One: true}, MaxBytes: 32768}).Records
	var first, second string
	for _, r := range before {
		if r.Kind == "path" {
			first = r.ID
		}
	}
	for _, r := range after {
		if r.Kind == "path" {
			second = r.ID
		}
	}
	if first == "" || first != second {
		t.Fatal("path ID depends on content/version")
	}
	s := Symbol{ID: "example:symbol:one", ItemID: d.Items[0].ID, Name: "One", Line: 1, State: "declared"}
	_, err := New(wire(t, d), []Symbol{s, s})
	outcome(t, err, Ambiguous)
	s.ItemID = "example:block:absent"
	_, err = New(wire(t, d), []Symbol{s})
	outcome(t, err, Missing)
	d.Items[2].SourcePath = d.Items[0].SourcePath
	_, err = New(wire(t, d), nil)
	outcome(t, err, Stale)
}

func TestCompleteLineExcerptBounds(t *testing.T) {
	r := Record{ID: "example:symbol:one", Path: "a.go", Line: 2}
	e, err := boundedExcerpt(r, []byte("first\né\nthird\nfourth"), 8)
	if err != nil || e.Content != "é\nthird" || e.Start != 2 || e.End != 3 {
		t.Fatalf("UTF8/line bound: %+v %v", e, err)
	}
	_, err = boundedExcerpt(r, []byte("first\nlong"), 3)
	outcome(t, err, Budget)
	r.Line = 9
	_, err = boundedExcerpt(r, []byte("one"), 30)
	outcome(t, err, Stale)
}

func TestExplicitFloorTransitiveSourceDependenciesAndUnresolvedRefusal(t *testing.T) {
	d := catalog(t)
	base := d.Sources[0]
	base.ID = "example:source:base"
	base.Pin.Alias = "base"
	base.Pin.Origin = "https://base.example.test/templates.git"
	base.Anchor.Origin = base.Pin.Origin
	d.Sources[0].Pin.Dependencies = []string{"base"}
	d.Sources = append(d.Sources, base)
	// Resource context requires the skill, which in turn requires the block.
	d.Items[2].Inputs.ContextFloor = []string{d.Items[1].ID}
	i := index(t, d)
	p := retrieve(t, i, Request{Query: Query{Text: "no-primary-match"}, Required: []string{d.Items[2].ID}, Limit: 1, MaxBytes: 32768})
	if p.TotalMatches != 0 || len(p.Records) != 3 || len(p.Sources) != 2 || len(p.RequiredFloor) != 5 {
		t.Fatal("explicit transitive floor/source dependency lost")
	}
	var dep bool
	for _, edge := range p.Relations {
		if edge.Kind == "source:depends-on" && edge.From == base.ID {
			dep = true
		}
	}
	if !dep {
		t.Fatal("source dependency dropped")
	}
	// An unresolved declared dependency cannot silently disappear from a floor.
	d.Edges = append(d.Edges, knowledge.Edge{From: "example:block:unknown", To: d.Items[2].ID, Layer: "workflow", Relation: "requires", State: "unresolved"})
	result, err := index(t, d).Retrieve(context.Background(), Request{Required: []string{d.Items[2].ID}, MaxBytes: 32768}, nil)
	outcome(t, err, Missing)
	if !reflect.DeepEqual(result, Packet{}) {
		t.Fatal("unresolved required context returned partial success")
	}
}
