package contextauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestSourceClosureCannotBeReconstructedFromData(t *testing.T) {
	ctx := context.Background()
	r := &trustload.Runtime{}
	for _, c := range []*VerifiedSourceClosure{nil, {}, {installed: r}} {
		if c.Recheck(ctx) == nil || c.RecheckFor(ctx, r) == nil {
			t.Fatal("fabricated carrier accepted")
		}
		if _, e := c.Borrow(ctx, r); e == nil {
			t.Fatal("fabricated borrow")
		}
		if _, e := c.RootResolution(ctx, r); e == nil {
			t.Fatal("fabricated root")
		}
		if _, e := c.OperationSubjects(ctx, r); e == nil {
			t.Fatal("fabricated subjects")
		}
		if _, e := c.Pins(ctx); e == nil {
			t.Fatal("fabricated pins")
		}
		if _, e := c.SourceGraph(ctx); e == nil {
			t.Fatal("fabricated graph")
		}
		if _, e := c.Catalogs(ctx); e == nil {
			t.Fatal("fabricated catalogs")
		}
		if _, e := c.CatalogData(ctx, "root"); e == nil {
			t.Fatal("fabricated images")
		}
		if _, e := c.Resolution(ctx, "root"); e == nil {
			t.Fatal("fabricated resolution")
		}
		if _, e := c.RootPin(ctx); e == nil {
			t.Fatal("fabricated root pin")
		}
		c.Close()
		c.Close()
	}
	var decoded VerifiedSourceClosure
	if e := json.Unmarshal([]byte(`{"installed":{},"root":"root","authenticated":true,"records":{"root":{}}}`), &decoded); e != nil {
		t.Fatal(e)
	}
	if decoded.RecheckFor(ctx, r) == nil {
		t.Fatal("JSON supplied authority")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, e := AdmitSourceClosure(ctx, r, &trustverify.VerifiedResolution{}, nil); e == nil {
			t.Fatal("raw empty runtime/resolution admitted")
		}
	}
}
