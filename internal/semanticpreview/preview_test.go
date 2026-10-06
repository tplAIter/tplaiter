package semanticpreview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/graphcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"github.com/tplAIter/tplaiter/internal/semanticgraph"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
)

func previewFixture(t *testing.T) (resultdto.SemanticPreviewData, Request, []semanticgraph.SourceFile, []graphcmd.SemanticFileFact) {
	t.Helper()
	raw := []byte("package sample\nfunc Value() int { return 1 }\n")
	files := []semanticgraph.SourceFile{{Path: "value.go", Bytes: raw}}
	facts := []graphcmd.SemanticFileFact{{Path: "value.go", Digest: evidencecas.Digest(raw), Mode: 0644, Bytes: len(raw)}}
	anchors, e := calculate(context.Background(), Request{APIVersion: RequestVersion, Action: "anchors", Paths: []string{"value.go"}}, files, facts, evidencecas.Digest([]byte("manifest")))
	if e != nil {
		t.Fatal(e)
	}
	var a resultdto.SemanticAnchor
	for _, anchor := range anchors.Images[0].BeforeAnchors {
		if anchor.Kind == "function-body" {
			a = anchor
		}
	}
	q := Request{APIVersion: RequestVersion, Action: "preview", Edits: []Edit{{ID: "change", Path: "value.go", Intent: "go.function-body.replace", ExpectedFileDigest: evidencecas.Digest(raw), BeforeGraphDigest: anchors.BeforeGraph.Digest, Anchor: a, Payload: "{ return 2 }"}}}
	return anchors, q, files, facts
}
func TestSemanticActualGraphAnchorsAndCompleteImages(t *testing.T) {
	_, q, files, facts := previewFixture(t)
	original := append([]byte(nil), files[0].Bytes...)
	d, e := calculate(context.Background(), q, files, facts, evidencecas.Digest([]byte("manifest")))
	if e != nil {
		t.Fatal(e)
	}
	if string(d.Images[0].After) != "package sample\nfunc Value() int { return 2 }\n" || !bytes.Equal(d.Images[0].Before, original) || !bytes.Equal(files[0].Bytes, original) {
		t.Fatal("lost immutable exact images")
	}
	if !strings.Contains(d.Images[0].Diff, "-func Value() int { return 1 }") || !strings.Contains(d.Images[0].Diff, "+func Value() int { return 2 }") {
		t.Fatal("not an actual full diff")
	}
	if d.CompilerVerification != "not-performed" || !d.NoEffects || len(d.Edits) != 1 || d.BeforeGraph.Digest == d.AfterGraph.Digest {
		t.Fatal("incorrect observation/graph mapping")
	}
	if d.Edits[0].Before.NodeID == "" || d.Edits[0].AfterEndByte <= d.Edits[0].AfterStartByte {
		t.Fatal("missing actual AST mapping")
	}
	for _, change := range []func(*Request){func(q *Request) { q.Edits[0].BeforeGraphDigest = evidencecas.Digest([]byte("stale")) }, func(q *Request) { q.Edits[0].ExpectedFileDigest = evidencecas.Digest([]byte("stale")) }, func(q *Request) { q.Edits[0].Anchor.StartByte++ }} {
		bad := q
		bad.Edits = append([]Edit{}, q.Edits...)
		change(&bad)
		if _, e := calculate(context.Background(), bad, files, facts, evidencecas.Digest([]byte("manifest"))); !errors.Is(e, ErrAnchor) {
			t.Fatal("accepted stale original precondition", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := calculate(ctx, q, files, facts, evidencecas.Digest([]byte("manifest"))); !errors.Is(e, context.Canceled) {
		t.Fatal("ignored cancellation", e)
	}
}
func TestSemanticWholeSDKBoundaryEscapedIDAndNoTruncation(t *testing.T) {
	_, q, files, facts := previewFixture(t)
	d, e := calculate(context.Background(), q, files, facts, evidencecas.Digest([]byte("manifest")))
	if e != nil {
		t.Fatal(e)
	}
	id, _ := json.Marshal(strings.Repeat("<&\\\"", 300))
	l := resultwire.GraphFrameLayout{APIVersion: resultwire.GraphFrameVersion, ID: id, Ceiling: 32768}
	cli, e := encodeFrame(d, "project", "/public/<root>&", "test", 32768, &l)
	if e != nil {
		t.Fatal(e)
	}
	var env resultdto.Result
	if e = json.Unmarshal(cli, &env); e != nil {
		t.Fatal(e)
	}
	mcp, e := resultwire.Frame(l.RequestID(), resultwire.Structured(env, false))
	if e != nil {
		t.Fatal(e)
	}
	floor := len(mcp)
	if len(cli) > floor {
		floor = len(cli)
	}
	l.Ceiling = floor
	exact, e := encodeFrame(d, "project", "/public/<root>&", "test", floor, &l)
	if e != nil || !bytes.Equal(cli, exact) {
		t.Fatal("exact whole-frame boundary", e)
	}
	l.Ceiling--
	if _, e := encodeFrame(d, "project", "/public/<root>&", "test", floor-1, &l); !errors.Is(e, ErrBudget) {
		t.Fatal("accepted one below full SDK frame", e)
	}
	id, _ = json.Marshal(strings.Repeat("<", 20000))
	l.ID = id
	l.Ceiling = 32768
	if _, e := encodeFrame(d, "project", "/public/<root>&", "test", 32768, &l); e == nil {
		t.Fatal("accepted over-budget normalized metadata")
	}
	t.Logf("complete images=%d CLI=%d SDK=%d exact floor=%d", len(d.Images), len(cli), len(mcp), floor)
}
func TestSemanticClosedRequestAndInvalidCarrier(t *testing.T) {
	_, q, _, _ := previewFixture(t)
	raw, _ := json.Marshal(q)
	if _, e := DecodeRequest(raw); e != nil {
		t.Fatal(e)
	}
	for _, b := range [][]byte{[]byte(strings.Replace(string(raw), `"action":"preview"`, `"action":"preview","action":"preview"`, 1)), []byte(strings.Replace(string(raw), `"startByte":`, `"StartByte":`, 1)), []byte(strings.Replace(string(raw), `"intent":"go.function-body.replace"`, `"intent":"apply"`, 1))} {
		if _, e := DecodeRequest(b); e == nil {
			t.Fatal("accepted nonclosed request")
		}
	}
	q.Edits = append(q.Edits, q.Edits[0])
	q.Edits[1].ID = "second"
	q.Edits[1].Path = "Value.go"
	if q.Validate() == nil {
		t.Fatal("accepted case alias")
	}
	var p Preview
	if p.Recheck(context.Background()) == nil {
		t.Fatal("zero carrier admitted")
	}
	p.Close()
	if _, e := Prepare(context.Background(), nil, Request{APIVersion: RequestVersion, Action: "anchors", Paths: []string{"value.go"}}, runtimeassembly.Options{}); e == nil {
		t.Fatal("caller path admitted without runtime")
	}
}

func TestSemanticOriginalSnapshotMultiEditPermutation(t *testing.T) {
	files := []semanticgraph.SourceFile{{Path: "a.go", Bytes: []byte("package sample\nfunc A(){\n // point\n}\n")}, {Path: "b.go", Bytes: []byte("package sample\nfunc B() int { return 1 }\n")}}
	facts := []graphcmd.SemanticFileFact{}
	for _, f := range files {
		facts = append(facts, graphcmd.SemanticFileFact{Path: f.Path, Digest: evidencecas.Digest(f.Bytes), Mode: 0644, Bytes: len(f.Bytes)})
	}
	anchors, e := calculate(context.Background(), Request{APIVersion: RequestVersion, Action: "anchors", Paths: []string{"b.go", "a.go"}}, files, facts, evidencecas.Digest([]byte("manifest")))
	if e != nil {
		t.Fatal(e)
	}
	edits := []Edit{}
	for _, image := range anchors.Images {
		for _, a := range image.BeforeAnchors {
			var edit Edit
			if image.Path == "a.go" && a.Kind == "comment" {
				edit = Edit{ID: "first", Intent: "go.comment-anchor.insert-statements", Comment: "// point", Payload: "_ = 1"}
			} else if image.Path == "b.go" && a.Kind == "function-body" {
				edit = Edit{ID: "second", Intent: "go.function-body.replace", Payload: "{ return 2 }"}
			} else {
				continue
			}
			edit.Path = image.Path
			edit.ExpectedFileDigest = image.BeforeDigest
			edit.BeforeGraphDigest = anchors.BeforeGraph.Digest
			edit.Anchor = a
			edits = append(edits, edit)
		}
	}
	if len(edits) != 2 {
		t.Fatal("missing independent actual anchors")
	}
	q := Request{APIVersion: RequestVersion, Action: "preview", Edits: edits}
	first, e := calculate(context.Background(), q, files, facts, evidencecas.Digest([]byte("manifest")))
	if e != nil {
		t.Fatal(e)
	}
	q.Edits = []Edit{edits[1], edits[0]}
	second, e := calculate(context.Background(), q, files, facts, evidencecas.Digest([]byte("manifest")))
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(first.Images, second.Images) || !reflect.DeepEqual(first.Edits, second.Edits) || !reflect.DeepEqual(first.AfterGraph, second.AfterGraph) || first.RequestDigest == second.RequestDigest {
		t.Fatal("original splices/order binding changed")
	}
	if string(first.Images[0].After) != "package sample\nfunc A(){\n _ = 1\n // point\n}\n" || string(first.Images[1].After) != "package sample\nfunc B() int { return 2 }\n" {
		t.Fatal("unexpected afterimages")
	}
}
