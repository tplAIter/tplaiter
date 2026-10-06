package resultdto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
)

func TestSemanticFactualDecoderClosedBase64AndHash(t *testing.T) {
	raw := []byte("package sample\n")
	g := graphdoc.New()
	g.Nodes = []graphdoc.Node{{ID: "package:go:sample.go:sample", Kind: "package", Language: "go", Path: "sample.go", Name: "sample", Line: 1}}
	if e := g.Canonicalize(); e != nil {
		t.Fatal(e)
	}
	d := SemanticPreviewData{APIVersion: "tplaiter.dev/semantic-preview-result/v1", Action: "anchors", Basis: "installed-project-observed-bytes", VerificationLevel: "go-syntax-only", CompilerVerification: "not-performed", Scope: "selected-go-files", NoEffects: true, RequestDigest: evidencecas.Digest([]byte("request")), SourceManifestDigest: evidencecas.Digest([]byte("manifest")), Images: []SemanticImage{{Path: "sample.go", Mode: 0644, Before: raw, After: raw, BeforeDigest: evidencecas.Digest(raw), AfterDigest: evidencecas.Digest(raw), BeforeBytes: len(raw), AfterBytes: len(raw), BeforeAnchors: []SemanticAnchor{}, AfterAnchors: []SemanticAnchor{}, Diff: ""}}, BeforeGraph: g, AfterGraph: g, AddedNodes: []string{}, RemovedNodes: []string{}, AddedEdges: []graphdoc.Edge{}, RemovedEdges: []graphdoc.Edge{}, Edits: []SemanticEditMapping{}}
	b, e := canonicaljson.Canonical(d)
	if e != nil {
		t.Fatal(e)
	}
	d.PreviewDigest = evidencecas.Digest(b)
	b, _ = json.Marshal(d)
	if _, e = DecodeSemanticPreviewData(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), `"noEffects":true`, `"noEffects":false`, 1), strings.Replace(string(b), `"before":"cGFja2FnZSBzYW1wbGUK"`, `"before":null`, 1), strings.Replace(string(b), `"beforeBytes":15`, `"beforeBytes":14`, 1), strings.Replace(string(b), `"action":"anchors"`, `"Action":"anchors"`, 1), strings.Replace(string(b), `"action":"anchors"`, `"action":"anchors","action":"anchors"`, 1)} {
		if bad == string(b) {
			t.Fatal("ineffective negative fixture")
		}
		if _, e = DecodeSemanticPreviewData([]byte(bad)); e == nil {
			t.Fatal("accepted false/unknown/corrupt observation")
		}
	}
}
