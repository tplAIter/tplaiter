package deps

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func sourcePin(alias, ref string) PinnedSource {
	return PinnedSource{
		APIVersion: "tplaiter.dev/pinned-source/v1", Alias: alias, ProviderID: "provider.base",
		Origin: "https://example.test/acme/base", TemplatePath: "templates/root", RequestedRef: ref,
		CommitAlgorithm: "sha1", Commit: "0123456789012345678901234567890123456789",
		TreeDigest:    strings.Repeat("sha256:4", 1) + strings.Repeat("4", 63),
		ContentDigest: "sha256:" + strings.Repeat("1", 64), ContractDigest: "sha256:" + strings.Repeat("2", 64), EvidenceDigest: "sha256:" + strings.Repeat("3", 64),
		Parameters: []Parameter{{Name: "flavor", Value: json.RawMessage(`"vanilla"`)}}, Dependencies: []string{},
	}
}

func TestSourceGraphLiteralIdentityVectors(t *testing.T) {
	alpha, beta := sourcePin("alpha", "refs/tags/v1"), sourcePin("beta", "refs/heads/main")
	g, err := BuildSourceGraph([]PinnedSource{beta, alpha})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 1 || len(g.Nodes[0].Provenance) != 2 {
		t.Fatalf("dedup/provenance=%+v", g.Nodes)
	}
	if got, want := g.Nodes[0].Identity.ParameterSHA256, "sha256:975f5dfd41b6b75c26c4ccba1240ec93731e936bd073453c21e541f9ca85b388"; got != want {
		t.Fatalf("parameters=%s", got)
	}
	if got, want := g.Nodes[0].Key, "sha256:29bc9b0253376137fd4df2c7df05787d26df72a5b9891290ee05fe7fa85ef1a1"; got != want {
		t.Fatalf("node=%s", got)
	}
	if got, want := g.Digest, "sha256:61b40d4543f651a0cb96aa2fdbf3e5bd23fabd47591cafe6f8b969dccbeed09f"; got != want {
		t.Fatalf("graph=%s", got)
	}
	if got := g.Nodes[0].Provenance; got[0].Alias != "alpha" || got[1].Alias != "beta" {
		t.Fatalf("provenance order=%+v", got)
	}
}

func TestSourceGraphIdentityMembershipAndConflicts(t *testing.T) {
	base := sourcePin("base", "refs/tags/v1")
	for _, tc := range []struct {
		name   string
		change func(*PinnedSource)
		want   string
	}{
		{"provider", func(p *PinnedSource) { p.ProviderID = "provider.alt" }, "sha256:e45bd1c602d013f59b56dd8b011ba1c824f36a21b5e76fa9426946e49757cc17"},
		{"content", func(p *PinnedSource) { p.ContentDigest = "sha256:" + strings.Repeat("a", 64) }, "sha256:b0bf6f6fe5dff03ab7cc870f3433401fb928d2d4ef6853d4e3db98df6fc1ec48"},
		{"evidence", func(p *PinnedSource) { p.EvidenceDigest = "sha256:" + strings.Repeat("b", 64) }, "sha256:380947d9685d2ceb737eb711087268cf7dd01d7282214cbae400c28b080b06a7"},
		{"parameters", func(p *PinnedSource) {
			p.Parameters = []Parameter{{Name: "flavor", Value: json.RawMessage(`"chocolate"`)}}
		}, "sha256:d2e0c4964017899dac33a0421b08654e638f4eb3d30d23d001009b9955369e97"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			p.Alias = "changed"
			tc.change(&p)
			identity, err := sourceIdentity(p)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "parameters" && identity.ParameterSHA256 != "sha256:3c05dffb106b4831050be38b10f403cb1e597eed8772589d8d801830e6beaa87" {
				t.Fatal(identity.ParameterSHA256)
			}
			got, err := sourceNodeKey(identity)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("key=%s", got)
			}
			_, err = BuildSourceGraph([]PinnedSource{base, p})
			var sourceErr *Error
			if !errorsAs(err, &sourceErr) || sourceErr.Code != SourceConflict || len(sourceErr.Chains) != 2 {
				t.Fatalf("conflict=%v", err)
			}
		})
	}
}

func TestSourceGraphCycleAndOrderAreDeterministic(t *testing.T) {
	a, b, c := sourcePin("alpha", "refs/tags/a"), sourcePin("beta", "refs/tags/b"), sourcePin("gamma", "refs/tags/c")
	// Give every alias a distinct immutable source while preserving graph shape.
	b.Origin, c.Origin = "https://example.test/acme/b", "https://example.test/acme/c"
	a.Dependencies, b.Dependencies, c.Dependencies = []string{"beta"}, []string{"gamma"}, []string{"alpha"}
	_, first := BuildSourceGraph([]PinnedSource{a, b, c})
	_, second := BuildSourceGraph([]PinnedSource{c, a, b})
	var one, two *Error
	if !errorsAs(first, &one) || !errorsAs(second, &two) || one.Code != SourceCycle || !reflect.DeepEqual(one.Chains, two.Chains) {
		t.Fatalf("cycles first=%v second=%v", first, second)
	}
}

func TestSourceGraphStrictWireAndRootDistinction(t *testing.T) {
	if _, err := BuildSourceGraph(nil); err == nil || !hasCode(err, SourceRootMissing) {
		t.Fatalf("missing root: %v", err)
	}
	leaf := sourcePin("leaf", "refs/tags/v1")
	if _, err := BuildSourceGraph([]PinnedSource{leaf}); err != nil {
		t.Fatalf("explicit empty closure: %v", err)
	}
	raw, err := json.Marshal(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePinnedSource(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		[]byte(`{"apiVersion":"tplaiter.dev/pinned-source/v1","alias":"a","alias":"b"}`),
		[]byte(`{"apiVersion":"tplaiter.dev/pinned-source/v1","unknown":true}`),
		[]byte(strings.Replace(string(raw), `"dependencies":[]`, `"dependencies":["x","x"]`, 1)),
		[]byte(strings.Replace(string(raw), `"commit":"0123456789012345678901234567890123456789"`, `"commit":"0123"`, 1)),
	} {
		if _, err := DecodePinnedSource(bad); err == nil {
			t.Fatalf("accepted strict invalid wire: %s", bad)
		}
	}
}

func TestDecodePinnedSourceRejectsRawNonIntegerScalarLexemes(t *testing.T) {
	p := sourcePin("leaf", "refs/tags/v1")
	p.Parameters = []Parameter{{Name: "count", Value: json.RawMessage(`0`)}}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		lexeme string
		valid  bool
	}{
		{"0", true},
		{"-1", true},
		{"9007199254740991", true},
		{"-9007199254740991", true},
		{"1.0", false},
		{"1e0", false},
		{"-0", false},
		{"9007199254740992", false},
		{"-9007199254740992", false},
	} {
		t.Run(tc.lexeme, func(t *testing.T) {
			candidate := []byte(strings.Replace(string(raw), `"value":0`, `"value":`+tc.lexeme, 1))
			_, err := DecodePinnedSource(candidate)
			if (err == nil) != tc.valid {
				t.Fatalf("lexeme %q valid=%v err=%v", tc.lexeme, tc.valid, err)
			}
		})
	}
}

func TestSourceGraphUsesAliasGrammarForParametersAndDependencies(t *testing.T) {
	p := sourcePin("root", "refs/tags/v1")
	p.Parameters = []Parameter{{Name: "not.valid", Value: json.RawMessage(`true`)}}
	if _, err := BuildSourceGraph([]PinnedSource{p}); err == nil {
		t.Fatal("parameter name outside alias grammar accepted")
	}
	p = sourcePin("root", "refs/tags/v1")
	p.Dependencies = []string{"not.valid"}
	if _, err := BuildSourceGraph([]PinnedSource{p}); err == nil {
		t.Fatal("dependency alias outside alias grammar accepted")
	}
	p.Dependencies = []string{"root"}
	if _, err := BuildSourceGraph([]PinnedSource{p}); err == nil {
		t.Fatal("self dependency accepted")
	}
}

func TestSourceGraphRootAndNestedPinnedSourcesCoexist(t *testing.T) {
	root, nested := sourcePin("root", "refs/tags/v1"), sourcePin("nested", "refs/tags/v1")
	nested.TemplatePath = "templates/nested"
	nested.Commit = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	root.Dependencies = []string{"nested"}
	g, err := BuildSourceGraph([]PinnedSource{root, nested})
	if err != nil || len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("root/nested graph=%+v err=%v", g, err)
	}
	escaping := nested
	escaping.TemplatePath = "../escape"
	if _, err := BuildSourceGraph([]PinnedSource{root, escaping}); err == nil {
		t.Fatal("escaping nested source accepted")
	}
}

func TestSourceGraphProvenanceDoesNotChangeDigestOrExposeHostPath(t *testing.T) {
	a, b := sourcePin("alpha", "refs/tags/v1"), sourcePin("beta", "refs/heads/main")
	g1, err := BuildSourceGraph([]PinnedSource{a, b})
	if err != nil {
		t.Fatal(err)
	}
	b.RequestedRef = "refs/tags/index-v2"
	g2, err := BuildSourceGraph([]PinnedSource{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if g1.Digest != g2.Digest || g1.Nodes[0].Key != g2.Nodes[0].Key {
		t.Fatalf("provenance changed graph: %s %s", g1.Digest, g2.Digest)
	}
	encoded, err := json.Marshal(g2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "/private-home/") || strings.Contains(string(encoded), "requestedRef\":\"") && strings.Contains(g2.Nodes[0].Key, "refs/") {
		t.Fatalf("host or provenance leaked into key: %s", encoded)
	}
}

func TestValidateSourceGraphRejectsForgedNodeAndDigest(t *testing.T) {
	g, err := BuildSourceGraph([]PinnedSource{sourcePin("alpha", "refs/tags/v1")})
	if err != nil || ValidateSourceGraph(g) != nil {
		t.Fatalf("valid graph=%v build=%v validate=%v", g, err, ValidateSourceGraph(g))
	}
	for _, mutate := range []func(*SourceGraph){
		func(v *SourceGraph) { v.Digest = "sha256:" + strings.Repeat("0", 64) },
		func(v *SourceGraph) { v.Nodes[0].Identity.ParameterSHA256 = "sha256:" + strings.Repeat("0", 64) },
	} {
		bad := *g
		bad.Nodes = append([]SourceNode(nil), g.Nodes...)
		mutate(&bad)
		if err := ValidateSourceGraph(&bad); err == nil {
			t.Fatal("forged graph accepted")
		}
	}
}

func TestSourceGraphContextOptionalClosureMatrix(t *testing.T) {
	if _, err := BuildSourceGraphWithContext(SourceGraphInput{}); !hasCode(err, SourceRootMissing) {
		t.Fatalf("nil root=%v", err)
	}
	root := sourcePin("root", "refs/tags/v1")
	malformed := root
	malformed.Commit = "short"
	if _, err := BuildSourceGraphWithContext(SourceGraphInput{Root: &malformed}); !hasCode(err, SourceInvalid) {
		t.Fatalf("malformed root classified as optional=%v", err)
	}
	absent, err := BuildSourceGraphWithContext(SourceGraphInput{Root: &root})
	if err != nil || absent.ClosureStatus != SourceOptionalEmpty {
		t.Fatalf("absent closure=%+v err=%v", absent, err)
	}
	present, err := BuildSourceGraphWithContext(SourceGraphInput{Root: &root, DependencyClosure: &SourceDependencyClosure{Pins: []PinnedSource{}}})
	if err != nil || present.ClosureStatus != SourceClosurePresent || present.Graph.Digest != absent.Graph.Digest {
		t.Fatalf("present closure=%+v err=%v", present, err)
	}
	if _, err := BuildSourceGraphWithContext(SourceGraphInput{Root: &root, DependencyClosure: &SourceDependencyClosure{}}); !hasCode(err, SourceClosureInput) {
		t.Fatalf("nil pins=%v", err)
	}
	root.Dependencies = []string{"dep"}
	if _, err := BuildSourceGraphWithContext(SourceGraphInput{Root: &root}); !hasCode(err, SourceDependencyMissing) {
		t.Fatalf("absent declared dependency=%v", err)
	}
	if _, err := BuildSourceGraphWithContext(SourceGraphInput{Root: &root, DependencyClosure: &SourceDependencyClosure{Pins: []PinnedSource{}}}); !hasCode(err, SourceDependencyMissing) {
		t.Fatalf("empty declared dependency=%v", err)
	}
	dep := sourcePin("dep", "refs/tags/v1")
	dep.Origin = "https://example.test/dep"
	if got, err := BuildSourceGraphWithContext(SourceGraphInput{Root: &root, DependencyClosure: &SourceDependencyClosure{Pins: []PinnedSource{dep}}}); err != nil || got.ClosureStatus != SourceClosurePresent || len(got.Graph.Nodes) != 2 {
		t.Fatalf("complete closure=%+v err=%v", got, err)
	}
	complete, err := BuildSourceGraphWithContext(SourceGraphInput{Root: &root, DependencyClosure: &SourceDependencyClosure{Pins: []PinnedSource{dep}}})
	if err != nil {
		t.Fatal(err)
	}
	complete.Graph.Nodes[0].Provenance[0].Alias = "changed"
	again, err := BuildSourceGraphWithContext(SourceGraphInput{Root: &root, DependencyClosure: &SourceDependencyClosure{Pins: []PinnedSource{dep}}})
	if err != nil || again.Graph.Nodes[0].Provenance[0].Alias == "changed" {
		t.Fatalf("context graph was not defensive: %+v err=%v", again, err)
	}
}

func TestValidateSourceGraphRejectsRehashedDuplicateTopology(t *testing.T) {
	root, dep := sourcePin("root", "refs/tags/v1"), sourcePin("dep", "refs/tags/v1")
	dep.Origin = "https://example.test/dep"
	root.Dependencies = []string{"dep"}
	g, err := BuildSourceGraph([]PinnedSource{root, dep})
	if err != nil {
		t.Fatal(err)
	}
	bad := cloneSourceGraph(*g)
	bad.Edges = append(bad.Edges, bad.Edges[0])
	bad.Digest, err = sourceGraphDigest(bad.Nodes, bad.Edges)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceGraph(&bad); err == nil {
		t.Fatal("rehashed duplicate edge accepted")
	}
	bad = cloneSourceGraph(*g)
	bad.Nodes[1].Provenance[0].Alias = bad.Nodes[0].Provenance[0].Alias
	bad.Digest, err = sourceGraphDigest(bad.Nodes, bad.Edges)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceGraph(&bad); err == nil {
		t.Fatal("rehashed duplicate alias accepted")
	}
}

func TestSourceGraphNodeEdgeAndDepthLimits(t *testing.T) {
	if _, err := BuildSourceGraph(make([]PinnedSource, maxSourceNodes+1)); !hasCode(err, SourceLimit) {
		t.Fatalf("node limit=%v", err)
	}
	chain := make([]PinnedSource, maxSourceDepth+1)
	for i := range chain {
		chain[i] = sourcePin(fmt.Sprintf("d%03d", i), "refs/tags/v1")
		chain[i].Origin = fmt.Sprintf("https://example.test/depth/%d", i)
		chain[i].Commit = fmt.Sprintf("%040x", i+1)
		if i > 0 {
			chain[i].Dependencies = []string{fmt.Sprintf("d%03d", i-1)}
		}
	}
	if _, err := BuildSourceGraph(chain); !hasCode(err, SourceLimit) {
		t.Fatalf("depth limit=%v", err)
	}
	edges := make([]PinnedSource, maxSourceNodes)
	for i := range edges {
		edges[i] = sourcePin(fmt.Sprintf("e%04d", i), "refs/tags/v1")
		edges[i].Origin = fmt.Sprintf("https://example.test/edge/%d", i)
		edges[i].Commit = fmt.Sprintf("%040x", i+1)
		if i >= 5 {
			edges[i].Dependencies = []string{fmt.Sprintf("e%04d", i-5), fmt.Sprintf("e%04d", i-4), fmt.Sprintf("e%04d", i-3), fmt.Sprintf("e%04d", i-2), fmt.Sprintf("e%04d", i-1)}
		}
	}
	if _, err := BuildSourceGraph(edges); !hasCode(err, SourceLimit) {
		t.Fatalf("edge limit=%v", err)
	}
}

func errorsAs(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		type unwrap interface{ Unwrap() error }
		u, ok := err.(unwrap)
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return false
}

func hasCode(err error, code string) bool { var e *Error; return errorsAs(err, &e) && e.Code == code }
