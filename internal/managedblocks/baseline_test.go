package managedblocks

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/provenance"
)

func baselineSource() provenance.RootSubject {
	d := func(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
	return provenance.RootSubject{Origin: "https://example.test/source", TemplatePath: "templates/root", RequestedRef: "refs/tags/v1", Commit: strings.Repeat("a", 40), TreeSHA256: d('1'), ContractSHA256: d('2'), StatementCAS: d('3'), SignatureCAS: d('4'), KeyFingerprint: d('5'), CheckpointCAS: d('6'), InclusionProofCAS: d('7')}
}

func TestBuildBaselineSeparatesSkeletonAndBlocksAndCopies(t *testing.T) {
	input := map[string][]byte{"a.go": []byte("package p\n// tplater:managed-begin id=one provider=root\nbody\n// tplater:managed-end id=one\n// tplater:managed-begin id=two provider=root\nbody two\n// tplater:managed-end id=two\n")}
	b, err := BuildBaseline(input, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Files["a.go"].Skeleton.Body != "package p\n" || b.Files["a.go"].Blocks["one"].Body != "body\n" || b.Files["a.go"].Blocks["one"].Anchor.Ordinal != 0 || b.Files["a.go"].Blocks["one"].Anchor.Before != "two" || b.Files["a.go"].Blocks["two"].Anchor.After != "one" {
		t.Fatalf("baseline=%+v", b)
	}
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	round, err := ParseBaseline(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := round.Marshal()
	if !bytes.Equal(raw, again) {
		t.Fatal("baseline round trip changed canonical bytes")
	}
	clone := b.Clone()
	f := clone.Files["a.go"]
	x := f.Blocks["one"]
	x.Body = "mutated"
	f.Blocks["one"] = x
	clone.Files["a.go"] = f
	if b.Files["a.go"].Blocks["one"].Body == "mutated" {
		t.Fatal("clone aliases block body")
	}
}

func TestBaselineRejectsUnknownProviderAndInvalidPath(t *testing.T) {
	input := map[string][]byte{"../escape": []byte("x")}
	if _, err := BuildBaseline(input, nil, nil); err == nil {
		t.Fatal("traversal path accepted")
	}
	valid := map[string][]byte{"a.go": []byte("// tplater:managed-begin id=x provider=missing\nbody\n// tplater:managed-end id=x\n")}
	if _, err := BuildBaseline(valid, nil, nil); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestBaselineNormalizesAcceptedNoncanonicalJSON(t *testing.T) {
	b, err := BuildBaseline(map[string][]byte{"a.go": []byte("package p\n")}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	noncanonical := []byte(" { \"files\" : { \"a.go\" : { \"blocks\" : {}, \"skeleton\" : { \"bodySHA256\" : \"" + b.Files["a.go"].Skeleton.BodySHA256 + "\", \"body\" : \"package p\\n\" } } }, \"schema\" : 1 } \n")
	parsed, err := ParseBaseline(noncanonical)
	if err != nil {
		t.Fatalf("accepted noncanonical baseline rejected: %v", err)
	}
	got, err := parsed.Marshal()
	if err != nil || !bytes.Equal(got, canonical) {
		t.Fatalf("normalization changed semantic baseline: err=%v got=%s want=%s", err, got, canonical)
	}
}

func TestBaselineUsesSharedRootSubjectValidation(t *testing.T) {
	for name, mutate := range map[string]func(*provenance.RootSubject){
		"non-hex commit":        func(s *provenance.RootSubject) { s.Commit = strings.Repeat("g", 40) },
		"invalid origin":        func(s *provenance.RootSubject) { s.Origin = "bad origin" },
		"invalid requested ref": func(s *provenance.RootSubject) { s.RequestedRef = "bad ref" },
		"backslash path":        func(s *provenance.RootSubject) { s.TemplatePath = `a\\b` },
		"control path":          func(s *provenance.RootSubject) { s.TemplatePath = "a\x00b" },
	} {
		t.Run(name, func(t *testing.T) {
			source := baselineSource()
			mutate(&source)
			if source.Validate() == nil {
				t.Fatal("shared validator accepted hostile source")
			}
			if _, err := BuildBaseline(map[string][]byte{"a.go": []byte("package p\n")}, []ProviderSource{{Provider: "root", Source: source}}, nil); err == nil {
				t.Fatal("baseline accepted hostile source")
			}
		})
	}
}

func TestBaselineUsesProviderGrammarForDirectAndParsedRecords(t *testing.T) {
	input := map[string][]byte{"a.go": []byte("// tplater:managed-begin id=one provider=provider.v1/path-2\nbody\n// tplater:managed-end id=one\n")}
	b, err := BuildBaseline(input, []ProviderSource{{Provider: "provider.v1/path-2", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatalf("valid provider grammar rejected by build: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("valid provider grammar rejected by direct validation: %v", err)
	}
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBaseline(raw); err != nil {
		t.Fatalf("valid provider grammar rejected by parser: %v", err)
	}
	for _, provider := range []string{"bad provider", "***"} {
		t.Run(provider, func(t *testing.T) {
			direct := b.Clone()
			file := direct.Files["a.go"]
			block := file.Blocks["one"]
			block.Provider = provider
			file.Blocks["one"] = block
			direct.Files["a.go"] = file
			if err := direct.Validate(); err == nil {
				t.Fatalf("direct baseline accepted hostile provider %q", provider)
			}
			parsedRaw := []byte(strings.Replace(string(raw), `"provider":"provider.v1/path-2"`, `"provider":"`+provider+`"`, 1))
			if _, err := ParseBaseline(parsedRaw); err == nil {
				t.Fatalf("parsed baseline accepted hostile provider %q", provider)
			}
		})
	}
}
