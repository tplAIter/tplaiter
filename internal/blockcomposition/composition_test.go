package blockcomposition

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/blockexport"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/provenance"
)

func digest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func source(provider string, c byte) provenance.RootSubject {
	return provenance.RootSubject{Origin: "https://example.test/" + provider, TemplatePath: "templates/" + provider, RequestedRef: "refs/tags/v1", Commit: strings.Repeat(string(c), 40), TreeSHA256: digest('1'), ContractSHA256: digest('2'), StatementCAS: digest('3'), SignatureCAS: digest('4'), KeyFingerprint: digest('5'), CheckpointCAS: digest('6'), InclusionProofCAS: digest('7')}
}

func provider(name string, c byte, bodies map[string][]byte) Provider {
	return Provider{Name: name, Source: managedblocks.ProviderSource{Provider: name, Source: source(name, c)}, Bodies: bodies}
}

func export(name, providerName, target string, blocks ...blockexport.Block) blockexport.BlockExport {
	for i := range blocks {
		blocks[i].Provider = providerName
	}
	return blockexport.BlockExport{APIVersion: blockexport.APIVersion, Kind: blockexport.Kind, Metadata: blockexport.Metadata{ID: name, Version: "1.0.0"}, Compatibility: blockexport.Compatibility{Tplater: ">=0.3.0", MarkerSchema: blockexport.MarkerSchema}, MergeStrategy: blockexport.MergeStrategy, Formatter: blockexport.Formatter{Adapter: "none", OptionsDigest: digest('a')}, Targets: []blockexport.Target{{Path: target, Blocks: blocks}}}
}

func block(id, body string, order int) blockexport.Block {
	return blockexport.Block{ID: id, Body: body, Layout: "layer_files", Order: order}
}

func TestComposeBindsProvidersBodiesAndDefensivelyCopies(t *testing.T) {
	path := "internal/service/service.go"
	in := Input{Exports: []blockexport.BlockExport{
		export("root", "root", path, block("root.service", "root.tmpl", 10)),
		export("security", "security", path, block("security.policy", "policy.tmpl", 20)),
	}, Providers: []Provider{
		provider("security", 'b', map[string][]byte{"policy.tmpl": []byte("policy\n")}),
		provider("root", 'a', map[string][]byte{"root.tmpl": []byte("root\n")}),
	}, Skeletons: map[string][]byte{path: []byte("package service\r\n")}}
	got, err := Compose(in)
	if err != nil {
		t.Fatal(err)
	}
	want := "package service\r\n// tplater:managed-begin id=root.service provider=root\r\nroot\r\n// tplater:managed-end id=root.service\r\n// tplater:managed-begin id=security.policy provider=security\r\npolicy\r\n// tplater:managed-end id=security.policy\r\n"
	if len(got.Targets) != 1 || !bytes.Equal(got.Targets[0].Content, []byte(want)) || strings.Join(got.Targets[0].IDs(), ",") != "root.service,security.policy" {
		t.Fatalf("result=%+v", got)
	}
	got.Targets[0].Content[0] = 'X'
	again, err := Compose(in)
	if err != nil || again.Targets[0].Content[0] == 'X' {
		t.Fatalf("result aliases input/output: %v", err)
	}
}

func TestComposeRejectsMissingDuplicateAndConflictingProviderBindings(t *testing.T) {
	path := "a.go"
	base := Input{Exports: []blockexport.BlockExport{export("root", "root", path, block("root.block", "body.tmpl", 1))}, Providers: []Provider{provider("root", 'a', map[string][]byte{"body.tmpl": []byte("body\n")})}, Skeletons: map[string][]byte{path: []byte("package p\n")}}
	for name, mutate := range map[string]func(*Input){
		"missing provider": func(v *Input) { v.Providers = nil },
		"missing body":     func(v *Input) { v.Providers[0].Bodies = map[string][]byte{} },
		"duplicate provider": func(v *Input) {
			v.Providers = append(v.Providers, v.Providers[0])
		},
		"conflicting source label": func(v *Input) { v.Providers[0].Source.Provider = "other" },
		"invalid source":           func(v *Input) { v.Providers[0].Source.Source.Commit = "short" },
		"missing skeleton":         func(v *Input) { v.Skeletons = nil },
	} {
		t.Run(name, func(t *testing.T) {
			in := base
			in.Providers = append([]Provider(nil), base.Providers...)
			in.Skeletons = map[string][]byte{path: append([]byte(nil), base.Skeletons[path]...)}
			mutate(&in)
			if _, err := Compose(in); err == nil {
				t.Fatal("invalid composition accepted")
			}
		})
	}
}

func TestComposeStableTypedDiagnostics(t *testing.T) {
	_, err := Compose(Input{Exports: []blockexport.BlockExport{export("root", "root", "a.go", block("a", "a.tmpl", 1))}, Skeletons: map[string][]byte{"a.go": nil}})
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != "PROVIDER_MISSING" || typed.Path != "a.go" || typed.ID != "a" {
		t.Fatalf("diagnostic=%v", err)
	}
}
