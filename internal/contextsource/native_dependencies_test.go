package contextsource

import (
	"encoding/json"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
)

func contextTestManifest() []byte {
	return []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: public-context\n  version: 1.0.0\n  description: Public task context\nengine:\n  type: gotemplate\n  root: files\nsettings: []\n")
}
func contextTestContract() NativeContextContract {
	return NativeContextContract{APIVersion: NativeContextContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(contextTestManifest()), Dependencies: []ContextDependency{{Alias: "dep", Origin: "https://example.test/source", TemplatePath: ".", CommitAlgorithm: "sha1", Commit: strings.Repeat("a", 40), TreeDigest: "sha256:" + strings.Repeat("b", 64), ContractDigest: "sha256:" + strings.Repeat("c", 64)}}}
}
func contextTestProof() ContextSourceProof {
	return ContextSourceProof{Subject: operationtrust.SelectionSubject{Origin: "https://example.test/source", TemplatePath: ".", RequestedRef: strings.Repeat("a", 40), Commit: strings.Repeat("a", 40), TreeSHA256: "sha256:" + strings.Repeat("b", 64), ContractSHA256: "sha256:" + strings.Repeat("c", 64)}, Evidence: operationtrust.SelectionEvidence{Format: "tplaiter.dev/publisher-statement/v1", StatementCAS: "sha256:" + strings.Repeat("d", 64), SignatureCAS: "sha256:" + strings.Repeat("e", 64), KeyFingerprint: "sha256:" + strings.Repeat("f", 64), CheckpointCAS: "sha256:" + strings.Repeat("1", 64), InclusionProofCAS: "sha256:" + strings.Repeat("2", 64)}}
}
func contextSchema(t *testing.T, name string) *js.Schema {
	t.Helper()
	schema, err := js.NewCompiler().Compile("../../schema/" + name + ".schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}
func contextSchemaCheck(t *testing.T, s *js.Schema, raw []byte, want bool) {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	err := s.Validate(v)
	if (err == nil) != want {
		t.Fatalf("schema accepted=%v want=%v error=%v", err == nil, want, err)
	}
}

func TestNativeContextV2ClosedWireAndSchema(t *testing.T) {
	manifest := contextTestManifest()
	raw := contextJSON(t, contextTestContract())
	schema := contextSchema(t, "native-template-contract.v2")
	if _, err := DecodeNativeContextContractV2(raw, manifest); err != nil {
		t.Fatal(err)
	}
	contextSchemaCheck(t, schema, raw, true)
	for _, bad := range []string{
		strings.Replace(string(raw), `"apiVersion":"tplaiter.dev/native-template-contract/v2"`, `"apiVersion":"tplaiter.dev/native-template-contract/v1"`, 1),
		strings.Replace(string(raw), `"manifestPath":"template.manifest.yaml",`, "", 1),
		strings.Replace(string(raw), `"manifestPath"`, `"ManifestPath"`, 1),
		strings.Replace(string(raw), `"dependencies":[`, `"selfCommit":"`+strings.Repeat("a", 40)+`","dependencies":[`, 1),
		strings.Replace(string(raw), `"commitAlgorithm":"sha1"`, `"commitAlgorithm":"sha256"`, 1),
		strings.Replace(string(raw), `"alias":"dep"`, `"alias":null`, 1),
	} {
		if _, err := DecodeNativeContextContractV2([]byte(bad), manifest); err == nil {
			t.Fatal("invalid contract accepted")
		}
		contextSchemaCheck(t, schema, []byte(bad), false)
	}
	duplicate := strings.Replace(string(raw), `"kind":"NativeTemplate"`, `"kind":"NativeTemplate","kind":"NativeTemplate"`, 1)
	if _, err := DecodeNativeContextContractV2([]byte(duplicate), manifest); err == nil {
		t.Fatal("duplicate key accepted")
	}
	c := contextTestContract()
	c.Dependencies = append(c.Dependencies, c.Dependencies[0])
	if _, err := DecodeNativeContextContractV2(contextJSON(t, c), manifest); err == nil {
		t.Fatal("duplicate alias accepted")
	}
	if _, err := DecodeNativeContextContractV2(raw, append(manifest, ' ')); err == nil {
		t.Fatal("manifest mismatch accepted")
	}
	for _, bad := range [][]byte{append(manifest, []byte("---\nother: true\n")...), []byte("root: &a {}\nother: *a\n"), []byte("Root: one\nroot: two\n")} {
		c := contextTestContract()
		c.ManifestSHA256 = evidencecas.Digest(bad)
		if _, err := DecodeNativeContextContractV2(contextJSON(t, c), bad); err == nil {
			t.Fatal("invalid native manifest accepted")
		}
	}
	if _, err := DecodeNativeContextContractV2(make([]byte, (1<<20)+1), manifest); err == nil {
		t.Fatal("byte bound ignored")
	}
	// New data cannot enter the unchanged v1 native adapter.
	if _, err := operationtrust.DecodeNativeContract(raw, manifest); err == nil {
		t.Fatal("v1 admitted v2")
	}
	old := operationtrust.NativeContract{APIVersion: operationtrust.NativeContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: []string{}}
	if _, err := operationtrust.DecodeNativeContract(contextJSON(t, old), manifest); err != nil {
		t.Fatal(err)
	}
	old.Dependencies = []string{"dep"}
	if _, err := operationtrust.DecodeNativeContract(contextJSON(t, old), manifest); err == nil {
		t.Fatal("v1 nonempty guard weakened")
	}
}

func TestSourceSelectionV2ClosedWireAndSchema(t *testing.T) {
	in := ContextSourceSelection{APIVersion: ContextSourceSelectionAPIVersion, Root: contextTestProof(), Sources: []ContextSourceProof{}}
	raw := contextJSON(t, in)
	schema := contextSchema(t, "source-selection-input.v2")
	if _, err := DecodeSourceSelectionV2(raw); err != nil {
		t.Fatal(err)
	}
	contextSchemaCheck(t, schema, raw, true)
	for _, bad := range []string{strings.Replace(string(raw), `"sources":[]`, `"sources":null`, 1), strings.Replace(string(raw), `,"sources":[]`, "", 1), strings.Replace(string(raw), `"sources":[]`, `"sources":[],"authenticated":true`, 1), strings.Replace(string(raw), `"root"`, `"Root"`, 1), strings.Replace(string(raw), `"format":"tplaiter.dev/publisher-statement/v1"`, `"format":"caller-grant"`, 1)} {
		if _, err := DecodeSourceSelectionV2([]byte(bad)); err == nil {
			t.Fatal("invalid selection accepted")
		}
		contextSchemaCheck(t, schema, []byte(bad), false)
	}
	in.Sources = []ContextSourceProof{in.Root}
	if _, err := DecodeSourceSelectionV2(contextJSON(t, in)); err == nil {
		t.Fatal("duplicate source accepted")
	}
	in.Sources = []ContextSourceProof{}
	in.Root.Subject.RequestedRef = "main"
	if _, err := DecodeSourceSelectionV2(contextJSON(t, in)); err == nil {
		t.Fatal("mutable ref accepted")
	}
	if _, err := DecodeSourceSelectionV2(make([]byte, (1<<20)+1)); err == nil {
		t.Fatal("input byte bound ignored")
	}
	if _, err := operationtrust.DecodeSourceSelection(raw); err == nil {
		t.Fatal("v1 accepted v2")
	}
}
