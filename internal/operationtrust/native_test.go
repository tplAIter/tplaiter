package operationtrust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"
)

func nativeWire(manifest []byte) []byte {
	h := sha256.Sum256(manifest)
	return []byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"sha256:` + hex.EncodeToString(h[:]) + `","dependencies":[]}`)
}

func TestDecodeNativeContractClosedAndSchemaParity(t *testing.T) {
	manifest := []byte("apiVersion: tplaiter.dev/v1alpha1\nkind: Template\n")
	raw := nativeWire(manifest)
	if _, err := DecodeNativeContract(raw, manifest); err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	schema, err := c.Compile("../../schema/native-template-contract.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("schema rejected valid Go wire: %v", err)
	}
	for _, bad := range [][]byte{
		[]byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"sha256:` + strings.Repeat("0", 64) + `","dependencies":[]}`),
		append(raw[:len(raw)-1], []byte(`,"portable":true}`)...),
		[]byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"sha256:` + strings.Repeat("0", 64) + `","dependencies":["x"]}`),
	} {
		if _, err := DecodeNativeContract(bad, manifest); !errors.Is(err, ErrSourceAdapterUnsupported) {
			t.Fatalf("bad native wire error = %v", err)
		}
	}
}

func TestDecodeSourceSelectionIsClosedPinnedAndEmpty(t *testing.T) {
	good := `{"apiVersion":"tplaiter.dev/source-selection-input/v1","subject":{"origin":"example.test/source","templatePath":".","requestedRef":"` + strings.Repeat("a", 40) + `","commit":"` + strings.Repeat("a", 40) + `","treeSHA256":"sha256:` + strings.Repeat("b", 64) + `","contractSHA256":"sha256:` + strings.Repeat("c", 64) + `"},"evidence":{"format":"tplaiter.dev/publisher-statement/v1","statementCAS":"sha256:` + strings.Repeat("d", 64) + `","signatureCAS":"sha256:` + strings.Repeat("e", 64) + `","keyFingerprint":"sha256:` + strings.Repeat("f", 64) + `","checkpointCAS":"sha256:` + strings.Repeat("1", 64) + `","inclusionProofCAS":"sha256:` + strings.Repeat("2", 64) + `"},"dependencies":[]}`
	if _, err := DecodeSourceSelection([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(good, `"dependencies":[]`, `"dependencies":["other"]`, 1),
		strings.Replace(good, `"requestedRef":"`+strings.Repeat("a", 40), `"requestedRef":"`+strings.Repeat("b", 40), 1),
		strings.Replace(good, `"dependencies":[]`, `"dependencies":[],"authority":"forged"`, 1),
	} {
		if _, err := DecodeSourceSelection([]byte(bad)); !errors.Is(err, ErrSourceAdapterUnsupported) {
			t.Fatalf("bad source input error = %v", err)
		}
	}
	if _, err := DecodeSourceSelection(make([]byte, 1<<20+1)); !errors.Is(err, ErrSourceAdapterUnsupported) {
		t.Fatal(err)
	}
}

func TestNativeSchemaRejectsNonemptyDependencies(t *testing.T) {
	if _, err := os.Stat("../../schema/native-template-contract.v1.schema.json"); err != nil {
		t.Fatal(err)
	}
}

func TestNativeManifestStructuralGuardsPrecedeExistingParser(t *testing.T) {
	valid, err := os.ReadFile("../../testdata/fixtures/single-basic/template.manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contract := nativeWire(valid)
	if _, err := requireNativeContract(contract, valid); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
	for _, raw := range [][]byte{
		[]byte("apiVersion: tplaiter.dev/v1alpha1\nkind: Template\nkind: Template\n"),
		[]byte("apiVersion: tplaiter.dev/v1alpha1\nkind: Template\nKind: Template\n"),
		[]byte("base: &base {x: y}\napiVersion: tplaiter.dev/v1alpha1\nkind: Template\nmetadata: *base\n"),
		[]byte("apiVersion: tplaiter.dev/v1alpha1\nkind: Template\n---\nkind: Template\n"),
		[]byte("apiVersion: tplaiter.dev/v1alpha1\nkind: Template\n---\n: [\n"),
	} {
		if _, err := requireNativeContract(nativeWire(raw), raw); !errors.Is(err, ErrSourceAdapterUnsupported) {
			t.Fatalf("structural manifest accepted: %v", err)
		}
	}
}
