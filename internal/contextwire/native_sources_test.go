package contextwire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextwire"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/execcontract"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
)

// These assignments are part of the process interface compatibility contract.
var _ execcontract.Runner = (*execx.RecordingRunner)(nil)
var _ execx.Runner = (execcontract.Runner)(nil)
var _ execx.Options = execcontract.Options{}
var _ execcontract.Result = execx.Result{}

func TestClosedSourceDataCannotSupplyAuthorityOrWidenV1(t *testing.T) {
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: public-example\n  version: 1.0.0\n  description: Public example\nengine:\n  type: gotemplate\n  root: files\nsettings: []\n")
	marshal := func(v any) []byte {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	v1 := contextwire.NativeContract{APIVersion: contextwire.NativeContractAPIVersion, Kind: contextwire.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: []string{}}
	if _, e := operationtrust.DecodeNativeContract(marshal(v1), manifest); e != nil {
		t.Fatal(e)
	}
	v1.Dependencies = []string{"dependency"}
	if _, e := operationtrust.DecodeNativeContract(marshal(v1), manifest); e == nil {
		t.Fatal("native v1 nonempty guard weakened")
	}
	v2 := contextwire.NativeContextContract{APIVersion: contextwire.NativeContextContractAPIVersion, Kind: contextwire.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: []contextwire.ContextDependency{}}
	if _, e := contextwire.DecodeNativeContextContractV2(marshal(v2), manifest); e != nil {
		t.Fatal(e)
	}
	if _, e := operationtrust.DecodeNativeContract(marshal(v2), manifest); e == nil {
		t.Fatal("ordinary native adapter accepted v2")
	}
	binding := contextwire.ContextSourceBindings{APIVersion: contextwire.ContextSourceBindingsAPIVersion, Kind: "ContextSourceBindings", Source: contextwire.ContextCatalogBinding{Alias: "root", ProviderID: "public.root", Parameters: []deps.Parameter{}, EntriesPath: "catalog/entries.json", PayloadDirectory: "catalog/payloads", ToolPath: "catalog/tool.md"}, Dependencies: []contextwire.ContextDependencyBinding{}}
	raw := marshal(binding)
	for name, bad := range map[string]string{
		"grant":            strings.Replace(string(raw), `"kind":"ContextSourceBindings"`, `"kind":"ContextSourceBindings","authenticated":true`, 1),
		"duplicate":        strings.Replace(string(raw), `"kind":"ContextSourceBindings"`, `"kind":"ContextSourceBindings","kind":"ContextSourceBindings"`, 1),
		"case":             strings.Replace(string(raw), `"source"`, `"Source"`, 1),
		"missing":          strings.Replace(string(raw), `,"dependencies":[]`, "", 1),
		"null":             strings.Replace(string(raw), `"parameters":[]`, `"parameters":null`, 1),
		"object-parameter": strings.Replace(string(raw), `"parameters":[]`, `"parameters":[{"name":"flavor","value":{"mode":"plain"}}]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := contextwire.DecodeContextSourceBindingsV2([]byte(bad)); e == nil {
				t.Fatal("non-closed data accepted")
			}
		})
	}
	for _, dst := range []any{nil, binding, (*contextwire.ContextSourceBindings)(nil)} {
		if e := contextwire.DecodeRequired(raw, dst, 64<<10); e == nil {
			t.Fatal("invalid destination accepted")
		}
	}
	var out contextwire.ContextSourceBindings
	if e := contextwire.DecodeRequired(raw, &out, len(raw)); e != nil {
		t.Fatal(e)
	}
	if e := contextwire.DecodeRequired(raw, &out, len(raw)-1); e == nil {
		t.Fatal("decoder limit raised")
	}
}
