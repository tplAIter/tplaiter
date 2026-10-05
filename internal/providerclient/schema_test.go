package providerclient

import (
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestRequestMatchesPermittedWireSchema(t *testing.T) {
	schema, e := jsonschema.NewCompiler().Compile("testdata/wire/session-v1.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, q := range []request{{Version: APIVersion, ID: "hello", Op: "handshake", SchemaVersions: []string{DescriptorVersion}, RequiredOperations: []string{"describe", "knowledge"}, RequiredCapabilities: []string{"local-curated-read"}}, {Version: APIVersion, ID: "knowledge-1", Op: "knowledge", SourceID: "example:source:template", Pin: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Projection: "page:1:opaque.synthetic.cursor", DeadlineMS: 2000, Budget: &Budget{ResponseBytes: 32768, MetadataBytes: 16384, SourceBytes: 8192}}} {
		var value any
		if e = json.Unmarshal(wire(t, q), &value); e != nil {
			t.Fatal(e)
		}
		if e = schema.Validate(value); e != nil {
			t.Fatal(e)
		}
	}
}
