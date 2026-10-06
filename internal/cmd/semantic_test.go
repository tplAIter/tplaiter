package cmd

import (
	"bytes"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSemanticPreviewClosedCommandSurface(t *testing.T) {
	c := newSemanticCmd()
	if len(c.Commands()) != 1 || c.Commands()[0].Name() != "preview" {
		t.Fatal("effect command exposed")
	}
	p := c.Commands()[0]
	if resultOperation(p) != resultdto.OperationSemanticPreview || classifyPrerun(p, nil) != prerunTrustOwned {
		t.Fatal("incorrect readonly authenticated route")
	}
	if p.Flags().Lookup("source-input") != nil || p.Flags().Lookup("apply") != nil {
		t.Fatal("authority/effect input exposed")
	}
}

func TestSemanticPublishedSchemasAcceptActualTypedFixtures(t *testing.T) {
	root := testfixture.ModuleRoot(t)
	compiler := jsonschema.NewCompiler()
	for _, name := range []string{"semantic-preview.v1.schema.json", "semantic-preview-result.v1.schema.json"} {
		raw, e := os.ReadFile(filepath.Join(root, "schema", name))
		if e != nil {
			t.Fatal(e)
		}
		value, e := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		uri := "https://tplaiter.dev/schema/" + name
		if e = compiler.AddResource(uri, value); e != nil {
			t.Fatal(e)
		}
		schema, e := compiler.Compile(uri)
		if e != nil {
			t.Fatal(e)
		}
		if name == "semantic-preview.v1.schema.json" {
			value, e = jsonschema.UnmarshalJSON(strings.NewReader(`{"apiVersion":"tplaiter.dev/semantic-preview/v1","action":"anchors","paths":["service.go"]}`))
			if e != nil || schema.Validate(value) != nil {
				t.Fatal("closed anchors schema refuses legal request", e)
			}
			for _, raw := range []string{`{"apiVersion":"tplaiter.dev/semantic-preview/v1","action":"apply","paths":["service.go"]}`, `{"apiVersion":"tplaiter.dev/semantic-preview/v1","action":"anchors","paths":["../service.go"]}`, `{"apiVersion":"tplaiter.dev/semantic-preview/v1","action":"anchors","paths":["service.go"],"permission":true}`} {
				value, _ = jsonschema.UnmarshalJSON(strings.NewReader(raw))
				if schema.Validate(value) == nil {
					t.Fatal("schema accepted unsupported/effect input")
				}
			}
		}
	}
}
