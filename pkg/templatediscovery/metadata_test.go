package templatediscovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"os"
	"strings"
	"testing"
)

func metadataFixture() Metadata {
	return Metadata{APIVersion: MetadataAPIVersion, CandidatePin: OriginalPin{SourceID: "example", Revision: "1.0.0", ContentSHA256: Digest([]byte("original closed pack"))}, Metadata: MetadataDescription{Name: "example", Version: "1.0.0", Description: "Neutral service description", Labels: map[string][]string{"tags": {"service", "сервис"}, "lang": {"go"}, "keywords": {"service", "сервис"}}, CandidateKind: KindTemplate, Readiness: Experimental, UseCases: []string{"Создать сервис"}, Blocks: []MetadataReference{}, Skills: []MetadataReference{}}}
}
func TestDiscoveryMetadataStrictCodecCustody(t *testing.T) {
	raw, _ := json.Marshal(metadataFixture())
	m, err := DecodeMetadata(raw)
	if err != nil {
		t.Fatal(err)
	}
	pin := SourcePin{Qualification: "owner-supplied", SourceID: m.CandidatePin.SourceID, Revision: m.CandidatePin.Revision, ContentSHA256: m.CandidatePin.ContentSHA256}
	c, err := CandidateFromMetadata(m, pin)
	if err != nil || c.MetadataSHA256 != Digest(raw) {
		t.Fatal("raw binding", err)
	}
	r, err := Rank(Query{Task: "Создать сервис"}, []Candidate{c})
	if err != nil || len(r.Suggestions) != 1 {
		t.Fatal("declared Russian usecase not matched", err)
	}
	if len(r.Suggestions[0].NextToolCalls) != 0 {
		t.Fatal("ranker manufactured private toolcall")
	}
	pin.Revision = "different"
	if _, err := CandidateFromMetadata(m, pin); err == nil {
		t.Fatal("original pin ignored")
	}
	pin.Revision = m.CandidatePin.Revision
	m.Metadata.Description = "caller changed bytes"
	if _, err := CandidateFromMetadata(m, pin); err == nil {
		t.Fatal("decoded metadata custody lost")
	}
	whitespace := append([]byte(" \n"), raw...)
	sha, err := MetadataSHA256(whitespace)
	if err != nil || sha != Digest(whitespace) || sha == Digest(raw) {
		t.Fatal("semantic/raw digest confusion")
	}
}
func TestDiscoveryMetadataRejectsClosedShapeAndByteLimits(t *testing.T) {
	raw, _ := json.Marshal(metadataFixture())
	bad := [][]byte{bytes.Replace(raw, []byte(`"apiVersion":`), []byte(`"unknown":1,"apiVersion":`), 1), bytes.Replace(raw, []byte(`"name":"example"`), []byte(`"name":"first","name":"example"`), 1), bytes.Replace(raw, []byte(`"lang":["go"]`), []byte(`"lang":["go"],"lang":["go"]`), 1), bytes.Replace(raw, []byte(`"blocks":[]`), []byte(`"blocks":null`), 1), bytes.Replace(raw, []byte(`"labels":{`), []byte(`"Labels":{`), 1), bytes.Replace(raw, []byte(`"experimental"`), []byte(`"production-approved"`), 1), append(append([]byte{}, raw...), []byte(`{}`)...), []byte(`null`), []byte(strings.Repeat(" ", MaxMetadataBytes+1))}
	for i, b := range bad {
		if _, err := DecodeMetadata(b); err == nil {
			t.Fatalf("case%d accepted", i)
		}
	}
	for _, change := range []func(*Metadata){func(m *Metadata) { m.Metadata.Description = " \n\t" }, func(m *Metadata) { m.Metadata.Description = strings.Repeat("я", 2049) }, func(m *Metadata) { m.Metadata.Labels = map[string][]string{} }, func(m *Metadata) { m.Metadata.Labels["empty"] = []string{} }, func(m *Metadata) { m.Metadata.Labels["keywords"] = []string{strings.Repeat("я", 129)} }} {
		m := metadataFixture()
		change(&m)
		raw, _ := json.Marshal(m)
		if _, err := DecodeMetadata(raw); err == nil {
			t.Fatal("invalid mandatory/UTF8 byte metadata accepted")
		}
	}
}

func TestDiscoveryMetadataMaximumProjectionAndInvalidUTF8(t *testing.T) {
	// Raw companion bounds stay64 groups/32 values. Normalized Candidate allows
	// one use-cases projection group, and merges up to64 declared values there.
	for _, existing := range []bool{false, true} {
		m := metadataFixture()
		m.Metadata.Labels = map[string][]string{}
		for i := 0; i < 64; i++ {
			m.Metadata.Labels[fmt.Sprintf("group-%02d", i)] = []string{"value"}
		}
		delete(m.Metadata.Labels, "group-00")
		m.Metadata.Labels["tags"] = []string{"service", "сервис"}
		if existing {
			delete(m.Metadata.Labels, "group-01")
			m.Metadata.Labels["use-cases"] = []string{}
			for i := 0; i < 32; i++ {
				m.Metadata.Labels["use-cases"] = append(m.Metadata.Labels["use-cases"], fmt.Sprintf("existing-%02d", i))
			}
		}
		m.Metadata.UseCases = []string{}
		for i := 0; i < 32; i++ {
			m.Metadata.UseCases = append(m.Metadata.UseCases, fmt.Sprintf("declared-%02d", i))
		}
		raw, _ := json.Marshal(m)
		decoded, err := DecodeMetadata(raw)
		if err != nil {
			t.Fatal(err)
		}
		c, err := CandidateFromMetadata(decoded, SourcePin{Qualification: "owner-supplied", SourceID: m.CandidatePin.SourceID, Revision: m.CandidatePin.Revision, ContentSHA256: m.CandidatePin.ContentSHA256})
		if err != nil {
			t.Fatal("valid raw boundary lost during projection", err)
		}
		if !existing && (len(c.Labels) != 65 || len(c.Labels["use-cases"]) != 32) {
			t.Fatal("new group lost", c.Labels)
		}
		if existing && (len(c.Labels) != 64 || len(c.Labels["use-cases"]) != 64) {
			t.Fatal("merged use cases lost", c.Labels)
		}
	}
	raw, _ := json.Marshal(metadataFixture())
	bad := bytes.Replace(raw, []byte("Neutral"), []byte{0xff, 0xfe}, 1)
	if _, err := DecodeMetadata(bad); err == nil {
		t.Fatal("raw invalid UTF8 accepted")
	}
}

func TestDiscoveryMetadataPublishedSchema(t *testing.T) {
	raw, err := os.ReadFile("../../schema/template-discovery-metadata.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err = compiler.AddResource("metadata.schema.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("metadata.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(metadataFixture())
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(input))
	if err != nil || schema.Validate(value) != nil {
		t.Fatal("codec fixture does not match published neutral schema", err)
	}
	m := metadataFixture()
	m.Metadata.Labels = map[string][]string{}
	invalid, _ := json.Marshal(m)
	value, _ = jsonschema.UnmarshalJSON(bytes.NewReader(invalid))
	if schema.Validate(value) == nil {
		t.Fatal("schema permits missing descriptive labels")
	}
	m = metadataFixture()
	m.Metadata.Description = strings.Repeat("я", 2049)
	input, _ = json.Marshal(m)
	value, _ = jsonschema.UnmarshalJSON(bytes.NewReader(input))
	if schema.Validate(value) != nil {
		t.Fatal("schema character length mistakenly claims UTF8 byte bound")
	}
	if _, err = DecodeMetadata(input); err == nil {
		t.Fatal("codec lost documented byte bound")
	}
}

func TestDiscoveryNewCompanionRequiresDescriptiveTags(t *testing.T) {
	for _, values := range [][]string{nil, {}, {""}, {" \n\t"}} {
		m := metadataFixture()
		if values == nil {
			delete(m.Metadata.Labels, "tags")
		} else {
			m.Metadata.Labels["tags"] = values
		}
		raw, _ := json.Marshal(m)
		if _, err := DecodeMetadata(raw); err == nil {
			t.Fatal("new lang/keywords-only/empty/blank tags companion accepted")
		}
	}
	m := metadataFixture()
	m.Metadata.Labels["tags"] = []string{"сервис", "сущность"}
	raw, _ := json.Marshal(m)
	if _, err := DecodeMetadata(raw); err != nil {
		t.Fatal("meaningful declared Russian tags refused", err)
	}
}
