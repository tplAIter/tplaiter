package mcpsrv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

var semanticExport = flag.String("semantic-export", "", "external semantic schema/proposal directory")

func init() {
	toolOperations["semantic_preview"] = []resultdto.Operation{resultdto.OperationSemanticPreview}
}
func TestSemanticDescriptorOriginalOraclesAndClosedInput(t *testing.T) {
	s := New("/not-executable", "test", nil)
	defer s.Close()
	before := s.MCP().ListTools()
	original := map[string][]byte{}
	for name, v := range before {
		if name == "semantic_preview" {
			continue
		}
		original[name], _ = json.Marshal(v.Tool)
	}
	s.addSemanticTools()
	for name, raw := range original {
		post, _ := json.Marshal(s.MCP().ListTools()[name].Tool)
		if !bytes.Equal(raw, post) {
			t.Fatal("changed existing tool descriptor", name)
		}
	}
	tool := s.MCP().ListTools()["semantic_preview"].Tool
	if tool.Annotations.ReadOnlyHint == nil || !*tool.Annotations.ReadOnlyHint {
		t.Fatal("readonly hint absent")
	}
	for _, key := range []string{"apply", "sourceInput", "reader", "permission"} {
		if _, ok := tool.InputSchema.Properties[key]; ok {
			t.Fatal("authority/effect parameter exposed")
		}
	}
	if !reflect.DeepEqual(semanticArgv(semanticArgs{Dir: "/project", Input: "/request", MaxBytes: 32768}), []string{"semantic", "preview", "--input", "/request", "--max-bytes", "32768", "--dir", "/project"}) {
		t.Fatal("CLI/MCP path diverges")
	}
}
func TestSemanticInputBoundAndOrdinaryForwarding(t *testing.T) {
	s := New("/not-executable", "test", nil)
	defer s.Close()
	var output bytes.Buffer
	g := newGraphTransport(context.Background(), s, bytes.NewReader(nil), &output, nil)
	input := &semanticInput{input: bufio.NewReader(bytes.NewBufferString("ordinary\n")), graph: g}
	raw, e := io.ReadAll(input)
	if e != nil || string(raw) != "ordinary\n" {
		t.Fatal("unrelated bytes changed", e)
	}
	tail := &semanticInfiniteFrameTail{}
	input = &semanticInput{input: bufio.NewReader(tail), graph: g}
	n, e := input.Read(make([]byte, 64))
	if n != 0 || e != errTransportFrameHandled || tail.consumed > maxTransportInputFrame+4096 || len(g.active) != 0 {
		t.Fatal("semantic predecode limit failed", n, e)
	}
	g.close()
}
func TestSemanticSchemaExport(t *testing.T) {
	if *semanticExport == "" {
		t.Skip("explicit external schema export")
	}
	generic, err := resultdto.GenerateSchema()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(*semanticExport, "result.v1.schema.json"), generic, 0600); err != nil {
		t.Fatal(err)
	}
	raw, e := semanticDataSchema()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(*semanticExport, "semantic-preview-result.v1.schema.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	s := New("/not-executable", "test", nil)
	defer s.Close()
	s.addSemanticTools()
	b, e := json.MarshalIndent(s.MCP().ListTools()["semantic_preview"].Tool, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(*semanticExport, "semantic-tool.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
}

type semanticInfiniteFrameTail struct{ consumed int }

func (r *semanticInfiniteFrameTail) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.consumed += len(p)
	return len(p), nil
}
