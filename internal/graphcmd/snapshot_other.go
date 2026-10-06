//go:build !darwin && !linux

package graphcmd

import (
	"context"
	"github.com/tplAIter/tplaiter/internal/semanticgraph"
)

type fileFact struct {
	Path  string `json:"path"`
	Hash  string `json:"hash"`
	Mode  uint32 `json:"mode"`
	Bytes int    `json:"bytes"`
}
type fileSnapshot struct {
	files  []semanticgraph.SourceFile
	facts  []fileFact
	digest string
}

func captureFiles(context.Context, string) (*fileSnapshot, error) {
	return nil, fail("GRAPH_INPUT_TOPOLOGY")
}
func (*fileSnapshot) close()                        {}
func (*fileSnapshot) recheck(context.Context) error { return fail("GRAPH_INPUT_TOPOLOGY") }

func cacheRead(string, string) ([]byte, error)  { return nil, fail("GRAPH_INPUT_TOPOLOGY") }
func cachePublish(string, string, []byte) error { return fail("GRAPH_INPUT_TOPOLOGY") }

func readInputFile(string) ([]byte, error) { return nil, fail("GRAPH_INPUT_TOPOLOGY") }
