package graphview

import (
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/graphdoc"
)

func TestRenderContainsDirectedTraversalAndEscapedData(t *testing.T) {
	d := graphdoc.New()
	d.Nodes = []graphdoc.Node{{ID: "a", Kind: "file", Name: "<script>bad</script>"}, {ID: "b", Kind: "declaration", Name: "b"}}
	d.Edges = []graphdoc.Edge{{From: "a", To: "b", Kind: "declares"}}
	if err := d.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	b, err := Render(d, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"dir.value!=='in'", "dir.value!=='out'", "Download context pack", "graphDownload"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(s, "<script>bad</script>") {
		t.Fatal("unescaped graph data")
	}
}
