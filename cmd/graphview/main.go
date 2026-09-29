// Command graphview creates a self-contained local graph explorer.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/graphview"
	"github.com/tplAIter/tplaiter/internal/semanticgraph"
)

func main() {
	input := flag.String("input", "", "graph JSON input")
	root := flag.String("root", "", "source directory to analyze or context root")
	sourcePath := flag.String("source-graph", "", "SourceGraph JSON")
	exportPath := flag.String("export-graph", "", "ExportGraph JSON")
	relations := flag.String("application-relations", "", "attributed application relation JSON")
	selected := flag.String("selected", "", "comma-separated context node IDs")
	include := flag.Bool("include-source", false, "include verified source excerpts")
	contextOut := flag.String("context-output", "", "context pack JSON output")
	output := flag.String("output", "graph.html", "HTML output")
	flag.Parse()
	var d graphdoc.Document
	var err error
	if *input != "" {
		var b []byte
		b, err = readBounded(*input)
		if err == nil {
			d, err = graphdoc.Decode(b)
		}
	} else if *sourcePath != "" {
		var b []byte
		var s deps.SourceGraph
		var x *exports.ExportGraph
		b, err = readBounded(*sourcePath)
		if err == nil {
			err = canonicaljson.DecodeStrict(b, &s)
		}
		if err == nil && *exportPath != "" {
			b, err = readBounded(*exportPath)
			if err == nil {
				var e exports.ExportGraph
				err = canonicaljson.DecodeStrict(b, &e)
				if err == nil {
					got, digestErr := exports.ExportGraphDigest(e.Selected, e.Edges)
					if digestErr != nil || got != e.Digest || validateExportGraph(e) != nil {
						err = fmt.Errorf("graphview: invalid export graph digest")
					}
				}
				x = &e
			}
		}
		var a []graphview.ApplicationRelation
		if err == nil && *relations != "" {
			b, err = readBounded(*relations)
			if err == nil {
				err = canonicaljson.DecodeStrict(b, &a)
			}
		}
		if err == nil {
			d, err = graphview.FromContracts(&s, x, a)
		}
	} else if *root != "" {
		d, err = semanticgraph.Analyze(context.Background(), *root, semanticgraph.Options{})
	} else {
		err = fmt.Errorf("provide -input, -source-graph, or -root")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var p *contextpack.Pack
	if *contextOut != "" || *include || *selected != "" {
		r := contextpack.Request{Root: *root, IncludeSource: *include}
		if *selected != "" {
			for _, id := range split(*selected) {
				r.Selected = append(r.Selected, id)
			}
		}
		v, e := contextpack.Build(d, r)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
		if e = contextpack.Verify(d, *root, v); e != nil && *include {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
		p = &v
		if *contextOut != "" {
			// The cap is defined over this compact wire representation. Do not
			// pretty-print after Build has accounted for it.
			b, _ := json.Marshal(v)
			if len(b) != v.Bytes || len(b) > contextpack.HardLimit {
				fmt.Fprintln(os.Stderr, "contextpack: emitted serialization exceeds accounting")
				os.Exit(2)
			}
			if e = os.WriteFile(*contextOut, b, 0o600); e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(2)
			}
		}
	}
	html, err := graphview.Render(d, graphview.Options{Context: p})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err = os.WriteFile(*output, html, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *output, len(html))
}

func split(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func readBounded(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, fmt.Errorf("graphview: input must be a regular file up to 1 MiB")
	}
	return os.ReadFile(path)
}

func validateExportGraph(g exports.ExportGraph) error {
	if len(g.Selected) == 0 || len(g.Selected) > 4096 || len(g.Edges) > 4096 {
		return fmt.Errorf("limit")
	}
	ids := map[string]bool{}
	for _, s := range g.Selected {
		if s.ID == "" || s.Name == "" || ids[s.ID] {
			return fmt.Errorf("selected")
		}
		ids[s.ID] = true
	}
	edges := map[string]bool{}
	for _, e := range g.Edges {
		k := e.Dependency + "\x00" + e.Consumer
		if !ids[e.Dependency] || !ids[e.Consumer] || e.Dependency == e.Consumer || edges[k] {
			return fmt.Errorf("edge")
		}
		edges[k] = true
	}
	return nil
}
