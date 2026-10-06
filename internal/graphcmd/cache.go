package graphcmd

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/semanticgraph"
	"os"
	"strings"
)

const maxCacheBytes = 8 << 20
const analyzerVersion = "tplaiter/ast-files/v1"

type cacheImage struct {
	APIVersion          string            `json:"apiVersion"`
	CacheKey            string            `json:"cacheKey"`
	AnalyzerVersion     string            `json:"analyzerVersion"`
	OptionsDigest       string            `json:"optionsDigest"`
	InputManifestDigest string            `json:"inputManifestDigest"`
	Files               []fileFact        `json:"files"`
	GraphDigest         string            `json:"graphDigest"`
	GraphBytes          int               `json:"graphBytes"`
	NodeCount           int               `json:"nodeCount"`
	EdgeCount           int               `json:"edgeCount"`
	DiagnosticCount     int               `json:"diagnosticCount"`
	Graph               graphdoc.Document `json:"graph"`
}

func cacheKey(s *fileSnapshot) string {
	return hashValue(struct{ Version, Options, Input string }{analyzerVersion, hashValue(semanticgraph.Options{MaxFiles: semanticgraph.MaxInputFiles}), s.digest})
}
func cacheName(key string) string { return strings.TrimPrefix(key, "sha256:") + ".json" }
func decodeCache(raw []byte) (cacheImage, error) {
	var v cacheImage
	if len(raw) > maxCacheBytes {
		return v, fail("GRAPH_CACHE_CORRUPT")
	}
	if e := canonicaljson.DecodeStrict(raw, &v); e != nil {
		return v, e
	}
	b, e := json.Marshal(v.Graph)
	if e != nil {
		return v, e
	}
	if v.APIVersion != "tplaiter.dev/graph-cache/v1" || v.AnalyzerVersion != analyzerVersion || v.GraphBytes != len(b) || v.GraphDigest != v.Graph.Digest || v.NodeCount != len(v.Graph.Nodes) || v.EdgeCount != len(v.Graph.Edges) || v.DiagnosticCount != len(v.Graph.Diagnostics) || len(v.Files) > semanticgraph.MaxInputFiles || hashValue(v.Files) != v.InputManifestDigest {
		return v, fail("GRAPH_CACHE_CORRUPT")
	}
	if e = graphdoc.Verify(v.Graph); e != nil {
		return v, e
	}
	return v, nil
}
func inspectCache(ctx context.Context, root string, s *fileSnapshot) (graphdoc.Document, string, error) {
	raw, e := cacheRead(root, cacheName(cacheKey(s)))
	if errors.Is(e, os.ErrNotExist) {
		old, oe := cacheRead(root, "current.json")
		if errors.Is(oe, os.ErrNotExist) {
			return graphdoc.Document{}, "missing", nil
		}
		if oe != nil {
			return graphdoc.Document{}, "corrupt", oe
		}
		if _, oe = decodeCache(old); oe != nil {
			return graphdoc.Document{}, "corrupt", oe
		}
		return graphdoc.Document{}, "stale", nil
	}
	if e != nil {
		return graphdoc.Document{}, "corrupt", e
	}
	v, e := decodeCache(raw)
	if e != nil {
		return graphdoc.Document{}, "corrupt", e
	}
	if v.CacheKey != cacheKey(s) || v.InputManifestDigest != s.digest || v.OptionsDigest != hashValue(semanticgraph.Options{MaxFiles: semanticgraph.MaxInputFiles}) {
		return graphdoc.Document{}, "stale", fail("GRAPH_SOURCE_STALE")
	}
	actual, e := semanticgraph.AnalyzeFiles(ctx, s.files, semanticgraph.Options{MaxFiles: semanticgraph.MaxInputFiles})
	if e != nil {
		return graphdoc.Document{}, "corrupt", e
	}
	if actual.Digest != v.GraphDigest {
		return graphdoc.Document{}, "corrupt", fail("GRAPH_CACHE_CORRUPT")
	}
	return v.Graph, "hit", nil
}
func analyze(ctx context.Context, s *fileSnapshot, root, mode string) (graphdoc.Document, string, error) {
	if mode == "read" {
		g, state, e := inspectCache(ctx, root, s)
		if e != nil {
			return g, state, fail("GRAPH_CACHE_CORRUPT")
		}
		if state == "hit" {
			return g, state, nil
		}
	}
	g, e := semanticgraph.AnalyzeFiles(ctx, s.files, semanticgraph.Options{MaxFiles: semanticgraph.MaxInputFiles})
	if e != nil {
		return g, "disabled", e
	}
	state := "disabled"
	if mode == "read" {
		_, state, _ = inspectCache(ctx, root, s)
	}
	if mode == "refresh" {
		state = "recomputed"
	}
	return g, state, nil
}
func publishCache(ctx context.Context, root string, s *fileSnapshot, g graphdoc.Document) error {
	if e := s.recheck(ctx); e != nil {
		return e
	}
	graph, e := json.Marshal(g)
	if e != nil {
		return e
	}
	v := cacheImage{APIVersion: "tplaiter.dev/graph-cache/v1", CacheKey: cacheKey(s), AnalyzerVersion: analyzerVersion, OptionsDigest: hashValue(semanticgraph.Options{MaxFiles: semanticgraph.MaxInputFiles}), InputManifestDigest: s.digest, Files: s.facts, GraphDigest: g.Digest, GraphBytes: len(graph), NodeCount: len(g.Nodes), EdgeCount: len(g.Edges), DiagnosticCount: len(g.Diagnostics), Graph: g}
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if _, e = decodeCache(raw); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = cachePublish(root, cacheName(v.CacheKey), raw); e != nil {
		return e
	}
	// A cancellation after the first publication may leave its CAS entry,
	// but must not advance the current pointer after cancellation is observed.
	if e = ctx.Err(); e != nil {
		return e
	}
	return cachePublish(root, "current.json", raw)
}
