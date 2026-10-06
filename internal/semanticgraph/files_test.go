package semanticgraph

import (
	"context"
	"strings"
	"testing"
)

func TestBoundedImagesSyntaxAndRefusals(t *testing.T) {
	files := []SourceFile{{"service.go", []byte("package service\nimport \"context\"\nfunc Handle(ctx context.Context) {}\n")}, {"service.rs", []byte("use std::io;\nfn handle() {}\n")}}
	g, e := AnalyzeFiles(context.Background(), files, Options{})
	if e != nil || len(g.Nodes) < 6 || len(g.Edges) < 4 {
		t.Fatalf("syntax: %+v %v", g, e)
	}
	for _, f := range [][]SourceFile{{files[0], files[0]}, {{"../service.go", []byte("package x")}}, {{"big.go", []byte(strings.Repeat("x", MaxFileBytes+1))}}} {
		if _, e = AnalyzeFiles(context.Background(), f, Options{}); e == nil {
			t.Fatal("accepted invalid images")
		}
	}
	if _, e = AnalyzeFiles(context.Background(), files, Options{Verify: true}); e == nil {
		t.Fatal("silently ignored compiler verification")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = AnalyzeFiles(ctx, files, Options{}); e == nil {
		t.Fatal("accepted cancellation")
	}
	partial, e := AnalyzeFiles(context.Background(), []SourceFile{{"broken.go", []byte("not Go syntax")}}, Options{})
	if e != nil || partial.Status != "partial" || len(partial.Diagnostics) != 1 {
		t.Fatal("parse warning lost", e)
	}
}
