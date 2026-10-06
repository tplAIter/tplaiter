package semanticgraph

import (
	"context"
	"fmt"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"path"
	"sort"
	"strings"
)

const MaxInputFiles = 256
const MaxFileBytes = 1 << 20
const MaxInputBytes = 16 << 20

// SourceFile carries parser input, not authenticated source authority.
type SourceFile struct {
	Path  string
	Bytes []byte
}

// AnalyzeFiles parses finite owned images, without toolchain or execution effects.
func AnalyzeFiles(ctx context.Context, files []SourceFile, opts Options) (graphdoc.Document, error) {
	d := graphdoc.New()
	d.Producer = "tplaiter semanticgraph files/v1"
	if ctx == nil || opts.Verify || len(files) == 0 || len(files) > MaxInputFiles || (opts.MaxFiles > 0 && len(files) > opts.MaxFiles) {
		return d, fmt.Errorf("semanticgraph: unsupported verification or input limit")
	}
	images := append([]SourceFile(nil), files...)
	sort.Slice(images, func(i, j int) bool { return images[i].Path < images[j].Path })
	seen := map[string]bool{}
	total := 0
	for _, f := range images {
		if e := ctx.Err(); e != nil {
			return d, e
		}
		key := strings.ToLower(f.Path)
		if f.Path == "" || path.Clean(f.Path) != f.Path || strings.HasPrefix(f.Path, "../") || strings.HasPrefix(f.Path, "/") || strings.ContainsAny(f.Path, "\\\x00") || language(f.Path) == "" || seen[key] || len(f.Bytes) > MaxFileBytes {
			return d, fmt.Errorf("semanticgraph: invalid bounded image")
		}
		seen[key] = true
		total += len(f.Bytes)
		if total > MaxInputBytes {
			return d, fmt.Errorf("semanticgraph: aggregate input limit")
		}
		addFile(&d, language(f.Path), f.Path, append([]byte(nil), f.Bytes...))
	}
	if len(d.Diagnostics) > 0 {
		d.Status = "partial"
	}
	return d, d.Canonicalize()
}
