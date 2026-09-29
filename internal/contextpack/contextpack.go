// Package contextpack produces deterministic, bounded retrieval metadata.
package contextpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/graphdoc"
)

const (
	DefaultLimit = 8192
	HardLimit    = 32768
)

var ErrBudget = errors.New("contextpack: minimum envelope exceeds byte limit")

type Request struct {
	Root          string
	Selected      []string
	MaxBytes      int
	IncludeSource bool
}
type Pack struct {
	APIVersion       string          `json:"apiVersion"`
	GraphDigest      string          `json:"graphDigest"`
	Nodes            []graphdoc.Node `json:"nodes"`
	Relations        []graphdoc.Edge `json:"relations"`
	Sources          []SourceExcerpt `json:"sources,omitempty"`
	SourceDigests    []Digest        `json:"sourceDigests"`
	Constraints      []string        `json:"constraints"`
	Diagnostics      []string        `json:"diagnostics"`
	OmittedNodes     int             `json:"omittedNodes"`
	OmittedRelations int             `json:"omittedRelations"`
	OmittedSources   int             `json:"omittedSources"`
	Bytes            int             `json:"bytes"`
	TokenEstimate    int             `json:"tokenEstimate"`
}
type Digest struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}
type SourceExcerpt struct {
	NodeID  string `json:"nodeID"`
	Path    string `json:"path"`
	Start   int    `json:"startLine"`
	End     int    `json:"endLine"`
	Content string `json:"content"`
	Digest  string `json:"contentDigest"`
}

// Build never returns a successful serialized Pack larger than MaxBytes.
func Build(d graphdoc.Document, req Request) (Pack, error) {
	if err := graphdoc.Verify(d); err != nil {
		return Pack{}, err
	}
	limit := req.MaxBytes
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > HardLimit {
		return Pack{}, fmt.Errorf("contextpack: max bytes must be 1..%d", HardLimit)
	}
	want := map[string]bool{}
	for _, id := range req.Selected {
		want[id] = true
	}
	nodes := []graphdoc.Node{}
	for _, n := range d.Nodes {
		if len(want) == 0 || want[n.ID] {
			nodes = append(nodes, n)
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	ids := map[string]bool{}
	for _, n := range nodes {
		ids[n.ID] = true
	}
	rels := []graphdoc.Edge{}
	for _, e := range d.Edges {
		if ids[e.From] && ids[e.To] {
			rels = append(rels, e)
		}
	}
	sort.Slice(rels, func(i, j int) bool {
		return rels[i].From+rels[i].To+rels[i].Kind < rels[j].From+rels[j].To+rels[j].Kind
	})
	sources := []SourceExcerpt{}
	p := Pack{APIVersion: "tplaiter.dev/context-pack/v1", GraphDigest: d.Digest, Nodes: []graphdoc.Node{}, Relations: []graphdoc.Edge{}, SourceDigests: []Digest{}, Constraints: []string{}, Diagnostics: []string{}}
	for _, n := range nodes {
		candidate := p
		candidate.Nodes = append(append([]graphdoc.Node{}, p.Nodes...), n)
		if fits(&candidate, limit) {
			p = candidate
		}
	}
	kept := map[string]bool{}
	for _, n := range p.Nodes {
		kept[n.ID] = true
	}
	for _, e := range rels {
		if kept[e.From] && kept[e.To] {
			candidate := p
			candidate.Relations = append(append([]graphdoc.Edge{}, p.Relations...), e)
			if fits(&candidate, limit) {
				p = candidate
			}
		}
	}
	if req.IncludeSource {
		for _, n := range p.Nodes {
			ex, ok := excerpt(req.Root, n)
			if !ok {
				continue
			}
			sources = append(sources, ex)
			if kept[ex.NodeID] {
				candidate := p
				candidate.Sources = append(append([]SourceExcerpt{}, p.Sources...), ex)
				candidate.SourceDigests = append(append([]Digest{}, p.SourceDigests...), Digest{Path: ex.Path, Digest: ex.Digest})
				p = candidate
			}
		}
	}
	for len(p.Sources) > 0 && serializedSize(p) > limit {
		p.Sources = p.Sources[:len(p.Sources)-1]
		p.SourceDigests = p.SourceDigests[:len(p.SourceDigests)-1]
		p.Bytes, p.TokenEstimate = 0, 0
	}
	p.OmittedNodes = len(nodes) - len(p.Nodes)
	p.OmittedRelations = len(rels) - len(p.Relations)
	p.OmittedSources = len(sources) - len(p.Sources)
	if p.OmittedNodes+p.OmittedRelations+p.OmittedSources > 0 {
		candidate := p
		candidate.Diagnostics = []string{"records omitted to satisfy byte limit"}
		if fits(&candidate, limit) {
			p = candidate
		}
	}
	if !fits(&p, limit) {
		return Pack{}, ErrBudget
	}
	return p, nil
}

func serializedSize(p Pack) int {
	raw, err := json.Marshal(p)
	if err != nil {
		return HardLimit + 1
	}
	return len(raw)
}

func fits(p *Pack, limit int) bool {
	for i := 0; i < 64; i++ {
		raw, err := json.Marshal(p)
		if err != nil {
			return false
		}
		b := len(raw)
		t := (b + 3) / 4
		if p.Bytes == b && p.TokenEstimate == t {
			return b <= limit
		}
		p.Bytes, p.TokenEstimate = b, t
	}
	// Accounting must reach a fixed point; an oscillating representation is
	// never advertised as bounded.
	return false
}

// Verify rejects graph/source selection or source-byte drift before export.
func Verify(d graphdoc.Document, root string, p Pack) error {
	if err := graphdoc.Verify(d); err != nil {
		return err
	}
	if p.APIVersion != "tplaiter.dev/context-pack/v1" || p.GraphDigest != d.Digest {
		return errors.New("contextpack: graph digest mismatch")
	}
	byID := map[string]graphdoc.Node{}
	for _, n := range d.Nodes {
		byID[n.ID] = n
	}
	for _, ex := range p.Sources {
		n, ok := byID[ex.NodeID]
		if !ok || n.Path != ex.Path {
			return errors.New("contextpack: excerpt node mismatch")
		}
		current, ok := excerpt(root, n)
		if !ok || current.Digest != ex.Digest || current.Start != ex.Start || current.End != ex.End || current.Content != ex.Content {
			return fmt.Errorf("contextpack: source drift %s", ex.Path)
		}
	}
	return nil
}

func excerpt(root string, n graphdoc.Node) (SourceExcerpt, bool) {
	rel := n.Path
	if root == "" || filepath.IsAbs(rel) || strings.Contains(rel, ".."+string(filepath.Separator)) {
		return SourceExcerpt{}, false
	}
	clean := filepath.Clean(rel)
	root, _ = filepath.Abs(root)
	path := filepath.Join(root, clean)
	check, err := filepath.Rel(root, path)
	if err != nil || check == ".." || strings.HasPrefix(check, ".."+string(filepath.Separator)) {
		return SourceExcerpt{}, false
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 {
		return SourceExcerpt{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return SourceExcerpt{}, false
	}
	sum := sha256.Sum256(b)
	dg := "sha256:" + hex.EncodeToString(sum[:])
	expected := ""
	for _, p := range n.Provenance {
		if p.Source == "filesystem" {
			expected = p.Evidence
			break
		}
	}
	if expected == "" || expected != dg {
		return SourceExcerpt{}, false
	}
	lines := strings.Split(string(b), "\n")
	line := n.Line
	if line < 1 {
		line = 1
	}
	start := line - 2
	if start < 0 {
		start = 0
	}
	end := start + 8
	if end > len(lines) {
		end = len(lines)
	}
	return SourceExcerpt{NodeID: n.ID, Path: filepath.ToSlash(rel), Start: start + 1, End: end, Content: strings.Join(lines[start:end], "\n"), Digest: dg}, true
}
