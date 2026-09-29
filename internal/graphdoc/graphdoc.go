// Package graphdoc defines the bounded, provenance-carrying graph wire format.
package graphdoc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const APIVersion = "tplaiter.dev/graph/v2"

const (
	MaxNodes       = 8192
	MaxEdges       = 32768
	MaxString      = 4096
	MaxAttributes  = 128
	MaxProvenance  = 128
	MaxDiagnostics = 1024
)

type Document struct {
	APIVersion  string       `json:"apiVersion"`
	Kind        string       `json:"kind"`
	Layer       string       `json:"layer"`
	Status      string       `json:"status"`
	Producer    string       `json:"producer"`
	Nodes       []Node       `json:"nodes"`
	Edges       []Edge       `json:"edges"`
	Diagnostics []Diagnostic `json:"diagnostics"`
	Digest      string       `json:"digest"`
}

type Node struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Language   string            `json:"language,omitempty"`
	Path       string            `json:"path,omitempty"`
	Name       string            `json:"name,omitempty"`
	Line       int               `json:"line,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Provenance []Provenance      `json:"provenance,omitempty"`
}

type Edge struct {
	From       string            `json:"from"`
	To         string            `json:"to"`
	Kind       string            `json:"kind"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Provenance []Provenance      `json:"provenance,omitempty"`
}

type Provenance struct {
	Source   string `json:"source,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Declared bool   `json:"declared,omitempty"`
	Detected bool   `json:"detected,omitempty"`
}

type Diagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

func New() Document {
	return Document{APIVersion: APIVersion, Kind: "Graph", Layer: "ast", Status: "ok", Producer: "tplaiter graph explorer", Nodes: []Node{}, Edges: []Edge{}, Diagnostics: []Diagnostic{}}
}

func (d *Document) Canonicalize() error {
	if d == nil {
		return errors.New("graph: nil document")
	}
	if d.APIVersion == "" {
		d.APIVersion = APIVersion
	}
	for i := range d.Nodes {
		d.Nodes[i].Attributes = copyMap(d.Nodes[i].Attributes)
		sort.Slice(d.Nodes[i].Provenance, func(a, b int) bool { return provKey(d.Nodes[i].Provenance[a]) < provKey(d.Nodes[i].Provenance[b]) })
	}
	for i := range d.Edges {
		d.Edges[i].Attributes = copyMap(d.Edges[i].Attributes)
		sort.Slice(d.Edges[i].Provenance, func(a, b int) bool { return provKey(d.Edges[i].Provenance[a]) < provKey(d.Edges[i].Provenance[b]) })
	}
	sort.Slice(d.Nodes, func(i, j int) bool { return d.Nodes[i].ID < d.Nodes[j].ID })
	sort.Slice(d.Edges, func(i, j int) bool {
		a, b := d.Edges[i], d.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Kind < b.Kind
	})
	sort.Slice(d.Diagnostics, func(i, j int) bool {
		a, b := d.Diagnostics[i], d.Diagnostics[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Code < b.Code
	})
	if err := d.validate(false); err != nil {
		return err
	}
	d.Digest = ""
	raw, _ := json.Marshal(d)
	sum := sha256.Sum256(raw)
	d.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return nil
}

func (d *Document) validate(checkDigest bool) error {
	if d.APIVersion != APIVersion || !validText(d.Kind) || !validText(d.Layer) || !validText(d.Status) || !validText(d.Producer) {
		return errors.New("graph: invalid envelope")
	}
	if d.Status != "ok" && d.Status != "partial" && d.Status != "error" {
		return errors.New("graph: invalid status")
	}
	if len(d.Diagnostics) > MaxDiagnostics {
		return errors.New("graph: diagnostic limit exceeded")
	}
	if len(d.Nodes) == 0 || len(d.Nodes) > MaxNodes || len(d.Edges) > MaxEdges {
		return errors.New("graph: node or edge limit exceeded")
	}
	seen := map[string]bool{}
	for _, n := range d.Nodes {
		if !validText(n.ID) || !validText(n.Kind) || seen[n.ID] {
			return fmt.Errorf("graph: invalid or duplicate node %q", n.ID)
		}
		seen[n.ID] = true
		if n.Line < 0 {
			return errors.New("graph: invalid line")
		}
		if !validOptionalText(n.Language) || !validOptionalText(n.Path) || !validOptionalText(n.Name) || !validMap(n.Attributes) || !validProvenance(n.Provenance) {
			return fmt.Errorf("graph: invalid node fields %q", n.ID)
		}
	}
	edges := map[string]bool{}
	for _, e := range d.Edges {
		if !validText(e.From) || !validText(e.To) || !validText(e.Kind) || !seen[e.From] || !seen[e.To] {
			return fmt.Errorf("graph: invalid edge %q -> %q", e.From, e.To)
		}
		k := e.From + "\x00" + e.To + "\x00" + e.Kind
		if edges[k] {
			return fmt.Errorf("graph: duplicate edge %q", k)
		}
		edges[k] = true
		if !validMap(e.Attributes) || !validProvenance(e.Provenance) {
			return errors.New("graph: invalid edge fields")
		}
	}
	for _, x := range d.Diagnostics {
		if !validText(x.Code) || !validText(x.Message) || !validOptionalText(x.Path) || x.Line < 0 || (x.Severity != "info" && x.Severity != "warning" && x.Severity != "error") {
			return errors.New("graph: invalid diagnostic")
		}
	}
	if checkDigest {
		want := d.Digest
		d.Digest = ""
		raw, _ := json.Marshal(d)
		sum := sha256.Sum256(raw)
		d.Digest = want
		if want != "sha256:"+hex.EncodeToString(sum[:]) {
			return errors.New("graph: digest mismatch")
		}
	}
	return nil
}

func Validate(d Document) error { return d.validate(false) }
func Verify(d Document) error   { return d.validate(true) }

func JSON(d Document) ([]byte, error) {
	if err := d.Canonicalize(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(d, "", "  ")
}

func Decode(raw []byte) (Document, error) {
	var d Document
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return d, fmt.Errorf("graph: invalid JSON: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, fmt.Errorf("graph: invalid JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return d, errors.New("graph: trailing JSON value")
	}
	if err := Verify(d); err != nil {
		return d, err
	}
	return d, nil
}

func validText(s string) bool {
	return s != "" && len(s) <= MaxString && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func validOptionalText(s string) bool { return s == "" || validText(s) }
func validMap(m map[string]string) bool {
	if len(m) > MaxAttributes {
		return false
	}
	for k, v := range m {
		if !validText(k) || !validText(v) {
			return false
		}
	}
	return true
}

func validProvenance(ps []Provenance) bool {
	if len(ps) > MaxProvenance {
		return false
	}
	for _, p := range ps {
		if !validOptionalText(p.Source) || !validOptionalText(p.Evidence) || (!p.Declared && !p.Detected) {
			return false
		}
	}
	return true
}

func copyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func provKey(p Provenance) string { return p.Source + "\x00" + p.Evidence }
