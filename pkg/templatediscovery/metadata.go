package templatediscovery

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const MetadataAPIVersion = "tplaiter.dev/template-discovery-metadata/v1"
const MaxMetadataBytes = 65536
const MetadataLocator = "discovery.metadata.json"

type OriginalPin struct {
	SourceID      string `json:"sourceID"`
	Revision      string `json:"revision"`
	ContentSHA256 string `json:"contentSHA256"`
}
type MetadataReference struct {
	ID            string      `json:"id"`
	SourcePin     OriginalPin `json:"sourcePin"`
	CandidateKind Kind        `json:"candidateKind"`
	Readiness     Readiness   `json:"readiness"`
}
type MetadataDescription struct {
	Name          string              `json:"name"`
	Version       string              `json:"version"`
	Description   string              `json:"description"`
	Labels        map[string][]string `json:"labels"`
	CandidateKind Kind                `json:"candidateKind"`
	Readiness     Readiness           `json:"readiness"`
	UseCases      []string            `json:"useCases"`
	Blocks        []MetadataReference `json:"blocks"`
	Skills        []MetadataReference `json:"skills"`
}

// Metadata is a separate companion; it does not extend an existing closed
// source pack. The original owner binds this raw digest independently.
type Metadata struct {
	APIVersion      string              `json:"apiVersion"`
	CandidatePin    OriginalPin         `json:"candidatePin"`
	Metadata        MetadataDescription `json:"metadata"`
	rawSHA256       string
	canonicalSHA256 string
}

func meaningful(s string, n int) bool {
	return utf8.ValidString(s) && len(s) <= n && strings.TrimSpace(s) != ""
}
func (p OriginalPin) valid() bool {
	return meaningful(p.SourceID, 256) && meaningful(p.Revision, 256) && digestRE.MatchString(p.ContentSHA256)
}
func exact(v any, names ...string) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(names) {
		return false
	}
	for _, n := range names {
		if m[n] == nil {
			return false
		}
	}
	return true
}

// readJSON rejects duplicate names recursively rather than relying on the
// encoding/json struct decoder's last-value or case-insensitive behavior.
func readJSON(dec *json.Decoder, depth int) (any, error) {
	if depth > 8 {
		return nil, ErrInput
	}
	token, err := dec.Token()
	if err != nil {
		return nil, ErrInput
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, ErrInput
			}
			key, ok := k.(string)
			if !ok {
				return nil, ErrInput
			}
			if _, exists := m[key]; exists {
				return nil, ErrInput
			}
			v, err := readJSON(dec, depth+1)
			if err != nil {
				return nil, err
			}
			m[key] = v
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrInput
		}
		return m, nil
	case '[':
		a := []any{}
		for dec.More() {
			v, err := readJSON(dec, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrInput
		}
		return a, nil
	}
	return nil, ErrInput
}
func metadataShape(v any) bool {
	if !exact(v, "apiVersion", "candidatePin", "metadata") {
		return false
	}
	root := v.(map[string]any)
	if !exact(root["candidatePin"], "sourceID", "revision", "contentSHA256") {
		return false
	}
	if !exact(root["metadata"], "name", "version", "description", "labels", "candidateKind", "readiness", "useCases", "blocks", "skills") {
		return false
	}
	m := root["metadata"].(map[string]any)
	labels, ok := m["labels"].(map[string]any)
	if !ok || len(labels) == 0 {
		return false
	}
	for _, v := range labels {
		a, ok := v.([]any)
		if !ok || len(a) == 0 {
			return false
		}
		for _, x := range a {
			if _, ok := x.(string); !ok {
				return false
			}
		}
	}
	for _, key := range []string{"useCases", "blocks", "skills"} {
		a, ok := m[key].([]any)
		if !ok {
			return false
		}
		if key == "useCases" {
			for _, x := range a {
				if _, ok := x.(string); !ok {
					return false
				}
			}
			continue
		}
		for _, x := range a {
			if !exact(x, "id", "sourcePin", "candidateKind", "readiness") {
				return false
			}
			if !exact(x.(map[string]any)["sourcePin"], "sourceID", "revision", "contentSHA256") {
				return false
			}
		}
	}
	return true
}
func (m Metadata) valid() bool {
	d := m.Metadata
	if m.APIVersion != MetadataAPIVersion || !m.CandidatePin.valid() || !nameRE.MatchString(d.Name) || !meaningful(d.Version, 128) || !meaningful(d.Description, 4096) || !d.CandidateKind.Valid() || !d.Readiness.Valid() || len(d.Labels["tags"]) < 1 || len(d.Labels) < 1 || len(d.Labels) > 64 || len(d.UseCases) > 32 || len(d.Blocks) > 32 || len(d.Skills) > 32 {
		return false
	}
	for k, v := range d.Labels {
		if !meaningful(k, 128) || len(v) == 0 || len(v) > 32 {
			return false
		}
		for _, s := range v {
			if !meaningful(s, 256) {
				return false
			}
		}
	}
	for _, s := range d.UseCases {
		if !meaningful(s, 256) {
			return false
		}
	}
	for _, refs := range [][]MetadataReference{d.Blocks, d.Skills} {
		seen := map[string]bool{}
		for _, r := range refs {
			if !meaningful(r.ID, 128) || seen[r.ID] || !r.SourcePin.valid() || !r.CandidateKind.Valid() || !r.Readiness.Valid() {
				return false
			}
			seen[r.ID] = true
		}
	}
	for _, pair := range []struct{ k, v string }{{"candidate-kind", string(d.CandidateKind)}, {"readiness", string(d.Readiness)}} {
		if v, ok := d.Labels[pair.k]; ok && (len(v) != 1 || v[0] != pair.v) {
			return false
		}
	}
	return true
}
func DecodeMetadata(raw []byte) (Metadata, error) {
	var m Metadata
	if len(raw) == 0 || len(raw) > MaxMetadataBytes || !utf8.Valid(raw) {
		return m, ErrInput
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tree, err := readJSON(dec, 0)
	if err != nil || !metadataShape(tree) {
		return m, ErrInput
	}
	if _, err := dec.Token(); err != io.EOF {
		return m, ErrInput
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if strict.Decode(&m) != nil || !m.valid() {
		return Metadata{}, ErrInput
	}
	m.rawSHA256 = Digest(raw)
	canonical, _ := json.Marshal(m)
	m.canonicalSHA256 = Digest(canonical)
	return m, nil
}
func MetadataSHA256(raw []byte) (string, error) {
	m, err := DecodeMetadata(raw)
	if err != nil {
		return "", err
	}
	return m.rawSHA256, nil
}

// CandidateFromMetadata checks the original data pin and codec custody only.
// Authentication and catalog availability remain the original source owner's job.
func CandidateFromMetadata(m Metadata, original SourcePin) (Candidate, error) {
	raw, _ := json.Marshal(m)
	if !m.valid() || m.canonicalSHA256 == "" || Digest(raw) != m.canonicalSHA256 || !original.Valid() || original.Qualification != "owner-supplied" || m.CandidatePin != (OriginalPin{original.SourceID, original.Revision, original.ContentSHA256}) {
		return Candidate{}, ErrInput
	}
	md := m.Metadata
	labels := map[string][]string{}
	for k, v := range md.Labels {
		labels[k] = append([]string{}, v...)
	}
	if len(md.UseCases) > 0 {
		labels["use-cases"] = append(labels["use-cases"], md.UseCases...)
	}
	c := Candidate{SourcePin: original, MetadataSHA256: m.rawSHA256, Name: md.Name, Version: md.Version, Description: md.Description, Labels: labels, CandidateKind: md.CandidateKind, Readiness: md.Readiness, Blocks: []Reference{}, Skills: []Reference{}}
	refs := func(input []MetadataReference) []Reference {
		out := []Reference{}
		for _, r := range input {
			out = append(out, Reference{ID: r.ID, SourcePin: SourcePin{Qualification: "owner-supplied", SourceID: r.SourcePin.SourceID, Revision: r.SourcePin.Revision, ContentSHA256: r.SourcePin.ContentSHA256}, CandidateKind: r.CandidateKind, Readiness: r.Readiness, DeclarationStatus: "metadata-declared", Availability: "metadata-declared"})
		}
		return out
	}
	c.Blocks = refs(md.Blocks)
	c.Skills = refs(md.Skills)
	return Identify(c)
}
