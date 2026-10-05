package contextsource

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustverify"

	"gopkg.in/yaml.v3"
)

const NativeContextContractAPIVersion = "tplaiter.dev/native-template-contract/v2"
const ContextSourceSelectionAPIVersion = "tplaiter.dev/source-selection-input/v2"
const MaxContextSources = 32

// ContextDependency names immutable external material, never the containing source.
type ContextDependency struct {
	Alias           string `json:"alias"`
	Origin          string `json:"origin"`
	TemplatePath    string `json:"templatePath"`
	CommitAlgorithm string `json:"commitAlgorithm"`
	Commit          string `json:"commit"`
	TreeDigest      string `json:"treeDigest"`
	ContractDigest  string `json:"contractDigest"`
}
type NativeContextContract struct {
	APIVersion     string              `json:"apiVersion"`
	Kind           string              `json:"kind"`
	ManifestPath   string              `json:"manifestPath"`
	ManifestSHA256 string              `json:"manifestSHA256"`
	Dependencies   []ContextDependency `json:"dependencies"`
}

// ContextSourceProof is untrusted evidence transport, not an admitted resolution.
type ContextSourceProof struct {
	Subject  operationtrust.SelectionSubject  `json:"subject"`
	Evidence operationtrust.SelectionEvidence `json:"evidence"`
}
type ContextSourceSelection struct {
	APIVersion string               `json:"apiVersion"`
	Root       ContextSourceProof   `json:"root"`
	Sources    []ContextSourceProof `json:"sources"`
}

var contextAliasRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)
var contextProviderRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
var contextDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var contextCommitRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
var errContextSources = errors.New("TRUST_CONTEXT_SOURCES_INVALID")
var errContextSourceLimit = errors.New("TRUST_CONTEXT_SOURCES_LIMIT")

// decodeContextWire checks every required key before a typed decoder can hide
// presence or case. RawMessage parameter values are validated separately.
func decodeContextWire(raw []byte, dst any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return errContextSources
	}
	if _, e := canonicaljson.Canonicalize(raw); e != nil {
		return errContextSources
	}
	if e := contextRequired(raw, reflect.TypeOf(dst).Elem()); e != nil {
		return e
	}
	if e := canonicaljson.DecodeStrict(raw, dst); e != nil {
		return errContextSources
	}
	return nil
}
func contextRequired(raw []byte, t reflect.Type) error {
	if t == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	if string(raw) == "null" {
		return errContextSources
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields) != t.NumField() {
			return errContextSources
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			k := strings.Split(f.Tag.Get("json"), ",")[0]
			v, ok := fields[k]
			if !ok {
				return errContextSources
			}
			if e := contextRequired(v, f.Type); e != nil {
				return e
			}
		}
	case reflect.Slice:
		var fields []json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return errContextSources
		}
		for _, v := range fields {
			if e := contextRequired(v, t.Elem()); e != nil {
				return e
			}
		}
	}
	return nil
}
func contextProof(p ContextSourceProof) error {
	s, e := p.Subject, p.Evidence
	if s.Origin == "" || len(s.Origin) > 4096 || strings.ContainsAny(s.Origin, "\x00\r\n") || !contextTemplatePath(s.TemplatePath) || !contextCommitRE.MatchString(s.Commit) || s.RequestedRef != s.Commit || !contextDigestRE.MatchString(s.TreeSHA256) || !contextDigestRE.MatchString(s.ContractSHA256) || e.Format != bootstrap.PublisherStatementAPIVersion {
		return errContextSources
	}
	for _, d := range []string{e.StatementCAS, e.SignatureCAS, e.KeyFingerprint, e.CheckpointCAS, e.InclusionProofCAS} {
		if !contextDigestRE.MatchString(d) {
			return errContextSources
		}
	}
	return nil
}
func contextTemplatePath(p string) bool { return p == "." || contextResourcePath(p) }
func contextSubject(p ContextSourceProof) trustverify.Subject {
	s := p.Subject
	return trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}
func contextEvidence(p ContextSourceProof) trustverify.EvidenceRefs {
	e := p.Evidence
	return trustverify.EvidenceRefs{Format: e.Format, StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint, CheckpointCAS: e.CheckpointCAS, InclusionProofCAS: e.InclusionProofCAS}
}
func contextSubjectKey(s trustverify.Subject) string {
	return s.Origin + "\x00" + s.TemplatePath + "\x00" + s.Commit
}
func DecodeSourceSelectionV2(raw []byte) (ContextSourceSelection, error) {
	var v ContextSourceSelection
	if decodeContextWire(raw, &v, 1<<20) != nil || v.APIVersion != ContextSourceSelectionAPIVersion || len(v.Sources) > MaxContextSources-1 {
		return v, errContextSources
	}
	if e := contextProof(v.Root); e != nil {
		return v, e
	}
	seen := map[string]bool{contextSubjectKey(contextSubject(v.Root)): true}
	for _, p := range v.Sources {
		if contextProof(p) != nil {
			return v, errContextSources
		}
		k := contextSubjectKey(contextSubject(p))
		if seen[k] {
			return v, errContextSources
		}
		seen[k] = true
	}
	return v, nil
}
func DecodeNativeContextContractV2(raw, manifest []byte) (NativeContextContract, error) {
	var v NativeContextContract
	if decodeContextWire(raw, &v, 1<<20) != nil || v.APIVersion != NativeContextContractAPIVersion || v.Kind != operationtrust.NativeContractKind || v.ManifestPath != "template.manifest.yaml" || v.ManifestSHA256 != contextRawDigest(manifest) || len(v.Dependencies) > MaxContextSources-1 || validateContextManifest(manifest) != nil {
		return v, errContextSources
	}
	for i, d := range v.Dependencies {
		if !contextAliasRE.MatchString(d.Alias) || (i > 0 && v.Dependencies[i-1].Alias >= d.Alias) || d.Origin == "" || len(d.Origin) > 4096 || strings.ContainsAny(d.Origin, "\x00\r\n") || !contextTemplatePath(d.TemplatePath) || !contextCommitRE.MatchString(d.Commit) || (len(d.Commit) == 40 && d.CommitAlgorithm != "sha1") || (len(d.Commit) == 64 && d.CommitAlgorithm != "sha256") || !contextDigestRE.MatchString(d.TreeDigest) || !contextDigestRE.MatchString(d.ContractDigest) {
			return v, errContextSources
		}
	}
	return v, nil
}
func contextParameters(ps []deps.Parameter) error {
	if ps == nil || len(ps) > 256 {
		return errContextSources
	}
	for i, p := range ps {
		if !contextAliasRE.MatchString(p.Name) || (i > 0 && ps[i-1].Name >= p.Name) || deps.ValidateScalarParameter(p.Value) != nil {
			return errContextSources
		}
	}
	return nil
}

func contextRawDigest(raw []byte) string { return evidencecas.Digest(raw) }

// New-version validation preserves native manifest restrictions and delegates
// actual template interpretation to the existing manifest engine.
func validateContextManifest(raw []byte) error {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var n yaml.Node
	if d.Decode(&n) != nil || len(n.Content) != 1 {
		return errContextSources
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return errContextSources
	}
	var walk func(*yaml.Node) error
	walk = func(n *yaml.Node) error {
		if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" {
			return errContextSources
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				key := strings.ToLower(k.Value)
				if k.Kind != yaml.ScalarNode || key == "<<" || seen[key] {
					return errContextSources
				}
				seen[key] = true
			}
		}
		for _, child := range n.Content {
			if e := walk(child); e != nil {
				return e
			}
		}
		return nil
	}
	if e := walk(n.Content[0]); e != nil {
		return e
	}
	tpl, e := manifest.ParseTemplate(raw)
	if e != nil {
		return e
	}
	return tpl.Validate()
}
