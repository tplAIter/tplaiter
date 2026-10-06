// Package contextwire owns closed source data codecs, never source admission.
package contextwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/manifest"

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

var contextAliasRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)
var contextProviderRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
var contextDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var contextCommitRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
var ErrSources = errors.New("TRUST_CONTEXT_SOURCES_INVALID")
var errContextSources = ErrSources
var ErrSourceLimit = errors.New("TRUST_CONTEXT_SOURCES_LIMIT")

// DecodeRequired checks every required key before a typed decoder can hide
// presence or case. RawMessage parameter values are validated separately.
func DecodeRequired(raw []byte, dst any, limit int) error {
	if dst == nil || reflect.TypeOf(dst).Kind() != reflect.Pointer || reflect.ValueOf(dst).IsNil() || len(raw) == 0 || len(raw) > limit {
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
func contextTemplatePath(p string) bool { return p == "." || contextResourcePath(p) }
func DecodeNativeContextContractV2(raw, manifest []byte) (NativeContextContract, error) {
	var v NativeContextContract
	if DecodeRequired(raw, &v, 1<<20) != nil || v.APIVersion != NativeContextContractAPIVersion || v.Kind != NativeContractKind || v.ManifestPath != "template.manifest.yaml" || v.ManifestSHA256 != contextRawDigest(manifest) || len(v.Dependencies) > MaxContextSources-1 || validateContextManifest(manifest) != nil {
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

const ContextSourceBindingsAPIVersion = "tplaiter.dev/context-source-bindings/v2"
const ContextSourceBindingsPath = "catalog/context-source-bindings.v2.json"

type ContextCatalogBinding struct {
	Alias            string           `json:"alias"`
	ProviderID       string           `json:"providerID"`
	Parameters       []deps.Parameter `json:"parameters"`
	EntriesPath      string           `json:"entriesPath"`
	PayloadDirectory string           `json:"payloadDirectory"`
	ToolPath         string           `json:"toolPath"`
}

// An association is authored by the consumer source and must match the
// authenticated dependency's own declaration before it becomes graph data.
type ContextDependencyBinding struct {
	Alias      string           `json:"alias"`
	ProviderID string           `json:"providerID"`
	Parameters []deps.Parameter `json:"parameters"`
}
type ContextSourceBindings struct {
	APIVersion   string                     `json:"apiVersion"`
	Kind         string                     `json:"kind"`
	Source       ContextCatalogBinding      `json:"source"`
	Dependencies []ContextDependencyBinding `json:"dependencies"`
}

func contextResourcePath(p string) bool {
	return utf8.ValidString(p) && len(p) <= 256 && fs.ValidPath(p) && p != "." && !strings.ContainsAny(p, "\\\x00\r\n") && exports.ValidatePortablePath(p) == nil
}
func DecodeContextSourceBindingsV2(raw []byte) (ContextSourceBindings, error) {
	var b ContextSourceBindings
	if DecodeRequired(raw, &b, 64<<10) != nil || b.APIVersion != ContextSourceBindingsAPIVersion || b.Kind != "ContextSourceBindings" || len(b.Dependencies) > MaxContextSources-1 {
		return b, errContextSources
	}
	s := b.Source
	if !contextAliasRE.MatchString(s.Alias) || !contextProviderRE.MatchString(s.ProviderID) || contextParameters(s.Parameters) != nil || !contextResourcePath(s.EntriesPath) || !contextResourcePath(s.PayloadDirectory) || !contextResourcePath(s.ToolPath) || s.EntriesPath == s.ToolPath {
		return b, errContextSources
	}
	for i, d := range b.Dependencies {
		if !contextAliasRE.MatchString(d.Alias) || d.Alias == s.Alias || !contextProviderRE.MatchString(d.ProviderID) || contextParameters(d.Parameters) != nil || (i > 0 && b.Dependencies[i-1].Alias >= d.Alias) {
			return b, errContextSources
		}
	}
	return b, nil
}

// ResourcePath preserves the portable source-resource path grammar.
func ResourcePath(p string) bool        { return contextResourcePath(p) }
func ValidateManifest(raw []byte) error { return validateContextManifest(raw) }

const NativeContractAPIVersion = "tplaiter.dev/native-template-contract/v1"
const NativeContractKind = "NativeTemplate"

var ErrNativeUnsupported = errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")

type NativeContract struct {
	APIVersion     string   `json:"apiVersion"`
	Kind           string   `json:"kind"`
	ManifestPath   string   `json:"manifestPath"`
	ManifestSHA256 string   `json:"manifestSHA256"`
	Dependencies   []string `json:"dependencies"`
}

func DecodeNativeContract(raw, manifestRaw []byte) (*NativeContract, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrNativeUnsupported
	}
	var v NativeContract
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, ErrNativeUnsupported
	}
	if v.APIVersion != NativeContractAPIVersion || v.Kind != NativeContractKind ||
		v.ManifestPath != "template.manifest.yaml" || v.Dependencies == nil || len(v.Dependencies) != 0 ||
		v.ManifestSHA256 != evidencecas.Digest(manifestRaw) {
		return nil, ErrNativeUnsupported
	}
	return &v, nil
}
