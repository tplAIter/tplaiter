package contextcmd

import (
	"encoding/json"
	"io/fs"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const RootBindingsAPIVersion = "tplaiter.dev/context-root-bindings/v1"
const DefaultRootBindingsPath = "catalog/context-root-bindings.v1.json"

type rootBindings struct {
	APIVersion string      `json:"apiVersion"`
	Kind       string      `json:"kind"`
	Source     rootBinding `json:"source"`
}
type rootBinding struct {
	Alias            string           `json:"alias"`
	ProviderID       string           `json:"providerID"`
	Parameters       []deps.Parameter `json:"parameters"`
	EntriesPath      string           `json:"entriesPath"`
	PayloadDirectory string           `json:"payloadDirectory"`
	ToolPath         string           `json:"toolPath"`
}

var rootAlias = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)
var rootProvider = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)

func rootPath(p string) bool {
	if !utf8.ValidString(p) || len(p) > 256 || !fs.ValidPath(p) || p == "." || strings.ContainsAny(p, "\\\x00\r\n") {
		return false
	}
	return exports.ValidatePortablePath(p) == nil
}

// Required keys are checked on raw JSON, before any normalization can hide a
// duplicate or substitute zero values. Root identity is deliberately absent.
func decodeRootBindings(raw []byte) (rootBindings, error) {
	var b rootBindings
	if len(raw) == 0 || len(raw) > 64<<10 {
		return b, fail(Invalid)
	}
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return b, fail(Invalid)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || len(top) != 3 {
		return b, fail(Invalid)
	}
	for _, k := range []string{"apiVersion", "kind", "source"} {
		if _, ok := top[k]; !ok {
			return b, fail(Invalid)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(top["source"], &fields); err != nil || len(fields) != 6 {
		return b, fail(Invalid)
	}
	for _, k := range []string{"alias", "providerID", "parameters", "entriesPath", "payloadDirectory", "toolPath"} {
		if _, ok := fields[k]; !ok {
			return b, fail(Invalid)
		}
	}
	if err := canonicaljson.DecodeStrict(raw, &b); err != nil {
		return b, fail(Invalid)
	}
	s := b.Source
	if b.APIVersion != RootBindingsAPIVersion || b.Kind != "ContextRootBindings" || !rootAlias.MatchString(s.Alias) || !rootProvider.MatchString(s.ProviderID) || s.Parameters == nil || len(s.Parameters) != 0 || !rootPath(s.EntriesPath) || !rootPath(s.PayloadDirectory) || !rootPath(s.ToolPath) || s.EntriesPath == s.ToolPath {
		return rootBindings{}, fail(Invalid)
	}
	return b, nil
}

// Only retained, verified source objects are read; no live provider path opens.
func rootBlob(s *trustverify.SourceSnapshot, p string, max int, metadata bool) ([]byte, string, error) {
	if s == nil || !rootPath(p) {
		return nil, "", fail(Invalid)
	}
	for _, e := range s.Entries() {
		if e.Path != p {
			continue
		}
		if e.Kind != "file" || (e.Mode != "100644" && e.Mode != "100755") || (metadata && e.Mode != "100644") {
			return nil, "", fail(Stale)
		}
		raw, ok := s.Blob(p)
		if !ok || evidencecas.Digest(raw) != e.ContentSHA256 {
			return nil, "", fail(Stale)
		}
		if len(raw) > max {
			return nil, "", fail(Budget)
		}
		return append([]byte(nil), raw...), e.Mode, nil
	}
	return nil, "", fail(Missing)
}
