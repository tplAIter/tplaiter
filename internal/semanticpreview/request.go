// Package semanticpreview calculates bounded syntax edits without effect authority.
package semanticpreview

import (
	"encoding/json"
	"errors"
	"go/token"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

const RequestVersion = "tplaiter.dev/semantic-preview/v1"
const MaxRequestBytes = 64 << 10

var ErrRequest = errors.New("SEMANTIC_REQUEST_INVALID")
var ErrAnchor = errors.New("SEMANTIC_ANCHOR_STALE")
var ErrSyntax = errors.New("SEMANTIC_SYNTAX_INVALID")
var ErrOverlap = errors.New("SEMANTIC_EDIT_OVERLAP")
var ErrBudget = errors.New("SEMANTIC_OUTPUT_BUDGET")
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var editIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)

type Request struct {
	APIVersion string   `json:"apiVersion"`
	Action     string   `json:"action"`
	Paths      []string `json:"paths,omitempty"`
	Edits      []Edit   `json:"edits,omitempty"`
}
type Edit struct {
	ID                 string                   `json:"id"`
	Path               string                   `json:"path"`
	Intent             string                   `json:"intent"`
	ExpectedFileDigest string                   `json:"expectedFileDigest"`
	BeforeGraphDigest  string                   `json:"beforeGraphDigest"`
	Anchor             resultdto.SemanticAnchor `json:"anchor"`
	Payload            string                   `json:"payload,omitempty"`
	ImportPath         string                   `json:"importPath,omitempty"`
	Alias              string                   `json:"alias,omitempty"`
	Comment            string                   `json:"comment,omitempty"`
}

func DecodeRequest(raw []byte) (Request, error) {
	var q Request
	if len(raw) == 0 || len(raw) > MaxRequestBytes || canonicaljson.DecodeStrict(raw, &q) != nil {
		return q, ErrRequest
	}
	// Native strict parsing rejects aliases/unknown/duplicate keys. Requiring the
	// structural scalar keys prevents zero-valued anchor omissions from passing.
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	for _, key := range []string{"apiVersion", "action"} {
		if _, ok := object[key]; !ok {
			return q, ErrRequest
		}
	}
	if q.Action == "preview" {
		var edits []map[string]json.RawMessage
		if json.Unmarshal(object["edits"], &edits) != nil {
			return q, ErrRequest
		}
		for _, e := range edits {
			for _, key := range []string{"id", "path", "intent", "expectedFileDigest", "beforeGraphDigest", "anchor"} {
				if _, ok := e[key]; !ok {
					return q, ErrRequest
				}
			}
			var a map[string]json.RawMessage
			if json.Unmarshal(e["anchor"], &a) != nil {
				return q, ErrRequest
			}
			for _, key := range []string{"kind", "key", "startByte", "endByte", "digest"} {
				if _, ok := a[key]; !ok {
					return q, ErrRequest
				}
			}
		}
	}
	return q, q.Validate()
}
func (q Request) Validate() error {
	if q.APIVersion != RequestVersion {
		return ErrRequest
	}
	seen := map[string]bool{}
	paths := map[string]bool{}
	payload := 0
	spellings := map[string]string{}
	switch q.Action {
	case "anchors":
		if len(q.Paths) < 1 || len(q.Paths) > 8 || q.Edits != nil {
			return ErrRequest
		}
		for _, p := range q.Paths {
			if !goPath(p) || paths[strings.ToLower(p)] {
				return ErrRequest
			}
			paths[strings.ToLower(p)] = true
		}
	case "preview":
		if len(q.Edits) < 1 || len(q.Edits) > 8 || q.Paths != nil {
			return ErrRequest
		}
		for _, e := range q.Edits {
			if !editIDPattern.MatchString(e.ID) || seen[e.ID] || !goPath(e.Path) || !digestPattern.MatchString(e.ExpectedFileDigest) || !digestPattern.MatchString(e.BeforeGraphDigest) || !digestPattern.MatchString(e.Anchor.Digest) || e.Anchor.StartByte < 0 || e.Anchor.EndByte < e.Anchor.StartByte || e.Anchor.Kind == "" || e.Anchor.Key == "" || !plainLF(e.Payload) || len(e.Payload) > 16<<10 {
				return ErrRequest
			}
			fold := strings.ToLower(e.Path)
			if original, ok := spellings[fold]; ok && original != e.Path {
				return ErrRequest
			}
			spellings[fold] = e.Path
			seen[e.ID] = true
			paths[strings.ToLower(e.Path)] = true
			payload += len(e.Payload)
			switch e.Intent {
			case "go.function-body.replace":
				if e.Payload == "" || e.ImportPath != "" || e.Alias != "" || e.Comment != "" || e.Anchor.Kind != "function-body" || e.Anchor.NodeID == "" {
					return ErrRequest
				}
			case "go.import.add":
				if e.Payload != "" || e.Comment != "" || e.ImportPath == "" || !plainLF(e.ImportPath) || strings.ContainsAny(e.ImportPath, "\n\t\"`\\ ") || e.Anchor.Kind != "import-boundary" || e.Anchor.NodeID != "" {
					return ErrRequest
				}
				if e.Alias != "" && e.Alias != "." && !token.IsIdentifier(e.Alias) {
					return ErrRequest
				}
			case "go.import.remove":
				if e.Payload != "" || e.Comment != "" || e.ImportPath == "" || e.Anchor.Kind != "import" || e.Anchor.NodeID == "" {
					return ErrRequest
				}
			case "go.comment-anchor.insert-statements":
				if e.Payload == "" || !strings.HasPrefix(e.Comment, "//") || strings.ContainsAny(e.Comment, "\r\n") || !plainLF(e.Comment) || e.ImportPath != "" || e.Alias != "" || e.Anchor.Kind != "comment" || e.Anchor.Key != e.Comment || strings.Contains(e.Payload, e.Comment) {
					return ErrRequest
				}
			default:
				return ErrRequest
			}
		}
		if len(paths) > 8 || payload > 32<<10 {
			return ErrRequest
		}
	default:
		return ErrRequest
	}
	return nil
}
func goPath(p string) bool {
	return p != "" && utf8.ValidString(p) && path.Clean(p) == p && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\\\x00\r\n") && path.Ext(p) == ".go"
}
func plainLF(s string) bool { return utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r") }
