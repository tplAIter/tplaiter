package resultdto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"path"
	"reflect"
	"strings"
)

const OperationSemanticPreview Operation = "semantic.preview"

func init() {
	operationRegistry[OperationSemanticPreview] = operationSpec{"SemanticPreview", ScopeProject}
}

// SemanticAnchor identifies an independently derived original syntax span.
// Its bytes/graph identity are preconditions, not authorization or a writer.
type SemanticAnchor struct {
	Kind      string `json:"kind"`
	Key       string `json:"key"`
	StartByte int    `json:"startByte"`
	EndByte   int    `json:"endByte"`
	Digest    string `json:"digest"`
	NodeID    string `json:"nodeId,omitempty"`
}
type SemanticImage struct {
	Path          string           `json:"path"`
	Mode          uint32           `json:"mode"`
	Before        []byte           `json:"before"`
	After         []byte           `json:"after"`
	BeforeDigest  string           `json:"beforeDigest"`
	AfterDigest   string           `json:"afterDigest"`
	BeforeBytes   int              `json:"beforeBytes"`
	AfterBytes    int              `json:"afterBytes"`
	BeforeAnchors []SemanticAnchor `json:"beforeAnchors"`
	AfterAnchors  []SemanticAnchor `json:"afterAnchors"`
	Diff          string           `json:"diff"`
}
type SemanticEditMapping struct {
	ID             string         `json:"id"`
	Path           string         `json:"path"`
	Intent         string         `json:"intent"`
	Before         SemanticAnchor `json:"before"`
	AfterStartByte int            `json:"afterStartByte"`
	AfterEndByte   int            `json:"afterEndByte"`
}
type SemanticPreviewData struct {
	APIVersion           string                `json:"apiVersion"`
	Action               string                `json:"action"`
	Basis                string                `json:"basis"`
	VerificationLevel    string                `json:"verificationLevel"`
	CompilerVerification string                `json:"compilerVerification"`
	Scope                string                `json:"scope"`
	NoEffects            bool                  `json:"noEffects"`
	RequestDigest        string                `json:"requestDigest"`
	SourceManifestDigest string                `json:"sourceManifestDigest"`
	PreviewDigest        string                `json:"previewDigest"`
	Images               []SemanticImage       `json:"images"`
	BeforeGraph          graphdoc.Document     `json:"beforeGraph"`
	AfterGraph           graphdoc.Document     `json:"afterGraph"`
	AddedNodes           []string              `json:"addedNodes"`
	RemovedNodes         []string              `json:"removedNodes"`
	AddedEdges           []graphdoc.Edge       `json:"addedEdges"`
	RemovedEdges         []graphdoc.Edge       `json:"removedEdges"`
	Edits                []SemanticEditMapping `json:"edits"`
}

// DecodeSemanticPreviewData consumes factual observations, not an admission
// carrier. Canonicalization rejects duplicate keys and unsafe scalar encodings.
func DecodeSemanticPreviewData(raw []byte) (SemanticPreviewData, error) {
	var d SemanticPreviewData
	if len(raw) == 0 || len(raw) > 32768 {
		return d, errors.New("SEMANTIC_RESULT_INVALID")
	}
	if _, e := canonicaljson.Canonicalize(raw); e != nil {
		return d, e
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&d); e != nil {
		return d, e
	}
	var value any
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if e := decoder.Decode(&value); e != nil {
		return d, e
	}
	if e := semanticExactFields(value, reflect.TypeOf(d)); e != nil {
		return d, e
	}
	return d, ValidateSemanticPreviewData(d)
}
func semanticExactFields(value any, t reflect.Type) error {
	if value == nil {
		return errors.New("SEMANTIC_RESULT_INVALID")
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("SEMANTIC_RESULT_INVALID")
		}
		fields := map[string]reflect.Type{}
		required := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			if len(tag) == 0 || tag[0] == "" || tag[0] == "-" {
				continue
			}
			fields[tag[0]] = f.Type
			required[tag[0]] = !strings.Contains(f.Tag.Get("json"), "omitempty")
		}
		for key, v := range object {
			field, ok := fields[key]
			if !ok {
				return errors.New("SEMANTIC_RESULT_INVALID")
			}
			if e := semanticExactFields(v, field); e != nil {
				return e
			}
			delete(required, key)
		}
		for _, needed := range required {
			if needed {
				return errors.New("SEMANTIC_RESULT_INVALID")
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			s, ok := value.(string)
			if !ok {
				return errors.New("SEMANTIC_RESULT_INVALID")
			}
			b, e := base64.StdEncoding.DecodeString(s)
			if e != nil || base64.StdEncoding.EncodeToString(b) != s {
				return errors.New("SEMANTIC_RESULT_INVALID")
			}
			return nil
		}
		values, ok := value.([]any)
		if !ok {
			return errors.New("SEMANTIC_RESULT_INVALID")
		}
		for _, v := range values {
			if e := semanticExactFields(v, t.Elem()); e != nil {
				return e
			}
		}
	case reflect.Map:
		values, ok := value.(map[string]any)
		if !ok {
			return errors.New("SEMANTIC_RESULT_INVALID")
		}
		for _, v := range values {
			if e := semanticExactFields(v, t.Elem()); e != nil {
				return e
			}
		}
	}
	return nil
}
func ValidateSemanticPreviewData(d SemanticPreviewData) error {
	invalid := errors.New("SEMANTIC_RESULT_INVALID")
	if d.APIVersion != "tplaiter.dev/semantic-preview-result/v1" || (d.Action != "anchors" && d.Action != "preview") || d.Basis != "installed-project-observed-bytes" || d.VerificationLevel != "go-syntax-only" || d.CompilerVerification != "not-performed" || d.Scope != "selected-go-files" || !d.NoEffects || !semanticDigest(d.RequestDigest) || !semanticDigest(d.SourceManifestDigest) || len(d.Images) < 1 || len(d.Images) > 8 || len(d.Edits) > 8 {
		return invalid
	}
	if graphdoc.Verify(d.BeforeGraph) != nil || graphdoc.Verify(d.AfterGraph) != nil {
		return invalid
	}
	previous := ""
	files := map[string]SemanticImage{}
	for _, image := range d.Images {
		if image.Path <= previous || path.Clean(image.Path) != image.Path || strings.HasPrefix(image.Path, "/") || strings.HasPrefix(image.Path, "../") || strings.ContainsAny(image.Path, "\\\x00\r\n") || path.Ext(image.Path) != ".go" || image.Mode > 0777 || image.Before == nil || image.After == nil || len(image.Before) > 1<<20 || len(image.After) > 1<<20 || image.BeforeBytes != len(image.Before) || image.AfterBytes != len(image.After) || evidencecas.Digest(image.Before) != image.BeforeDigest || evidencecas.Digest(image.After) != image.AfterDigest {
			return invalid
		}
		previous = image.Path
		fold := strings.ToLower(image.Path)
		if _, ok := files[fold]; ok {
			return invalid
		}
		files[fold] = image
		for _, set := range []struct {
			raw     []byte
			anchors []SemanticAnchor
		}{{image.Before, image.BeforeAnchors}, {image.After, image.AfterAnchors}} {
			for _, a := range set.anchors {
				if a.StartByte < 0 || a.EndByte < a.StartByte || a.EndByte > len(set.raw) || a.Kind == "" || a.Key == "" || evidencecas.Digest(set.raw[a.StartByte:a.EndByte]) != a.Digest {
					return invalid
				}
			}
		}
	}
	ids := map[string]bool{}
	for _, edit := range d.Edits {
		image, ok := files[strings.ToLower(edit.Path)]
		if !ok || edit.Path != image.Path || edit.ID == "" || ids[edit.ID] || edit.AfterStartByte < 0 || edit.AfterEndByte < edit.AfterStartByte || edit.AfterEndByte > len(image.After) {
			return invalid
		}
		ids[edit.ID] = true
		found := false
		for _, a := range image.BeforeAnchors {
			if reflect.DeepEqual(a, edit.Before) {
				found = true
			}
		}
		if !found {
			return invalid
		}
	}
	if d.Action == "anchors" && (len(d.Edits) != 0 || !reflect.DeepEqual(d.BeforeGraph, d.AfterGraph)) {
		return invalid
	}
	pin := d.PreviewDigest
	d.PreviewDigest = ""
	raw, e := canonicaljson.Canonical(d)
	if e != nil || evidencecas.Digest(raw) != pin {
		return invalid
	}
	return nil
}
func semanticDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	b, e := hex.DecodeString(s[7:])
	return e == nil && hex.EncodeToString(b) == s[7:]
}
