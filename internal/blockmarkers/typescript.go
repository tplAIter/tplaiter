package blockmarkers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/managedblocks"
)

const (
	MaxTypeScriptReportBytes = 8 << 20
	MaxTypeScriptComments    = 65536
	typeScriptReportAPI      = "tplaiter.dev/typescript-comments/v1"
)

type TypeScriptComment struct {
	Kind      string `json:"kind"`
	StartByte int    `json:"startByte"`
	EndByte   int    `json:"endByte"`
}
type TypeScriptReport struct {
	APIVersion     string              `json:"apiVersion"`
	Language       string              `json:"language"`
	Path           string              `json:"path"`
	InputSHA256    string              `json:"inputSHA256"`
	ProviderSHA256 string              `json:"providerSHA256"`
	Comments       []TypeScriptComment `json:"comments"`
}

var (
	tsReportDigest   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tsReportPathPart = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// ParseTypeScriptReport decodes an untrusted, transient provider report. It
// creates no authority and performs no I/O.
func ParseTypeScriptReport(raw []byte) (TypeScriptReport, error) {
	if len(raw) == 0 || len(raw) > MaxTypeScriptReportBytes || !utf8.Valid(raw) {
		return TypeScriptReport{}, fmt.Errorf("typescript report: invalid wire")
	}
	if err := scanReportJSON(bytes.NewReader(raw)); err != nil {
		return TypeScriptReport{}, fmt.Errorf("typescript report: invalid JSON: %w", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil || len(keys) != 6 {
		return TypeScriptReport{}, fmt.Errorf("typescript report: closed fields")
	}
	for _, key := range []string{"apiVersion", "language", "path", "inputSHA256", "providerSHA256", "comments"} {
		if _, ok := keys[key]; !ok {
			return TypeScriptReport{}, fmt.Errorf("typescript report: missing field %s", key)
		}
	}
	if bytes.Equal(bytes.TrimSpace(keys["comments"]), []byte("null")) || len(bytes.TrimSpace(keys["comments"])) == 0 || bytes.TrimSpace(keys["comments"])[0] != '[' {
		return TypeScriptReport{}, fmt.Errorf("typescript report: comments must be array")
	}
	var commentWire []map[string]json.RawMessage
	if err := json.Unmarshal(keys["comments"], &commentWire); err != nil || len(commentWire) > MaxTypeScriptComments {
		return TypeScriptReport{}, fmt.Errorf("typescript report: invalid comments")
	}
	integer := regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	for _, c := range commentWire {
		if len(c) != 3 {
			return TypeScriptReport{}, fmt.Errorf("typescript report: closed comment fields")
		}
		for _, key := range []string{"kind", "startByte", "endByte"} {
			if _, ok := c[key]; !ok {
				return TypeScriptReport{}, fmt.Errorf("typescript report: missing comment field")
			}
		}
		if bytes.Equal(bytes.TrimSpace(c["kind"]), []byte("null")) || len(bytes.TrimSpace(c["kind"])) == 0 || bytes.TrimSpace(c["kind"])[0] != '"' || bytes.Equal(bytes.TrimSpace(c["startByte"]), []byte("null")) || bytes.Equal(bytes.TrimSpace(c["endByte"]), []byte("null")) {
			return TypeScriptReport{}, fmt.Errorf("typescript report: invalid comment field type")
		}
		var kind string
		if err := json.Unmarshal(c["kind"], &kind); err != nil || (kind != "line" && kind != "block") {
			return TypeScriptReport{}, fmt.Errorf("typescript report: invalid comment kind")
		}
		if !integer.Match(c["startByte"]) || !integer.Match(c["endByte"]) {
			return TypeScriptReport{}, fmt.Errorf("typescript report: invalid integer")
		}
	}
	var wire struct {
		APIVersion, Language, Path, InputSHA256, ProviderSHA256 string
		Comments                                                []TypeScriptComment
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil || requireReportEOF(dec) != nil {
		return TypeScriptReport{}, fmt.Errorf("typescript report: malformed wire")
	}
	if wire.APIVersion != typeScriptReportAPI || (wire.Language != "typescript" && wire.Language != "tsx") || !validTypeScriptPath(wire.Language, wire.Path) || !tsReportDigest.MatchString(wire.InputSHA256) || !tsReportDigest.MatchString(wire.ProviderSHA256) || len(wire.Comments) > MaxTypeScriptComments {
		return TypeScriptReport{}, fmt.Errorf("typescript report: invalid fields")
	}
	return TypeScriptReport{wire.APIVersion, wire.Language, wire.Path, wire.InputSHA256, wire.ProviderSHA256, append([]TypeScriptComment(nil), wire.Comments...)}, nil
}

func ValidateTypeScriptReport(report TypeScriptReport, providerSHA256 string, content []byte) ([]Marker, error) {
	if report.APIVersion != typeScriptReportAPI || !validTypeScriptPath(report.Language, report.Path) || !tsReportDigest.MatchString(report.InputSHA256) || !tsReportDigest.MatchString(report.ProviderSHA256) || !tsReportDigest.MatchString(providerSHA256) || report.ProviderSHA256 != providerSHA256 || len(content) > MaxSourceBytes || bytes.IndexByte(content, 0) >= 0 || !utf8.Valid(content) || report.InputSHA256 != digestBytes(content) {
		return nil, fmt.Errorf("typescript report: binding mismatch")
	}
	if len(report.Comments) > MaxTypeScriptComments {
		return nil, fmt.Errorf("typescript report: comment limit")
	}
	spans := make([]commentSpan, 0, len(report.Comments))
	previousEnd := 0
	for i, c := range report.Comments {
		if c.Kind != "line" && c.Kind != "block" || c.StartByte < 0 || c.StartByte >= c.EndByte || c.EndByte > len(content) || i > 0 && c.StartByte < previousEnd || !utf8Boundary(content, c.StartByte) || !utf8Boundary(content, c.EndByte) {
			return nil, fmt.Errorf("typescript report: invalid comment range")
		}
		raw := content[c.StartByte:c.EndByte]
		if c.Kind == "line" && !bytes.HasPrefix(raw, []byte("//")) || c.Kind == "block" && (!bytes.HasPrefix(raw, []byte("/*")) || !bytes.HasSuffix(raw, []byte("*/"))) {
			return nil, fmt.Errorf("typescript report: invalid comment delimiter")
		}
		spans = append(spans, commentSpan{c.StartByte, c.EndByte})
		previousEnd = c.EndByte
	}
	doc, err := managedblocks.Parse(report.Path, content)
	if err != nil {
		return nil, fmt.Errorf("typescript report: marker parse")
	}
	markers := make([]Marker, 0, len(doc.Regions)*2)
	for _, region := range doc.Regions {
		for _, m := range []Marker{{Kind: KindBegin, ID: region.ID, Provider: region.Provider, Start: region.Start, End: region.BodyStart}, {Kind: KindEnd, ID: region.ID, Start: region.BodyEnd, End: region.EndOffset}} {
			start, end := markerCommentBounds(content, m.Start, m.End)
			if start < 0 || !hasExactComment(spans, start, end) {
				return nil, fmt.Errorf("typescript report: marker is not a reported comment")
			}
			markers = append(markers, m)
		}
	}
	return append([]Marker(nil), markers...), nil
}

func digestBytes(b []byte) string       { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func utf8Boundary(b []byte, n int) bool { return n == 0 || n == len(b) || (b[n]&0xc0) != 0x80 }
func validTypeScriptPath(language, p string) bool {
	if p == "" || len([]byte(p)) > 4096 || utf8.RuneCountInString(p) > 1024 || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\:\x00\r\n\t") || !utf8.ValidString(p) {
		return false
	}
	parts := strings.Split(p, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || !tsReportPathPart.MatchString(part) {
			return false
		}
	}
	return language == "tsx" && strings.HasSuffix(p, ".tsx") || language == "typescript" && (strings.HasSuffix(p, ".ts") || strings.HasSuffix(p, ".mts") || strings.HasSuffix(p, ".cts"))
}

func scanReportJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	if err := scanReportValue(d); err != nil {
		return err
	}
	return requireReportEOF(d)
}

func scanReportValue(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if x, ok := t.(json.Delim); ok {
		if x == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return fmt.Errorf("duplicate key")
				}
				seen[s] = true
				if e = scanReportValue(d); e != nil {
					return e
				}
			}
			_, err = d.Token()
			return err
		}
		if x == '[' {
			for d.More() {
				if err := scanReportValue(d); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
	}
	return nil
}

func requireReportEOF(d *json.Decoder) error {
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
