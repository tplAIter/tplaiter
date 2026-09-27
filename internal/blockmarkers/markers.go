// Package blockmarkers proves that managed-block delimiters occupy real
// comment tokens in an original Go or Rust source file. It is deliberately
// pure: parsing a marker never implies that a file compiles or is executable.
package blockmarkers

import (
	"bytes"
	"fmt"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/managedblocks"
)

const MaxSourceBytes = 16 << 20

type Language string

const (
	LanguageGo   Language = "go"
	LanguageRust Language = "rust"
)

type ErrorCode string

const (
	CodeUnsupportedLanguage ErrorCode = "marker-language-unsupported"
	CodeInvalidSource       ErrorCode = "marker-invalid-source"
	CodeSyntax              ErrorCode = "marker-syntax"
	CodeLexical             ErrorCode = "marker-lexical"
	CodeNotComment          ErrorCode = "marker-not-comment"
	CodeMarker              ErrorCode = "marker-invalid"
)

// Error intentionally contains no source excerpt. Paths and source are
// caller-owned and must not be retained by this package.
type Error struct {
	Path string
	Code ErrorCode
}

func (e *Error) Error() string { return fmt.Sprintf("block markers: %s: %s", e.Path, e.Code) }

type Kind string

const (
	KindBegin Kind = "begin"
	KindEnd   Kind = "end"
)

// Marker offsets are byte offsets into the exact input passed to Validate.
type Marker struct {
	Kind     Kind
	ID       string
	Provider string
	Start    int
	End      int
}

type commentSpan struct{ start, end int }

// Validate returns a defensive copy of the ordered delimiter stream. It
// accepts only Go and Rust; TypeScript has its separately gated provider.
func Validate(language Language, path string, content []byte) ([]Marker, error) {
	if err := validSource(path, content); err != nil {
		return nil, err
	}
	var (
		comments []commentSpan
		err      error
	)
	switch language {
	case LanguageGo:
		comments, err = goComments(path, content)
	case LanguageRust:
		comments, err = rustComments(path, content)
	default:
		return nil, &Error{Path: path, Code: CodeUnsupportedLanguage}
	}
	if err != nil {
		return nil, err
	}
	return markersInComments(path, content, comments)
}

func validSource(path string, content []byte) error {
	if len(content) > MaxSourceBytes || bytes.IndexByte(content, 0) >= 0 || !utf8.Valid(content) {
		return &Error{Path: path, Code: CodeInvalidSource}
	}
	return nil
}

func markersInComments(path string, content []byte, comments []commentSpan) ([]Marker, error) {
	doc, err := managedblocks.Parse(path, content)
	if err != nil {
		return nil, &Error{Path: path, Code: CodeMarker}
	}
	markers := make([]Marker, 0, len(doc.Regions)*2)
	for _, region := range doc.Regions {
		begin := Marker{Kind: KindBegin, ID: region.ID, Provider: region.Provider, Start: region.Start, End: region.BodyStart}
		end := Marker{Kind: KindEnd, ID: region.ID, Start: region.BodyEnd, End: region.EndOffset}
		for _, marker := range []Marker{begin, end} {
			start, finish := markerCommentBounds(content, marker.Start, marker.End)
			if start < 0 || !hasExactComment(comments, start, finish) {
				return nil, &Error{Path: path, Code: CodeNotComment}
			}
			markers = append(markers, marker)
		}
	}
	return append([]Marker(nil), markers...), nil
}

// markerCommentBounds trims only indentation and line terminators around a
// marker line. The remaining bytes must be one entire language comment token.
func markerCommentBounds(content []byte, start, end int) (int, int) {
	if start < 0 || end < start || end > len(content) {
		return -1, -1
	}
	line := content[start:end]
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	left := 0
	for left < len(line) && (line[left] == ' ' || line[left] == '\t') {
		left++
	}
	right := len(line)
	for right > left && (line[right-1] == ' ' || line[right-1] == '\t') {
		right--
	}
	if left == right {
		return -1, -1
	}
	return start + left, start + right
}

func hasExactComment(comments []commentSpan, start, end int) bool {
	for _, comment := range comments {
		if comment.start == start && comment.end == end {
			return true
		}
	}
	return false
}
