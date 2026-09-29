package managedblocks

import (
	"bytes"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	beginPattern = regexp.MustCompile(`^tplater:managed-begin id=([A-Za-z][A-Za-z0-9._-]{0,127}) provider=([A-Za-z][A-Za-z0-9._/-]{0,127})$`)
	endPattern   = regexp.MustCompile(`^tplater:managed-end id=([A-Za-z][A-Za-z0-9._-]{0,127})$`)
)

type markerKind uint8

const (
	markerNone markerKind = iota
	markerBegin
	markerEnd
)

type parsedMarker struct {
	kind         markerKind
	id, provider string
}
type sourceLine struct {
	start, end, line int
	data             []byte
}

func Parse(path string, content []byte) (Document, error) {
	doc := Document{ByID: make(map[string]Region)}
	if line := invalidEncodingLine(content); line != 0 {
		return doc, &Error{Path: path, Line: line, Code: CodeInvalidEncoding}
	}
	var open *struct {
		marker parsedMarker
		line   sourceLine
	}
	closed := map[string]struct{}{}
	for _, ln := range splitSourceLines(content) {
		marker, mentioned, code := parseMarkerLine(ln.data)
		if code != "" {
			return Document{}, &Error{Path: path, Line: ln.line, Code: code, ID: marker.id}
		}
		if !mentioned {
			continue
		}
		switch marker.kind {
		case markerBegin:
			if open != nil {
				return Document{}, &Error{Path: path, Line: ln.line, Code: CodeNestedRegion, ID: marker.id}
			}
			if _, ok := closed[marker.id]; ok {
				return Document{}, &Error{Path: path, Line: ln.line, Code: CodeDuplicateID, ID: marker.id}
			}
			open = &struct {
				marker parsedMarker
				line   sourceLine
			}{marker, ln}
		case markerEnd:
			if open == nil {
				code := CodeEndWithoutBegin
				if len(closed) > 0 {
					code = CodeOverlappingRegion
				}
				return Document{}, &Error{Path: path, Line: ln.line, Code: code, ID: marker.id}
			}
			if marker.id != open.marker.id {
				return Document{}, &Error{Path: path, Line: ln.line, Code: CodeEndIDMismatch, ID: marker.id}
			}
			r := Region{ID: marker.id, Provider: open.marker.provider, Begin: cloneBytes(content[open.line.start:open.line.end]), Body: cloneBytes(content[open.line.end:ln.start]), End: cloneBytes(content[ln.start:ln.end]), BeginLine: open.line.line, EndLine: ln.line, Ordinal: len(doc.Regions), Start: open.line.start, BodyStart: open.line.end, BodyEnd: ln.start, EndOffset: ln.end}
			doc.Regions = append(doc.Regions, r)
			doc.ByID[r.ID] = r
			closed[r.ID] = struct{}{}
			open = nil
		}
	}
	if open != nil {
		return Document{}, &Error{Path: path, Line: open.line.line, Code: CodeBeginWithoutEnd, ID: open.marker.id}
	}
	doc.Gaps = make([][]byte, 0, len(doc.Regions)+1)
	previous := 0
	for _, r := range doc.Regions {
		doc.Gaps = append(doc.Gaps, cloneBytes(content[previous:r.Start]))
		previous = r.EndOffset
	}
	doc.Gaps = append(doc.Gaps, cloneBytes(content[previous:]))
	doc.Prefix = cloneBytes(doc.Gaps[0])
	doc.Suffix = cloneBytes(doc.Gaps[len(doc.Gaps)-1])
	return doc, nil
}

func invalidEncodingLine(content []byte) int {
	line := 1
	for len(content) > 0 {
		if content[0] == 0 {
			return line
		}
		if content[0] == '\n' {
			line++
			content = content[1:]
			continue
		}
		_, size := utf8.DecodeRune(content)
		if size == 1 && content[0] >= utf8.RuneSelf {
			return line
		}
		content = content[size:]
	}
	return 0
}

func splitSourceLines(content []byte) []sourceLine {
	if len(content) == 0 {
		return nil
	}
	lines := make([]sourceLine, 0, bytes.Count(content, []byte{'\n'})+1)
	for start, n := 0, 1; start < len(content); n++ {
		rel := bytes.IndexByte(content[start:], '\n')
		end := len(content)
		if rel >= 0 {
			end = start + rel + 1
		}
		lines = append(lines, sourceLine{start, end, n, content[start:end]})
		start = end
	}
	return lines
}

func parseMarkerLine(raw []byte) (parsedMarker, bool, ErrorCode) {
	line := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	count := strings.Count(line, "tplater:managed-")
	if count == 0 {
		return parsedMarker{}, false, ""
	}
	if count != 1 {
		return parsedMarker{}, true, CodeMalformedMarker
	}
	payload, ok := commentPayload(strings.TrimSpace(line))
	if !ok {
		return parsedMarker{}, true, CodeMarkerNotComment
	}
	if strings.Contains(payload, "tplater:begin") || strings.Contains(payload, "tplater:end") {
		if !strings.HasPrefix(payload, "tplater:managed-") {
			return parsedMarker{}, true, CodeMalformedMarker
		}
	}
	if m := beginPattern.FindStringSubmatch(payload); m != nil {
		return parsedMarker{kind: markerBegin, id: m[1], provider: m[2]}, true, ""
	}
	if m := endPattern.FindStringSubmatch(payload); m != nil {
		return parsedMarker{kind: markerEnd, id: m[1]}, true, ""
	}
	if strings.HasPrefix(payload, "tplater:managed-") {
		if !strings.HasPrefix(payload, "tplater:managed-begin") && !strings.HasPrefix(payload, "tplater:managed-end") {
			return parsedMarker{}, true, CodeUnknownMarker
		}
		return parsedMarker{}, true, CodeMalformedMarker
	}
	return parsedMarker{}, true, CodeMalformedMarker
}

func commentPayload(line string) (string, bool) {
	for _, p := range []string{"//", "#", ";"} {
		if strings.HasPrefix(line, p) {
			return strings.TrimSpace(strings.TrimPrefix(line, p)), true
		}
	}
	if strings.HasPrefix(line, "<!--") && strings.HasSuffix(line, "-->") {
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "<!--"), "-->")), true
	}
	if strings.HasPrefix(line, "/*") && strings.HasSuffix(line, "*/") {
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "/*"), "*/")), true
	}
	return "", false
}
