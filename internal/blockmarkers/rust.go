package blockmarkers

import (
	"unicode"
	"unicode/utf8"
)

const (
	maxRustBlockNesting = 128
	maxRustRawHashes    = 255
)

type rustLiteralKind struct {
	raw, byteDomain, cDomain bool
}

var (
	rustNormal  = rustLiteralKind{}
	rustByte    = rustLiteralKind{byteDomain: true}
	rustC       = rustLiteralKind{cDomain: true}
	rustRaw     = rustLiteralKind{raw: true}
	rustRawByte = rustLiteralKind{raw: true, byteDomain: true}
	rustRawC    = rustLiteralKind{raw: true, cDomain: true}
)

func rustComments(path string, source []byte) ([]commentSpan, error) {
	comments := make([]commentSpan, 0)
	for i := 0; i < len(source); {
		switch source[i] {
		case '/':
			if i+1 < len(source) && source[i+1] == '/' {
				start := i
				i += 2
				for i < len(source) && source[i] != '\n' && source[i] != '\r' {
					i++
				}
				comments = append(comments, commentSpan{start: start, end: i})
				continue
			}
			if i+1 < len(source) && source[i+1] == '*' {
				start, end, ok := scanRustBlockComment(source, i)
				if !ok {
					return nil, rustLexical(path)
				}
				comments = append(comments, commentSpan{start: start, end: end})
				i = end
				continue
			}
		case '"':
			if rustIdentifierBefore(source, i) {
				return nil, rustLexical(path)
			}
			end, ok := scanRustQuoted(source, i+1, rustNormal)
			if !ok {
				return nil, rustLexical(path)
			}
			i = end
			continue
		case '\'':
			if rustIdentifierBefore(source, i) {
				return nil, rustLexical(path)
			}
			end, charLiteral, ok := scanRustCharOrLifetime(source, i)
			if !ok {
				return nil, rustLexical(path)
			}
			if charLiteral {
				i = end
				continue
			}
		case 'b', 'c', 'r':
			end, matched, ok := scanRustPrefixedLiteral(source, i)
			if !ok {
				return nil, rustLexical(path)
			}
			if matched {
				i = end
				continue
			}
		}
		_, n := utf8.DecodeRune(source[i:])
		if n == 0 {
			return nil, rustLexical(path)
		}
		i += n
	}
	return comments, nil
}

func rustLexical(path string) error { return &Error{Path: path, Code: CodeLexical} }

func scanRustBlockComment(source []byte, start int) (int, int, bool) {
	i, depth := start+2, 1
	for i < len(source) {
		if i+1 < len(source) {
			switch {
			case source[i] == '/' && source[i+1] == '*':
				depth++
				if depth > maxRustBlockNesting {
					return 0, 0, false
				}
				i += 2
				continue
			case source[i] == '*' && source[i+1] == '/':
				depth--
				i += 2
				if depth == 0 {
					return start, i, true
				}
				continue
			}
		}
		_, n := utf8.DecodeRune(source[i:])
		i += n
	}
	return 0, 0, false
}

// scanRustQuoted recognizes only the literal spelling necessary to prove that
// subsequent comment delimiters are outside a supported literal. It is not a
// parser, compiler, or semantic validator.
func scanRustQuoted(source []byte, i int, kind rustLiteralKind) (int, bool) {
	for i < len(source) {
		switch source[i] {
		case '"':
			return i + 1, true
		case '\\':
			var ok bool
			i, ok = scanRustQuotedEscape(source, i, kind)
			if !ok {
				return 0, false
			}
		case '\r':
			return 0, false
		case '\n':
			i++
		default:
			if kind.byteDomain && source[i] >= utf8.RuneSelf {
				return 0, false
			}
			_, n := utf8.DecodeRune(source[i:])
			i += n
		}
	}
	return 0, false
}

func scanRustQuotedEscape(source []byte, start int, kind rustLiteralKind) (int, bool) {
	i := start + 1
	if i >= len(source) {
		return 0, false
	}
	// Rust's string continuation is backslash-LF. CR and CRLF are rejected by
	// this bounded lexer rather than treated as a platform-normalized newline.
	if source[i] == '\n' {
		return i + 1, true
	}
	if source[i] == '\r' {
		return 0, false
	}
	switch source[i] {
	case 'n', 'r', 't', '\\', '\'', '"':
		return i + 1, true
	case '0':
		return i + 1, !kind.cDomain
	case 'x':
		value, end, ok := scanRustHexEscape(source, i)
		if !ok || kind.cDomain && value == 0 || !kind.byteDomain && !kind.cDomain && value > 0x7f {
			return 0, false
		}
		return end, true
	case 'u':
		if kind.byteDomain {
			return 0, false
		}
		value, end, ok := scanRustUnicodeEscape(source, i)
		if !ok || kind.cDomain && value == 0 {
			return 0, false
		}
		return end, true
	default:
		return 0, false
	}
}

func scanRustRaw(source []byte, quote, hashes int, kind rustLiteralKind) (int, bool) {
	i := quote + 1
	for i < len(source) {
		if source[i] == '\r' || kind.byteDomain && source[i] >= utf8.RuneSelf {
			return 0, false
		}
		if source[i] == '"' {
			j := i + 1
			for n := 0; n < hashes && j < len(source) && source[j] == '#'; n, j = n+1, j+1 {
			}
			if j == i+1+hashes {
				return j, true
			}
		}
		_, n := utf8.DecodeRune(source[i:])
		i += n
	}
	return 0, false
}

func scanRustPrefixedLiteral(source []byte, start int) (int, bool, bool) {
	if rustIdentifierBefore(source, start) {
		// An identifier immediately followed by a supported-prefix spelling is
		// a reserved adjacency, not a literal authority boundary.
		if rustPrefixLooksLiteral(source, start) {
			return 0, true, false
		}
		return start + 1, false, true
	}
	i := start
	kind := rustNormal
	switch source[start] {
	case 'b':
		kind = rustByte
		i++
	case 'c':
		kind = rustC
		i++
	case 'r':
		kind = rustRaw
		i++
	}
	if i < len(source) && source[i] == 'r' && source[start] != 'r' {
		kind.raw = true
		i++
	}
	if kind.raw {
		hashes := 0
		for i < len(source) && source[i] == '#' {
			hashes++
			i++
		}
		if hashes > maxRustRawHashes {
			return 0, true, false
		}
		if i >= len(source) || source[i] != '"' {
			// `r#ident` is a raw identifier and has no literal body. Raw
			// lifetime forms are deliberately rejected at the apostrophe branch.
			return start + 1, false, true
		}
		end, ok := scanRustRaw(source, i, hashes, kind)
		return end, true, ok
	}
	if i < len(source) && source[i] == '"' && i > start {
		end, ok := scanRustQuoted(source, i+1, kind)
		return end, true, ok
	}
	if source[start] == 'b' && start+1 < len(source) && source[start+1] == '\'' {
		end, ok := scanRustByteCharLiteral(source, start+1)
		return end, true, ok
	}
	return start + 1, false, true
}

func rustPrefixLooksLiteral(source []byte, start int) bool {
	i := start + 1
	if i < len(source) && source[start] != 'r' && source[i] == 'r' {
		i++
	}
	for i < len(source) && source[i] == '#' {
		i++
	}
	if i >= len(source) {
		return false
	}
	return source[i] == '"' || source[start] == 'b' && source[start+1] == '\''
}

func scanRustCharOrLifetime(source []byte, start int) (int, bool, bool) {
	if start+2 < len(source) && source[start+1] == 'r' && source[start+2] == '#' {
		// Raw lifetimes have edition-specific grammar. This bounded scanner does
		// not need them for comment recognition and rejects them before they can
		// shield a marker line.
		return 0, false, false
	}
	if end, ok := scanRustCharLiteral(source, start, false); ok {
		return end, true, true
	}
	i := start + 1
	if i >= len(source) {
		return 0, false, false
	}
	r, n := utf8.DecodeRune(source[i:])
	if n == 0 || !rustIdentStart(r) {
		return 0, false, false
	}
	i += n
	for i < len(source) {
		r, n = utf8.DecodeRune(source[i:])
		if n == 0 || !rustIdentContinue(r) {
			break
		}
		i += n
	}
	return i, false, true
}

func scanRustByteCharLiteral(source []byte, start int) (int, bool) {
	return scanRustCharLiteral(source, start, true)
}

func scanRustCharLiteral(source []byte, start int, byteLiteral bool) (int, bool) {
	if start < 0 || start >= len(source) || source[start] != '\'' || start+1 >= len(source) {
		return 0, false
	}
	i := start + 1
	if source[i] == '\\' {
		var ok bool
		i, ok = scanRustCharEscape(source, i, byteLiteral)
		if !ok {
			return 0, false
		}
	} else {
		r, n := utf8.DecodeRune(source[i:])
		if n == 0 || r == utf8.RuneError && n == 1 || r == '\'' || r == '\\' || r == '\n' || r == '\r' || r == '\t' || byteLiteral && r > 0x7f {
			return 0, false
		}
		i += n
	}
	if i >= len(source) || source[i] != '\'' {
		return 0, false
	}
	return i + 1, true
}

func scanRustCharEscape(source []byte, start int, byteLiteral bool) (int, bool) {
	i := start + 1
	if i >= len(source) {
		return 0, false
	}
	switch source[i] {
	case 'n', 'r', 't', '\\', '0', '\'', '"':
		return i + 1, true
	case 'x':
		value, end, ok := scanRustHexEscape(source, i)
		if !ok || !byteLiteral && value > 0x7f {
			return 0, false
		}
		return end, true
	case 'u':
		if byteLiteral {
			return 0, false
		}
		_, end, ok := scanRustUnicodeEscape(source, i)
		return end, ok
	default:
		return 0, false
	}
}

func scanRustHexEscape(source []byte, start int) (int, int, bool) {
	if start+2 >= len(source) || source[start] != 'x' || !rustHex(source[start+1]) || !rustHex(source[start+2]) {
		return 0, 0, false
	}
	return rustHexValue(source[start+1])*16 + rustHexValue(source[start+2]), start + 3, true
}

func scanRustUnicodeEscape(source []byte, start int) (int, int, bool) {
	if start+1 >= len(source) || source[start] != 'u' || source[start+1] != '{' {
		return 0, 0, false
	}
	i, value, digits := start+2, 0, 0
	previousUnderscore := false
	for i < len(source) && source[i] != '}' {
		if source[i] == '_' {
			if digits == 0 || previousUnderscore {
				return 0, 0, false
			}
			previousUnderscore = true
			i++
			continue
		}
		if digits == 6 || !rustHex(source[i]) {
			return 0, 0, false
		}
		value = value*16 + rustHexValue(source[i])
		digits++
		previousUnderscore = false
		i++
	}
	if i >= len(source) || digits == 0 || previousUnderscore || value > utf8.MaxRune || value >= 0xd800 && value <= 0xdfff {
		return 0, 0, false
	}
	return value, i + 1, true
}

func rustIdentifierBefore(source []byte, start int) bool {
	if start == 0 {
		return false
	}
	r, _ := utf8.DecodeLastRune(source[:start])
	// This is intentionally a conservative bounded XID policy: ASCII Rust
	// identifier continuations are recognized exactly enough for this lexer;
	// every non-ASCII scalar is treated as identifier-adjacent. False rejects
	// are safer than letting an unmodeled XID prefix shield a marker comment.
	return r == '_' || r >= utf8.RuneSelf || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func rustIdentStart(r rune) bool { return r == '_' || unicode.IsLetter(r) }
func rustIdentContinue(r rune) bool {
	return rustIdentStart(r) || unicode.IsDigit(r)
}
func rustHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}
func rustHexValue(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	default:
		return int(b-'A') + 10
	}
}
