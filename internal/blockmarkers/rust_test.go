package blockmarkers

import (
	"errors"
	"strings"
	"testing"
)

func TestRustCommentsAndLiteralLookalikes(t *testing.T) {
	valid := []byte("// tplater:managed-begin id=a provider=p\nlet r = r###\"// not marker\"###; let b = b\"/* no */\"; let c = c\"// no\";\nlet ch = '\\n'; let life: &'a str = \"x\";\n// tplater:managed-end id=a\n")
	markers, err := Validate(LanguageRust, "x.rs", valid)
	if err != nil || len(markers) != 2 {
		t.Fatalf("markers=%#v err=%v", markers, err)
	}
	for _, tc := range []string{
		"let s = r#\"\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n\"#;\n",
		"/*\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n*/\n",
		"let s = \"// tplater:managed-begin id=a provider=p\";\n",
	} {
		_, err := Validate(LanguageRust, "x.rs", []byte(tc))
		var got *Error
		if !errors.As(err, &got) || got.Code != CodeNotComment && got.Code != CodeMarker {
			t.Fatalf("lookalike err=%v", err)
		}
	}
}

func TestRustLexicalBoundsAndMalformedLiterals(t *testing.T) {
	deep := strings.Repeat("/*", maxRustBlockNesting+1) + strings.Repeat("*/", maxRustBlockNesting+1)
	raw := "let x = r" + strings.Repeat("#", maxRustRawHashes+1) + "\"x\";"
	for _, source := range []string{"/* unterminated", "let x = \"unterminated", deep, raw} {
		_, err := Validate(LanguageRust, "x.rs", []byte(source))
		var got *Error
		if !errors.As(err, &got) || got.Code != CodeLexical {
			t.Fatalf("source=%q err=%v", source[:min(len(source), 24)], err)
		}
	}
}

func TestRustCharAndLifetimeLexicalBoundary(t *testing.T) {
	for _, source := range []string{
		"let a: &'static str = \"x\"; let b: &'a str = \"y\";",
		`let a = 'x'; let b = '\n'; let c = '\''; let d = '\u{1F600}'; let e = b'\x7f';`,
	} {
		if markers, err := Validate(LanguageRust, "x.rs", []byte(source)); err != nil || len(markers) != 0 {
			t.Fatalf("valid char/lifetime rejected source=%q markers=%#v err=%v", source, markers, err)
		}
	}
	for _, source := range []string{
		"let x = 'ab';",
		"let x = b'ab';",
		"let x = ';",
		"let x = b';",
		"let x = '\\u{}';",
		"let x = '\\u{D800}';",
		"let x = '\\u{110000}';",
		"let x = '\\u{wat}';",
		"let x = '\\x0g';",
		"let x = '\\q';",
		"let x = '\\n;",
		"let x = '\\\n';",
		"let x = b'\\u{1F600}';",
	} {
		markers, err := Validate(LanguageRust, "x.rs", []byte(source))
		var got *Error
		if markers != nil || !errors.As(err, &got) || got.Code != CodeLexical {
			t.Fatalf("malformed char accepted source=%q markers=%#v err=%v", source, markers, err)
		}
	}
}

func TestRustRawStringDelimiterBoundsAndCByteForms(t *testing.T) {
	for _, source := range []string{
		`let a = r"text // not a comment"; let b = br#"/* no */"#; let c = cr##"// no"##;`,
		"let a = \"escaped \\\" // no\"; let b = b\"escaped \\\" /* no\"; let c = c\"line\\\ncontinuation\"; let raw = r#ident;",
		"let max = r" + strings.Repeat("#", maxRustRawHashes) + "\"x\"" + strings.Repeat("#", maxRustRawHashes) + ";",
	} {
		if _, err := Validate(LanguageRust, "x.rs", []byte(source)); err != nil {
			t.Fatalf("valid literal rejected: %v", err)
		}
	}
}

func TestRustQuotedEscapesFailClosedBeforeMarkerProof(t *testing.T) {
	for _, tc := range []struct {
		name, literal string
	}{
		{"normal-invalid", `"\q"`},
		{"byte-invalid", `b"\q"`},
		{"c-invalid", `c"\q"`},
		{"normal-unicode-bad", `"\u{}"`},
		{"byte-unicode-unsupported", `b"\u{41}"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "let s = " + tc.literal + ";\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n"
			markers, err := Validate(LanguageRust, "x.rs", []byte(source))
			var got *Error
			if markers != nil || !errors.As(err, &got) || got.Code != CodeLexical {
				t.Fatalf("invalid escape accepted: markers=%#v err=%v", markers, err)
			}
		})
	}
	for _, tc := range []struct {
		name, literal string
	}{
		{"normal-escaped-quote", `"quote: \""`},
		{"normal-continuation", "\"line\\\ncontinued\""},
		{"byte-escaped-quote", `b"quote: \""`},
		{"byte-continuation", "b\"line\\\ncontinued\""},
		{"c-hex", `c"hex: \x41"`},
		{"c-escaped-quote", `c"quote: \""`},
		{"c-unicode", `c"\u{41}"`},
		{"normal-unicode-separator", `"\u{1_F600}"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "let s = " + tc.literal + ";\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n"
			markers, err := Validate(LanguageRust, "x.rs", []byte(source))
			if err != nil || len(markers) != 2 {
				t.Fatalf("valid escape rejected: markers=%#v err=%v", markers, err)
			}
		})
	}
}

func TestRustRejectsMarkerLookalikesInByteAndCString(t *testing.T) {
	for _, tc := range []struct {
		name, source string
	}{
		{"byte", `let s = b"// tplater:managed-begin id=a provider=p";`},
		{"byte-escaped", `let s = b"prefix \" // tplater:managed-end id=a";`},
		{"c", `let s = c"// tplater:managed-begin id=a provider=p";`},
		{"c-escaped", `let s = c"prefix \x41 // tplater:managed-end id=a";`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markers, err := Validate(LanguageRust, "x.rs", []byte(tc.source+"\n"))
			var got *Error
			if markers != nil || !errors.As(err, &got) || got.Code != CodeMarker {
				t.Fatalf("literal marker lookalike accepted: markers=%#v err=%v", markers, err)
			}
		})
	}
}

func TestRustRejectsMarkerLookalikesInRawByteAndRawCString(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"raw-byte", "let s = br#\"// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\"#;"},
		{"raw-c", "let s = cr#\"// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\"#;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markers, err := Validate(LanguageRust, "x.rs", []byte(tc.body+"\n"))
			var got *Error
			if markers != nil || !errors.As(err, &got) || got.Code != CodeMarker {
				t.Fatalf("raw literal marker lookalike accepted: markers=%#v err=%v", markers, err)
			}
		})
	}

	for _, tc := range []struct {
		name, body string
	}{
		{"raw-byte-external-marker-control", `let s = br#"literal body"#;`},
		{"raw-c-external-marker-control", `let s = cr#"literal body"#;`},
	} {
		t.Run(tc.name, func(t *testing.T) { requireRustMarkers(t, tc.body) })
	}
}

func TestRustNestedCommentIsOneToken(t *testing.T) {
	content := []byte("/* outer /* inner */ outer */\n// tplater:managed-begin id=a provider=p\nlet x = 1;\n// tplater:managed-end id=a\n")
	markers, err := Validate(LanguageRust, "x.rs", content)
	if err != nil || len(markers) != 2 {
		t.Fatalf("nested comment scan markers=%#v err=%v", markers, err)
	}
}

func TestRustMarkerCRLFAndNoFinalNewline(t *testing.T) {
	content := []byte("// tplater:managed-begin id=a provider=p\r\nlet x = 1;\r\n// tplater:managed-end id=a")
	markers, err := Validate(LanguageRust, "x.rs", content)
	if err != nil || len(markers) != 2 {
		t.Fatalf("markers=%#v err=%v", markers, err)
	}
}

func TestRustMarkerIdentityMutationMatrix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"dropped-end", "// tplater:managed-begin id=a provider=p\n"},
		{"added-end", "// tplater:managed-end id=a\n"},
		{"duplicate", "// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n"},
		{"renamed-end", "// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=b\n"},
		{"reordered-nested", "// tplater:managed-begin id=b provider=p\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n// tplater:managed-end id=b\n"},
		{"provider-field-on-end", "// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a provider=q\n"},
		{"token-class-string", "let x = \"// tplater:managed-begin id=a provider=p\";\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markers, err := Validate(LanguageRust, "x.rs", []byte(tc.content))
			if err == nil || markers != nil {
				t.Fatalf("mutation accepted: markers=%#v err=%v", markers, err)
			}
			var got *Error
			if !errors.As(err, &got) {
				t.Fatalf("non-typed error: %v", err)
			}
		})
	}
}

func rustMarkerSource(body string) string {
	return body + "\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n"
}

func requireRustMarkers(t *testing.T, body string) {
	t.Helper()
	markers, err := Validate(LanguageRust, "x.rs", []byte(rustMarkerSource(body)))
	if err != nil || len(markers) != 2 {
		t.Fatalf("valid literal rejected: markers=%#v err=%v", markers, err)
	}
}

func requireRustLexical(t *testing.T, body string) {
	t.Helper()
	markers, err := Validate(LanguageRust, "x.rs", []byte(rustMarkerSource(body)))
	var got *Error
	if markers != nil || !errors.As(err, &got) || got.Code != CodeLexical {
		t.Fatalf("invalid literal accepted: markers=%#v err=%v", markers, err)
	}
}

func TestRustLiteralKindBoundaryMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"normal-unicode", `let s = "é";`},
		{"normal-lf", "let s = \"a\nb\";"},
		{"normal-x7f", `let s = "\x7f";`},
		{"normal-unicode-scalar", `let s = "\u{1_F600}";`},
		{"normal-continuation", "let s = \"a\\\nb\";"},
		{"raw-lf-backslash", "let s = r\"a\\\nb\";"},
		{"raw-255-hashes", "let s = r" + strings.Repeat("#", maxRustRawHashes) + "\"x\"" + strings.Repeat("#", maxRustRawHashes) + ";"},
		{"byte-ascii-lf", "let s = b\"a\nb\";"},
		{"byte-x00-xff", `let s = b"\x00\xff";`},
		{"byte-continuation", "let s = b\"a\\\nb\";"},
		{"raw-byte-ascii", "let s = br#\"a\\\nb\"#;"},
		{"raw-byte-255-hashes", "let s = br" + strings.Repeat("#", maxRustRawHashes) + "\"x\"" + strings.Repeat("#", maxRustRawHashes) + ";"},
		{"c-unicode", `let s = c"é\u{41}\x01\xff";`},
		{"c-lf-continuation", "let s = c\"a\nb\\\nc\";"},
		{"raw-c-unicode", "let s = cr#\"é\\\nb\"#;"},
		{"raw-c-255-hashes", "let s = cr" + strings.Repeat("#", maxRustRawHashes) + "\"é\"" + strings.Repeat("#", maxRustRawHashes) + ";"},
		{"character-unicode-x7f-tab-escape", `let a = 'é'; let b = '\x7f'; let c = '\t';`},
		{"byte-character-bounds", `let a = b'\x00'; let b = b'\xff'; let c = b'\t';`},
		{"ordinary-lifetime", `let x: &'static str = "x";`},
		{"raw-identifier", `let r#name = 1;`},
	} {
		t.Run(tc.name, func(t *testing.T) { requireRustMarkers(t, tc.body) })
	}
	for _, tc := range []struct {
		name, body string
	}{
		{"normal-x80", `let s = "\x80";`},
		{"normal-xff", `let s = "\xff";`},
		{"normal-cr", "let s = \"a\rb\";"},
		{"normal-crlf-continuation", "let s = \"a\\\r\nb\";"},
		{"raw-cr", "let s = r\"a\rb\";"},
		{"raw-256-hashes", "let s = r" + strings.Repeat("#", maxRustRawHashes+1) + "\"x\"" + strings.Repeat("#", maxRustRawHashes+1) + ";"},
		{"raw-unterminated", `let s = r#"x";`},
		{"byte-non-ascii", `let s = b"é";`},
		{"byte-cr", "let s = b\"a\rb\";"},
		{"byte-crlf-continuation", "let s = b\"a\\\r\nb\";"},
		{"raw-byte-non-ascii", `let s = br"é";`},
		{"raw-byte-cr", "let s = br\"a\rb\";"},
		{"raw-byte-256-hashes", "let s = br" + strings.Repeat("#", maxRustRawHashes+1) + "\"x\"" + strings.Repeat("#", maxRustRawHashes+1) + ";"},
		{"raw-byte-unterminated", `let s = br#"x";`},
		{"c-zero", `let s = c"\0";`},
		{"c-x00", `let s = c"\x00";`},
		{"c-u0", `let s = c"\u{0}";`},
		{"c-cr", "let s = c\"a\rb\";"},
		{"c-crlf-continuation", "let s = c\"a\\\r\nb\";"},
		{"raw-c-cr", "let s = cr\"a\rb\";"},
		{"raw-c-256-hashes", "let s = cr" + strings.Repeat("#", maxRustRawHashes+1) + "\"x\"" + strings.Repeat("#", maxRustRawHashes+1) + ";"},
		{"raw-c-unterminated", `let s = cr#"x";`},
		{"character-tab", "let x = '\t';"},
		{"character-x80", `let x = '\x80';`},
		{"character-xff", `let x = '\xff';`},
		{"byte-character-tab", "let x = b'\t';"},
		{"malformed-character", `let x = 'ab';`},
		{"reserved-identifier-quote", `let x = foo"marker shield";`},
		{"reserved-identifier-single-quote", `let x = c'x';`},
		{"raw-lifetime-unsupported", `let x: &'r#name str = "x";`},
	} {
		t.Run(tc.name, func(t *testing.T) { requireRustLexical(t, tc.body) })
	}
}

func TestRustGlobalNULFailsBeforeLiteralRecognition(t *testing.T) {
	markers, err := Validate(LanguageRust, "x.rs", []byte("let s = cr\"x\x00\";\n"))
	var got *Error
	if markers != nil || !errors.As(err, &got) || got.Code != CodeInvalidSource {
		t.Fatalf("NUL accepted: markers=%#v err=%v", markers, err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
