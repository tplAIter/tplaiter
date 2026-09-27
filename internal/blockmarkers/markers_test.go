package blockmarkers

import (
	"errors"
	"reflect"
	"testing"
)

func TestGoMarkerTokensUseOriginalBytes(t *testing.T) {
	content := []byte("package p\r\n// tplater:managed-begin id=alpha provider=root\r\nvar café = \"😀\"\r\n// tplater:managed-end id=alpha\r\n")
	got, err := Validate(LanguageGo, "x.go", content)
	if err != nil {
		t.Fatal(err)
	}
	want := []Marker{{Kind: KindBegin, ID: "alpha", Provider: "root", Start: 11, End: 60}, {Kind: KindEnd, ID: "alpha", Start: 80, End: 113}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("markers=%#v", got)
	}
	got[0].ID = "changed"
	again, err := Validate(LanguageGo, "x.go", content)
	if err != nil || again[0].ID != "alpha" {
		t.Fatalf("defensive result err=%v markers=%#v", err, again)
	}
}

func TestGoRejectsMarkerLookalikesAndSyntax(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		code    ErrorCode
	}{
		{"interpreted", "package p\nvar x = \"// tplater:managed-begin id=a provider=p\"\n", CodeMarker},
		{"raw", "package p\nvar x = `\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n`\n", CodeNotComment},
		{"outer-block", "package p\n/*\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n*/\n", CodeNotComment},
		{"syntax", "package p\nfunc ( {\n", CodeSyntax},
		{"bom", "\ufeffpackage p\n", CodeInvalidSource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(LanguageGo, "x.go", []byte(tc.content))
			var got *Error
			if !errors.As(err, &got) || got.Code != tc.code {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestGoRejectsEscapedStringAndRuneMarkerLookalikes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"escaped-interpreted", `package p
var x = "escaped \" // tplater:managed-begin id=a provider=p"
`},
		{"rune", `package p
var r = '\'' // tplater:managed-end id=a
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markers, err := Validate(LanguageGo, "x.go", []byte(tc.content))
			var got *Error
			if markers != nil || !errors.As(err, &got) || got.Code != CodeMarker {
				t.Fatalf("lookalike accepted: markers=%#v err=%v", markers, err)
			}
		})
	}
}

func TestMarkerPairIdentityFailuresRemainClosed(t *testing.T) {
	for _, content := range [][]byte{
		[]byte("// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=b\n"),
		[]byte("// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n"),
	} {
		if _, err := Validate(LanguageGo, "x.go", append([]byte("package p\n"), content...)); err == nil {
			t.Fatal("invalid marker identity accepted")
		}
	}
}

func TestGoMarkerIdentityMutationMatrix(t *testing.T) {
	// Each mutation changes one aspect of the ordered delimiter stream. The
	// C grammar must reject it before this package can return a partial stream.
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
		{"token-class-string", "var x = \"// tplater:managed-begin id=a provider=p\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markers, err := Validate(LanguageGo, "x.go", []byte("package p\n"+tc.content))
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
