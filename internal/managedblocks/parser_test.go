package managedblocks

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParseSupportedCommentAliasesAndExactRoundTrip(t *testing.T) {
	for _, tc := range []struct{ begin, end string }{
		{"// tplater:managed-begin id=a provider=root", "// tplater:managed-end id=a"},
		{"# tplater:managed-begin id=a provider=dep/api", "# tplater:managed-end id=a"},
		{"; tplater:managed-begin id=a provider=root", "; tplater:managed-end id=a"},
		{"<!-- tplater:managed-begin id=a provider=root -->", "<!-- tplater:managed-end id=a -->"},
		{"/* tplater:managed-begin id=a provider=root */", "/* tplater:managed-end id=a */"},
	} {
		input := []byte("head\n" + tc.begin + "\r\nbody\r\n" + tc.end + "\r\ntail")
		doc, err := Parse("x.go", input)
		if err != nil {
			t.Fatal(err)
		}
		wantProvider := "root"
		if strings.HasPrefix(tc.begin, "# ") {
			wantProvider = "dep/api"
		}
		if len(doc.Regions) != 1 || doc.Regions[0].Provider != wantProvider {
			t.Fatalf("region=%+v", doc.Regions)
		}
		var got []byte
		for i, r := range doc.Regions {
			got = append(got, doc.Gaps[i]...)
			got = append(got, r.Bytes()...)
		}
		got = append(got, doc.Gaps[len(doc.Gaps)-1]...)
		if !bytes.Equal(got, input) {
			t.Fatal("round trip changed bytes")
		}
	}
}

func TestParseRejectsMalformedNestedAndRawLookalikes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		code ErrorCode
	}{
		{"unknown", []byte("// tplater:managed-other id=a\n"), CodeUnknownMarker},
		{"raw", []byte("x // tplater:managed-end id=a\n"), CodeMarkerNotComment},
		{"nested", []byte("// tplater:managed-begin id=a provider=p\n// tplater:managed-begin id=b provider=p\n"), CodeNestedRegion},
		{"unbalanced", []byte("// tplater:managed-begin id=a provider=p\n"), CodeBeginWithoutEnd},
		{"mismatch", []byte("// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=b\n"), CodeEndIDMismatch},
		{"duplicate", []byte("// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n// tplater:managed-begin id=a provider=p\n"), CodeDuplicateID},
		{"overlap", []byte("// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n// tplater:managed-end id=a\n"), CodeOverlappingRegion},
		{"invalid id", []byte("// tplater:managed-begin id=a/b provider=p\n"), CodeMalformedMarker},
		{"invalid provider", []byte("// tplater:managed-begin id=a provider=bad provider\n"), CodeMalformedMarker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("file", tc.in)
			var pe *Error
			if !errors.As(err, &pe) || pe.Code != tc.code {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
