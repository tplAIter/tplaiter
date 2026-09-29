package operationtrust

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/testfixture"
)

func TestFormatterNativeEnvelopeIsPerHost(t *testing.T) {
	for _, tc := range []struct{ goos, goarch, want string }{
		{"darwin", "arm64", FormatterEnvelopeDarwinArm64},
		{"darwin", "amd64", ""},
		{"linux", "amd64", FormatterEnvelopeLinuxAmd64},
		{"linux", "arm64", FormatterEnvelopeLinuxArm64},
		{"linux", "386", ""},
		{"windows", "amd64", ""},
	} {
		if got := formatterNativeEnvelopeFor(tc.goos, tc.goarch); got != tc.want {
			t.Errorf("%s/%s envelope=%q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

// The fixture mirror must match production so signed fixture records name the
// envelope this host admits.
func TestFormatterNativeEnvelopeFixtureMirror(t *testing.T) {
	if got, want := testfixture.FormatterNativeEnvelope(), FormatterNativeEnvelope(); got != want {
		t.Fatalf("testfixture envelope %q != operationtrust %q", got, want)
	}
}
