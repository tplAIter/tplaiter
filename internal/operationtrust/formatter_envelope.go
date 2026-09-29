package operationtrust

import "runtime"

// Formatter native envelopes bind a signed formatter tool record to the exact
// structural admission policy of the host's approved runner (internal/execx).
// A record signed for one envelope never admits a tool on another host.
const (
	FormatterEnvelopeDarwinArm64 = "darwin-arm64-dyld-libsystem-libresolv-v1"
	FormatterEnvelopeLinuxAmd64  = "linux-amd64-static-elf-v1"
	FormatterEnvelopeLinuxArm64  = "linux-arm64-static-elf-v1"
)

// FormatterNativeEnvelope returns the envelope identifier accepted on this
// host, or "" where no approved runner exists (every record is then refused).
func FormatterNativeEnvelope() string {
	return formatterNativeEnvelopeFor(runtime.GOOS, runtime.GOARCH)
}

func formatterNativeEnvelopeFor(goos, goarch string) string {
	switch goos + "/" + goarch {
	case "darwin/arm64":
		return FormatterEnvelopeDarwinArm64
	case "linux/amd64":
		return FormatterEnvelopeLinuxAmd64
	case "linux/arm64":
		return FormatterEnvelopeLinuxArm64
	default:
		return ""
	}
}
