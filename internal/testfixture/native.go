package testfixture

import (
	"os"
	"runtime"
)

// NativeTargetEnv returns the GOOS/GOARCH environment entries for building a
// helper tool that the host's approved runner admits (Darwin arm64 Mach-O or
// Linux static ELF). Fixtures must not hard-code one platform: a tool built
// for another host is correctly refused by the runner's native envelope.
func NativeTargetEnv() []string {
	return []string{"GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH}
}

// FormatterNativeEnvelope mirrors operationtrust.FormatterNativeEnvelope for
// fixtures (testfixture cannot import operationtrust: operationtrust's own
// tests import this package). operationtrust's tests assert the two agree.
func FormatterNativeEnvelope() string {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		return "darwin-arm64-dyld-libsystem-libresolv-v1"
	case "linux/amd64":
		return "linux-amd64-static-elf-v1"
	case "linux/arm64":
		return "linux-arm64-static-elf-v1"
	default:
		return ""
	}
}

// PrivateTempBase returns a symlink-free, persistent temporary base for trust
// fixtures. On Darwin /tmp and /var are symlinks into /private, which the
// no-follow store and stage walks refuse, so /private/var/tmp is used; Linux
// uses /var/tmp, falling back to /tmp.
func PrivateTempBase() string {
	for _, base := range []string{"/private/var/tmp", "/var/tmp"} {
		if info, err := os.Lstat(base); err == nil && info.IsDir() {
			return base
		}
	}
	return "/tmp"
}
