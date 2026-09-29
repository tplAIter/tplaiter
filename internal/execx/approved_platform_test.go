package execx

import "testing"

func TestApprovedHostSupportedIsClosed(t *testing.T) {
	for _, tc := range []struct {
		goos, goarch string
		want         bool
	}{
		{"darwin", "arm64", true},
		{"darwin", "amd64", false},
		{"linux", "amd64", true},
		{"linux", "arm64", true},
		{"linux", "386", false},
		{"linux", "riscv64", false},
		{"windows", "amd64", false},
		{"freebsd", "amd64", false},
	} {
		if got := approvedHostSupported(tc.goos, tc.goarch); got != tc.want {
			t.Errorf("%s/%s supported=%v, want %v", tc.goos, tc.goarch, got, tc.want)
		}
	}
}
