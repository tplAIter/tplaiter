package execx

// approvedHostSupported is the closed list of hosts with an approved runner:
// Darwin arm64 (Mach-O dyld/libSystem envelope) and Linux amd64/arm64
// (static ELF envelope). Intel macOS and every other host stay typed
// TRUST_EXECUTION_UNAVAILABLE until a native envelope is reviewed for them.
func approvedHostSupported(goos, goarch string) bool {
	switch goos {
	case "darwin":
		return goarch == "arm64"
	case "linux":
		return goarch == "amd64" || goarch == "arm64"
	default:
		return false
	}
}
