package trustload

// StorePlatformAvailable reports whether this build supports the secure trust
// store (currently Darwin only; Linux support is tracked separately). Callers
// outside the package, such as test fixtures, use it to skip store-backed
// scenarios on unsupported hosts instead of failing.
func StorePlatformAvailable() bool { return storePlatformAvailable() }
