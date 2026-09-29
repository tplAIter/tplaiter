package testfixture

import (
	"os/exec" //nolint:depguard // tests locate the local Go toolchain
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var goRoot = sync.OnceValues(func() (string, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return "", err
	}
	out, err := exec.Command(goBin, "env", "GOROOT").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
})

// GoRoot returns the GOROOT of the go command on PATH, as reported by
// `go env GOROOT`. It replaces the deprecated runtime.GOROOT, which reflects
// the build machine rather than the toolchain available to the test.
func GoRoot(tb testing.TB) string {
	tb.Helper()
	root, err := goRoot()
	if err != nil || root == "" {
		tb.Skipf("go toolchain unavailable: %v", err)
	}
	return root
}

// GoBinary returns the absolute path of the go command inside GoRoot.
func GoBinary(tb testing.TB) string {
	tb.Helper()
	return filepath.Join(GoRoot(tb), "bin", "go")
}
