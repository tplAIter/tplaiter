package testfixture

import (
	"os"
	"os/exec" //nolint:depguard // the fixture builds and runs the real tplaiter binary
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Installed is a tplaiter binary linked against an operator-pinned OSS
// registration exactly like `make install` does (ADR-005).
type Installed struct {
	// Bin is the absolute, symlink-free path of the binary.
	Bin string
	// Root is the OSS install root holding the trust documents and store.
	Root string
	// RegistrationSHA256 is the registration digest linked into Bin.
	RegistrationSHA256 string
	// Provisioned reports whether `trust provision` enrolled the store. It
	// is false only where the secure store is unavailable (platforms other
	// than darwin and Linux).
	Provisioned bool
}

// BuildInstalled generates an OSS installation in a fresh temporary
// directory, builds the repository's main package with the same linker pins
// as the Makefile, and runs the first-run `trust provision`. Wherever the
// trust store platform is available (darwin, Linux) it must succeed.
func BuildInstalled(t testing.TB) *Installed {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	result, err := ossinstall.Generate(ossinstall.Options{Root: filepath.Join(dir, "trust")})
	if err != nil {
		t.Fatalf("generate OSS installation: %v", err)
	}
	bin := filepath.Join(dir, "bin", "tplaiter")
	pkg := "github.com/tplAIter/tplaiter/internal/cmd"
	ldflags := "-X " + pkg + ".installedRegistrationPath=" + result.RegistrationPath +
		" -X " + pkg + ".installedRegistrationSHA256=" + result.RegistrationSHA256
	build := exec.Command(GoBinary(t), "build", "-trimpath", "-ldflags", ldflags, "-o", bin, ".")
	build.Dir = ModuleRoot(t)
	build.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build installed binary: %v\n%s", err, out)
	}
	installed := &Installed{Bin: bin, Root: result.Root, RegistrationSHA256: result.RegistrationSHA256}
	provision := exec.Command(bin, "trust", "provision")
	provision.Dir = dir
	provision.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TPLAITER_HOME=" + filepath.Join(dir, "home")}
	out, err := provision.CombinedOutput()
	switch {
	case err == nil:
		installed.Provisioned = true
	case trustload.StorePlatformAvailable():
		t.Fatalf("trust provision: %v\n%s", err, out)
	default:
		t.Logf("trust provision unavailable on %s: %s", runtime.GOOS, strings.TrimSpace(string(out)))
	}
	return installed
}

// ModuleRoot returns the root module directory (the one holding go.mod with
// the tplaiter module path), found by walking up from the working directory.
func ModuleRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && strings.Contains(string(raw), "module github.com/tplAIter/tplaiter\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("tplaiter module root not found")
		}
		dir = parent
	}
}
