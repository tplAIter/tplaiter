package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestInstalledInvocationRejectsMissingPartialAndMalformedPins(t *testing.T) {
	oldPath, oldDigest := installedRegistrationPath, installedRegistrationSHA256
	t.Cleanup(func() { installedRegistrationPath, installedRegistrationSHA256 = oldPath, oldDigest })
	for _, tc := range []struct{ path, digest string }{{"", ""}, {"/tmp/x", ""}, {"", "sha256:bad"}, {"/tmp/x", "not-a-pin"}} {
		installedRegistrationPath, installedRegistrationSHA256 = tc.path, tc.digest
		if _, err := installedInvocation(context.Background()); err == nil {
			t.Fatalf("accepted %#v", tc)
		}
	}
}

func TestInstalledInvocationSeparatesRawPinFromClosedConfig(t *testing.T) {
	oldPath, oldDigest := installedRegistrationPath, installedRegistrationSHA256
	t.Cleanup(func() { installedRegistrationPath, installedRegistrationSHA256 = oldPath, oldDigest })
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "registration.json")
	raw := []byte(`{"apiVersion":"tplaiter.dev/installed-launch-registration/v1","unexpected":true}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	installedRegistrationPath = path
	installedRegistrationSHA256 = "sha256:" + hex.EncodeToString(make([]byte, sha256.Size))
	if _, err := installedInvocation(context.Background()); !errors.Is(err, trustload.ErrPinMismatch) {
		t.Fatalf("changed raw registration: %v", err)
	}
	h := sha256.Sum256(raw)
	installedRegistrationSHA256 = "sha256:" + hex.EncodeToString(h[:])
	if _, err := installedInvocation(context.Background()); !errors.Is(err, trustload.ErrConfigInvalid) {
		t.Fatalf("independently pinned closed config: %v", err)
	}
}

func TestInstalledInvocationRejectsTrailingDuplicateAndUnknownRegistrationFields(t *testing.T) {
	oldPath, oldDigest := installedRegistrationPath, installedRegistrationSHA256
	t.Cleanup(func() { installedRegistrationPath, installedRegistrationSHA256 = oldPath, oldDigest })
	for _, raw := range []string{`{} trailing`, `{"apiVersion":"x","apiVersion":"x"}`, `{"unknown":true}`} {
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "registration.json")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(raw))
		installedRegistrationPath, installedRegistrationSHA256 = path, "sha256:"+hex.EncodeToString(h[:])
		if _, err := installedInvocation(context.Background()); !errors.Is(err, trustload.ErrConfigInvalid) {
			t.Fatalf("independently pinned malformed registration %q: %v", raw, err)
		}
	}
}

func TestInstalledInvocationRejectsUnsafeRegistrationFiles(t *testing.T) {
	oldPath, oldDigest := installedRegistrationPath, installedRegistrationSHA256
	t.Cleanup(func() { installedRegistrationPath, installedRegistrationSHA256 = oldPath, oldDigest })
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	installedRegistrationSHA256 = "sha256:" + hex.EncodeToString(make([]byte, sha256.Size))
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "registration-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	installedRegistrationPath = link
	if _, err := installedInvocation(context.Background()); !errors.Is(err, trustload.ErrAnchorMissing) {
		t.Fatalf("symlink registration: %v", err)
	}
	oversize := filepath.Join(root, "registration-oversize.json")
	if err := os.WriteFile(oversize, make([]byte, trustCommandDocumentLimit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	installedRegistrationPath = oversize
	if _, err := installedInvocation(context.Background()); !errors.Is(err, trustload.ErrAnchorMissing) {
		t.Fatalf("oversize registration: %v", err)
	}
	if runtime.GOOS != "darwin" {
		return
	}
	fifo := filepath.Join(root, "registration-fifo.json")
	if out, err := exec.Command("/usr/bin/mkfifo", fifo).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo: %v %q", err, out)
	}
	installedRegistrationPath = fifo
	done := make(chan error, 1)
	go func() { _, err := installedInvocation(context.Background()); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, trustload.ErrAnchorMissing) {
			t.Fatalf("FIFO registration: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FIFO registration blocked closed reader")
	}
}
