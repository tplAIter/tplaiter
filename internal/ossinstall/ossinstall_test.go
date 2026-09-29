package ossinstall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// recordingRand is a deterministic entropy source that remembers every
// 32-byte read (ed25519 seeds) so tests can prove no seed reaches disk.
type recordingRand struct {
	next  byte
	seeds [][]byte
}

func (r *recordingRand) Read(p []byte) (int, error) {
	for i := range p {
		r.next++
		p[i] = r.next
	}
	if len(p) == ed25519.SeedSize {
		r.seeds = append(r.seeds, append([]byte(nil), p...))
	}
	return len(p), nil
}

func tempRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "trust")
}

func loadRegistration(t *testing.T, result Result) *Registration {
	t.Helper()
	raw, err := os.ReadFile(result.RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if result.RegistrationSHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("registration digest %s does not match file bytes", result.RegistrationSHA256)
	}
	registration, err := DecodeRegistration(raw)
	if err != nil {
		t.Fatalf("DecodeRegistration: %v", err)
	}
	return registration
}

func TestGenerateProducesLoadableOSSInstallation(t *testing.T) {
	root := tempRoot(t)
	result, err := Generate(Options{Root: root, Rand: &recordingRand{}, Now: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if result.Reused || result.Root != root || !strings.HasPrefix(result.InstallationID, "oss-") {
		t.Fatalf("unexpected result %+v", result)
	}
	registration := loadRegistration(t, result)
	if registration.Profile != bootstrap.ProfileOSS || registration.ProjectKey != DefaultProjectKey {
		t.Fatalf("registration %+v", registration)
	}
	loaded, err := trustload.Load(context.Background(), registration.Selection())
	if err != nil {
		t.Fatalf("trustload.Load: %v", err)
	}
	if loaded.Install.Profile != bootstrap.ProfileOSS || loaded.Install.OSS == nil || !strings.HasPrefix(loaded.Install.OSS.StorePath, root+"/") {
		t.Fatalf("runtime install %+v", loaded.Install)
	}
	provisioning, err := bootstrap.DecodeProvisioningRecord(loaded.ProvisioningJSON)
	if err != nil || provisioning.Mode != "operator-pinned" || provisioning.EvidenceClass != bootstrap.EvidenceProduction {
		t.Fatalf("provisioning %+v: %v", provisioning, err)
	}
	if _, err := os.Stat(loaded.Install.OSS.StorePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Generate must not create the trust store (provisioning does): %v", err)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is accessible to group/other: %v", path, info.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateNeverPersistsPrivateKeys(t *testing.T) {
	root := tempRoot(t)
	entropy := &recordingRand{}
	if _, err := Generate(Options{Root: root, Rand: entropy}); err != nil {
		t.Fatal(err)
	}
	if len(entropy.seeds) != 2 {
		t.Fatalf("expected an anchor and a placeholder publisher seed, got %d", len(entropy.seeds))
	}
	var needles [][]byte
	for _, seed := range entropy.seeds {
		private := ed25519.NewKeyFromSeed(seed)
		for _, secret := range [][]byte{seed, private} {
			needles = append(needles, secret,
				[]byte(base64.StdEncoding.EncodeToString(secret)),
				[]byte(base64.RawURLEncoding.EncodeToString(secret)),
				[]byte(hex.EncodeToString(secret)))
		}
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, needle := range needles {
			if bytes.Contains(raw, needle) {
				t.Errorf("private key material found in %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateReusesValidInstallationAndRotatesOnRequest(t *testing.T) {
	root := tempRoot(t)
	first, err := Generate(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	again, err := Generate(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !again.Reused || again.RegistrationSHA256 != first.RegistrationSHA256 || again.InstallationID != first.InstallationID {
		t.Fatalf("reinstall did not reuse: first=%+v again=%+v", first, again)
	}
	rotated, err := Generate(Options{Root: root, Rotate: true})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Reused || rotated.RegistrationSHA256 == first.RegistrationSHA256 || rotated.InstallationID == first.InstallationID {
		t.Fatalf("rotation kept the installation: %+v", rotated)
	}
	loadRegistration(t, rotated)
}

func TestGenerateRefusesForeignOrDamagedRoot(t *testing.T) {
	t.Run("unrelated_files", func(t *testing.T) {
		root := tempRoot(t)
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("mine"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Generate(Options{Root: root}); !errors.Is(err, ErrInstallRootConflict) {
			t.Fatalf("Generate over unrelated files: %v", err)
		}
	})
	t.Run("tampered_runtime_config", func(t *testing.T) {
		root := tempRoot(t)
		if _, err := Generate(Options{Root: root}); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "config", "policy.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, ' '), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Generate(Options{Root: root}); !errors.Is(err, ErrInstallRootConflict) {
			t.Fatalf("Generate over a tampered installation: %v", err)
		}
		if _, err := Generate(Options{Root: root, Rotate: true}); err != nil {
			t.Fatalf("rotation must replace a damaged installation: %v", err)
		}
	})
	t.Run("relative_root", func(t *testing.T) {
		if _, err := Generate(Options{Root: "relative/trust"}); err == nil {
			t.Fatal("relative install root accepted")
		}
	})
}

func TestGenerateWithConfiguredPublishers(t *testing.T) {
	root := tempRoot(t)
	public, _, err := ed25519.GenerateKey(&recordingRand{})
	if err != nil {
		t.Fatal(err)
	}
	objects := filepath.Join(filepath.Dir(root), "objects")
	if err := os.Mkdir(objects, 0o700); err != nil {
		t.Fatal(err)
	}
	publisher := Publisher{Issuer: "fixture-publisher", PublicKeyBase64: base64.StdEncoding.EncodeToString(public), SourceOrigin: "https://git.example.test/templates", ObjectRoot: objects}
	result, err := Generate(Options{Root: root, Publishers: []Publisher{publisher}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	loaded, err := trustload.Load(context.Background(), loadRegistration(t, result).Selection())
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := bootstrap.DecodeDescriptorDocument(loaded.DescriptorJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(descriptor.PublisherScopes) != 1 || descriptor.PublisherScopes[0].SourceOrigin != publisher.SourceOrigin || descriptor.PublisherScopes[0].TemplatePath != "." {
		t.Fatalf("publisher scopes %+v", descriptor.PublisherScopes)
	}
	if len(loaded.Install.ObjectOrigins) != 1 || loaded.Install.ObjectOrigins[0].RootPath != objects {
		t.Fatalf("object origins %+v", loaded.Install.ObjectOrigins)
	}

	for name, bad := range map[string]Publisher{
		"short_key":     {Issuer: "x", PublicKeyBase64: base64.StdEncoding.EncodeToString([]byte("short")), SourceOrigin: "https://git.example.test/x"},
		"relative_objs": {Issuer: "x", PublicKeyBase64: publisher.PublicKeyBase64, SourceOrigin: "https://git.example.test/x", ObjectRoot: "objects"},
	} {
		if _, err := Generate(Options{Root: tempRoot(t), Publishers: []Publisher{bad}}); err == nil {
			t.Errorf("%s: invalid publisher accepted", name)
		}
	}
}

func TestGenerateRefusesToDropRequestedPublishersOnReuse(t *testing.T) {
	newPublisher := func(t *testing.T, issuer, origin string) Publisher {
		t.Helper()
		public, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		return Publisher{Issuer: issuer, PublicKeyBase64: base64.StdEncoding.EncodeToString(public), SourceOrigin: origin}
	}
	fixture := newPublisher(t, "fixture-publisher", "https://git.example.test/templates")

	t.Run("placeholder_install_then_publishers", func(t *testing.T) {
		root := tempRoot(t)
		first, err := Generate(Options{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Generate(Options{Root: root, Publishers: []Publisher{fixture}}); !errors.Is(err, ErrPublishersChanged) {
			t.Fatalf("publishers over a placeholder install: %v", err)
		}
		// The refused request left the existing installation intact.
		kept, err := Generate(Options{Root: root})
		if err != nil || !kept.Reused || kept.RegistrationSHA256 != first.RegistrationSHA256 {
			t.Fatalf("existing installation changed after refusal: %+v err=%v", kept, err)
		}
		rotated, err := Generate(Options{Root: root, Publishers: []Publisher{fixture}, Rotate: true})
		if err != nil || rotated.Reused {
			t.Fatalf("rotation with publishers: %+v err=%v", rotated, err)
		}
		loaded, err := trustload.Load(context.Background(), loadRegistration(t, rotated).Selection())
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := bootstrap.DecodeDescriptorDocument(loaded.DescriptorJSON)
		if err != nil {
			t.Fatal(err)
		}
		if len(descriptor.PublisherScopes) != 1 || descriptor.PublisherScopes[0].Issuer != fixture.Issuer {
			t.Fatalf("rotated scopes %+v", descriptor.PublisherScopes)
		}
	})

	t.Run("same_publishers_reuse", func(t *testing.T) {
		root := tempRoot(t)
		first, err := Generate(Options{Root: root, Publishers: []Publisher{fixture}})
		if err != nil {
			t.Fatal(err)
		}
		again, err := Generate(Options{Root: root, Publishers: []Publisher{fixture}})
		if err != nil || !again.Reused || again.RegistrationSHA256 != first.RegistrationSHA256 {
			t.Fatalf("identical publishers not reused: %+v err=%v", again, err)
		}
		// No publishers requested keeps the configured installation as is.
		kept, err := Generate(Options{Root: root})
		if err != nil || !kept.Reused || kept.RegistrationSHA256 != first.RegistrationSHA256 {
			t.Fatalf("plain reinstall did not keep publishers: %+v err=%v", kept, err)
		}
	})

	t.Run("changed_publishers_refused", func(t *testing.T) {
		root := tempRoot(t)
		if _, err := Generate(Options{Root: root, Publishers: []Publisher{fixture}}); err != nil {
			t.Fatal(err)
		}
		otherKey := newPublisher(t, fixture.Issuer, fixture.SourceOrigin)
		otherPath := fixture
		otherPath.TemplatePath = "templates/service"
		extra := newPublisher(t, "second-publisher", "https://git.example.test/more")
		objects := t.TempDir()
		otherObjects := fixture
		otherObjects.ObjectRoot = objects
		for name, publishers := range map[string][]Publisher{
			"rotated_key":     {otherKey},
			"template_path":   {otherPath},
			"added_publisher": {fixture, extra},
			"object_root":     {otherObjects},
		} {
			if _, err := Generate(Options{Root: root, Publishers: publishers}); !errors.Is(err, ErrPublishersChanged) {
				t.Errorf("%s: %v, want ErrPublishersChanged", name, err)
			}
		}
	})

	t.Run("invalid_publishers_rejected_before_reuse", func(t *testing.T) {
		root := tempRoot(t)
		if _, err := Generate(Options{Root: root}); err != nil {
			t.Fatal(err)
		}
		bad := Publisher{Issuer: "x", PublicKeyBase64: "not-a-key", SourceOrigin: "https://git.example.test/x"}
		if _, err := Generate(Options{Root: root, Publishers: []Publisher{bad}}); err == nil || errors.Is(err, ErrPublishersChanged) {
			t.Fatalf("invalid publisher: %v", err)
		}
	})
}

func TestDecodeRegistrationRejectsDevelopmentAndUnknownFields(t *testing.T) {
	for name, raw := range map[string]string{
		"development": `{"apiVersion":"` + RegistrationAPIVersion + `","profile":"development","runtimeConfig":{"path":"/a","sha256":"x"},"operatorRecord":{"path":"/b","sha256":"y"},"installationID":"i","projectKey":"p"}`,
		"unknown":     `{"apiVersion":"` + RegistrationAPIVersion + `","profile":"oss","extra":true}`,
		"api":         `{"apiVersion":"tplaiter.dev/other/v1","profile":"oss","runtimeConfig":{"path":"/a","sha256":"x"},"operatorRecord":{"path":"/b","sha256":"y"},"installationID":"i","projectKey":"p"}`,
		"no_project":  `{"apiVersion":"` + RegistrationAPIVersion + `","profile":"oss","runtimeConfig":{"path":"/a","sha256":"x"},"operatorRecord":{"path":"/b","sha256":"y"},"installationID":"i","projectKey":""}`,
	} {
		if _, err := DecodeRegistration([]byte(raw)); !errors.Is(err, trustload.ErrConfigInvalid) {
			t.Errorf("%s: DecodeRegistration = %v", name, err)
		}
	}
}

func TestGenerateFailsOnEntropyError(t *testing.T) {
	if _, err := Generate(Options{Root: tempRoot(t), Rand: io.LimitReader(&recordingRand{}, 8)}); err == nil {
		t.Fatal("Generate succeeded without entropy")
	}
}
