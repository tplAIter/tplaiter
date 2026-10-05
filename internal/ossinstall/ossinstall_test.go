package ossinstall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
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

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertTestFile(t *testing.T, path, content string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must survive: %v", path, err)
	}
	if string(raw) != content {
		t.Fatalf("%s changed: %q", path, raw)
	}
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
		if _, err := Generate(Options{Root: root}); !errors.Is(err, ErrInstallRootForeign) {
			t.Fatalf("Generate over unrelated files: %v", err)
		}
		if strings.Contains(ErrInstallRootForeign.Error(), "rotat") {
			t.Fatalf("the foreign-root error must not suggest rotation: %v", ErrInstallRootForeign)
		}
	})
	t.Run("rotate_over_foreign_entries", func(t *testing.T) {
		root := tempRoot(t)
		notes := filepath.Join(root, "notes.txt")
		project := filepath.Join(root, "projects", "x")
		writeTestFile(t, notes, "mine")
		writeTestFile(t, project, "important")
		if _, err := Generate(Options{Root: root, Rotate: true}); !errors.Is(err, ErrInstallRootForeign) {
			t.Fatalf("rotation over foreign entries: %v", err)
		}
		assertTestFile(t, notes, "mine")
		assertTestFile(t, project, "important")
	})
	t.Run("rotate_over_generated_names_without_ownership", func(t *testing.T) {
		// Only names Generate would own, but no marker and no registration:
		// ownership is not proven, so nothing may be removed.
		root := tempRoot(t)
		project := filepath.Join(root, "projects", "important", "file")
		config := filepath.Join(root, "config", "x")
		writeTestFile(t, project, "important")
		writeTestFile(t, config, "x")
		for _, rotate := range []bool{false, true} {
			if _, err := Generate(Options{Root: root, Rotate: rotate}); !errors.Is(err, ErrInstallRootForeign) {
				t.Fatalf("Generate (rotate=%v) over unowned generated names: %v", rotate, err)
			}
		}
		assertTestFile(t, project, "important")
		assertTestFile(t, config, "x")
	})
	t.Run("rotate_over_owned_install_with_foreign_entry", func(t *testing.T) {
		root := tempRoot(t)
		if _, err := Generate(Options{Root: root}); err != nil {
			t.Fatal(err)
		}
		notes := filepath.Join(root, "notes.txt")
		writeTestFile(t, notes, "mine")
		if _, err := Generate(Options{Root: root, Rotate: true}); !errors.Is(err, ErrInstallRootForeign) {
			t.Fatalf("rotation over an installation with a foreign entry: %v", err)
		}
		assertTestFile(t, notes, "mine")
		if _, err := os.Stat(filepath.Join(root, RegistrationFile)); err != nil {
			t.Fatalf("refused rotation removed the registration: %v", err)
		}
	})
	t.Run("rotate_legacy_install_without_marker", func(t *testing.T) {
		root := tempRoot(t)
		if _, err := Generate(Options{Root: root}); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, OwnershipMarker)); err != nil {
			t.Fatal(err)
		}
		if _, err := Generate(Options{Root: root, Rotate: true}); err != nil {
			t.Fatalf("rotation of a registration-proven installation: %v", err)
		}
		assertTestFile(t, filepath.Join(root, OwnershipMarker), ownershipMarkerContent)
	})
	t.Run("legacy_install_with_non_marker_entry", func(t *testing.T) {
		// A legacy installation whose marker name holds a directory is
		// refused before rotation removes any generated entry.
		root := tempRoot(t)
		if _, err := Generate(Options{Root: root}); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(root, OwnershipMarker)
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(marker, 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(marker, "keep"), "user data")
		if _, err := Generate(Options{Root: root, Rotate: true}); !errors.Is(err, ErrInstallRootForeign) {
			t.Fatalf("rotation over a non-marker entry: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, RegistrationFile)); err != nil {
			t.Fatalf("refused rotation removed the registration: %v", err)
		}
		assertTestFile(t, filepath.Join(marker, "keep"), "user data")
	})
	t.Run("marker_only_root", func(t *testing.T) {
		root := tempRoot(t)
		writeTestFile(t, filepath.Join(root, OwnershipMarker), ownershipMarkerContent)
		if _, err := Generate(Options{Root: root}); err != nil {
			t.Fatalf("Generate after an interrupted first run: %v", err)
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

func TestLocalProviderWriterRealV2AndReuse(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := trustload.ProjectContext{Key: "local-preview", ProjectID: "project.local-preview", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(base, "project")}
	spec := LocalProviderSpec{RegistrationID: "public-synthetic", ProjectKeys: []string{project.Key}, Protocol: "local-provider.session/v1", Qualification: trustload.LocalObserved, Limits: trustload.LocalReadLimits{FrameBytes: 32768, TotalBytes: 2097152, Pages: 128, SourceBytes: 8192, DeadlineMs: 2000}}
	spec.Endpoint.Kind = "unix"
	spec.Endpoint.SocketPath = "/private/tmp/public-synthetic/session.sock"
	spec.Endpoint.OwnerUID = uint32(os.Geteuid())
	opts := Options{Root: filepath.Join(base, "install"), ProjectContexts: []trustload.ProjectContext{project}, LocalProviders: []LocalProviderSpec{spec}}
	result, err := GenerateWithContext(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(result.RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := DecodeRegistration(raw)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := trustload.Load(context.Background(), registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Install.APIVersion != trustload.RuntimeInstallV2APIVersion || len(loaded.Install.LocalProviders) != 1 {
		t.Fatal("writer did not produce registered v2")
	}
	doc, err := os.ReadFile(loaded.Install.LocalProviders[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	_ = json.Unmarshal(doc, &document)
	if document["installationID"] != result.InstallationID {
		t.Fatal("generator installation binding")
	}
	again, err := GenerateWithContext(context.Background(), opts)
	if err != nil || !again.Reused || again.RegistrationSHA256 != result.RegistrationSHA256 {
		t.Fatal("real reuse", err)
	}
	changed := opts
	changed.LocalProviders = append([]LocalProviderSpec(nil), opts.LocalProviders...)
	changed.LocalProviders[0].Endpoint.SocketPath = "/private/tmp/public-synthetic/changed.sock"
	if _, err = GenerateWithContext(context.Background(), changed); !errors.Is(err, ErrEnrollmentChanged) {
		t.Fatal("changed selection accepted", err)
	}
}

// Exercises actual emitted documents, not manufactured installed authority.
func TestLocalProviderActualGenerateSchemaLexicalParity(t *testing.T) {
	registrationSchema, err := jsonschema.NewCompiler().Compile("../../schema/local-provider-registration.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	runtimeSchema, err := jsonschema.NewCompiler().Compile("../../schema/runtime-install.v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, token    string
		extraGlobalKey bool
	}{
		{"form-feed", "host\fpreview", false},
		{"vertical-tab", "host\vpreview", false},
		{"non-ascii-whitespace", "host\u00a0preview", false},
		{"unicode", "hôte", false},
		{"utf8-64-bytes", strings.Repeat("é", 32), false},
		{"global-key-over-64", "host", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			pc := trustload.ProjectContext{Key: "counter", ProjectID: "project.counter", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(base, "project")}
			contexts := []trustload.ProjectContext{pc}
			if tc.extraGlobalKey {
				contexts = append(contexts, trustload.ProjectContext{Key: strings.Repeat("k", 65), ProjectID: "project.extra", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(base, "extra")})
			}
			spec := LocalProviderSpec{RegistrationID: tc.token, ProjectKeys: []string{pc.Key}, Protocol: "local-provider.session/v1", Qualification: trustload.LocalObserved, Limits: trustload.LocalReadLimits{FrameBytes: 32768, TotalBytes: 2097152, Pages: 128, SourceBytes: 8192, DeadlineMs: 2000}}
			spec.Endpoint.Kind = "unix"
			spec.Endpoint.SocketPath = "/private/tmp/public-synthetic/session.sock"
			spec.Endpoint.OwnerUID = uint32(os.Geteuid())
			generated, e := Generate(Options{Root: filepath.Join(base, "installation"), ProjectContexts: contexts, LocalProviders: []LocalProviderSpec{spec}})
			if e != nil {
				t.Fatal("actual Generate", e)
			}
			launchRaw, e := os.ReadFile(generated.RegistrationPath)
			if e != nil {
				t.Fatal(e)
			}
			launch, e := DecodeRegistration(launchRaw)
			if e != nil {
				t.Fatal(e)
			}
			loaded, e := trustload.Load(context.Background(), launch.Selection())
			if e != nil {
				t.Fatal(e)
			}
			for _, doc := range []struct {
				path   string
				schema *jsonschema.Schema
			}{{loaded.Install.LocalProviders[0].Path, registrationSchema}, {launch.RuntimeConfig.Path, runtimeSchema}} {
				raw, e := os.ReadFile(doc.path)
				if e != nil {
					t.Fatal(e)
				}
				value, e := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
				if e != nil {
					t.Fatal(e)
				}
				if e = doc.schema.Validate(value); e != nil {
					t.Fatal("actual emitted schema mismatch", e)
				}
			}
		})
	}
}
