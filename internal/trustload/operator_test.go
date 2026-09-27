package trustload

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
)

type loadFixture struct {
	dir          string
	installPath  string
	descriptor   bootstrap.DescriptorDocument
	provisioning bootstrap.ProvisioningRecord
	operator     OperatorPinRecord
	policy       []byte
	install      RuntimeInstall
	selection    LaunchSelection
}

func newLoadFixture(t *testing.T) *loadFixture {
	t.Helper()
	dir := noFollowTempDir(t)
	key := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	publicKey := key.Public().(ed25519.PublicKey)
	descriptor := bootstrap.DescriptorDocument{
		APIVersion:           bootstrap.DescriptorAPIVersion,
		Profile:              bootstrap.ProfileOSS,
		AuthorityID:          "synthetic-authority",
		Anchors:              []bootstrap.DescriptorAnchor{{Fingerprint: bootstrap.Fingerprint(publicKey), PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey)}},
		Threshold:            1,
		AllowedPolicyOrigins: []string{"https://example.test/policy"},
		PublisherScopes: []bootstrap.PublisherScope{{
			PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", SourceOrigin: "https://example.test/source", TemplatePath: "templates/base", Predicate: "https://example.test/predicate", Usage: "template-source",
		}},
	}
	descriptor.DescriptorSHA256 = descriptor.ComputedSHA256()
	f := &loadFixture{
		dir:         dir,
		installPath: filepath.Join(dir, "runtime.json"),
		descriptor:  descriptor,
		operator: OperatorPinRecord{
			APIVersion:       OperatorPinRecordAPIVersion,
			Method:           "operator-pinned",
			DescriptorSHA256: descriptor.DescriptorSHA256,
		},
		policy: []byte(`{"policy":"fixed"}`),
	}
	f.write(t)
	return f
}

func (f *loadFixture) write(t *testing.T) {
	t.Helper()
	descriptorRaw, err := json.Marshal(f.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	operatorRaw, err := json.Marshal(f.operator)
	if err != nil {
		t.Fatal(err)
	}
	if f.provisioning.APIVersion == "" {
		f.provisioning = bootstrap.ProvisioningRecord{
			APIVersion:                   bootstrap.ProvisioningAPIVersion,
			Mode:                         "operator-pinned",
			DescriptorSHA256:             f.operator.DescriptorSHA256,
			AuthenticationEvidenceSHA256: rawSHA256(operatorRaw),
			EvidenceClass:                bootstrap.EvidenceSimulated,
		}
		f.provisioning.ProvisioningSHA256 = f.provisioning.ComputedSHA256()
	}
	provisioningRaw, err := json.Marshal(f.provisioning)
	if err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string][]byte{
		filepath.Join(f.dir, "descriptor.json"):   descriptorRaw,
		filepath.Join(f.dir, "provisioning.json"): provisioningRaw,
		filepath.Join(f.dir, "operator.json"):     operatorRaw,
		filepath.Join(f.dir, "policy.json"):       f.policy,
	} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.install = RuntimeInstall{
		APIVersion:      RuntimeInstallAPIVersion,
		InstallationID:  "install.test",
		Profile:         bootstrap.ProfileOSS,
		MinimumProfile:  bootstrap.ProfileOSS,
		Descriptor:      FilePin{Path: filepath.Join(f.dir, "descriptor.json"), SHA256: rawSHA256(descriptorRaw)},
		Provisioning:    FilePin{Path: filepath.Join(f.dir, "provisioning.json"), SHA256: rawSHA256(provisioningRaw)},
		OperatorRecord:  FilePin{Path: filepath.Join(f.dir, "operator.json"), SHA256: rawSHA256(operatorRaw)},
		ExecutionPolicy: FilePin{Path: filepath.Join(f.dir, "policy.json"), SHA256: rawSHA256(f.policy)},
		ProjectContexts: []ProjectContext{},
		ObjectOrigins:   []ObjectOrigin{},
		EvidenceRoot:    filepath.Join(f.dir, "evidence"),
		ScratchRoot:     filepath.Join(f.dir, "scratch"),
		OSS: &OSSInstall{
			StorePath: filepath.Join(f.dir, "store"), InitialStatePath: filepath.Join(f.dir, "state.json"), InitialStateSHA256: rawSHA256([]byte("state")),
			InitialBundlePath: filepath.Join(f.dir, "bundle.json"), InitialBundleSHA256: rawSHA256([]byte("bundle")),
		},
	}
	f.writeInstall(t)
}

func (f *loadFixture) writeInstall(t *testing.T) {
	t.Helper()
	digest := f.writeUnvalidatedInstall(t)
	raw := mustReadFile(t, f.installPath)
	decoded, err := DecodeRuntimeInstall(raw)
	if err != nil {
		t.Fatal(err)
	}
	decodedDigest, err := decoded.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if decodedDigest != digest {
		t.Fatalf("runtime digest changes on fixed JSON round trip: %s != %s", decodedDigest, digest)
	}
	for _, pin := range []FilePin{f.install.Descriptor, f.install.Provisioning, f.install.OperatorRecord, f.install.ExecutionPolicy} {
		if _, err := configFileBytes(pin); err != nil {
			t.Fatalf("fixture pin %s: %v", pin.Path, err)
		}
	}
}

func (f *loadFixture) writeUnvalidatedInstall(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(f.install)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.installPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := f.install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f.selection = LaunchSelection{Profile: f.install.Profile, RuntimeConfig: FilePin{Path: f.installPath, SHA256: digest}, OperatorRecord: f.install.OperatorRecord, InstallationID: f.install.InstallationID}
	return digest
}

// Darwin's /tmp and /var are symlinked roots. The production no-follow reader
// correctly rejects those routes, so use its physical temporary root here.
func noFollowTempDir(t *testing.T) string {
	t.Helper()
	root := "/private/var/tmp"
	if _, err := os.Stat(root); err != nil {
		root = "/tmp"
	}
	dir, err := os.MkdirTemp(root, "tplaiter-trustload-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestLoadAcceptsDistinctRawPinsAndBootstrapSelfHashes(t *testing.T) {
	f := newLoadFixture(t)
	if f.install.Descriptor.SHA256 == f.descriptor.DescriptorSHA256 {
		t.Fatal("fixture does not distinguish descriptor raw and domain digests")
	}
	if f.install.Provisioning.SHA256 == f.provisioning.ProvisioningSHA256 {
		t.Fatal("fixture does not distinguish provisioning raw and domain digests")
	}
	loaded, err := Load(context.Background(), f.selection)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.Operator.DescriptorSHA256 != f.descriptor.DescriptorSHA256 || string(loaded.PolicyJSON) != string(f.policy) {
		t.Fatal("loaded fixed provenance differs from registered fixture")
	}
	loaded.DescriptorJSON[0] ^= 1
	if string(loaded.DescriptorJSON) == string(mustReadFile(t, f.install.Descriptor.Path)) {
		t.Fatal("Load returned aliased descriptor bytes")
	}
}

func TestLoadRejectsIndependentProvenanceTampering(t *testing.T) {
	t.Run("raw descriptor pin", func(t *testing.T) {
		f := newLoadFixture(t)
		if err := os.WriteFile(f.install.Descriptor.Path, []byte(`{"tampered":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(context.Background(), f.selection); err != ErrPinMismatch {
			t.Fatalf("Load() error = %v, want raw pin mismatch", err)
		}
	})
	t.Run("descriptor self hash", func(t *testing.T) {
		f := newLoadFixture(t)
		f.descriptor.AuthorityID = "tampered-authority"
		f.write(t) // Re-pins raw bytes while retaining the stale domain self-hash.
		if _, err := Load(context.Background(), f.selection); err != ErrProvenanceUnavailable {
			t.Fatalf("Load() error = %v, want descriptor self-hash rejection", err)
		}
	})
	t.Run("operator descriptor binding", func(t *testing.T) {
		f := newLoadFixture(t)
		f.operator.DescriptorSHA256 = rawSHA256([]byte("other-descriptor"))
		f.write(t)
		if _, err := Load(context.Background(), f.selection); err != ErrProvenanceUnavailable {
			t.Fatalf("Load() error = %v, want operator binding rejection", err)
		}
	})
	t.Run("provisioning descriptor binding", func(t *testing.T) {
		f := newLoadFixture(t)
		f.provisioning.DescriptorSHA256 = rawSHA256([]byte("other-descriptor"))
		f.provisioning.ProvisioningSHA256 = f.provisioning.ComputedSHA256()
		f.write(t)
		if _, err := Load(context.Background(), f.selection); err != ErrProvenanceUnavailable {
			t.Fatalf("Load() error = %v, want provisioning descriptor binding rejection", err)
		}
	})
	t.Run("provisioning authentication evidence", func(t *testing.T) {
		f := newLoadFixture(t)
		f.provisioning.AuthenticationEvidenceSHA256 = rawSHA256([]byte("other-operator-record"))
		f.provisioning.ProvisioningSHA256 = f.provisioning.ComputedSHA256()
		f.write(t)
		if _, err := Load(context.Background(), f.selection); err != ErrProvenanceUnavailable {
			t.Fatalf("Load() error = %v, want authentication binding rejection", err)
		}
	})
	t.Run("record class", func(t *testing.T) {
		f := newLoadFixture(t)
		f.provisioning.EvidenceClass = bootstrap.EvidenceClass("candidate-asserted-production")
		f.provisioning.ProvisioningSHA256 = f.provisioning.ComputedSHA256()
		f.write(t)
		if _, err := Load(context.Background(), f.selection); err != ErrProvenanceUnavailable {
			t.Fatalf("Load() error = %v, want record-class rejection", err)
		}
	})
	t.Run("fixed registration", func(t *testing.T) {
		f := newLoadFixture(t)
		f.selection.InstallationID = "other-install"
		if _, err := Load(context.Background(), f.selection); err != ErrPinMismatch {
			t.Fatalf("Load() error = %v, want fixed registration rejection", err)
		}
	})
	t.Run("registered operator pin", func(t *testing.T) {
		f := newLoadFixture(t)
		f.selection.OperatorRecord.SHA256 = rawSHA256([]byte("other-operator-record"))
		if _, err := Load(context.Background(), f.selection); err != ErrPinMismatch {
			t.Fatalf("Load() error = %v, want operator registration rejection", err)
		}
	})
	t.Run("minimum profile", func(t *testing.T) {
		f := newLoadFixture(t)
		f.install.MinimumProfile = bootstrap.ProfileOrganization
		f.writeUnvalidatedInstall(t)
		if _, err := Load(context.Background(), f.selection); err != ErrConfigInvalid {
			t.Fatalf("Load() error = %v, want minimum-profile rejection", err)
		}
	})
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLoadRejectsMissingOrUnregisteredSelection(t *testing.T) {
	selection := LaunchSelection{Profile: "oss", RuntimeConfig: FilePin{"/var/tmp/no-such-runtime.json", "sha256:" + strings.Repeat("0", 64)}, OperatorRecord: FilePin{"/var/tmp/no-such-operator.json", "sha256:" + strings.Repeat("1", 64)}, InstallationID: "install.test"}
	if _, err := Load(context.Background(), selection); err == nil {
		t.Fatal("accepted missing fixed installation")
	}
	if _, err := Load(context.Background(), LaunchSelection{}); err == nil {
		t.Fatal("accepted empty launch selection")
	}
}

func TestLoadDoesNotWriteOnFailure(t *testing.T) {
	selection := LaunchSelection{Profile: "oss", RuntimeConfig: FilePin{"/var/tmp/trustload-does-not-exist/runtime.json", "sha256:" + strings.Repeat("0", 64)}, OperatorRecord: FilePin{"/var/tmp/trustload-does-not-exist/operator.json", "sha256:" + strings.Repeat("1", 64)}, InstallationID: "install.test"}
	if _, err := Load(context.Background(), selection); err == nil {
		t.Fatal("accepted missing installation")
	}
}

func TestSecureReadRejectsFinalAndParentSymlinks(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(realDir, "record.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(root, "final.json")
	if err := os.Symlink(file, final); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReadFile(final, maxDocument); err == nil {
		t.Fatal("accepted final symlink")
	}
	parent := filepath.Join(root, "parent")
	if err := os.Symlink(realDir, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReadFile(filepath.Join(parent, "record.json"), maxDocument); err == nil {
		t.Fatal("accepted parent symlink")
	}
}
