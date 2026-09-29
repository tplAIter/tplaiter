package stateledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/provenance"
)

const fixtureID = "123e4567-e89b-12d3-a456-426614174000"

func fixtureDir(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata", "state-ledger", "v1"}, parts...)...)
}

func d(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func fixtureProfile() bootstrap.ProfileBinding {
	return bootstrap.ProfileBinding{APIVersion: bootstrap.ProfileBindingAPIVersion, ID: bootstrap.ProfileOSS, DefinitionVersion: 1, ConfigSHA256: d('a'), PolicySHA256: d('b'), AuthoritySHA256: d('c'), Assurance: bootstrap.PublisherVerified, EvidenceClass: bootstrap.EvidenceProduction}
}

// fixtureRoot is the sealed provenance v2 root lock used by every test. It
// matches the canonical provenance package fixture byte for byte.
func fixtureRoot(t *testing.T) provenance.RootTemplateLock {
	t.Helper()
	lock, err := SealRootLock(provenance.RootTemplateLock{
		APIVersion: provenance.RootTemplateLockAPIVersion, Kind: provenance.RootTemplateLockKind, TrustProfile: fixtureProfile(),
		Policy: provenance.PolicyBinding{PolicySHA256: d('b')},
		Root: provenance.RootSubject{
			Origin: "https://example.test/templates", TemplatePath: "base", RequestedRef: "refs/tags/v1", Commit: strings.Repeat("a", 40),
			TreeSHA256: d('1'), ContractSHA256: d('2'), StatementCAS: d('3'), SignatureCAS: d('4'), KeyFingerprint: d('5'), CheckpointCAS: d('6'), InclusionProofCAS: d('7'),
		},
		Renderer: provenance.RendererIdentity{Name: "go-text-template", Version: "v2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if lock.RootLockSHA256 != "sha256:0fdf1f81a9dd8a7ae8474a1ec5a63d47e395c6e1217e3cf8af0da9f5ca2efab1" {
		t.Fatalf("fixture root digest drifted: %s", lock.RootLockSHA256)
	}
	return lock
}

func writeRootLock(t *testing.T, projectRoot string, lock provenance.RootTemplateLock) {
	t.Helper()
	raw, err := canonicaljson.Canonical(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(projectRoot, StateDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, StateDir, RootLockFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// legacyProject writes the v1alpha1 fixture marker and the sealed root lock.
func legacyProjectRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	marker, err := os.ReadFile(fixtureDir("project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, StateDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, StateDir, "project.yaml"), marker, 0o644); err != nil {
		t.Fatal(err)
	}
	writeRootLock(t, root, fixtureRoot(t))
	return root
}

type testRootVerifier struct{ lock provenance.RootTemplateLock }

func (v testRootVerifier) VerifyRoot(context.Context, string) (RootEvidence, error) {
	r := v.lock.Root
	return RootEvidence{Origin: r.Origin, TemplatePath: r.TemplatePath, RequestedRef: r.RequestedRef, Commit: r.Commit, RootLockSHA256: v.lock.RootLockSHA256}, nil
}

type testManifestVerifier struct{}

func (testManifestVerifier) VerifyDependencyFree(_ context.Context, _ string, r RootEvidence) (ManifestEvidence, error) {
	return ManifestEvidence{ManifestSHA256: d('c'), RootLockSHA256: r.RootLockSHA256, RootCommit: r.Commit, NoDependencies: true, NoExtends: true, NoBlocks: true}, nil
}

func migrationOptions(t *testing.T) Options {
	return Options{RootVerifier: testRootVerifier{fixtureRoot(t)}, ManifestVerifier: testManifestVerifier{}}
}

type testSecrets struct{ seen []SecretLocator }

func (s *testSecrets) DigestSecret(_ context.Context, l SecretLocator) (SecretDigestResult, error) {
	s.seen = append(s.seen, l)
	if strings.HasSuffix(l.RelativePath, ".db") {
		return SecretDigestResult{Classified: true, Digest: d('d')}, nil
	}
	return SecretDigestResult{}, nil
}

// fakeAuthority stands in for *trustverify.Runtime.
type fakeAuthority struct{ binding bootstrap.ProfileBinding }

func (a fakeAuthority) Binding() bootstrap.ProfileBinding { return a.binding }
func (a fakeAuthority) CheckBinding(b bootstrap.ProfileBinding) error {
	if !a.binding.Equal(b) {
		return errors.New("binding mismatch")
	}
	return nil
}

// mapCAS is an in-memory evidencecas.Reader.
type mapCAS map[string][]byte

func (m mapCAS) Read(_ context.Context, digest string) ([]byte, error) {
	b, ok := m[digest]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func fullCAS() mapCAS {
	return mapCAS{d('3'): {1}, d('4'): {1}, d('6'): {1}, d('7'): {1}}
}

// stableProject builds a complete project/v2 project by applying the legacy
// migration and adding every remaining ledger.
func stableProject(t *testing.T) string {
	t.Helper()
	root := legacyProjectRoot(t)
	opts := migrationOptions(t)
	plan, err := Plan(root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPlan(root, opts, plan.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"baseline.json", "ownership.json", "resources.lock.json", "ai-managed.json", "generator-targets.lock.json", "managed-blocks.json", "migrations.json"} {
		raw, err := os.ReadFile(fixtureDir("project", StateDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, StateDir, name), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
