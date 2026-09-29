package trustload

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestOpenRuntimeComposesAuthenticatedOSSReaders(t *testing.T) {
	requireNativeStore(t)
	fixture := runtimeFixture(t)
	runtime, err := OpenRuntime(context.Background(), RuntimeOptions{
		Selection: fixture.selection, ProjectKey: "project", Clock: fixedRuntimeClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.TrustRuntime() == nil {
		t.Fatal("missing composed stable runtime")
	}
	if got := runtime.ScratchRoot(); got != fixture.load.install.ScratchRoot {
		t.Fatalf("ScratchRoot() = %q, want authenticated %q", got, fixture.load.install.ScratchRoot)
	}
	if got := runtime.ProjectContext(); got != fixture.load.install.ProjectContexts[0] {
		t.Fatalf("ProjectContext() = %#v, want authenticated %#v", got, fixture.load.install.ProjectContexts[0])
	}
	// The accessor retains the constructor's authenticated locator; later
	// configuration writes cannot select a caller-controlled replacement.
	callerSelected := filepath.Join(fixture.load.dir, "caller-scratch")
	fixture.load.install.ScratchRoot = callerSelected
	fixture.load.writeInstall(t)
	if got := runtime.ScratchRoot(); got == callerSelected {
		t.Fatalf("ScratchRoot() accepted later caller-selected path %q", got)
	}
	callerProjectRoot := filepath.Join(fixture.load.dir, "caller-project")
	fixture.load.install.ProjectContexts[0].RootPath = callerProjectRoot
	fixture.load.writeInstall(t)
	if got := runtime.ProjectContext().RootPath; got == callerProjectRoot {
		t.Fatalf("ProjectContext() accepted later caller-selected root %q", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.TrustRuntime() != nil {
		t.Fatal("closed composition retained runtime")
	}
	if got := runtime.ScratchRoot(); got != "" {
		t.Fatalf("closed ScratchRoot() = %q", got)
	}
	if got := runtime.ProjectContext(); got != (ProjectContext{}) {
		t.Fatalf("closed ProjectContext() = %#v", got)
	}
	if got := (*Runtime)(nil).ScratchRoot(); got != "" {
		t.Fatalf("nil ScratchRoot() = %q", got)
	}
	if got := (*Runtime)(nil).ProjectContext(); got != (ProjectContext{}) {
		t.Fatalf("nil ProjectContext() = %#v", got)
	}
}

func TestRuntimeReadersReloadFixedPolicyAndProject(t *testing.T) {
	requireNativeStore(t)
	fixture := runtimeFixture(t)
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	readers := runtimeReaders{selection: fixture.selection, projectKey: "project", store: store}
	project, err := (projectReader{readers}).Load(context.Background())
	if err != nil || project.ProjectID != "project.test" || project.MinimumProfile != "oss" {
		t.Fatalf("project reader = %#v, %v", project, err)
	}
	policy, err := (policyReader{readers}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if policy.ExpectedPolicySHA256 == fixture.load.install.ExecutionPolicy.SHA256 {
		t.Fatal("policy reader returned raw FilePin digest instead of semantic policy digest")
	}
	if err := os.WriteFile(fixture.load.install.ExecutionPolicy.Path, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (policyReader{readers}).Load(context.Background()); err == nil {
		t.Fatal("reader retained policy after fixed raw pin drift")
	}
}

func TestRuntimeEvidenceReaderRehashesStoreAndFixedCASBytes(t *testing.T) {
	requireNativeStore(t)
	fixture := runtimeFixture(t)
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var ref string
	var want []byte
	for ref, want = range fixture.evidence {
		break
	}
	if ref == "" {
		t.Fatal("fixture has no evidence")
	}
	hex := ref[len("sha256:"):]
	localPath := filepath.Join(fixture.load.install.EvidenceRoot, "sha256", hex[:2], hex[2:])
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, want, 0o600); err != nil {
		t.Fatal(err)
	}
	local, err := evidencecas.NewFSReader(fixture.load.install.EvidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	got, err := (runtimeReaders{store: store, localEvidence: local}).Read(context.Background(), ref)
	if err != nil || string(got) != string(want) || evidencecas.Digest(got) != ref {
		t.Fatalf("evidence reader = %q, %v", got, err)
	}
}

func TestOpenRuntimeOrganizationFailsBeforeOSSConstruction(t *testing.T) {
	f := newLoadFixture(t)
	f.descriptor.Profile = bootstrap.ProfileOrganization
	f.descriptor.DescriptorSHA256 = f.descriptor.ComputedSHA256()
	f.operator.DescriptorSHA256 = f.descriptor.DescriptorSHA256
	f.provisioning = bootstrap.ProvisioningRecord{}
	f.write(t)
	f.provisioning.EvidenceClass = bootstrap.EvidenceProduction
	f.provisioning.ProvisioningSHA256 = f.provisioning.ComputedSHA256()
	f.write(t)
	f.install.Profile = bootstrap.ProfileOrganization
	f.install.OSS = nil
	f.install.Protected = &ProtectedInstall{AdapterID: "protected.test"}
	f.writeInstall(t)
	if _, err := OpenRuntime(context.Background(), RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: fixedRuntimeClock{}}); !errors.Is(err, ErrProtectedUnavailable) {
		t.Fatalf("OpenRuntime() error = %v, want protected unavailable", err)
	}
}

type fixedRuntimeClock struct{}

func (fixedRuntimeClock) Now() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }

func runtimeFixture(t *testing.T) bootstrapFixture {
	t.Helper()
	fixture := newBootstrapFixture(t)
	objectRoot := filepath.Join(fixture.load.dir, "objects")
	if err := os.Mkdir(objectRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(fixture.load.dir, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	policy := trustverify.ExecutionPolicy{
		APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "policy.test", Profile: "oss", MinimumProfile: "oss",
		Validity:             trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"},
		Principals:           []trustverify.Principal{{ID: "principal:publisher"}, {ID: "principal:submitter"}},
		IssuerPrincipals:     []trustverify.IssuerPrincipal{{Issuer: "publisher-1", PrincipalID: "principal:publisher"}},
		SourceRules:          []trustverify.SourceRule{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: "https://example.test/source", TemplatePath: "templates/base", Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"}},
		Approvers:            []trustverify.Approver{},
		AllowInvocationHuman: false, MaxTimeoutMillis: 1000,
	}
	var err error
	policy.PolicySHA256, err = policy.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	fixture.load.policy, err = json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	fixture.load.write(t)
	// newBootstrapFixture pins the initial semantic OSS state and bundle. Keep
	// those authenticated values while changing only C's reader registrations.
	fixture.load.install.OSS.InitialStateSHA256 = fixture.loaded.Install.OSS.InitialStateSHA256
	fixture.load.install.OSS.InitialBundleSHA256 = fixture.loaded.Install.OSS.InitialBundleSHA256
	fixture.load.install.ProjectContexts = []ProjectContext{{Key: "project", ProjectID: "project.test", SubmitterPrincipalID: "principal:submitter", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(fixture.load.dir, "project")}}
	fixture.load.install.ObjectOrigins = []ObjectOrigin{{Origin: "https://example.test/source", RootPath: objectRoot}}
	fixture.load.writeInstall(t)
	fixture.selection = fixture.load.selection
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	return fixture
}
