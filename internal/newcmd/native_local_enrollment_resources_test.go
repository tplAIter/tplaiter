//go:build darwin || linux

package newcmd

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Exercise the production capture/sign/enroll/verify/new composition, using
// exact public Git objects and fresh operator keys rather than fixture seeds.
// This is an API integration test; stock install/CLI/MCP smoke is separate.
func TestNativeLocalOperatorPublicGoEnrollmentAndResources(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rawObjects := filepath.Join(base, "raw")
	if err := os.Mkdir(rawObjects, 0o700); err != nil {
		t.Fatal(err)
	}
	_, publicSubject := nativeGoSource(t, rawObjects, "", "", "")
	repository := filepath.Join(base, "source")
	entries, err := os.ReadDir(rawObjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		id := entry.Name()
		raw, err := os.ReadFile(filepath.Join(rawObjects, id))
		if err != nil {
			t.Fatal(err)
		}
		objectPath := filepath.Join(repository, ".git", "objects", id[:2], id[2:])
		if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(objectPath)
		if err != nil {
			t.Fatal(err)
		}
		writer := zlib.NewWriter(file)
		if _, err := writer.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repository, ".git", "config"), []byte("[core]\nrepositoryformatversion=0\nbare=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "project")
	result, err := ossinstall.GenerateWithContext(ctx, ossinstall.Options{
		Root:            filepath.Join(base, "installation"),
		LocalSources:    []sourcepackage.CaptureInput{{RepositoryPath: repository, Origin: publicSubject.Origin, TemplatePath: ".", Commit: publicGoCommit}},
		ProjectContexts: []trustload.ProjectContext{{Key: "go", ProjectID: "project-local-go", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: target}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PublicationState != "committed" {
		t.Fatalf("installation publication: %s", result.PublicationState)
	}
	registrationRaw, err := os.ReadFile(result.RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	if evidencecas.Digest(registrationRaw) != result.RegistrationSHA256 {
		t.Fatal("registration raw pin mismatch")
	}
	registration, err := ossinstall.DecodeRegistration(registrationRaw)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := trustload.Load(ctx, registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	// Enroll only the ordinary bootstrap closure. Source CAS remains in the
	// published installation; it is not injected as privileged store material.
	stateRaw, err := os.ReadFile(loaded.Install.OSS.InitialStatePath)
	if err != nil {
		t.Fatal(err)
	}
	bundleRaw, err := os.ReadFile(loaded.Install.OSS.InitialBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := trustload.DecodeStoredBundle(bundleRaw)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := evidencecas.NewFSReader(loaded.Install.EvidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	refs := []string{bundle.EnvelopeCAS, bundle.ReceiptCAS, bundle.Transparency.CheckpointCAS, bundle.Transparency.InclusionProofCAS}
	evidence := map[string][]byte{}
	for i := 0; i < len(refs); i++ {
		ref := refs[i]
		if _, ok := evidence[ref]; ok {
			continue
		}
		raw, err := reader.Read(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		evidence[ref] = raw
		if ref == bundle.EnvelopeCAS {
			envelope, err := bootstrap.DecodeEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range envelope.RootKeys {
				refs = append(refs, key.PublicKeyCAS)
			}
			for _, signature := range envelope.Signatures {
				refs = append(refs, signature.SignatureCAS)
			}
		}
	}
	factory := func(r evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(r, bootstrap.ClockFunc(time.Now), nil, 0)
	}
	if err := trustload.Enroll(ctx, registration.Selection(), factory, stateRaw, bundleRaw, evidence); err != nil {
		t.Fatal(err)
	}
	runtime, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: registration.Selection(), ProjectKey: "go", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	selectionsRaw, err := os.ReadFile(result.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var selections []operationtrust.SourceSelection
	if err := canonicaljson.DecodeStrict(selectionsRaw, &selections); err != nil || len(selections) != 1 {
		t.Fatalf("selection: %v %v", selections, err)
	}
	selected := selections[0]
	if selected.TrustSubject() != publicSubject {
		t.Fatal("capture changed exact public subject")
	}
	resolution, err := runtime.TrustRuntime().VerifySubject(ctx, selected.TrustSubject(), selected.EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	if !resolution.ValidFor(runtime.TrustRuntime(), runtime.TrustRuntime().Binding()) {
		t.Fatal("source capability not runtime-bound")
	}
	recordRaw, err := os.ReadFile(filepath.Join(result.Root, "config", "local-publisher.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record ossinstall.LocalPublication
	if err := canonicaljson.DecodeStrict(recordRaw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Issuer != "local-operator-"+strings.TrimPrefix(record.KeyFingerprint, "sha256:") || record.Mode != "local-operator" || record.Subject.Commit != publicGoCommit || record.Subject.TreeSHA256 != publicSubject.TreeSHA256 || record.Subject.ContractSHA256 != publicSubject.ContractSHA256 || record.KeyFingerprint != selected.Evidence.KeyFingerprint || bytes.Contains(recordRaw, []byte(repository)) {
		t.Fatal("local operator publication tuple mismatch")
	}
	// Once verified, removal of the input object repository cannot affect new.
	if err := os.RemoveAll(repository); err != nil {
		t.Fatal(err)
	}
	sourceInput, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	d := Deps{Runtime: runtime, Home: home, SourceInput: sourceInput, Runner: noNativeResourceSpawn{t}, Out: &bytes.Buffer{}}
	opts := Options{Ref: publicGoCommit, ProjectName: "Local Go", Dir: target, Module: "example.test/neutral", Defaults: true, NoHooks: true, NoDepsCheck: true, CLIVersion: "v1.0.0"}
	if err := Run(ctx, opts, d); err != nil {
		t.Fatal(err)
	}
	assertNativeGoResources(t, &t5DIntegrationFixture{project: target, source: publicSubject}, d)
	// This checks today's stable profile-bound ledger validation only. Project
	// identity hardening is independently reviewed; do not assert that contract.
	if _, err := stateledger.VerifyStable(ctx, target, runtime.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		t.Fatal(err)
	}
}
