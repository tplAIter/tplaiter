package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"github.com/tplAIter/tplaiter/internal/update"
)

func TestTrustCommandsGateBeforeHomeForMissingAnchor(t *testing.T) {
	home, err := os.MkdirTemp("/var/tmp", "tplaiter-t5f-home-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	t.Setenv("TPLATER_HOME", "")
	t.Setenv("TPLAITER_HOME", "")

	for name, args := range map[string][]string{
		"new":     {"new", "0123456789012345678901234567890123456789", "project"},
		"inspect": {"trust", "inspect"},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := newTrustRootCommand(invocation{})
			cmd.SetArgs(args)
			err := cmd.Execute()
			if !errors.Is(err, trustload.ErrAnchorMissing) {
				t.Fatalf("Execute(%v) error = %v, want TRUST_ANCHOR_MISSING", args, err)
			}
			if _, statErr := os.Stat(home); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("Execute(%v) initialized synthetic HOME: %v", args, statErr)
			}
		})
	}
}

func TestTrustFactoryLeavesDescriptiveAndLocalRoutesAvailable(t *testing.T) {
	cmd := newTrustRootCommand(invocation{})
	cmd.SetArgs([]string{"new", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("new --help error = %v", err)
	}

	cmd = newTrustRootCommand(invocation{})
	cmd.SetArgs([]string{"update", "--check", "--all"})
	if err := cmd.Execute(); !errors.Is(err, update.ErrLifecycleUnavailable) {
		t.Fatalf("update --check --all error = %v, want %v", err, update.ErrLifecycleUnavailable)
	}
}

func TestTrustFactoryVersionAndUntrustedInputErrorsStaySafe(t *testing.T) {
	testfixture.RequireTrustStore(t)
	cmd := newTrustRootCommand(invocation{})
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--version error = %v", err)
	}

	f := t5FTrustFixture(t)
	provision := newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	provision.SetArgs([]string{"trust", "provision"})
	if err := provision.Execute(); err != nil {
		t.Fatalf("provision fixture: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), bad); err != nil {
		t.Fatal(err)
	}
	cmd = newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	cmd.SetArgs([]string{"new", "--dry-run", "--source-input", bad, "0123456789012345678901234567890123456789", "project"})
	err := cmd.Execute()
	if err == nil || err.Error() != "TRUST_SOURCE_ADAPTER_UNSUPPORTED" || strings.Contains(err.Error(), bad) {
		t.Fatalf("untrusted source-input error = %v", err)
	}
}

func TestTrustCobraRejectsUntrustedOverridesWithoutMutatingAuthority(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := t5FTrustFixture(t)
	provision := newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	provision.SetArgs([]string{"trust", "provision"})
	if err := provision.Execute(); err != nil {
		t.Fatalf("provision fixture: %v", err)
	}
	beforeProject := t5FDirectoryDigest(t, f.projectRoot)
	beforeStore := t5FDirectoryDigest(t, f.store)
	oversize := filepath.Join(t.TempDir(), "oversize-selection.json")
	if err := os.WriteFile(oversize, make([]byte, trustCommandDocumentLimit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"new", "--dry-run", "--source-input", oversize, strings.Repeat("0", 40), "project"},
		{"update", "--dry-run", "--source-input", oversize, "--to", strings.Repeat("0", 40)},
	} {
		cmd := newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil || err.Error() != "TRUST_SOURCE_ADAPTER_UNSUPPORTED" || strings.Contains(err.Error(), oversize) {
			t.Fatalf("Execute(%v) error = %v, want safe source denial", args, err)
		}
	}
	unknown := newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	unknown.SetArgs([]string{"update", "--dry-run", "--target-input", oversize})
	if err := unknown.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("removed --target-input accepted: %v", err)
	}
	badSelection := f.selection
	badSelection.RuntimeConfig.SHA256 = "sha256:" + strings.Repeat("0", 64)
	pinned := newTrustRootCommand(invocation{Selection: badSelection, ProjectKey: "project", Clock: f.clock})
	pinned.SetArgs([]string{"trust", "inspect"})
	if err := pinned.Execute(); err == nil || strings.Contains(err.Error(), badSelection.RuntimeConfig.Path) {
		t.Fatalf("tampered runtime pin error = %v", err)
	}
	if got := t5FDirectoryDigest(t, f.projectRoot); got != beforeProject {
		t.Fatalf("project changed after rejected inputs: got %s want %s", got, beforeProject)
	}
	if got := t5FDirectoryDigest(t, f.store); got != beforeStore {
		t.Fatalf("authority store changed after rejected inputs: got %s want %s", got, beforeStore)
	}
}

func TestRegisteredLockReaderRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, ".tplaiter")
	if err := os.Mkdir(metadata, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "root-template.lock.json")
	if err := os.WriteFile(outside, []byte(`{"not":"a lock"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(metadata, "root-template.lock.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegisteredLock(context.Background(), root, "root-template.lock.json"); !errors.Is(err, errRegisteredLock) {
		t.Fatalf("symlink lock error = %v, want bounded nofollow rejection", err)
	}
}

func TestRegisteredProjectPreimageUsesAggregateBoundedRegularReads(t *testing.T) {
	t.Run("empty regular file", func(t *testing.T) {
		root := t5FDescriptorTempDir(t)
		path := filepath.Join(root, "empty.txt")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		before := t5FDirectoryDigest(t, root)
		got, err := registeredProjectPreimage(context.Background(), root)
		if err != nil {
			t.Fatalf("empty file preimage: %v", err)
		}
		if want := t5FExpectedPreimage("empty.txt", nil); got != want {
			t.Fatalf("empty file preimage = %q, want %q", got, want)
		}
		if after := t5FDirectoryDigest(t, root); after != before {
			t.Fatalf("empty preimage read changed project: got %s want %s", after, before)
		}
	})
	t.Run("over one MiB within aggregate", func(t *testing.T) {
		root := t5FDescriptorTempDir(t)
		data := bytes.Repeat([]byte("a"), trustCommandDocumentLimit+1)
		path := filepath.Join(root, "large.txt")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		before := t5FDirectoryDigest(t, root)
		got, err := registeredProjectPreimage(context.Background(), root)
		if err != nil {
			t.Fatalf("large file preimage: %v", err)
		}
		if want := t5FExpectedPreimage("large.txt", data); got != want {
			t.Fatalf("large file preimage = %q, want %q", got, want)
		}
		if after := t5FDirectoryDigest(t, root); after != before {
			t.Fatalf("large preimage read changed project: got %s want %s", after, before)
		}
	})
	t.Run("aggregate over 64 MiB", func(t *testing.T) {
		root := t5FDescriptorTempDir(t)
		path := filepath.Join(root, "too-large.txt")
		t5FWriteActualData(t, path, (64<<20)+1)
		before := t5FFileSHA256(t, path)
		if _, err := registeredProjectPreimage(context.Background(), root); err == nil || err.Error() != "TRUST_SOURCE_ADAPTER_UNSUPPORTED" {
			t.Fatalf("over-aggregate preimage error = %v, want TRUST_SOURCE_ADAPTER_UNSUPPORTED", err)
		}
		if after := t5FFileSHA256(t, path); after != before {
			t.Fatalf("over-aggregate denial changed project file: got %s want %s", after, before)
		}
	})
}

func TestTrustProvisionThenInspectUsesActualStoreAuthority(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := t5FTrustFixture(t)
	runtimeRaw, err := readFixedTrustDocument(context.Background(), f.selection.RuntimeConfig.Path)
	if err != nil {
		t.Fatalf("read runtime config: %v", err)
	}
	install, err := trustload.DecodeRuntimeInstall(runtimeRaw)
	if err != nil {
		t.Fatalf("decode runtime config: %v", err)
	}
	if got, err := install.Digest(); err != nil || got != f.selection.RuntimeConfig.SHA256 {
		t.Fatalf("runtime config digest = %q, %v, want %q", got, err, f.selection.RuntimeConfig.SHA256)
	}
	operatorRaw, err := readFixedTrustDocument(context.Background(), install.OperatorRecord.Path)
	if err != nil || evidencecas.Digest(operatorRaw) != install.OperatorRecord.SHA256 {
		t.Fatalf("operator pin = %q, %v, want %q", evidencecas.Digest(operatorRaw), err, install.OperatorRecord.SHA256)
	}
	loaded, err := trustload.Load(context.Background(), f.selection)
	if err != nil {
		t.Fatalf("preflight Load: %v", err)
	}
	if _, err := trustverify.DecodeExecutionPolicy(loaded.PolicyJSON); err != nil {
		t.Fatalf("preflight policy: %v", err)
	}
	bundleRaw, err := readFixedTrustDocument(context.Background(), loaded.Install.OSS.InitialBundlePath)
	if err != nil {
		t.Fatalf("read initial bundle: %v", err)
	}
	bundle, err := trustload.DecodeStoredBundle(bundleRaw)
	if err != nil {
		t.Fatalf("decode initial bundle: %v", err)
	}
	if got, err := bundle.Digest(); err != nil || got != loaded.Install.OSS.InitialBundleSHA256 {
		t.Fatalf("initial bundle digest = %q, %v, want %q", got, err, loaded.Install.OSS.InitialBundleSHA256)
	}
	if _, err := fixedBundleEvidence(context.Background(), loaded.Install.EvidenceRoot, bundleRaw); err != nil {
		t.Fatalf("fixed initial evidence: %v", err)
	}
	// Diagnose the same bootstrap inputs before the store lifecycle wraps errors.
	if err := t5FVerifyInitial(context.Background(), loaded, bundleRaw, f.clock); err != nil {
		t.Fatalf("initial bootstrap verification: %v", err)
	}
	cmd := newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	cmd.SetArgs([]string{"trust", "provision"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("trust provision: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.store, "bootstrap.active")); err != nil {
		t.Fatalf("provision did not publish active store marker: %v", err)
	}
	cmd = newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	cmd.SetArgs([]string{"trust", "inspect"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("trust inspect after provision: %v", err)
	}
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	if err != nil {
		t.Fatalf("OpenRuntime: %v", err)
	}
	prepared, err := operationtrust.PrepareNew(context.Background(), runtime, operationtrust.PrepareNewInput{SourceInput: t5FSelection(f.source, f.sourceRefs), Render: renderref.Input{Values: renderref.Values(map[string]any{}), Repo: "t5f"}, RendererVersion: "v1"})
	if err != nil {
		t.Fatalf("prepare persisted source pair: %v", err)
	}
	if _, err := operationtrust.PrepareNew(context.Background(), runtime, operationtrust.PrepareNewInput{SourceInput: t5FSelection(f.target, f.targetRefs), Render: renderref.Input{Values: renderref.Values(map[string]any{}), Repo: "t5f"}, RendererVersion: "v1"}); err != nil {
		t.Fatalf("prepare target: %v", err)
	}
	projectRoot := runtime.ProjectContext().RootPath
	if err := os.Mkdir(filepath.Join(projectRoot, ".tplaiter"), 0o755); err != nil {
		t.Fatal(err)
	}
	rootRaw, err := json.Marshal(prepared.RootLock())
	if err != nil {
		t.Fatal(err)
	}
	depsRaw, err := json.Marshal(prepared.DependencyLock())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".tplaiter", "root-template.lock.json"), rootRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".tplaiter", "template.lock.json"), depsRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	sourceInputPath := filepath.Join(projectRoot, "source-selection.json")
	targetInputPath := filepath.Join(projectRoot, "target-selection.json")
	if err := os.WriteFile(sourceInputPath, t5FSelection(f.source, f.sourceRefs), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetInputPath, t5FSelection(f.target, f.targetRefs), 0o644); err != nil {
		t.Fatal(err)
	}
	registered, err := registeredSourceInput(context.Background(), runtime)
	if err != nil {
		t.Fatalf("registered source input: %v", err)
	}
	selection, err := operationtrust.DecodeSourceSelection(registered)
	if err != nil {
		t.Fatalf("decode registered source: %v", err)
	}
	if _, err := runtime.TrustRuntime().VerifySubject(context.Background(), selection.TrustSubject(), selection.EvidenceRefs()); err != nil {
		t.Logf("registered=%+v source=%+v refs=%+v", selection.Subject, f.source, selection.Evidence)
		t.Fatalf("verify registered source: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	cmd = newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	cmd.SetArgs([]string{"new", "--dry-run", "--source-input", sourceInputPath, f.source.Commit, "project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("new dry-run: %v", err)
	}
	cmd = newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	cmd.SetArgs([]string{"update", "--dry-run", "--source-input", targetInputPath, "--to", f.target.Commit})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("update dry-run: %v", err)
	}
	nextBundle, nextEvidence := t5FRefreshBundle(t, f)
	for digest, raw := range nextEvidence {
		t5FWriteCAS(t, f.evidenceRoot, digest, raw)
	}
	refreshInputPath := filepath.Join(projectRoot, "refresh-bundle.json")
	if err := os.WriteFile(refreshInputPath, nextBundle, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	cmd.SetArgs([]string{"trust", "refresh", "--bundle-input", refreshInputPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("trust refresh: %v", err)
	}
	cmd = newTrustRootCommand(invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	cmd.SetArgs([]string{"trust", "recover-state"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("trust recover-state: %v", err)
	}
}

type t5FFixture struct {
	selection              trustload.LaunchSelection
	clock                  bootstrap.Clock
	store                  string
	evidenceRoot           string
	bundleRaw              []byte
	projectRoot            string
	source, target         trustverify.Subject
	sourceRefs, targetRefs trustverify.EvidenceRefs
	publisher              ed25519.PrivateKey
	now                    time.Time
}

func t5FTrustFixture(t *testing.T) t5FFixture {
	return t5FTrustFixtureWith(t, t5FFixtureOptions{})
}

type t5FFixtureOptions struct {
	Anchor, Publisher ed25519.PrivateKey
	Now               time.Time
}

func t5FTrustFixtureWith(t *testing.T, options t5FFixtureOptions) t5FFixture {
	t.Helper()
	base := "/private/var/tmp"
	if _, err := os.Stat(base); err != nil {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "tplaiter-t5f-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for _, name := range []string{"scratch", "project", "evidence", "objects"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	now := options.Now
	if now.IsZero() {
		now = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	}
	clock := bootstrap.ClockFunc(func() time.Time { return now })
	anchor, publisher := options.Anchor, options.Publisher
	if anchor == nil {
		anchor = ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	}
	if publisher == nil {
		publisher = ed25519.NewKeyFromSeed([]byte("12345678901234567890123456789012"))
	}
	validity := bootstrap.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}
	if !options.Now.IsZero() {
		validity = bootstrap.Validity{NotBefore: now.Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: now.Add(24 * time.Hour).UTC().Format(time.RFC3339)}
	}
	evidence := map[string][]byte{}
	put := func(raw []byte) string {
		digest := evidencecas.Digest(raw)
		evidence[digest] = append([]byte(nil), raw...)
		return digest
	}
	publisherPublic := publisher.Public().(ed25519.PublicKey)
	rootKey := put([]byte(bootstrap.EncodePublicKey(publisherPublic)))
	envelope := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: "t5f-authority", Sequence: 1, Validity: validity, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(publisherPublic), PublicKeyCAS: rootKey, Issuer: "publisher-1", Status: "active"}}, Threshold: 1, Revocations: []bootstrap.Revocation{}}
	envelope.PayloadSHA256, err = envelope.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := hex.DecodeString(envelope.PayloadSHA256[7:])
	anchorPublic := anchor.Public().(ed25519.PublicKey)
	envelope.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchorPublic), SignatureCAS: put([]byte(bootstrap.EncodeSignature(ed25519.Sign(anchor, payload))))}}
	envelopeRef := put(t5FJSON(t, envelope))
	_, source := t5FWriteNativeSource(t, filepath.Join(dir, "objects"), "source", "hello source\n")
	_, target := t5FWriteNativeSource(t, filepath.Join(dir, "objects"), "target", "hello target\n")
	sourceRefs := t5FPublisherEvidence(t, evidence, publisher, source, "publisher-1")
	targetRefs := t5FPublisherEvidence(t, evidence, publisher, target, "publisher-1")
	leaf0, leaf1, leaf2 := bootstrap.HashLeaf([]byte(envelope.PayloadSHA256)), bootstrap.HashLeaf([]byte(sourceRefs.StatementCAS)), bootstrap.HashLeaf([]byte(targetRefs.StatementCAS))
	left := bootstrap.HashChildren(leaf0, leaf1)
	rootHash := bootstrap.HashChildren(left, leaf2)
	checkpointRef := put(t5FJSON(t, bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: envelope.AuthorityID, TreeSize: 3, RootHash: "sha256:" + hex.EncodeToString(rootHash[:])}))
	inclusionRef := put(t5FJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 3, Hashes: []string{"sha256:" + hex.EncodeToString(leaf1[:]), "sha256:" + hex.EncodeToString(leaf2[:])}}))
	sourceRefs.CheckpointCAS, sourceRefs.InclusionProofCAS = checkpointRef, put(t5FJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 1, TreeSize: 3, Hashes: []string{"sha256:" + hex.EncodeToString(leaf0[:]), "sha256:" + hex.EncodeToString(leaf2[:])}}))
	targetRefs.CheckpointCAS, targetRefs.InclusionProofCAS = checkpointRef, put(t5FJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 2, TreeSize: 3, Hashes: []string{"sha256:" + hex.EncodeToString(left[:])}}))
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: envelope.AuthorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: envelope.PayloadSHA256, TreeSize: 3, CheckpointDigest: checkpointRef}
	receipt.ReceiptDigest, err = receipt.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	receiptRef := put(t5FJSON(t, receipt))
	descriptor := bootstrap.DescriptorDocument{APIVersion: bootstrap.DescriptorAPIVersion, Profile: bootstrap.ProfileOSS, AuthorityID: envelope.AuthorityID, Anchors: []bootstrap.DescriptorAnchor{{Fingerprint: bootstrap.Fingerprint(anchorPublic), PublicKeyBase64: base64.StdEncoding.EncodeToString(anchorPublic)}}, Threshold: 1, AllowedPolicyOrigins: []string{"https://example.test/policy"}, PublisherScopes: []bootstrap.PublisherScope{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", SourceOrigin: "https://example.test/source", TemplatePath: ".", Predicate: "https://example.test/predicate", Usage: "template-source"}}}
	descriptor.DescriptorSHA256 = descriptor.ComputedSHA256()
	operator := trustload.OperatorPinRecord{APIVersion: trustload.OperatorPinRecordAPIVersion, Method: "operator-pinned", DescriptorSHA256: descriptor.DescriptorSHA256}
	operatorRaw := t5FJSON(t, operator)
	provisioning := bootstrap.ProvisioningRecord{APIVersion: bootstrap.ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: descriptor.DescriptorSHA256, AuthenticationEvidenceSHA256: evidencecas.Digest(operatorRaw), EvidenceClass: bootstrap.EvidenceSimulated}
	provisioning.ProvisioningSHA256 = provisioning.ComputedSHA256()
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: descriptor.DescriptorSHA256, ProvisioningSHA256: provisioning.ProvisioningSHA256, AuthorityID: envelope.AuthorityID, Sequence: 1, EnvelopePayloadSHA256: envelope.PayloadSHA256, ReceiptDigest: receipt.ReceiptDigest, TreeSize: 3, CheckpointDigest: checkpointRef}
	state.StateSHA256 = state.ComputedSHA256()
	policy := trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "t5f-policy", Profile: "oss", MinimumProfile: "oss", Validity: trustverify.Validity{NotBefore: validity.NotBefore, NotAfter: validity.NotAfter}, Principals: []trustverify.Principal{{ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []trustverify.IssuerPrincipal{{Issuer: "publisher-1", PrincipalID: "principal:publisher"}}, SourceRules: []trustverify.SourceRule{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: "https://example.test/source", TemplatePath: ".", Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"}}, Approvers: []trustverify.Approver{}, AllowInvocationHuman: false, MaxTimeoutMillis: 1000}
	policy.PolicySHA256, err = policy.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	descriptorRaw, provisioningRaw, policyRaw, stateRaw := t5FJSON(t, descriptor), t5FJSON(t, provisioning), t5FJSON(t, policy), t5FJSON(t, state)
	paths := map[string][]byte{"descriptor.json": descriptorRaw, "provisioning.json": provisioningRaw, "operator.json": operatorRaw, "policy.json": policyRaw, "state.json": stateRaw}
	for name, raw := range paths {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := trustload.StoredBundle{APIVersion: "tplaiter.dev/stored-bootstrap-bundle/v1", EnvelopeCAS: envelopeRef, ReceiptCAS: receiptRef, Transparency: trustload.StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: inclusionRef}}
	bundleRaw := t5FJSON(t, bundle)
	bundleDigest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	for digest, raw := range evidence {
		hexDigest := digest[len("sha256:"):]
		blobDir := filepath.Join(dir, "evidence", "sha256", hexDigest[:2])
		if err := os.MkdirAll(blobDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blobDir, hexDigest[2:]), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	install := trustload.RuntimeInstall{APIVersion: trustload.RuntimeInstallAPIVersion, InstallationID: "t5f-install", Profile: bootstrap.ProfileOSS, MinimumProfile: bootstrap.ProfileOSS, Descriptor: t5FPin(filepath.Join(dir, "descriptor.json"), descriptorRaw), Provisioning: t5FPin(filepath.Join(dir, "provisioning.json"), provisioningRaw), OperatorRecord: t5FPin(filepath.Join(dir, "operator.json"), operatorRaw), ExecutionPolicy: t5FPin(filepath.Join(dir, "policy.json"), policyRaw), ProjectContexts: []trustload.ProjectContext{{Key: "project", ProjectID: "project-t5f", SubmitterPrincipalID: "principal:submitter", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(dir, "project")}}, ObjectOrigins: []trustload.ObjectOrigin{{Origin: "https://example.test/source", RootPath: filepath.Join(dir, "objects")}}, EvidenceRoot: filepath.Join(dir, "evidence"), ScratchRoot: filepath.Join(dir, "scratch"), OSS: &trustload.OSSInstall{StorePath: filepath.Join(dir, "store"), InitialStatePath: filepath.Join(dir, "state.json"), InitialStateSHA256: state.StateSHA256, InitialBundlePath: filepath.Join(dir, "bundle.json"), InitialBundleSHA256: bundleDigest}}
	installRaw := t5FJSON(t, install)
	installPath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(installPath, installRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	installDigest, err := install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return t5FFixture{selection: trustload.LaunchSelection{Profile: bootstrap.ProfileOSS, RuntimeConfig: trustload.FilePin{Path: installPath, SHA256: installDigest}, OperatorRecord: install.OperatorRecord, InstallationID: install.InstallationID}, clock: clock, store: install.OSS.StorePath, evidenceRoot: install.EvidenceRoot, bundleRaw: bundleRaw, projectRoot: filepath.Join(dir, "project"), source: source, target: target, sourceRefs: sourceRefs, targetRefs: targetRefs, publisher: publisher, now: now}
}

func t5FJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func t5FPin(path string, raw []byte) trustload.FilePin {
	return trustload.FilePin{Path: path, SHA256: evidencecas.Digest(raw)}
}

func t5FWriteNativeSource(t *testing.T, root, suffix, output string) ([]byte, trustverify.Subject) {
	t.Helper()
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: t5f-" + suffix + "\n  version: 1.0.0\n  description: fixture\nengine:\n  type: gotemplate\n  root: files\nsettings:\n  - group: label\n    title: Label\n    type: string\n    default: ok\n")
	h := sha256.Sum256(manifest)
	contract := []byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"sha256:` + hex.EncodeToString(h[:]) + `","dependencies":[]}`)
	objects := map[string][]byte{}
	add := func(kind string, data []byte) string {
		raw := append([]byte(kind+" "+t5FItoa(len(data))+"\x00"), data...)
		sum := sha1.Sum(raw)
		id := hex.EncodeToString(sum[:])
		objects[id] = raw
		return id
	}
	file := add("blob", []byte(output))
	files := t5FTree(add, []t5FTreeEntry{{mode: "100644", name: "hello.txt.tmpl", oid: file}})
	manifestID, contractID := add("blob", manifest), add("blob", contract)
	rootID := t5FTree(add, []t5FTreeEntry{{mode: "40000", name: "files", oid: files}, {mode: "100644", name: "template.contract.json", oid: contractID}, {mode: "100644", name: "template.manifest.yaml", oid: manifestID}})
	commit := add("commit", []byte("tree "+rootID+"\n\nauthor t5f <t5f@example.test> 0 +0000\n"))
	for id, raw := range objects {
		if err := os.WriteFile(filepath.Join(root, id), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries := []trustverify.SourceEntry{{Path: "files", Kind: "directory", Mode: "40000"}, {Path: "files/hello.txt.tmpl", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte(output))}, {Path: "template.contract.json", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(contract)}, {Path: "template.manifest.yaml", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(manifest)}}
	treeDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-content-tree/v1", struct {
		APIVersion string                    `json:"apiVersion"`
		Entries    []trustverify.SourceEntry `json:"entries"`
	}{"tplaiter.dev/source-content-tree/v1", entries})
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", evidencecas.Digest(contract)})
	if err != nil {
		t.Fatal(err)
	}
	return contract, trustverify.Subject{Origin: "https://example.test/source", TemplatePath: ".", RequestedRef: commit, Commit: commit, TreeSHA256: treeDigest, ContractSHA256: contractDigest}
}

type t5FTreeEntry struct{ mode, name, oid string }

func t5FTree(add func(string, []byte) string, entries []t5FTreeEntry) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var raw []byte
	for _, e := range entries {
		b, _ := hex.DecodeString(e.oid)
		raw = append(raw, []byte(e.mode+" "+e.name+"\x00")...)
		raw = append(raw, b...)
	}
	return add("tree", raw)
}

func t5FItoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func t5FPublisherEvidence(t *testing.T, store map[string][]byte, key ed25519.PrivateKey, subject trustverify.Subject, issuer string) trustverify.EvidenceRefs {
	t.Helper()
	put := func(b []byte) string { d := evidencecas.Digest(b); store[d] = append([]byte(nil), b...); return d }
	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://example.test/policy", Issuer: issuer, Predicate: "https://example.test/predicate", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: subject.Origin, TemplatePath: subject.TemplatePath, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}}
	raw := t5FJSON(t, statement)
	statementCAS := put(raw)
	digest, err := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := hex.DecodeString(digest[7:])
	signature := put([]byte(bootstrap.EncodeSignature(ed25519.Sign(key, hash))))
	return trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: statementCAS, SignatureCAS: signature, KeyFingerprint: bootstrap.Fingerprint(key.Public().(ed25519.PublicKey))}
}

func t5FSelection(s trustverify.Subject, e trustverify.EvidenceRefs) []byte {
	return []byte(`{"apiVersion":"tplaiter.dev/source-selection-input/v1","subject":{"origin":"` + s.Origin + `","templatePath":"` + s.TemplatePath + `","requestedRef":"` + s.RequestedRef + `","commit":"` + s.Commit + `","treeSHA256":"` + s.TreeSHA256 + `","contractSHA256":"` + s.ContractSHA256 + `"},"evidence":{"format":"` + e.Format + `","statementCAS":"` + e.StatementCAS + `","signatureCAS":"` + e.SignatureCAS + `","keyFingerprint":"` + e.KeyFingerprint + `","checkpointCAS":"` + e.CheckpointCAS + `","inclusionProofCAS":"` + e.InclusionProofCAS + `"},"dependencies":[]}`)
}

// t5FRefreshBundle constructs a successor using the same persisted evidence
// tree as the command. It deliberately has a distinct authority sequence and
// target tree, so refresh reaches the real rotation and store-update path.
func t5FRefreshBundle(t *testing.T, f t5FFixture) ([]byte, map[string][]byte) {
	return t5FRefreshBundleWithValidity(t, f, nil)
}

func t5FRefreshBundleWithValidity(t *testing.T, f t5FFixture, validity *bootstrap.Validity) ([]byte, map[string][]byte) {
	t.Helper()
	current, err := trustload.DecodeStoredBundle(f.bundleRaw)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := evidencecas.NewFSReader(f.evidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	oldEnvelopeRaw, err := reader.Read(context.Background(), current.EnvelopeCAS)
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope, err := bootstrap.DecodeEnvelope(oldEnvelopeRaw)
	if err != nil {
		t.Fatal(err)
	}
	oldReceiptRaw, err := reader.Read(context.Background(), current.ReceiptCAS)
	if err != nil {
		t.Fatal(err)
	}
	oldReceipt, err := bootstrap.DecodeReceipt(oldReceiptRaw)
	if err != nil {
		t.Fatal(err)
	}
	added := map[string][]byte{}
	put := func(raw []byte) string {
		digest := evidencecas.Digest(raw)
		added[digest] = append([]byte(nil), raw...)
		return digest
	}
	newKey := ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123"))
	if !f.now.Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) {
		_, newKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	newPublic := newKey.Public().(ed25519.PublicKey)
	newKeyRef := put([]byte(bootstrap.EncodePublicKey(newPublic)))
	overlap := "2026-12-01T00:00:00Z"
	if !f.now.Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) {
		overlap = f.now.Add(time.Hour).UTC().Format(time.RFC3339)
	}
	nextValidity := oldEnvelope.Validity
	if validity != nil {
		nextValidity = *validity
	}
	next := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: oldEnvelope.AuthorityID, Sequence: oldEnvelope.Sequence + 1, Validity: nextValidity, AllowedPolicyOrigins: oldEnvelope.AllowedPolicyOrigins, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(newPublic), PublicKeyCAS: newKeyRef, Issuer: "publisher-1", Status: "active"}}, Threshold: 1, RevocationEpoch: oldEnvelope.RevocationEpoch + 1, Revocations: []bootstrap.Revocation{}, Rotation: &bootstrap.Rotation{PreviousSequence: oldEnvelope.Sequence, OverlapUntil: overlap}}
	next.PayloadSHA256, err = next.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := hex.DecodeString(next.PayloadSHA256[len("sha256:"):])
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []ed25519.PrivateKey{f.publisher, newKey} {
		signature := put([]byte(bootstrap.EncodeSignature(ed25519.Sign(key, payload))))
		next.Signatures = append(next.Signatures, bootstrap.Signature{KeyFingerprint: bootstrap.Fingerprint(key.Public().(ed25519.PublicKey)), SignatureCAS: signature})
	}
	sort.Slice(next.Signatures, func(i, j int) bool { return next.Signatures[i].KeyFingerprint < next.Signatures[j].KeyFingerprint })
	leaf0 := bootstrap.HashLeaf([]byte(oldEnvelope.PayloadSHA256))
	leaf1 := bootstrap.HashLeaf([]byte(f.sourceRefs.StatementCAS))
	leaf2 := bootstrap.HashLeaf([]byte(f.targetRefs.StatementCAS))
	leaf3 := bootstrap.HashLeaf([]byte(next.PayloadSHA256))
	left := bootstrap.HashChildren(leaf0, leaf1)
	root := bootstrap.HashChildren(left, bootstrap.HashChildren(leaf2, leaf3))
	checkpointRef := put(t5FJSON(t, bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: next.AuthorityID, TreeSize: 4, RootHash: "sha256:" + hex.EncodeToString(root[:])}))
	inclusionRef := put(t5FJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 3, TreeSize: 4, Hashes: []string{"sha256:" + hex.EncodeToString(leaf2[:]), "sha256:" + hex.EncodeToString(left[:])}}))
	consistencyRef := put(t5FJSON(t, bootstrap.ConsistencyProof{APIVersion: bootstrap.ConsistencyAPIVersion, OldTreeSize: 3, NewTreeSize: 4, Hashes: []string{"sha256:" + hex.EncodeToString(leaf2[:]), "sha256:" + hex.EncodeToString(leaf3[:]), "sha256:" + hex.EncodeToString(left[:])}}))
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: next.AuthorityID, HighestAcceptedSequence: next.Sequence, EnvelopePayloadSHA256: next.PayloadSHA256, RevocationEpoch: next.RevocationEpoch, TreeSize: 4, CheckpointDigest: checkpointRef, PreviousReceiptDigest: oldReceipt.ReceiptDigest}
	receipt.ReceiptDigest, err = receipt.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	envelopeRef := put(t5FJSON(t, next))
	receiptRef := put(t5FJSON(t, receipt))
	bundle := trustload.StoredBundle{APIVersion: "tplaiter.dev/stored-bootstrap-bundle/v1", EnvelopeCAS: envelopeRef, ReceiptCAS: receiptRef, Transparency: trustload.StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: inclusionRef, ConsistencyProofCAS: consistencyRef}}
	return t5FJSON(t, bundle), added
}

func t5FWriteCAS(t *testing.T, root, digest string, raw []byte) {
	t.Helper()
	if evidencecas.Digest(raw) != digest || !strings.HasPrefix(digest, "sha256:") {
		t.Fatal("invalid fixture CAS blob")
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	dir := filepath.Join(root, "sha256", hexDigest[:2])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hexDigest[2:]), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func t5FDirectoryDigest(t *testing.T, root string) string {
	t.Helper()
	var entries []string
	contents := map[string][]byte{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		entries = append(entries, rel)
		if entry.Type().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			contents[rel] = raw
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(entries)
	h := sha256.New()
	for _, entry := range entries {
		_, _ = h.Write([]byte(entry))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(contents[entry])
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func t5FExpectedPreimage(rel string, data []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(rel))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(data)
	_, _ = h.Write([]byte{0})
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func t5FWriteActualData(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	block := bytes.Repeat([]byte("z"), 1<<20)
	for size > 0 {
		part := block
		if size < int64(len(part)) {
			part = part[:size]
		}
		n, err := f.Write(part)
		if err != nil || n != len(part) {
			t.Fatalf("write actual fixture data: %d, %v", n, err)
		}
		size -= int64(n)
	}
}

func t5FDescriptorTempDir(t *testing.T) string {
	t.Helper()
	base := "/private/var/tmp"
	if _, err := os.Stat(base); err != nil {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "tplaiter-t5f-preimage-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func t5FFileSHA256(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type t5FExternal struct{ snapshot bootstrap.ProvisionedSnapshot }

func (e t5FExternal) Load(context.Context) (bootstrap.ProvisionedSnapshot, error) {
	return e.snapshot, nil
}

func t5FVerifyInitial(ctx context.Context, loaded *trustload.Loaded, raw []byte, clock bootstrap.Clock) error {
	stateRaw, err := readFixedTrustDocument(ctx, loaded.Install.OSS.InitialStatePath)
	if err != nil {
		return err
	}
	ext, err := bootstrap.LoadExternal(ctx, t5FExternal{snapshot: bootstrap.ProvisionedSnapshot{DescriptorJSON: loaded.DescriptorJSON, ProvisioningJSON: loaded.ProvisioningJSON, OSSStateJSON: stateRaw, ExpectedDescriptorSHA256: loaded.Operator.DescriptorSHA256, ExpectedProvisioningSHA256: provisioningDigest(loaded.ProvisioningJSON), ExpectedOSSStateSHA256: loaded.Install.OSS.InitialStateSHA256, InitialOSSStateSHA256: loaded.Install.OSS.InitialStateSHA256}})
	if err != nil {
		return err
	}
	b, err := trustload.DecodeStoredBundle(raw)
	if err != nil {
		return err
	}
	reader, err := evidencecas.NewFSReader(loaded.Install.EvidenceRoot)
	if err != nil {
		return err
	}
	defer reader.Close()
	envelope, err := reader.Read(ctx, b.EnvelopeCAS)
	if err != nil {
		return err
	}
	receipt, err := reader.Read(ctx, b.ReceiptCAS)
	if err != nil {
		return err
	}
	v, err := bootstrap.NewVerifier(reader, clock, nil, 0)
	if err != nil {
		return err
	}
	_, err = v.VerifyOSS(ctx, ext, bootstrap.Bundle{Envelope: envelope, Receipt: receipt, Transparency: bootstrap.TransparencyEvidence{CheckpointCAS: b.Transparency.CheckpointCAS, InclusionProofCAS: b.Transparency.InclusionProofCAS, ConsistencyProofCAS: b.Transparency.ConsistencyProofCAS}})
	return err
}

func provisioningDigest(raw []byte) string {
	v, err := bootstrap.DecodeProvisioningRecord(raw)
	if err != nil {
		return ""
	}
	return v.ProvisioningSHA256
}
