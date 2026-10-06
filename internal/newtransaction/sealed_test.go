package newtransaction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/managed"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestSealedOutputsCannotAdoptMutableStage(t *testing.T) {
	for _, drift := range []string{"bytes", "mode", "extra"} {
		t.Run(drift, func(t *testing.T) {
			home, target := t.TempDir(), t.TempDir()
			files := map[string][]byte{"hello.txt": []byte("approved")}
			tx, err := BeginSealedWithFault(home, target, files, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Release()
			// Altering the caller's buffers after Begin cannot change authority.
			files["hello.txt"][0] = 'X'
			name := filepath.Join(tx.Workspace(), "hello.txt")
			if err := os.WriteFile(name, []byte("approved"), 0o644); err != nil {
				t.Fatal(err)
			}
			switch drift {
			case "bytes":
				err = os.WriteFile(name, []byte("unapproved"), 0o644)
			case "mode":
				err = os.Chmod(name, 0o755)
			case "extra":
				err = os.WriteFile(filepath.Join(tx.Workspace(), "foreign"), []byte("keep"), 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := tx.Journal().TargetAfterSHA
			if err := tx.SealOutputs(); !errors.Is(err, ErrOwnershipUncertain) {
				t.Fatalf("adopted observed tree: %v", err)
			}
			if err := tx.Abort(); !errors.Is(err, ErrOwnershipUncertain) {
				t.Fatalf("abort deleted unowned stage: %v", err)
			}
			loaded, err := Load(home, tx.ID())
			if err != nil || loaded.Journal().TargetAfterSHA != before || loaded.sealedReady {
				t.Fatalf("seal changed on refusal: %v", err)
			}
			if _, err := os.Stat(name); err != nil {
				t.Fatal("ambiguous content removed")
			}
		})
	}
}

func TestSealedAbortRestoresOnlyProvenOwnedTree(t *testing.T) {
	home, target := t.TempDir(), t.TempDir()
	tx, err := BeginSealedWithFault(home, target, map[string][]byte{"hello.txt": []byte("approved")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := os.WriteFile(filepath.Join(tx.Workspace(), "hello.txt"), []byte("approved"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.SealOutputs(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Abort(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("owned abort did not restore empty target: %v %v", entries, err)
	}
}

func TestSealedCommittedRecoveryRetainsChangedTree(t *testing.T) {
	home, target := t.TempDir(), t.TempDir()
	tx, err := BeginSealedWithFault(home, target, map[string][]byte{"hello.txt": []byte("approved")}, func(point string) error {
		if point == "commit.before_marker_remove" {
			return ErrInjectedCrash
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := os.WriteFile(filepath.Join(tx.Workspace(), "hello.txt"), []byte("approved"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.SealOutputs(); err != nil {
		t.Fatal(err)
	}
	plan := RegistryPlan{Home: home, After: []byte("version: 1\nitems: []\n")}
	if err := tx.PrepareRegistry(plan); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(plan); !errors.Is(err, ErrInjectedCrash) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "hello.txt"), []byte("foreign edit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Continue(home, tx.ID(), home); !errors.Is(err, ErrOwnershipUncertain) {
		t.Fatalf("recovery finalized changed afterimage: %v", err)
	}
	if err := tx.Finalize(); !errors.Is(err, ErrOwnershipUncertain) {
		t.Fatalf("finalize removed evidence of drift: %v", err)
	}
	raw, err := os.ReadFile(state.ProjectsPath(home))
	if err != nil || !bytes.Equal(raw, plan.After) {
		t.Fatal("committed registry changed")
	}
	if _, err := Load(home, tx.ID()); err != nil {
		t.Fatal("lost committed recovery journal")
	}
}

// Concrete signed two-version fixture copied from the accepted newcmd trust
// harness. No fake runtime, trusted Boolean or unsigned checkout is used.
type managedNewIntegrationFixture struct {
	dir, scratch, project, evidence string
	selection                       trustload.LaunchSelection
	policy                          trustverify.ExecutionPolicy
	approver                        ed25519.PrivateKey
	anchor, publisher               ed25519.PrivateKey
	source, target                  trustverify.Subject
	sourceRefs, targetRefs          trustverify.EvidenceRefs
}
type managedNewClock struct{}

func (managedNewClock) Now() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }

func managedNewNewIntegrationFixture(t *testing.T, extras ...string) *managedNewIntegrationFixture {
	t.Helper()
	return managedNewNewIntegrationFixtureWithSource(t, managedNewWriteNativeSource, extras...)
}

func managedNewNewIntegrationFixtureWithSource(t *testing.T, writeSource func(*testing.T, string, string, string, string) ([]byte, trustverify.Subject), extras ...string) *managedNewIntegrationFixture {
	t.Helper()
	sourceExtra, targetExtra := "", ""
	if len(extras) > 0 {
		sourceExtra = extras[0]
	}
	if len(extras) > 1 {
		targetExtra = extras[1]
	}
	base := "/private/var/tmp"
	if _, err := os.Stat(base); err != nil {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "tplaiter-t5d-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &managedNewIntegrationFixture{dir: dir, scratch: filepath.Join(dir, "scratch"), project: filepath.Join(dir, "project"), evidence: filepath.Join(dir, "evidence"), anchor: ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901")), publisher: ed25519.NewKeyFromSeed([]byte("12345678901234567890123456789012")), approver: ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123"))}
	for _, p := range []string{f.scratch, f.project, f.evidence, filepath.Join(dir, "objects")} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sourceContract, source := writeSource(t, filepath.Join(dir, "objects"), "source", "hello source\nstable\n", sourceExtra)
	_, target := writeSource(t, filepath.Join(dir, "objects"), "target", "hello target\nstable\n", targetExtra)
	f.source, f.target = source, target
	evidence := map[string][]byte{}
	put := func(b []byte) string { d := evidencecas.Digest(b); evidence[d] = append([]byte(nil), b...); return d }
	anchorPub, publisherPub := f.anchor.Public().(ed25519.PublicKey), f.publisher.Public().(ed25519.PublicKey)
	rootRef := put([]byte(bootstrap.EncodePublicKey(publisherPub)))
	env := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: "t5d-authority", Sequence: 1, Validity: bootstrap.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(publisherPub), PublicKeyCAS: rootRef, Issuer: "publisher-1", Status: "active"}}, Threshold: 1, RevocationEpoch: 0, Revocations: []bootstrap.Revocation{}}
	env.PayloadSHA256, err = env.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := hex.DecodeString(env.PayloadSHA256[7:])
	env.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchorPub), SignatureCAS: put([]byte(bootstrap.EncodeSignature(ed25519.Sign(f.anchor, payload))))}}
	envRaw, _ := json.Marshal(env)
	envRef := put(envRaw)
	f.sourceRefs = managedNewPublisherEvidence(t, evidence, f.publisher, source, "publisher-1")
	f.targetRefs = managedNewPublisherEvidence(t, evidence, f.publisher, target, "publisher-1")
	leaf0, leaf1, leaf2 := bootstrap.HashLeaf([]byte(env.PayloadSHA256)), bootstrap.HashLeaf([]byte(f.sourceRefs.StatementCAS)), bootstrap.HashLeaf([]byte(f.targetRefs.StatementCAS))
	left := bootstrap.HashChildren(leaf0, leaf1)
	rootHash := bootstrap.HashChildren(left, leaf2)
	checkpointRef := put(managedNewJSON(t, bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: env.AuthorityID, TreeSize: 3, RootHash: "sha256:" + hex.EncodeToString(rootHash[:])}))
	inclusionRef := put(managedNewJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 3, Hashes: []string{"sha256:" + hex.EncodeToString(leaf1[:]), "sha256:" + hex.EncodeToString(leaf2[:])}}))
	f.sourceRefs.CheckpointCAS, f.sourceRefs.InclusionProofCAS = checkpointRef, put(managedNewJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 1, TreeSize: 3, Hashes: []string{"sha256:" + hex.EncodeToString(leaf0[:]), "sha256:" + hex.EncodeToString(leaf2[:])}}))
	f.targetRefs.CheckpointCAS, f.targetRefs.InclusionProofCAS = checkpointRef, put(managedNewJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 2, TreeSize: 3, Hashes: []string{"sha256:" + hex.EncodeToString(left[:])}}))
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: env.AuthorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, TreeSize: 3, CheckpointDigest: checkpointRef}
	receipt.ReceiptDigest, err = receipt.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	receiptRef := put(managedNewJSON(t, receipt))
	desc := bootstrap.DescriptorDocument{APIVersion: bootstrap.DescriptorAPIVersion, Profile: bootstrap.ProfileOSS, AuthorityID: env.AuthorityID, Anchors: []bootstrap.DescriptorAnchor{{Fingerprint: bootstrap.Fingerprint(anchorPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(anchorPub)}}, Threshold: 1, AllowedPolicyOrigins: []string{"https://example.test/policy"}, PublisherScopes: []bootstrap.PublisherScope{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", SourceOrigin: source.Origin, TemplatePath: ".", Predicate: "https://example.test/predicate", Usage: "template-source"}}}
	desc.DescriptorSHA256 = desc.ComputedSHA256()
	opRecord := trustload.OperatorPinRecord{APIVersion: trustload.OperatorPinRecordAPIVersion, Method: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256}
	opRaw := managedNewJSON(t, opRecord)
	prov := bootstrap.ProvisioningRecord{APIVersion: bootstrap.ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256, AuthenticationEvidenceSHA256: evidencecas.Digest(opRaw), EvidenceClass: bootstrap.EvidenceSimulated}
	prov.ProvisioningSHA256 = prov.ComputedSHA256()
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: desc.DescriptorSHA256, ProvisioningSHA256: prov.ProvisioningSHA256, AuthorityID: env.AuthorityID, Sequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, ReceiptDigest: receipt.ReceiptDigest, TreeSize: 3, CheckpointDigest: checkpointRef}
	state.StateSHA256 = state.ComputedSHA256()
	approverPub := f.approver.Public().(ed25519.PublicKey)
	f.policy = trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "t5d-policy", Profile: "oss", MinimumProfile: "oss", Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Principals: []trustverify.Principal{{ID: "principal:approver"}, {ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []trustverify.IssuerPrincipal{{Issuer: "publisher-1", PrincipalID: "principal:publisher"}}, SourceRules: []trustverify.SourceRule{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: source.Origin, TemplatePath: ".", Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"}}, Approvers: []trustverify.Approver{{ID: "t5d-approver", PrincipalID: "principal:approver", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(approverPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(approverPub), Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Scopes: []trustverify.ApprovalScope{{ProjectID: "project-t5d", OperationScope: "new", ActionKind: "formatter", Origin: source.Origin, TemplatePath: "."}}}}, AllowInvocationHuman: false, MaxTimeoutMillis: 5000}
	f.policy.PolicySHA256, err = f.policy.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	descRaw, provRaw, policyRaw := managedNewJSON(t, desc), managedNewJSON(t, prov), managedNewJSON(t, f.policy)
	paths := map[string][]byte{filepath.Join(dir, "descriptor.json"): descRaw, filepath.Join(dir, "provisioning.json"): provRaw, filepath.Join(dir, "operator.json"): opRaw, filepath.Join(dir, "policy.json"): policyRaw, filepath.Join(dir, "state.json"): managedNewJSON(t, state)}
	for p, b := range paths {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := trustload.StoredBundle{APIVersion: "tplaiter.dev/stored-bootstrap-bundle/v1", EnvelopeCAS: envRef, ReceiptCAS: receiptRef, Transparency: trustload.StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: inclusionRef}}
	bundleRaw := managedNewJSON(t, bundle)
	bundleDigest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	install := trustload.RuntimeInstall{APIVersion: trustload.RuntimeInstallAPIVersion, InstallationID: "t5d-install", Profile: bootstrap.ProfileOSS, MinimumProfile: bootstrap.ProfileOSS, Descriptor: managedNewPin(filepath.Join(dir, "descriptor.json"), descRaw), Provisioning: managedNewPin(filepath.Join(dir, "provisioning.json"), provRaw), OperatorRecord: managedNewPin(filepath.Join(dir, "operator.json"), opRaw), ExecutionPolicy: managedNewPin(filepath.Join(dir, "policy.json"), policyRaw), ProjectContexts: []trustload.ProjectContext{{Key: "project", ProjectID: "project-t5d", SubmitterPrincipalID: "principal:submitter", MinimumProfile: bootstrap.ProfileOSS, RootPath: f.project}}, ObjectOrigins: []trustload.ObjectOrigin{{Origin: source.Origin, RootPath: filepath.Join(dir, "objects")}}, EvidenceRoot: f.evidence, ScratchRoot: f.scratch, OSS: &trustload.OSSInstall{StorePath: filepath.Join(dir, "store"), InitialStatePath: filepath.Join(dir, "state.json"), InitialStateSHA256: state.StateSHA256, InitialBundlePath: filepath.Join(dir, "bundle.json"), InitialBundleSHA256: bundleDigest}}
	installRaw := managedNewJSON(t, install)
	installPath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(installPath, installRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f.selection = trustload.LaunchSelection{Profile: bootstrap.ProfileOSS, RuntimeConfig: trustload.FilePin{Path: installPath, SHA256: digest}, OperatorRecord: install.OperatorRecord, InstallationID: install.InstallationID}
	factory := func(r evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(r, managedNewClock{}, nil, 0)
	}
	if err := trustload.Enroll(context.Background(), f.selection, factory, managedNewJSON(t, state), bundleRaw, evidence); err != nil {
		t.Fatalf("Enroll concrete store: %v", err)
	}
	_ = sourceContract
	return f
}

func managedNewWriteNativeSource(t *testing.T, root, suffix, output, extra string) ([]byte, trustverify.Subject) {
	t.Helper()
	return managedNewWriteNativeSourceFiles(t, root, suffix, output, extra, nil)
}

// Extra output files are included in the exact signed target Git tree.
func managedNewWriteNativeSourceFiles(t *testing.T, root, suffix, output, extra string, extras map[string][]byte) ([]byte, trustverify.Subject) {
	t.Helper()
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: t5d-" + suffix + "\n  version: 1.0.0\n  description: fixture\nengine:\n  type: gotemplate\n  root: files\nsettings:\n  - group: label\n    title: Label\n    type: string\n    default: ok\n" + "generators:\n  - kind: entity\n    snippet: generators/entity.tmpl\n    target: entity.go\n" + extra)
	h := sha256.Sum256(manifest)
	contract := []byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"sha256:` + hex.EncodeToString(h[:]) + `","dependencies":[]}`)
	objects := map[string][]byte{}
	add := func(kind string, data []byte) string {
		raw := append([]byte(kind+" "+strconv.Itoa(len(data))+"\x00"), data...)
		sum := sha1.Sum(raw)
		id := hex.EncodeToString(sum[:])
		objects[id] = raw
		return id
	}
	blob := func(b []byte) string { return add("blob", b) }
	outputs := map[string][]byte{"main.go.tmpl": []byte("package fixture\n// tplater:managed-begin id=body provider=root\nfunc f(){ }\n// tplater:managed-end id=body\n")}
	tool := testfixture.NewGofmtFixture(t).Tool()
	info, err := buildinfo.Read(bytes.NewReader(tool))
	if err != nil {
		t.Fatal(err)
	}
	record, err := canonicaljson.Canonical(map[string]any{"apiVersion": "tplaiter.dev/formatter-tool/v1", "adapter": "gofmt-stdin-v1", "toolID": "gofmt", "toolVersion": strings.TrimPrefix(info.GoVersion, "go"), "binarySHA256": evidencecas.Digest(tool), "versionEvidence": map[string]any{"kind": "go-buildinfo", "identity": info.GoVersion}, "nativeEnvelope": operationtrust.FormatterNativeEnvelope()})
	if err != nil {
		t.Fatal(err)
	}
	formatter := managedNewTree(add, []managedNewTreeEntry{{mode: "100755", name: "native-tool", oid: blob(tool)}, {mode: "100644", name: "tool.json", oid: blob(record)}})
	if suffix == "target" {
		for p, raw := range extras {
			if p == "!delete:hello.txt.tmpl" {
				delete(outputs, "hello.txt.tmpl")
				continue
			}
			outputs[p] = raw
		}
	}
	files, outputEntries := managedNewFileTree(add, outputs, "files/")
	snippet := []byte("snippet-" + suffix + "\nstable\n")
	generators := managedNewTree(add, []managedNewTreeEntry{{mode: "100644", name: "entity.tmpl", oid: blob(snippet)}})
	manifestID, contractID := blob(manifest), blob(contract)
	rootID := managedNewTree(add, []managedNewTreeEntry{{mode: "40000", name: "formatter", oid: formatter}, {mode: "40000", name: "files", oid: files}, {mode: "40000", name: "generators", oid: generators}, {mode: "100644", name: "template.contract.json", oid: contractID}, {mode: "100644", name: "template.manifest.yaml", oid: manifestID}})
	commit := add("commit", []byte("tree "+rootID+"\n\nauthor t5d <t5d@example.test> 0 +0000\n"))
	for id, raw := range objects {
		if err := os.WriteFile(filepath.Join(root, id), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries := []trustverify.SourceEntry{{Path: "formatter", Kind: "directory", Mode: "40000"}, {Path: "formatter/native-tool", Kind: "file", Mode: "100755", ContentSHA256: evidencecas.Digest(tool)}, {Path: "formatter/tool.json", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(record)}, {Path: "files", Kind: "directory", Mode: "40000"}, {Path: "generators", Kind: "directory", Mode: "40000"}, {Path: "generators/entity.tmpl", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(snippet)}, {Path: "template.contract.json", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(contract)}, {Path: "template.manifest.yaml", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(manifest)}}
	entries = append(entries, outputEntries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
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

type managedNewTreeEntry struct{ mode, name, oid string }

func managedNewTree(add func(string, []byte) string, entries []managedNewTreeEntry) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var raw []byte
	for _, e := range entries {
		b, _ := hex.DecodeString(e.oid)
		raw = append(raw, []byte(e.mode+" "+e.name+"\x00")...)
		raw = append(raw, b...)
	}
	return add("tree", raw)
}

func managedNewJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func managedNewPin(path string, raw []byte) trustload.FilePin {
	return trustload.FilePin{Path: path, SHA256: evidencecas.Digest(raw)}
}

func managedNewPublisherEvidence(t *testing.T, store map[string][]byte, key ed25519.PrivateKey, subject trustverify.Subject, issuer string) trustverify.EvidenceRefs {
	t.Helper()
	put := func(b []byte) string { d := evidencecas.Digest(b); store[d] = append([]byte(nil), b...); return d }
	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://example.test/policy", Issuer: issuer, Predicate: "https://example.test/predicate", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: subject.Origin, TemplatePath: subject.TemplatePath, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}}
	raw := managedNewJSON(t, statement)
	statementCAS := put(raw)
	digest, err := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := hex.DecodeString(digest[7:])
	signature := put([]byte(bootstrap.EncodeSignature(ed25519.Sign(key, hash))))
	return trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: statementCAS, SignatureCAS: signature, KeyFingerprint: bootstrap.Fingerprint(key.Public().(ed25519.PublicKey))}
}

func managedNewSelection(s trustverify.Subject, e trustverify.EvidenceRefs) []byte {
	return []byte(`{"apiVersion":"tplaiter.dev/source-selection-input/v1","subject":{"origin":"` + s.Origin + `","templatePath":"` + s.TemplatePath + `","requestedRef":"` + s.RequestedRef + `","commit":"` + s.Commit + `","treeSHA256":"` + s.TreeSHA256 + `","contractSHA256":"` + s.ContractSHA256 + `"},"evidence":{"format":"` + e.Format + `","statementCAS":"` + e.StatementCAS + `","signatureCAS":"` + e.SignatureCAS + `","keyFingerprint":"` + e.KeyFingerprint + `","checkpointCAS":"` + e.CheckpointCAS + `","inclusionProofCAS":"` + e.InclusionProofCAS + `"},"dependencies":[]}`)
}

func managedNewFileTree(add func(string, []byte) string, files map[string][]byte, prefix string) (string, []trustverify.SourceEntry) {
	children := map[string]map[string][]byte{}
	direct := map[string][]byte{}
	for p, raw := range files {
		name, rest, nested := strings.Cut(p, "/")
		if nested {
			if children[name] == nil {
				children[name] = map[string][]byte{}
			}
			children[name][rest] = raw
		} else {
			direct[name] = raw
		}
	}
	entries := []trustverify.SourceEntry{}
	tree := []managedNewTreeEntry{}
	for name, raw := range direct {
		tree = append(tree, managedNewTreeEntry{mode: "100644", name: name, oid: add("blob", raw)})
		entries = append(entries, trustverify.SourceEntry{Path: prefix + name, Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(raw)})
	}
	for name, files := range children {
		id, nested := managedNewFileTree(add, files, prefix+name+"/")
		tree = append(tree, managedNewTreeEntry{mode: "40000", name: name, oid: id})
		entries = append(entries, trustverify.SourceEntry{Path: prefix + name, Kind: "directory", Mode: "40000"})
		entries = append(entries, nested...)
	}
	return managedNewTree(add, tree), entries
}

func managedNewApprove(t *testing.T, f *managedNewIntegrationFixture, request trustverify.ExecutionRequest) trustverify.ApprovalRefs {
	t.Helper()
	approval := trustverify.ExecutionApproval{APIVersion: trustverify.ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: request.RequestSHA256, ProfileBindingSHA256: request.ProfileBindingSHA256, OperationInputsSHA256: request.OperationInputsSHA256, ProjectID: request.ProjectID, Scope: request.Scope, ApproverID: f.policy.Approvers[0].ID, IdentityClass: f.policy.Approvers[0].IdentityClass, ExecutionPolicySHA256: f.policy.PolicySHA256, Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, KeyFingerprint: f.policy.Approvers[0].KeyFingerprint}
	var err error
	approval.GrantSHA256, err = approval.ComputeGrantSHA256()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := hex.DecodeString(approval.GrantSHA256[7:])
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte(bootstrap.EncodeSignature(ed25519.Sign(f.approver, grant)))
	approval.SignatureCAS = evidencecas.Digest(signature)
	raw := managedNewJSON(t, approval)
	ref := evidencecas.Digest(raw)
	for name, data := range map[string][]byte{approval.SignatureCAS: signature, ref: raw} {
		file := filepath.Join(f.evidence, "sha256", name[7:9], name[9:])
		if err = os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: ref}
}

func TestManagedNewPublicationColdSameID(t *testing.T) {
	ctx := context.Background()
	f := managedNewNewIntegrationFixture(t)
	r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	home := filepath.Join(f.dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	input := formatproof.NewCleanInput{APIVersion: "tplaiter.dev/managed-new-clean-input/v1", Home: home, Ref: f.source.Commit, SourceInput: managedNewSelection(f.source, f.sourceRefs), ToolSource: managedNewSelection(f.source, f.sourceRefs), Render: renderref.Input{Values: settings.Values{"label": "ok"}, Project: manifest.ProjectInfo{Name: "Managed", Slug: "managed", Module: "example.test/managed"}, Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: "pinned"}, RendererVersion: "v1", Origins: map[string]survey.Source{"label": survey.SourceDefault}}
	prepared, err := formatproof.PrepareNewClean(ctx, r, input)
	if err != nil {
		t.Fatal(err)
	}
	approvals := map[string]trustverify.ApprovalRefs{}
	for _, request := range prepared.Requests() {
		approvals[request.RequestSHA256] = managedNewApprove(t, f, request)
	}
	clean, err := formatproof.StageNewClean(ctx, prepared, approvals)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := formatproof.BuildNewPublication(ctx, prepared, clean)
	if err != nil {
		t.Fatal(err)
	}
	images, err := publication.ImagesFor(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	effects := map[string][]byte{}
	for _, ref := range prepared.References() {
		for ordinal := 1; ordinal <= 2; ordinal++ {
			path := filepath.Join(r.ScratchRoot(), "formatter-evidence", strings.TrimPrefix(ref.FrameSHA256, "sha256:"), fmt.Sprintf("pass-%d-completed.json", ordinal))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			effects[path] = raw
		}
	}
	tx, err := BeginManagedSealed(ctx, r, publication)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	id := tx.ID()
	for name, raw := range images {
		path := filepath.Join(tx.Workspace(), filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.SealOutputs(); err != nil {
		t.Fatal(err)
	}
	registryHome, before, after, err := publication.RegistryFor(r)
	if err != nil {
		t.Fatal(err)
	}
	plan := RegistryPlan{Home: registryHome, Before: before, After: after}
	if err := tx.PrepareRegistry(plan); err != nil {
		t.Fatal(err)
	}
	tx.fault = func(point string) error {
		if point == "commit.before_marker_remove" {
			return ErrInjectedCrash
		}
		return nil
	}
	if err := tx.Commit(plan); !errors.Is(err, ErrInjectedCrash) {
		t.Fatalf("real commit boundary: %v", err)
	}
	if err := Continue(home, id, home); !errors.Is(err, ErrManagedAdmission) {
		t.Fatalf("generic recovery admitted managed content: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	cold, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	loaded, err := Load(home, id)
	if err != nil || loaded.ID() != id || loaded.Journal().Phase != Committed {
		t.Fatalf("same-ID carrier: %v", err)
	}

	// A well-formed completed record with an invalid MAC must retain the same
	// transaction and never acquire a replacement formatter execution.
	for path, original := range effects {
		var signed map[string]json.RawMessage
		if err := json.Unmarshal(original, &signed); err != nil {
			t.Fatal(err)
		}
		signed["mac"] = json.RawMessage(`"` + strings.Repeat("0", 64) + `"`)
		tampered, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ContinueManaged(ctx, cold, home, id); err == nil {
			t.Fatal("tampered completion admitted")
		}
		held, err := Load(home, id)
		if err != nil || held.Journal().Phase != Committed {
			t.Fatal("refusal advanced or removed journal")
		}
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		break
	}
	// Exact ownership remains mandatory even with valid historical effects.
	mainPath := filepath.Join(f.project, "main.go")
	if err := os.WriteFile(mainPath, []byte("package foreign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ContinueManaged(ctx, cold, home, id); !errors.Is(err, ErrOwnershipUncertain) {
		t.Fatalf("foreign afterimage admitted: %v", err)
	}
	if raw, err := os.ReadFile(mainPath); err != nil || string(raw) != "package foreign\n" {
		t.Fatal("foreign content overwritten")
	}
	if err := os.WriteFile(mainPath, images["main.go"], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ContinueManaged(ctx, cold, home, id); err != nil {
		t.Fatal(err)
	}
	for name, want := range images {
		got, err := os.ReadFile(filepath.Join(f.project, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("cold afterimage %s: %v", name, err)
		}
	}
	projection, err := managed.ReadNew(ctx, cold, home, input.RendererVersion)
	if err != nil {
		t.Fatalf("fresh managed clean reader: %v", err)
	}
	if len(projection.Blocks().Files) == 0 {
		t.Fatal("missing authenticated clean blocks")
	}
	reconstructed, err := managed.ReconstructNew(ctx, cold, home, input.RendererVersion, images)
	if err != nil || len(reconstructed.Blocks().Files) == 0 {
		t.Fatalf("immutable beforeimage projection: %v", err)
	}
	controls := map[string][]byte{}
	for name, raw := range images {
		controls[name] = append([]byte(nil), raw...)
	}
	controls[".tplaiter/managed-blocks.json"] = []byte(`{"schema":1,"files":{}}`)
	if _, err := managed.ReconstructNew(ctx, cold, home, input.RendererVersion, controls); err == nil {
		t.Fatal("mismatched managed beforeimage accepted")
	}
	controls[".tplaiter/managed-blocks.json"] = images[".tplaiter/managed-blocks.json"]
	delete(controls, ".tplaiter/manifest.snapshot.yaml")
	if _, err := managed.ReconstructNew(ctx, cold, home, input.RendererVersion, controls); err == nil {
		t.Fatal("missing signed snapshot beforeimage accepted")
	}

	if _, err := managed.ReadNew(ctx, cold, home, "wrong-renderer"); err == nil {
		t.Fatal("wrong renderer accepted")
	}
	if _, err := managed.ReadNew(ctx, cold, filepath.Join(f.dir, "other-home"), input.RendererVersion); err == nil {
		t.Fatal("wrong home accepted")
	}
	lineagePath := filepath.Join(f.project, ".tplaiter", "managed-lineage.json")
	lineageRaw, err := os.ReadFile(lineagePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lineagePath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.ReadNew(ctx, cold, home, input.RendererVersion); err == nil {
		t.Fatal("tampered lineage accepted")
	}
	if err := os.WriteFile(lineagePath, lineageRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lineagePath); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.ReadNew(ctx, cold, home, input.RendererVersion); err == nil {
		t.Fatal("stripped lineage accepted")
	}
	if err := os.WriteFile(lineagePath, lineageRaw, 0o644); err != nil {
		t.Fatal(err)
	}

	registry, err := os.ReadFile(state.ProjectsPath(home))
	if err != nil || !bytes.Equal(registry, after) {
		t.Fatal("cold registry changed")
	}
	for path, want := range effects {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("completed formatter effect replaced")
		}
	}
	if _, err := Load(home, id); !errors.Is(err, ErrNoActive) {
		t.Fatalf("completion retained active journal: %v", err)
	}
	t.Logf("actual signed New publication and fresh-runtime SAME-ID completion: %s; completed formatter records unchanged", id)
}

func TestOrdinarySealedNewCannotAdmitManagedAfterimages(t *testing.T) {
	for _, files := range []map[string][]byte{
		{"main.go": []byte("package p\n// tplater:managed-begin id=x provider=root\n// tplater:managed-end id=x\n")},
		{".tplaiter/managed-lineage.json": []byte(`{}`)},
		{".tplaiter/managed-blocks.json": []byte(`{"schema":1,"files":{"main.go":{}}}`)},
	} {
		if _, err := BeginSealedWithFault(t.TempDir(), t.TempDir(), files, nil); !errors.Is(err, ErrManagedAdmission) {
			t.Fatalf("generic managed input admitted: %v", err)
		}
	}
}

func TestManagedNewPreparedAbortColdSameID(t *testing.T) {
	ctx := context.Background()
	f := managedNewNewIntegrationFixture(t)
	r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	home := filepath.Join(f.dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	input := formatproof.NewCleanInput{APIVersion: "tplaiter.dev/managed-new-clean-input/v1", Home: home, Ref: f.source.Commit, SourceInput: managedNewSelection(f.source, f.sourceRefs), ToolSource: managedNewSelection(f.source, f.sourceRefs), Render: renderref.Input{Values: settings.Values{"label": "ok"}, Project: manifest.ProjectInfo{Name: "Managed", Slug: "managed", Module: "example.test/managed"}, Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: "pinned"}, RendererVersion: "v1", Origins: map[string]survey.Source{"label": survey.SourceDefault}}
	prepared, err := formatproof.PrepareNewClean(ctx, r, input)
	if err != nil {
		t.Fatal(err)
	}
	approvals := map[string]trustverify.ApprovalRefs{}
	for _, request := range prepared.Requests() {
		approvals[request.RequestSHA256] = managedNewApprove(t, f, request)
	}
	clean, err := formatproof.StageNewClean(ctx, prepared, approvals)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := formatproof.BuildNewPublication(ctx, prepared, clean)
	if err != nil {
		t.Fatal(err)
	}
	images, err := publication.ImagesFor(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := BeginManagedSealed(ctx, r, publication)
	if err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	for name, raw := range images {
		path := filepath.Join(tx.Workspace(), filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.SealOutputs(); err != nil {
		t.Fatal(err)
	}
	tx.Release()
	if err := AbortByID(home, id); !errors.Is(err, ErrManagedAdmission) {
		t.Fatalf("generic abort admitted managed images: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	cold, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	if err := AbortManaged(ctx, cold, home, id); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(f.project)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cold abort did not restore exact empty target: %v %v", entries, err)
	}
	if _, err := os.Stat(state.ProjectsPath(home)); !os.IsNotExist(err) {
		t.Fatalf("abort published registry: %v", err)
	}
	if _, err := Load(home, id); !errors.Is(err, ErrNoActive) {
		t.Fatalf("abort retained active journal: %v", err)
	}
	t.Logf("source-bound prepared New abort preserved SAME-ID %s and zero registry publication", id)
}

// A finite test-only fixture producer. It executes the real owner; no journal,
// approval, grant or execution-authority value is accepted from its caller.
func TestStateLedgerOwnerFixtureBridge(t *testing.T) {
	if os.Getenv("TPLAITER_NEW_OWNER_FIXTURE") != "1" {
		return
	}
	var q struct {
		Operation string `json:"operation"`
		Home      string `json:"home"`
		Target    string `json:"target"`
		ID        string `json:"id"`
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	if err != nil || len(raw) > 65536 || len(raw) == 0 {
		t.Fatal("missing or oversized fixture request")
	}
	if err := canonicaljson.DecodeStrict(raw, &q); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(q.Home) {
		t.Fatal("absolute owned fixture home required")
	}
	var id, phase, target string
	switch q.Operation {
	case "begin":
		if q.ID != "" || !filepath.IsAbs(q.Target) || q.Home == q.Target {
			t.Fatal("invalid begin geometry")
		}
		tx, err := Begin(q.Home, q.Target)
		if err != nil {
			t.Fatal(err)
		}
		id, phase, target = tx.ID(), string(tx.Journal().Phase), tx.Journal().Target
		tx.Release()
	case "abort":
		if q.Target != "" || !validID(q.ID) {
			t.Fatal("invalid abort geometry")
		}
		tx, err := Load(q.Home, q.ID)
		if err != nil {
			t.Fatal(err)
		}
		id, target = q.ID, tx.Journal().Target
		if err := AbortByID(q.Home, q.ID); err != nil {
			t.Fatal(err)
		}
		phase = "aborted"
	default:
		t.Fatal("unknown fixture operation")
	}
	out := os.NewFile(3, "fixture-response")
	if out == nil {
		t.Fatal("missing result descriptor")
	}
	defer out.Close()
	reply := struct {
		ID     string `json:"id"`
		Phase  string `json:"phase"`
		Target string `json:"target"`
	}{id, phase, target}
	if err := json.NewEncoder(out).Encode(reply); err != nil {
		t.Fatal(err)
	}
}
