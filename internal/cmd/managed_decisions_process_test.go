package cmd

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
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/linkcmd"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/newimages"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	linktx "github.com/tplAIter/tplaiter/internal/projecttransaction/link"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

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
	return managedNativeIntegrationFixtureWithScope(t, "new", writeSource, extras...)
}

func managedNativeIntegrationFixtureWithScope(t *testing.T, scope string, writeSource func(*testing.T, string, string, string, string) ([]byte, trustverify.Subject), extras ...string) *managedNewIntegrationFixture {
	if scope != "new" && scope != "link" && scope != "update" {
		t.Fatal("invalid fixture owner scope")
	}

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
	f.policy = trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "t5d-policy", Profile: "oss", MinimumProfile: "oss", Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Principals: []trustverify.Principal{{ID: "principal:approver"}, {ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []trustverify.IssuerPrincipal{{Issuer: "publisher-1", PrincipalID: "principal:publisher"}}, SourceRules: []trustverify.SourceRule{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: source.Origin, TemplatePath: ".", Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"}}, Approvers: []trustverify.Approver{{ID: "t5d-approver", PrincipalID: "principal:approver", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(approverPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(approverPub), Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Scopes: []trustverify.ApprovalScope{{ProjectID: "project-t5d", OperationScope: scope, ActionKind: "formatter", Origin: source.Origin, TemplatePath: "."}}}}, AllowInvocationHuman: false, MaxTimeoutMillis: 5000}
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
	// Lifecycle readers intentionally use the separate fixed raw evidence CAS;
	// the bootstrap store is not its fallback. Populate only this fixture's
	// already-authenticated public blobs in the configured owned CAS layout.
	for digest, raw := range evidence {
		hex := strings.TrimPrefix(digest, "sha256:")
		if len(hex) != 64 || evidencecas.Digest(raw) != digest {
			t.Fatal("invalid fixture CAS blob")
		}
		dir := filepath.Join(f.evidence, "sha256", hex[:2])
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, hex[2:]), raw, 0o600); err != nil {
			t.Fatal(err)
		}
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

// This is the installed entrypoint, not a mock command or framework-only
// dispatch. Templates and operator evidence are synthetic fixture authority.
func TestManagedNewInstalledCLIAndMCP(t *testing.T) {
	for _, channel := range []string{"cli", "mcp"} {
		t.Run(channel, func(t *testing.T) {
			f := managedNewNewIntegrationFixture(t)
			base := f.dir
			home := filepath.Join(base, "process-home")
			if err := os.Mkdir(home, 0o700); err != nil {
				t.Fatal(err)
			}
			registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
			raw := managedNewJSON(t, registration)
			registrationPath := filepath.Join(base, "registration.json")
			if err := os.WriteFile(registrationPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(base, "tplaiter")
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			build := exec.CommandContext(ctx, testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=v-managed -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+evidencecas.Digest(raw), "-o", binary, ".")
			build.Dir = filepath.Join("..", "..")
			build.Env = append(testBuildEnv(home), "PYTHONDONTWRITEBYTECODE=1")
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("installed build: %v %s", err, out)
			}
			image, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("installed image=%s registration=%s source=%s channel=%s", evidencecas.Digest(image), evidencecas.Digest(raw), f.source.Commit, channel)
			sourcePath, formatPath := filepath.Join(base, "source.json"), filepath.Join(base, "format.json")
			sourceRaw := managedNewSelection(f.source, f.sourceRefs)
			if err := os.WriteFile(sourcePath, sourceRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			selected, err := operationtrust.DecodeSourceSelection(sourceRaw)
			if err != nil {
				t.Fatal(err)
			}
			controls := FormatInput{APIVersion: FormatInputAPIVersion, ToolSource: *selected, Approvals: []FormatApproval{}}
			writeControls := func(path string, v FormatInput) {
				t.Helper()
				if err := os.WriteFile(path, managedNewJSON(t, v), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeControls(formatPath, controls)
			runCLI := func(phase string, path string) (resultdto.Result, error) {
				args := []string{"new", f.source.Commit, "Managed", "--dir", f.project, "--source-input", sourcePath, "--format-input", path, "--defaults", "--json"}
				if phase != "" {
					args = append(args, "--"+phase)
				}
				c := exec.CommandContext(ctx, binary, args...)
				c.Dir = base
				c.Env = append(testProcessEnv(home), "PYTHONDONTWRITEBYTECODE=1")
				output, runErr := c.Output()
				var env resultdto.Result
				if err := json.Unmarshal(output, &env); err != nil {
					t.Fatalf("CLI envelope: %v %s run=%v", err, output, runErr)
				}
				t.Logf("CLI phase=%s status=%s", phase, env.Status)
				return env, runErr
			}

			readerRun := func(verb string) (resultdto.Result, error) {
				args := []string{verb, "--dir", f.project, "--json"}
				if verb == "settings" {
					args = []string{"settings", "list", "--dir", f.project, "--json"}
				}
				c := exec.CommandContext(ctx, binary, args...)
				c.Dir = base
				c.Env = append(testProcessEnv(home), "PYTHONDONTWRITEBYTECODE=1")
				raw, err := c.Output()
				var env resultdto.Result
				if decode := json.Unmarshal(raw, &env); decode != nil {
					t.Fatalf("reader envelope %s: %v %s", verb, decode, raw)
				}
				return env, err
			}
			call := runCLI
			if channel == "mcp" {
				server := exec.CommandContext(ctx, binary, "mcp-server")
				server.Dir = base
				server.Env = append(testProcessEnv(home), "PYTHONDONTWRITEBYTECODE=1")
				input, err := server.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				output, err := server.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := server.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					_ = input.Close()
					if err := server.Wait(); err != nil && ctx.Err() == nil {
						t.Errorf("MCP shutdown: %v", err)
					}
				}()
				enc, dec := json.NewEncoder(input), json.NewDecoder(output)
				id := 0
				request := func(method string, params any) json.RawMessage {
					t.Helper()
					id++
					if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
						t.Fatal(err)
					}
					var response struct {
						ID      int             `json:"id"`
						Result  json.RawMessage `json:"result"`
						Error   json.RawMessage `json:"error"`
						JSONRPC string          `json:"jsonrpc"`
					}
					if err := dec.Decode(&response); err != nil {
						t.Fatal(err)
					}
					if response.ID != id || len(response.Error) != 0 {
						t.Fatalf("MCP transport: %s", response.Error)
					}
					return response.Result
				}
				request("initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "managed-new-test", "version": "1"}})
				readerRun = func(verb string) (resultdto.Result, error) {
					name := "project_diff"
					if verb == "settings" {
						name = "settings_list"
					}
					raw := request("tools/call", map[string]any{"name": name, "arguments": map[string]any{"dir": f.project}})
					var reply struct {
						IsError           bool            `json:"isError"`
						StructuredContent json.RawMessage `json:"structuredContent"`
						Content           []struct {
							Type string `json:"type"`
							Text string `json:"text"`
						} `json:"content"`
					}
					if err := json.Unmarshal(raw, &reply); err != nil {
						t.Fatal(err)
					}
					data := reply.StructuredContent
					if len(data) == 0 {
						for _, part := range reply.Content {
							if part.Type == "text" {
								data = []byte(part.Text)
								break
							}
						}
					}
					var env resultdto.Result
					if err := json.Unmarshal(data, &env); err != nil {
						t.Fatalf("reader MCP %s: %v %s", verb, err, data)
					}
					if reply.IsError {
						return env, fmt.Errorf("reader MCP refusal")
					}
					return env, nil
				}

				if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); err != nil {
					t.Fatal(err)
				}
				call = func(phase string, path string) (resultdto.Result, error) {
					args := map[string]any{"ref": f.source.Commit, "name": "Managed", "dir": base, "targetDir": f.project, "sourceInput": sourcePath, "formatInput": path, "defaults": true}
					if phase == "prepare" {
						args["prepare"] = true
					}
					if phase == "format-stage" {
						args["formatStage"] = true
					}
					raw := request("tools/call", map[string]any{"name": "project_new", "arguments": args})
					var result struct {
						IsError           bool            `json:"isError"`
						StructuredContent json.RawMessage `json:"structuredContent"`
						Content           []struct {
							Type string `json:"type"`
							Text string `json:"text"`
						} `json:"content"`
					}
					if err := json.Unmarshal(raw, &result); err != nil {
						t.Fatal(err)
					}
					data := result.StructuredContent
					if len(data) == 0 {
						for _, block := range result.Content {
							if block.Type == "text" {
								data = []byte(block.Text)
								break
							}
						}
					}
					var env resultdto.Result
					if err := json.Unmarshal(data, &env); err != nil {
						t.Fatalf("MCP envelope: %v %s", err, data)
					}
					t.Logf("MCP phase=%s status=%s", phase, env.Status)
					if result.IsError {
						return env, fmt.Errorf("MCP application refusal")
					}
					return env, nil
				}
			}
			preview, err := call("prepare", formatPath)
			if err != nil {
				t.Fatal(err)
			}
			var report newcmd.ManagedPreparation
			for _, diagnostic := range preview.Diagnostics {
				if diagnostic.Code == "TPL-I-MANAGED-NEW-PHASE" {
					data := map[string]any{"apiVersion": "tplaiter.dev/managed-new-preparation/v1", "requests": diagnostic.Details["requests"], "references": diagnostic.Details["references"]}
					if err := json.Unmarshal(managedNewJSON(t, data), &report); err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(report.Requests) != 2 || report.Requests[0].Action.ID == report.Requests[1].Action.ID {
				t.Fatal("missing distinct actual formatter requests")
			}
			if entries, err := os.ReadDir(f.project); err != nil || len(entries) != 0 {
				t.Fatal("prepare published project")
			}
			if _, err := call("", formatPath); err == nil {
				t.Fatal("publication without formatter evidence admitted")
			}
			stage := controls
			for _, q := range report.Requests {
				ref := managedNewApprove(t, f, q)
				stage.Approvals = append(stage.Approvals, FormatApproval{RequestSHA256: q.RequestSHA256, ApprovalCAS: ref.ApprovalCAS})
			}
			stagePath := filepath.Join(base, "stage.json")
			writeControls(stagePath, stage)
			if _, err := call("format-stage", stagePath); err != nil {
				t.Fatal(err)
			}
			if entries, err := os.ReadDir(f.project); err != nil || len(entries) != 0 {
				t.Fatal("formatter stage published project")
			}
			if _, err := call("", formatPath); err != nil {
				t.Fatal(err)
			}
			rendered, err := os.ReadFile(filepath.Join(f.project, "main.go"))
			if err != nil || !bytes.Contains(rendered, []byte("func f()")) || !bytes.Contains(rendered, []byte("tplater:managed-begin")) {
				t.Fatalf("normal managed New: %v %s", err, rendered)
			}
			if _, err := os.Stat(filepath.Join(f.project, ".tplaiter", "managed-lineage.json")); err != nil {
				t.Fatal("missing admitted clean lineage")
			}

			for _, verb := range []string{"diff", "settings"} {
				env, err := readerRun(verb)
				if err != nil || env.Status != "ok" {
					t.Fatalf("actual %s %s reader: %v %+v", channel, verb, err, env)
				}
				if verb == "diff" && (env.Summary.FilesChanged != 0 || env.Summary.BlocksChanged != 0) {
					t.Fatalf("fresh formatted clean drift: %+v", env.Summary)
				}
			}
			lineage := filepath.Join(f.project, ".tplaiter", "managed-lineage.json")
			original, err := os.ReadFile(lineage)
			if err != nil {
				t.Fatal(err)
			}
			for _, mutation := range []string{"tamper", "strip"} {
				if mutation == "tamper" {
					err = os.WriteFile(lineage, []byte(`{}`), 0o644)
				} else {
					err = os.Remove(lineage)
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, verb := range []string{"diff", "settings"} {
					if env, err := readerRun(verb); err == nil && env.Status == "ok" {
						t.Fatalf("%s %s accepted %s lineage", channel, verb, mutation)
					}
				}
				if err := os.WriteFile(lineage, original, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			t.Log("actual installed Diff clean and Settings Read accepted authenticated New projection; stripped/tampered lineage refused")
			t.Log("actual installed source-owned New prepare -> two approved formatting passes -> sealed managed creation; synthetic authority only")
		})
	}
}

// The seed bytes are an existing operator project, not a reported formatter
// receipt. Both required native effects below execute through real approvals.
func TestManagedLinkNativeOwnerColdSameIDAndInodes(t *testing.T) {
	f := managedNativeIntegrationFixtureWithScope(t, "link", managedNewWriteNativeSource)
	ctx := context.Background()
	r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	home := filepath.Join(f.dir, "link-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	source := managedNewSelection(f.source, f.sourceRefs)
	opts := newcmd.Options{Ref: f.source.Commit, ProjectName: "Managed", Dir: f.project, Defaults: true, CLIVersion: "v1"}
	native, err := newcmd.PrepareNativeContext(ctx, opts, newcmd.Deps{Runtime: r, Home: home, SourceInput: source})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := newimages.Build(*native)
	if err != nil {
		t.Fatal(err)
	}
	type held struct {
		info os.FileInfo
		raw  []byte
	}
	originals := map[string]held{}
	for name, raw := range seed {
		if strings.HasPrefix(name, ".tplaiter/") {
			continue
		}
		if strings.HasSuffix(name, ".go") {
			raw, err = format.Source(raw)
			if err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(f.project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		originals[name] = held{info: info, raw: bytes.Clone(raw)}
	}
	input := linkcmd.Input{Action: "link", Ref: f.source.Commit, Name: "Managed", Source: source, Choices: map[string]string{}, Managed: &linkcmd.ManagedInput{APIVersion: "tplaiter.dev/managed-link-input/v1", ToolSource: source}}
	prep, err := linkcmd.PrepareManaged(ctx, r, home, input, "v1")
	if err != nil {
		t.Fatal(err)
	}
	requests, err := prep.Requests(ctx)
	if err != nil || len(requests) != 2 {
		t.Fatalf("real Link requests %v %+v", err, requests)
	}
	if requests[0].Scope != "link" || requests[1].Scope != "link" || requests[0].RequestSHA256 == requests[1].RequestSHA256 {
		t.Fatal("purpose-bound distinct Link requests missing")
	}
	if err := prep.Stage(ctx, nil); err == nil {
		t.Fatal("missing real operator approvals accepted")
	}
	refs := map[string]trustverify.ApprovalRefs{}
	for _, request := range requests {
		refs[request.RequestSHA256] = managedNewApprove(t, f, request)
	}
	if err := prep.Stage(ctx, refs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(f.project, ".tplaiter")); !os.IsNotExist(err) {
		t.Fatal("formatter stage published state", err)
	}
	afterStage, err := prep.Requests(ctx)
	if err != nil || len(afterStage) != 0 {
		t.Fatal("completed Link requests resurrected", err)
	}
	proofRoots := filepath.Join(f.scratch, "formatter-evidence")
	effects := map[string]held{}
	if err := filepath.WalkDir(proofRoots, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := os.Stat(name)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		effects[name] = held{info: info, raw: raw}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p, err := linkcmd.Prepare(ctx, r, home, prep.Input(), "v1")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := linktx.Begin(ctx, p, p.Fingerprint(), "v1")
	if err != nil {
		if tx != nil {
			tx.Release()
		}
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	fresh, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	cold, err := linktx.Open(ctx, fresh, home, id, "v1")
	if err != nil {
		t.Fatal("actual cold Link owner", err)
	}
	defer cold.Release()
	if cold.ID() != id {
		t.Fatal("cold Link ID changed")
	}
	if err := cold.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for name, old := range originals {
		path := filepath.Join(f.project, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, old.raw) || !os.SameFile(info, old.info) || info.Mode() != old.info.Mode() || !info.ModTime().Equal(old.info.ModTime()) {
			t.Fatal("Link changed existing user bytes, mode, inode or mtime", name, err)
		}
	}
	for name, old := range effects {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(raw, old.raw) || !os.SameFile(info, old.info) || !info.ModTime().Equal(old.info.ModTime()) {
			t.Fatal("cold Link reran or replaced completed effects", name, err)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/managed-lineage.json")); err != nil || len(raw) == 0 {
		t.Fatal("missing actual Link lineage", err)
	}
	t.Logf("actual Link prepared-owner cold commit sameID=%s two-native-effects=%d user-inodes=%d", id, len(requests), len(originals))
}

func TestManagedLinkInstalledCLIAndMCP(t *testing.T) {
	for _, channel := range []string{"cli", "mcp"} {
		t.Run(channel, func(t *testing.T) {
			f := managedNativeIntegrationFixtureWithScope(t, "link", managedNewWriteNativeSource)
			base := f.dir
			home := filepath.Join(base, "process-home")
			if err := os.Mkdir(home, 0o700); err != nil {
				t.Fatal(err)
			}
			// Link requires an existing installed application home; create only
			// the controlled fixture directory, never an authority document.
			if err := os.Mkdir(filepath.Join(home, "tplaiter"), 0o700); err != nil {
				t.Fatal(err)
			}
			// These seed bytes represent an existing operator project, not effects.
			runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
			if err != nil {
				t.Fatal(err)
			}
			native, err := newcmd.PrepareNativeContext(context.Background(), newcmd.Options{Ref: f.source.Commit, ProjectName: "Managed", Dir: f.project, Defaults: true, CLIVersion: "v-managed"}, newcmd.Deps{Runtime: runtime, Home: home, SourceInput: managedNewSelection(f.source, f.sourceRefs)})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := newimages.Build(*native)
			if err != nil {
				t.Fatal(err)
			}
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
			type originalFile struct {
				raw  []byte
				info os.FileInfo
			}
			originals := map[string]originalFile{}
			for name, raw := range seed {
				if strings.HasPrefix(name, ".tplaiter/") {
					continue
				}
				if strings.HasSuffix(name, ".go") {
					raw, err = format.Source(raw)
					if err != nil {
						t.Fatal(err)
					}
				}
				path := filepath.Join(f.project, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0o644); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				originals[name] = originalFile{bytes.Clone(raw), info}
			}
			checkOriginals := func() {
				t.Helper()
				for name, original := range originals {
					path := filepath.Join(f.project, name)
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					info, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(raw, original.raw) || !os.SameFile(info, original.info) || info.Mode() != original.info.Mode() || !info.ModTime().Equal(original.info.ModTime()) {
						t.Fatal("installed Link changed user bytes/mode/inode/mtime", name)
					}
				}
			}
			checkUnpublished := func() {
				t.Helper()
				checkOriginals()
				if _, err := os.Lstat(filepath.Join(f.project, ".tplaiter")); !os.IsNotExist(err) {
					t.Fatal("prepare/stage published Link state", err)
				}
			}
			registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
			raw := managedNewJSON(t, registration)
			registrationPath := filepath.Join(base, "registration.json")
			if err := os.WriteFile(registrationPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(base, "tplaiter")
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			build := exec.CommandContext(ctx, testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=v-managed -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+evidencecas.Digest(raw), "-o", binary, ".")
			build.Dir = filepath.Join("..", "..")
			build.Env = append(testBuildEnv(home), "PYTHONDONTWRITEBYTECODE=1")
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("installed build: %v %s", err, out)
			}
			image, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("installed image=%s registration=%s source=%s channel=%s", evidencecas.Digest(image), evidencecas.Digest(raw), f.source.Commit, channel)
			sourcePath, formatPath := filepath.Join(base, "source.json"), filepath.Join(base, "format.json")
			sourceRaw := managedNewSelection(f.source, f.sourceRefs)
			if err := os.WriteFile(sourcePath, sourceRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			selected, err := operationtrust.DecodeSourceSelection(sourceRaw)
			if err != nil {
				t.Fatal(err)
			}
			controls := FormatInput{APIVersion: FormatInputAPIVersion, ToolSource: *selected, Approvals: []FormatApproval{}}
			writeControls := func(path string, v FormatInput) {
				t.Helper()
				if err := os.WriteFile(path, managedNewJSON(t, v), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeControls(formatPath, controls)
			runCLI := func(phase string, path string) (resultdto.Result, error) {
				args := []string{"link", f.source.Commit, "Managed", "--dir", f.project, "--source-input", sourcePath, "--format-input", path, "--json"}
				if phase != "" {
					args = append(args, "--"+phase)
				}
				c := exec.CommandContext(ctx, binary, args...)
				c.Dir = base
				c.Env = append(testProcessEnv(home), "PYTHONDONTWRITEBYTECODE=1")
				output, runErr := c.Output()
				var env resultdto.Result
				if err := json.Unmarshal(output, &env); err != nil {
					t.Fatalf("CLI envelope: %v %s run=%v", err, output, runErr)
				}
				t.Logf("CLI phase=%s status=%s", phase, env.Status)
				if runErr != nil {
					for _, d := range env.Diagnostics {
						t.Logf("refusal code=%s message=%s", d.Code, d.Message)
					}
				}
				return env, runErr
			}

			readerRun := func(verb string) (resultdto.Result, error) {
				args := []string{verb, "--dir", f.project, "--json"}
				if verb == "settings" {
					args = []string{"settings", "list", "--dir", f.project, "--json"}
				}
				c := exec.CommandContext(ctx, binary, args...)
				c.Dir = base
				c.Env = append(testProcessEnv(home), "PYTHONDONTWRITEBYTECODE=1")
				raw, err := c.Output()
				var env resultdto.Result
				if decode := json.Unmarshal(raw, &env); decode != nil {
					t.Fatalf("reader envelope %s: %v %s", verb, decode, raw)
				}
				return env, err
			}
			call := runCLI
			if channel == "mcp" {
				server := exec.CommandContext(ctx, binary, "mcp-server")
				server.Dir = base
				server.Env = append(testProcessEnv(home), "PYTHONDONTWRITEBYTECODE=1")
				input, err := server.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				output, err := server.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := server.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					_ = input.Close()
					if err := server.Wait(); err != nil && ctx.Err() == nil {
						t.Errorf("MCP shutdown: %v", err)
					}
				}()
				enc, dec := json.NewEncoder(input), json.NewDecoder(output)
				id := 0
				request := func(method string, params any) json.RawMessage {
					t.Helper()
					id++
					if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
						t.Fatal(err)
					}
					var response struct {
						ID      int             `json:"id"`
						Result  json.RawMessage `json:"result"`
						Error   json.RawMessage `json:"error"`
						JSONRPC string          `json:"jsonrpc"`
					}
					if err := dec.Decode(&response); err != nil {
						t.Fatal(err)
					}
					if response.ID != id || len(response.Error) != 0 {
						t.Fatalf("MCP transport: %s", response.Error)
					}
					return response.Result
				}
				request("initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "managed-link-test", "version": "1"}})
				readerRun = func(verb string) (resultdto.Result, error) {
					name := "project_diff"
					if verb == "settings" {
						name = "settings_list"
					}
					raw := request("tools/call", map[string]any{"name": name, "arguments": map[string]any{"dir": f.project}})
					var reply struct {
						IsError           bool            `json:"isError"`
						StructuredContent json.RawMessage `json:"structuredContent"`
						Content           []struct {
							Type string `json:"type"`
							Text string `json:"text"`
						} `json:"content"`
					}
					if err := json.Unmarshal(raw, &reply); err != nil {
						t.Fatal(err)
					}
					data := reply.StructuredContent
					if len(data) == 0 {
						for _, part := range reply.Content {
							if part.Type == "text" {
								data = []byte(part.Text)
								break
							}
						}
					}
					var env resultdto.Result
					if err := json.Unmarshal(data, &env); err != nil {
						t.Fatalf("reader MCP %s: %v %s", verb, err, data)
					}
					if reply.IsError {
						return env, fmt.Errorf("reader MCP refusal")
					}
					return env, nil
				}

				if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); err != nil {
					t.Fatal(err)
				}
				call = func(phase string, path string) (resultdto.Result, error) {
					args := map[string]any{"action": "link", "ref": f.source.Commit, "name": "Managed", "dir": f.project, "sourceInput": sourcePath, "formatInput": path}
					if phase == "prepare" {
						args["prepare"] = true
					}
					if phase == "format-stage" {
						args["formatStage"] = true
					}
					raw := request("tools/call", map[string]any{"name": "project_link", "arguments": args})
					var result struct {
						IsError           bool            `json:"isError"`
						StructuredContent json.RawMessage `json:"structuredContent"`
						Content           []struct {
							Type string `json:"type"`
							Text string `json:"text"`
						} `json:"content"`
					}
					if err := json.Unmarshal(raw, &result); err != nil {
						t.Fatal(err)
					}
					data := result.StructuredContent
					if len(data) == 0 {
						for _, block := range result.Content {
							if block.Type == "text" {
								data = []byte(block.Text)
								break
							}
						}
					}
					var env resultdto.Result
					if err := json.Unmarshal(data, &env); err != nil {
						t.Fatalf("MCP envelope: %v %s", err, data)
					}
					t.Logf("MCP phase=%s status=%s", phase, env.Status)
					if result.IsError {
						for _, d := range env.Diagnostics {
							t.Logf("refusal code=%s message=%s", d.Code, d.Message)
						}
						return env, fmt.Errorf("MCP application refusal")
					}
					return env, nil
				}
			}
			preview, err := call("prepare", formatPath)
			if err != nil {
				t.Fatal(err)
			}
			var report newcmd.ManagedPreparation
			for _, diagnostic := range preview.Diagnostics {
				if diagnostic.Code == "TPL-I-MANAGED-LINK-PHASE" {
					data := map[string]any{"apiVersion": "tplaiter.dev/managed-new-preparation/v1", "requests": diagnostic.Details["requests"], "references": diagnostic.Details["references"]}
					if err := json.Unmarshal(managedNewJSON(t, data), &report); err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(report.Requests) != 2 || report.Requests[0].Action.ID == report.Requests[1].Action.ID {
				t.Fatal("missing distinct actual formatter requests")
			}
			checkUnpublished()
			if _, err := call("", formatPath); err == nil {
				t.Fatal("publication without formatter evidence admitted")
			}
			stage := controls
			for _, q := range report.Requests {
				if q.Scope != "link" {
					t.Fatal("installed Link request has wrong purpose")
				}
				ref := managedNewApprove(t, f, q)
				stage.Approvals = append(stage.Approvals, FormatApproval{RequestSHA256: q.RequestSHA256, ApprovalCAS: ref.ApprovalCAS})
			}
			stagePath := filepath.Join(base, "stage.json")
			writeControls(stagePath, stage)
			if _, err := call("format-stage", stagePath); err != nil {
				t.Fatal(err)
			}
			checkUnpublished()
			if _, err := call("", formatPath); err != nil {
				t.Fatal(err)
			}
			rendered, err := os.ReadFile(filepath.Join(f.project, "main.go"))
			if err != nil || !bytes.Contains(rendered, []byte("func f()")) || !bytes.Contains(rendered, []byte("tplater:managed-begin")) {
				t.Fatalf("normal managed Link: %v %s", err, rendered)
			}
			if _, err := os.Stat(filepath.Join(f.project, ".tplaiter", "managed-lineage.json")); err != nil {
				t.Fatal("missing admitted clean lineage")
			}

			for _, verb := range []string{"diff", "settings"} {
				env, err := readerRun(verb)
				if err != nil || env.Status != "ok" {
					t.Fatalf("actual %s %s reader: %v %+v", channel, verb, err, env)
				}
				if verb == "diff" && (env.Summary.FilesChanged != 0 || env.Summary.BlocksChanged != 0) {
					t.Fatalf("fresh formatted clean drift: %+v", env.Summary)
				}
			}
			lineage := filepath.Join(f.project, ".tplaiter", "managed-lineage.json")
			original, err := os.ReadFile(lineage)
			if err != nil {
				t.Fatal(err)
			}
			for _, mutation := range []string{"tamper", "strip"} {
				if mutation == "tamper" {
					err = os.WriteFile(lineage, []byte(`{}`), 0o644)
				} else {
					err = os.Remove(lineage)
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, verb := range []string{"diff", "settings"} {
					if env, err := readerRun(verb); err == nil && env.Status == "ok" {
						t.Fatalf("%s %s accepted %s lineage", channel, verb, mutation)
					}
				}
				if err := os.WriteFile(lineage, original, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			t.Log("actual installed Diff clean and Settings Read accepted authenticated Link projection; stripped/tampered lineage refused")
			checkOriginals()
			t.Log("actual installed source-owned Link prepare -> two approved formatting passes -> source/effect publication; user inodes preserved; synthetic authority only")
		})
	}
}
