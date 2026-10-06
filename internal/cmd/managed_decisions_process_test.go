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
	"errors"
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

	"github.com/tplAIter/tplaiter/internal/survey"

	"github.com/tplAIter/tplaiter/internal/newtransaction"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/diffcmd"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/linkcmd"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/newimages"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	linktx "github.com/tplAIter/tplaiter/internal/projecttransaction/link"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/managed"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/settingscmd"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"github.com/tplAIter/tplaiter/internal/updateplan"
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
	if scope != "new" && scope != "link" && scope != "update" && scope != "link-update" {
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
	if scope == "link-update" {
		f.policy.Approvers[0].Scopes = []trustverify.ApprovalScope{
			{ProjectID: "project-t5d", OperationScope: "link", ActionKind: "formatter", Origin: source.Origin, TemplatePath: "."},
			{ProjectID: "project-t5d", OperationScope: "update", ActionKind: "formatter", Origin: source.Origin, TemplatePath: "."},
		}
	}
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

func TestManagedUpdateDecisionNativePhases(t *testing.T) {
	for _, action := range []string{"keep", "drop", "rename"} {
		t.Run(action, func(t *testing.T) {
			writer := func(t *testing.T, root, suffix, output, extra string) ([]byte, trustverify.Subject) {
				files := map[string][]byte{"main.go.tmpl": []byte("package fixture\n")}
				if action == "rename" {
					extra += "managedBlocks:\n  version: 1\n  replacements:\n    - path: main.go\n      provider: root\n      oldID: body\n      newID: next\n"
					files["main.go.tmpl"] = []byte("package fixture\n// tplater:managed-begin id=next provider=root\nfunc f(){ }\n// tplater:managed-end id=next\n")
				}
				if suffix != "target" {
					extra = ""
				}
				return managedNewWriteNativeSourceFiles(t, root, suffix, output, extra, files)
			}
			f := managedNativeIntegrationFixtureWithScope(t, "link-update", writer)
			ctx := context.Background()
			r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			home := filepath.Join(f.dir, "update-home")
			if err := os.Mkdir(home, 0o700); err != nil {
				t.Fatal(err)
			}
			source := managedNewSelection(f.source, f.sourceRefs)
			target := managedNewSelection(f.target, f.targetRefs)
			native, err := newcmd.PrepareNativeContext(ctx, newcmd.Options{Ref: f.source.Commit, ProjectName: "Managed", Dir: f.project, Defaults: true, CLIVersion: "v1"}, newcmd.Deps{Runtime: r, Home: home, SourceInput: source})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := newimages.Build(*native)
			if err != nil {
				t.Fatal(err)
			}
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
			}
			linked, err := linkcmd.PrepareManaged(ctx, r, home, linkcmd.Input{Action: "link", Ref: f.source.Commit, Name: "Managed", Source: source, Choices: map[string]string{}, Managed: &linkcmd.ManagedInput{APIVersion: "tplaiter.dev/managed-link-input/v1", ToolSource: source}}, "v1")
			if err != nil {
				t.Fatal(err)
			}
			requests, err := linked.Requests(ctx)
			if err != nil {
				t.Fatal(err)
			}
			approvals := map[string]trustverify.ApprovalRefs{}
			for _, q := range requests {
				approvals[q.RequestSHA256] = managedNewApprove(t, f, q)
			}
			if err := linked.Stage(ctx, approvals); err != nil {
				t.Fatal(err)
			}
			linkPlan, err := linkcmd.Prepare(ctx, r, home, linked.Input(), "v1")
			if err != nil {
				t.Fatal(err)
			}
			tx, err := linktx.Begin(ctx, linkPlan, linkPlan.Fingerprint(), "v1")
			if err != nil {
				if tx != nil {
					tx.Release()
				}
				t.Fatal(err)
			}
			err = tx.Commit(ctx)
			tx.Release()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.project, "main.go")
			old, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ours := bytes.ReplaceAll(old, []byte("func f() {}"), []byte("func f() { println(1) }"))
			if bytes.Equal(ours, old) {
				t.Fatal("missing local edit")
			}
			if err := os.WriteFile(path, ours, 0o644); err != nil {
				t.Fatal(err)
			}
			lockRaw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/root-template.lock.json"))
			if err != nil {
				t.Fatal(err)
			}
			sourceLock, err := provenance.DecodeRootTemplateLock(lockRaw)
			if err != nil {
				t.Fatal(err)
			}
			blocksRaw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/managed-blocks.json"))
			if err != nil {
				t.Fatal(err)
			}
			blocks, err := managedblocks.ParseBaseline(blocksRaw)
			if err != nil {
				t.Fatal(err)
			}
			render := renderref.Input{Repo: "pinned", Values: settings.Values{"label": "ok"}, Project: manifest.ProjectInfo{Name: "Managed", Slug: "managed"}}
			targetSnapshot, err := operationtrust.PrepareSnapshot(ctx, r, operationtrust.PrepareSnapshotInput{SourceInput: target, Render: render, RendererVersion: "v1"})
			if err != nil {
				t.Fatal(err)
			}
			d := managedblocks.Decision{Action: action, Path: "main.go", Provider: "root", OldID: "body", SourceRootLockSHA256: sourceLock.RootLockSHA256, TargetRootLockSHA256: targetSnapshot.RootLock().RootLockSHA256, BaselineBodySHA256: blocks.Files["main.go"].Blocks["body"].BodySHA256, ObservedFileSHA256: evidencecas.Digest(ours)}
			if action == "rename" {
				d.NewID = "next"
				formatted, err := format.Source(targetSnapshot.Rendered().Files["main.go"])
				if err != nil {
					t.Fatal(err)
				}
				doc, err := managedblocks.Parse("main.go", formatted)
				if err != nil {
					t.Fatal(err)
				}
				d.TargetBodySHA256 = evidencecas.Digest(doc.ByID["next"].Body)
			}
			decisionRaw, err := canonicaljson.Canonical(managedblocks.Decisions{APIVersion: managedblocks.DecisionsAPIVersion, Decisions: []managedblocks.Decision{d}})
			if err != nil {
				t.Fatal(err)
			}
			backend, err := updateplan.New(r, home, "v1")
			if err != nil {
				t.Fatal(err)
			}
			input := updateplan.Input{SourceInput: source, TargetInput: target}
			transport := updateplan.ManagedInput{ToolSource: source, Decisions: decisionRaw}
			prep, err := backend.PrepareManagedEffects(ctx, input, transport)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"clean-target", "merged-candidate"} {
				phase, requests, err := prep.PhaseRequests(ctx)
				if err != nil || phase != want || len(requests) != 2 {
					t.Fatalf("phase=%s expected=%s requests=%d err=%v", phase, want, len(requests), err)
				}
				if err := prep.StageCurrentPhase(ctx, nil); err == nil {
					t.Fatal("missing signed approvals accepted")
				}
				approvals := map[string]trustverify.ApprovalRefs{}
				for _, q := range requests {
					if q.Scope != "update" {
						t.Fatal("wrong native purpose")
					}
					approvals[q.RequestSHA256] = managedNewApprove(t, f, q)
				}
				if err := prep.StageCurrentPhase(ctx, approvals); err != nil {
					t.Fatal(err)
				}
			}
			report, err := prep.Report(ctx)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, ours) {
				t.Fatal("effects published project", err)
			}
			retained, err := backend.PrepareManagedEffects(ctx, input, transport)
			if err != nil {
				t.Fatal(err)
			}
			phase, pending, err := retained.PhaseRequests(ctx)
			if err != nil || phase != "complete" || len(pending) != 0 {
				t.Fatal("completed effects rerun", phase, len(pending), err)
			}
			again, err := retained.Report(ctx)
			if err != nil || !bytes.Equal(again.CandidateFiles["main.go"], report.CandidateFiles["main.go"]) {
				t.Fatal("retained candidate differs", err)
			}
			candidate := report.CandidateFiles["main.go"]
			if action == "drop" && bytes.Contains(candidate, []byte("println")) {
				t.Fatal("drop retained local body")
			}
			if action != "drop" && !bytes.Contains(candidate, []byte("println(1)")) {
				t.Fatal("local body lost", string(candidate))
			}
			if action == "keep" && report.Blocks.Files["main.go"].Blocks["body"].Tombstone == nil {
				t.Fatal("keep tombstone missing")
			}
			if action == "rename" && (bytes.Contains(candidate, []byte("id=body")) || !bytes.Contains(candidate, []byte("id=next"))) {
				t.Fatal("signed rename failed")
			}
			input.Managed = &transport
			plan, err := backend.Prepare(ctx, input)
			if err != nil {
				t.Fatal("managed writer plan", err)
			}
			transaction, err := projecttransaction.BeginUpdate(ctx, plan, plan.Fingerprint())
			if err != nil {
				if transaction != nil {
					transaction.Release()
				}
				t.Fatal("managed writer begin", err)
			}
			id := transaction.ID()
			transaction.Release()
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			cold, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Close()
			continued, err := projecttransaction.OpenUpdate(ctx, cold, home, id, "v1")
			if err != nil {
				t.Fatal("managed cold open", err)
			}
			if continued.ID() != id {
				continued.Release()
				t.Fatal("cold update changed ID")
			}
			err = continued.Commit(ctx)
			continued.Release()
			if err != nil {
				t.Fatal("managed cold commit", err)
			}
			actual, err = os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, candidate) {
				t.Fatal("published candidate differs", err)
			}
			clean, err := managed.Read(ctx, cold, home, "v1")
			if err != nil {
				t.Fatal("committed managed reader", err)
			}
			if !bytes.Equal(managedNewJSON(t, clean.Blocks()), managedNewJSON(t, report.Blocks)) {
				t.Fatal("committed block ledger differs")
			}
			view, err := settingscmd.NewNative(cold, home, "v1")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := view.Read(ctx); err != nil {
				t.Fatal("postupdate settings reader", err)
			}
			if _, err := diffcmd.Run(ctx, cold, diffcmd.Options{Home: home, RendererVersion: "v1", SecretProvider: readonlyHomeClassifier{}}); err != nil {
				t.Fatal("postupdate diff reader", err)
			}
			if action == "keep" {
				unknown := bytes.Replace(actual, []byte("id=body"), []byte("id=unknown"), -1)
				if bytes.Equal(unknown, actual) {
					t.Fatal("retained block fixture missing")
				}
				if err := os.WriteFile(path, unknown, 0o644); err != nil {
					t.Fatal(err)
				}
				if _, err := diffcmd.Run(ctx, cold, diffcmd.Options{Home: home, RendererVersion: "v1", SecretProvider: readonlyHomeClassifier{}}); err == nil {
					t.Fatal("authenticated tombstone admitted unrelated topology")
				}
				if err := os.WriteFile(path, actual, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("actual signed %s: clean/merged native pairs -> sealed SAME-ID %s fresh-runtime commit -> authenticated ledger/Settings/Diff; synthetic operator authority", action, id)
		})
	}
}

type contextFixtureClock struct{}

func (contextFixtureClock) Now() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }

type contextFixture struct {
	runtime    *trustload.Runtime
	selection  trustload.LaunchSelection
	input      contextsource.ContextSourceSelection
	objectRoot string
	policyPath string
	proofs     map[string]contextsource.ContextSourceProof
	files      map[string]map[string][]byte
}

func contextJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func contextWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(p), 0o700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, b, 0o600); e != nil {
		t.Fatal(e)
	}
}

func contextPin(p string, b []byte) trustload.FilePin {
	return trustload.FilePin{Path: p, SHA256: evidencecas.Digest(b)}
}

func contextRawHash(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func contextMerkle(h bootstrap.MerkleHash) string { return "sha256:" + hex.EncodeToString(h[:]) }

// Source objects and real publisher evidence are synthetic public data. The
// actual installed loader, stable runtime and SourceReader perform admission;
// no fixture snapshot/resolution/reader is supplied to the carrier.
func newContextFixture(t *testing.T, alter func(string, map[string][]byte)) *contextFixture {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	f := &contextFixture{objectRoot: filepath.Join(dir, "objects"), policyPath: filepath.Join(dir, "policy.json"), proofs: map[string]contextsource.ContextSourceProof{}, files: map[string]map[string][]byte{}}
	for _, p := range []string{f.objectRoot, filepath.Join(dir, "evidence"), filepath.Join(dir, "scratch")} {
		if e := os.Mkdir(p, 0o700); e != nil {
			t.Fatal(e)
		}
	}
	origin := "https://example.test/context-sources"
	subjects := map[string]trustverify.Subject{}
	add := func(kind string, data []byte) string {
		raw := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(data))), data...)
		h := sha1.Sum(raw)
		id := hex.EncodeToString(h[:])
		contextWrite(t, filepath.Join(f.objectRoot, id), raw)
		return id
	}
	var tree func(map[string][]byte, string) string
	tree = func(files map[string][]byte, prefix string) string {
		entries := map[string]bool{}
		for p := range files {
			if strings.HasPrefix(p, prefix) {
				rest := strings.TrimPrefix(p, prefix)
				name, _, nested := strings.Cut(rest, "/")
				entries[name] = entries[name] || nested
			}
		}
		names := []string{}
		for n := range entries {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool {
			a, b := names[i], names[j]
			if entries[a] {
				a += "/"
			}
			if entries[b] {
				b += "/"
			}
			return a < b
		})
		raw := []byte{}
		for _, name := range names {
			mode := "100644"
			id := ""
			if entries[name] {
				mode = "40000"
				id = tree(files, prefix+name+"/")
			} else {
				if strings.HasSuffix(prefix+name, "/formatter/native-tool") {
					mode = "100755"
				}
				id = add("blob", files[prefix+name])
			}
			oid, _ := hex.DecodeString(id)
			raw = append(raw, []byte(mode+" "+name+"\x00")...)
			raw = append(raw, oid...)
		}
		return add("tree", raw)
	}
	parameters := []deps.Parameter{{Name: "flavor", Value: json.RawMessage(`"plain"`)}}
	for _, alias := range []string{"leaf", "a", "b", "root"} {
		refs := []contextsource.ContextDependency{}
		associations := []contextsource.ContextDependencyBinding{}
		requirements := []exports.ExportRequirement{}
		depsAliases := []string{}
		if alias == "a" || alias == "b" {
			depsAliases = []string{"leaf"}
		}
		if alias == "root" {
			depsAliases = []string{"a", "b"}
		}
		for _, dep := range depsAliases {
			s := subjects[dep]
			refs = append(refs, contextsource.ContextDependency{Alias: dep, Origin: s.Origin, TemplatePath: s.TemplatePath, CommitAlgorithm: "sha1", Commit: s.Commit, TreeDigest: s.TreeSHA256, ContractDigest: s.ContractSHA256})
			associations = append(associations, contextsource.ContextDependencyBinding{Alias: dep, ProviderID: "provider." + dep, Parameters: parameters})
			requirements = append(requirements, exports.ExportRequirement{Selector: dep + ".block.notes", ContractDigest: s.ContractSHA256, CompatibleRange: ">=1.0.0 <2.0.0"})
		}
		manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: context-" + alias + "\n  version: 1.0.0\n  description: Public task context\nengine:\n  type: gotemplate\n  root: files\nsettings: []\n")
		if alias == "root" {
			manifest = append(manifest, []byte("generators:\n  - kind: entity\n    snippet: generators/entity.tmpl\n    target: entity.go\n")...)
		}
		var contract []byte
		if alias == "leaf" {
			contract = contextJSON(t, operationtrust.NativeContract{APIVersion: operationtrust.NativeContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: []string{}})
		} else {
			contract = contextJSON(t, contextsource.NativeContextContract{APIVersion: contextsource.NativeContextContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: refs})
		}
		binding := contextsource.ContextSourceBindings{APIVersion: contextsource.ContextSourceBindingsAPIVersion, Kind: "ContextSourceBindings", Source: contextsource.ContextCatalogBinding{Alias: alias, ProviderID: "provider." + alias, Parameters: parameters, EntriesPath: "catalog/entries.json", PayloadDirectory: "catalog/payloads", ToolPath: "catalog/tool.md"}, Dependencies: associations}
		content := []byte("Complete inert procedure for " + alias + ". Read every required prerequisite; no tool execution.\n")
		payload := contextJSON(t, exports.ExportPayload{APIVersion: exports.ExportPayloadAPIVersion, ExportID: "notes", Files: []exports.PayloadFile{{SourcePath: "docs/notes.md", TargetPath: "context/" + alias + ".md", Mode: "100644", ContentSHA256: evidencecas.Digest(content)}}, Slots: []exports.PayloadSlot{}, Blocks: []exports.PayloadBlock{}})
		tool := []byte("Inert file context only.\n")
		domain := "block"
		if alias == "root" {
			domain = "skill"
		}
		entry := exports.ExportEntry{ID: "notes", Domain: domain, Name: "notes", Version: "1.0.0", ContentDigest: evidencecas.Digest(payload), ToolDigest: evidencecas.Digest(tool), Parameters: []exports.ScalarParameter{}, Requires: requirements}
		files := map[string][]byte{"template.manifest.yaml": manifest, "template.contract.json": contract, contextsource.ContextSourceBindingsPath: contextJSON(t, binding), "catalog/entries.json": contextJSON(t, []exports.ExportEntry{entry}), "catalog/tool.md": tool, "catalog/payloads/notes.json": payload, "docs/notes.md": content, "files/hello.txt.tmpl": []byte("Hello public project.\n")}
		if alias == "root" {
			files["generators/entity.tmpl"] = []byte("type {{.Name}} struct{}\n")
			files["files/main.go.tmpl"] = []byte("package fixture\n// tplater:managed-begin id=body provider=root-content\nfunc F( ) int {return 1}\n// tplater:managed-end id=body\n")
		}
		if alias == "leaf" {
			toolBytes := testfixture.NewGofmtFixture(t).Tool()
			info, err := buildinfo.Read(bytes.NewReader(toolBytes))
			if err != nil {
				t.Fatal(err)
			}
			files["formatter/native-tool"] = toolBytes
			files["formatter/tool.json"], err = canonicaljson.Canonical(map[string]any{"apiVersion": "tplaiter.dev/formatter-tool/v1", "adapter": "gofmt-stdin-v1", "toolID": "gofmt", "toolVersion": strings.TrimPrefix(info.GoVersion, "go"), "binarySHA256": evidencecas.Digest(toolBytes), "versionEvidence": map[string]any{"kind": "go-buildinfo", "identity": info.GoVersion}, "nativeEnvelope": operationtrust.FormatterNativeEnvelope()})
			if err != nil {
				t.Fatal(err)
			}
		}
		if alter != nil {
			alter(alias, files)
		}
		f.files[alias] = files
		prefixed := map[string][]byte{}
		for name, raw := range files {
			prefixed[alias+"/"+name] = raw
		}
		root := tree(prefixed, "")
		commit := add("commit", []byte("tree "+root+"\n\nPublic context fixture\n"))
		reader, e := trustload.NewObjectReader([]trustload.ObjectOrigin{{Origin: origin, RootPath: f.objectRoot}})
		if e != nil {
			t.Fatal(e)
		}
		captured, e := trustverify.CaptureSource(context.Background(), reader, trustverify.SourceIdentity{Origin: origin, TemplatePath: alias, Commit: commit}, trustverify.DefaultSourceLimits())
		reader.Close()
		if e != nil {
			t.Fatal(e)
		}
		subjects[alias] = captured.Subject()
	}

	anchor := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	publisher := ed25519.NewKeyFromSeed([]byte("12345678901234567890123456789012"))
	approver := ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123"))
	var err error
	var policy trustverify.ExecutionPolicy
	evidence := map[string][]byte{}
	put := func(b []byte) string { d := evidencecas.Digest(b); evidence[d] = append([]byte(nil), b...); return d }
	anchorPub, publisherPub := anchor.Public().(ed25519.PublicKey), publisher.Public().(ed25519.PublicKey)
	rootRef := put([]byte(bootstrap.EncodePublicKey(publisherPub)))
	env := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: "t6b-authority", Sequence: 1, Validity: bootstrap.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(publisherPub), PublicKeyCAS: rootRef, Issuer: "publisher-1", Status: "active"}}, Threshold: 1, RevocationEpoch: 0, Revocations: []bootstrap.Revocation{}}
	if env.PayloadSHA256, err = env.ComputePayloadSHA256(); err != nil {
		t.Fatal(err)
	}
	payload, _ := hex.DecodeString(env.PayloadSHA256[7:])
	env.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchorPub), SignatureCAS: put([]byte(bootstrap.EncodeSignature(ed25519.Sign(anchor, payload))))}}
	envRef := put(contextJSON(t, env))

	aliases := []string{"a", "b", "leaf", "root"}
	leaves := []bootstrap.MerkleHash{bootstrap.HashLeaf([]byte(env.PayloadSHA256))}
	for _, alias := range aliases {
		subject := subjects[alias]
		statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Predicate: "https://example.test/predicate", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: subject.Origin, TemplatePath: subject.TemplatePath, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}}
		digest, e := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
		if e != nil {
			t.Fatal(e)
		}
		refs := operationtrust.SelectionEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: put(contextJSON(t, statement)), SignatureCAS: put([]byte(bootstrap.EncodeSignature(ed25519.Sign(publisher, contextRawHash(t, digest))))), KeyFingerprint: bootstrap.Fingerprint(publisherPub)}
		f.proofs[alias] = contextsource.ContextSourceProof{Subject: operationtrust.SelectionSubject{Origin: subject.Origin, TemplatePath: subject.TemplatePath, RequestedRef: subject.Commit, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}, Evidence: refs}
		leaves = append(leaves, bootstrap.HashLeaf([]byte(refs.StatementCAS)))
	}
	var merkle func([]bootstrap.MerkleHash) bootstrap.MerkleHash
	merkle = func(v []bootstrap.MerkleHash) bootstrap.MerkleHash {
		if len(v) == 1 {
			return v[0]
		}
		n := 1
		for n*2 < len(v) {
			n *= 2
		}
		return bootstrap.HashChildren(merkle(v[:n]), merkle(v[n:]))
	}
	var inclusion func([]bootstrap.MerkleHash, int) []string
	inclusion = func(v []bootstrap.MerkleHash, i int) []string {
		if len(v) == 1 {
			return []string{}
		}
		n := 1
		for n*2 < len(v) {
			n *= 2
		}
		if i < n {
			return append(inclusion(v[:n], i), contextMerkle(merkle(v[n:])))
		}
		return append(inclusion(v[n:], i-n), contextMerkle(merkle(v[:n])))
	}
	checkpointRef := put(contextJSON(t, bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: env.AuthorityID, TreeSize: uint64(len(leaves)), RootHash: contextMerkle(merkle(leaves))}))
	envProof := put(contextJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: uint64(len(leaves)), Hashes: inclusion(leaves, 0)}))
	for i, alias := range aliases {
		p := f.proofs[alias]
		p.Evidence.CheckpointCAS = checkpointRef
		p.Evidence.InclusionProofCAS = put(contextJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: uint64(i + 1), TreeSize: uint64(len(leaves)), Hashes: inclusion(leaves, i+1)}))
		f.proofs[alias] = p
	}
	f.input = contextsource.ContextSourceSelection{APIVersion: contextsource.ContextSourceSelectionAPIVersion, Root: f.proofs["root"], Sources: []contextsource.ContextSourceProof{f.proofs["a"], f.proofs["b"], f.proofs["leaf"]}}
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: env.AuthorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, TreeSize: uint64(len(leaves)), CheckpointDigest: checkpointRef}
	if receipt.ReceiptDigest, err = receipt.ComputeDigest(); err != nil {
		t.Fatal(err)
	}
	receiptRef := put(contextJSON(t, receipt))
	scopes := []bootstrap.PublisherScope{}
	for _, alias := range aliases {
		scopes = append(scopes, bootstrap.PublisherScope{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", SourceOrigin: origin, TemplatePath: alias, Predicate: "https://example.test/predicate", Usage: "template-source"})
	}
	desc := bootstrap.DescriptorDocument{APIVersion: bootstrap.DescriptorAPIVersion, Profile: bootstrap.ProfileOSS, AuthorityID: env.AuthorityID, Anchors: []bootstrap.DescriptorAnchor{{Fingerprint: bootstrap.Fingerprint(anchorPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(anchorPub)}}, Threshold: 1, AllowedPolicyOrigins: []string{"https://example.test/policy"}, PublisherScopes: scopes}
	desc.DescriptorSHA256 = desc.ComputedSHA256()
	opRecord := trustload.OperatorPinRecord{APIVersion: trustload.OperatorPinRecordAPIVersion, Method: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256}
	opRaw := contextJSON(t, opRecord)
	prov := bootstrap.ProvisioningRecord{APIVersion: bootstrap.ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256, AuthenticationEvidenceSHA256: evidencecas.Digest(opRaw), EvidenceClass: bootstrap.EvidenceSimulated}
	prov.ProvisioningSHA256 = prov.ComputedSHA256()
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: desc.DescriptorSHA256, ProvisioningSHA256: prov.ProvisioningSHA256, AuthorityID: env.AuthorityID, Sequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, ReceiptDigest: receipt.ReceiptDigest, TreeSize: uint64(len(leaves)), CheckpointDigest: checkpointRef}
	state.StateSHA256 = state.ComputedSHA256()
	approverPub := approver.Public().(ed25519.PublicKey)
	policy = trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "t6b-policy", Profile: "oss", MinimumProfile: "oss", Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Principals: []trustverify.Principal{{ID: "principal:approver"}, {ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []trustverify.IssuerPrincipal{{Issuer: "publisher-1", PrincipalID: "principal:publisher"}}, SourceRules: []trustverify.SourceRule{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: origin, TemplatePath: ".", Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"}}, Approvers: []trustverify.Approver{{ID: "t6b-approver", PrincipalID: "principal:approver", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(approverPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(approverPub), Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Scopes: []trustverify.ApprovalScope{{ProjectID: "project-t6b", OperationScope: "new", ActionKind: "formatter", Origin: origin, TemplatePath: "root"}}}}, AllowInvocationHuman: false, MaxTimeoutMillis: 5000}
	if policy.PolicySHA256, err = policy.ComputePolicySHA256(); err != nil {
		t.Fatal(err)
	}
	policy.SourceRules = []trustverify.SourceRule{}
	for _, alias := range aliases {
		policy.SourceRules = append(policy.SourceRules, trustverify.SourceRule{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: origin, TemplatePath: alias, Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"})
	}
	if policy.PolicySHA256, err = policy.ComputePolicySHA256(); err != nil {
		t.Fatal(err)
	}
	descRaw, provRaw, policyRaw := contextJSON(t, desc), contextJSON(t, prov), contextJSON(t, policy)
	for p, b := range map[string][]byte{filepath.Join(dir, "descriptor.json"): descRaw, filepath.Join(dir, "provisioning.json"): provRaw, filepath.Join(dir, "operator.json"): opRaw, filepath.Join(dir, "policy.json"): policyRaw, filepath.Join(dir, "state.json"): contextJSON(t, state)} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := trustload.StoredBundle{APIVersion: "tplaiter.dev/stored-bootstrap-bundle/v1", EnvelopeCAS: envRef, ReceiptCAS: receiptRef, Transparency: trustload.StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: envProof}}
	bundleRaw := contextJSON(t, bundle)
	bundleDigest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	install := trustload.RuntimeInstall{APIVersion: trustload.RuntimeInstallAPIVersion, InstallationID: "t6b-install", Profile: bootstrap.ProfileOSS, MinimumProfile: bootstrap.ProfileOSS, Descriptor: contextPin(filepath.Join(dir, "descriptor.json"), descRaw), Provisioning: contextPin(filepath.Join(dir, "provisioning.json"), provRaw), OperatorRecord: contextPin(filepath.Join(dir, "operator.json"), opRaw), ExecutionPolicy: contextPin(filepath.Join(dir, "policy.json"), policyRaw), ProjectContexts: []trustload.ProjectContext{{Key: "project", ProjectID: "project-t6b", SubmitterPrincipalID: "principal:submitter", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(dir, "project")}}, ObjectOrigins: []trustload.ObjectOrigin{{Origin: origin, RootPath: filepath.Join(dir, "objects")}}, EvidenceRoot: filepath.Join(dir, "evidence"), ScratchRoot: filepath.Join(dir, "scratch"), OSS: &trustload.OSSInstall{StorePath: filepath.Join(dir, "store"), InitialStatePath: filepath.Join(dir, "state.json"), InitialStateSHA256: state.StateSHA256, InitialBundlePath: filepath.Join(dir, "bundle.json"), InitialBundleSHA256: bundleDigest}}
	installRaw := contextJSON(t, install)
	installPath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(installPath, installRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	installDigest, err := install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f.selection = trustload.LaunchSelection{Profile: bootstrap.ProfileOSS, RuntimeConfig: trustload.FilePin{Path: installPath, SHA256: installDigest}, OperatorRecord: install.OperatorRecord, InstallationID: install.InstallationID}
	factory := func(r evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(r, contextFixtureClock{}, nil, 0)
	}
	if err := trustload.Enroll(context.Background(), f.selection, factory, contextJSON(t, state), bundleRaw, evidence); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	runtime, e := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: contextFixtureClock{}})
	if e != nil {
		t.Fatal(e)
	}
	f.input = contextsource.ContextSourceSelection{APIVersion: contextsource.ContextSourceSelectionAPIVersion, Root: f.proofs["root"], Sources: []contextsource.ContextSourceProof{f.proofs["a"], f.proofs["b"], f.proofs["leaf"]}}
	f.runtime = runtime
	t.Cleanup(func() { runtime.Close() })
	return f
}

func TestContextManagedNewInstalledCLIAndMCP(t *testing.T) {
	for _, channel := range []string{"cli", "mcp"} {
		t.Run(channel, func(t *testing.T) {
			dag := newContextFixture(t, nil)
			baseDir := filepath.Dir(dag.policyPath)
			var actualPolicy trustverify.ExecutionPolicy
			policyRaw, err := os.ReadFile(dag.policyPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(policyRaw, &actualPolicy); err != nil {
				t.Fatal(err)
			}
			rootProof := dag.proofs["root"]
			rootSelection := operationtrust.SourceSelection{Subject: rootProof.Subject, Evidence: rootProof.Evidence}
			f := &managedNewIntegrationFixture{dir: baseDir, project: dag.runtime.ProjectContext().RootPath, scratch: dag.runtime.ScratchRoot(), evidence: filepath.Join(baseDir, "evidence"), selection: dag.selection, policy: actualPolicy, approver: ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123")), source: rootSelection.TrustSubject()}
			if err := dag.runtime.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.project, 0o755); err != nil {
				t.Fatal(err)
			}
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
			ctx, cancel := context.WithTimeout(context.Background(), 175*time.Second)
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
			sourceRaw := contextJSON(t, dag.input)
			if err := os.WriteFile(sourcePath, sourceRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			leaf := dag.proofs["leaf"]
			toolRaw := contextJSON(t, operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: leaf.Subject, Evidence: leaf.Evidence, Dependencies: []string{}})
			selected, err := operationtrust.DecodeSourceSelection(toolRaw)
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
			if err != nil || !bytes.Contains(rendered, []byte("func F()")) || !bytes.Contains(rendered, []byte("tplater:managed-begin")) {
				t.Fatalf("normal managed New: %v %s", err, rendered)
			}
			if _, err := os.Stat(filepath.Join(f.project, ".tplaiter", "managed-lineage.json")); err != nil {
				t.Fatal("missing admitted clean lineage")
			}

			rootRaw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/root-template.lock.json"))
			if err != nil {
				t.Fatal(err)
			}
			depRaw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/template.lock.json"))
			if err != nil {
				t.Fatal(err)
			}
			rootLock, err := provenance.DecodeRootTemplateLock(rootRaw)
			if err != nil {
				t.Fatal(err)
			}
			dependencyLock, err := provenance.DecodeTemplateLock(depRaw)
			if err != nil || len(dependencyLock.Dependencies) != 3 || provenance.ValidateLockPair(*rootLock, *dependencyLock) != nil {
				t.Fatal("complete installed DAG lock", err)
			}
			lineage, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/managed-lineage.json"))
			if err != nil || !bytes.Contains(lineage, []byte("tplaiter.dev/managed-lineage/v2")) {
				t.Fatal("v2 publication lineage", err)
			}
			resource, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/generators/generators/entity.tmpl"))
			if err != nil || len(resource) == 0 {
				t.Fatal("real root generator image", err)
			}
			t.Log("actual installed v2 New: CLI/MCP prepare -> two distinct approved native effects -> source-owned project/registry publication, full DAG and root generator images; synthetic operator authority")
		})
	}
}

func TestManagedUpdateInstalledCLIAndMCP(t *testing.T) {
	for _, channel := range []string{"cli", "mcp", "cold-cli"} {
		t.Run(channel, func(t *testing.T) {
			action := "rename"
			writer := func(t *testing.T, root, suffix, output, extra string) ([]byte, trustverify.Subject) {
				files := map[string][]byte{"main.go.tmpl": []byte("package fixture\n")}
				if action == "rename" {
					extra += "managedBlocks:\n  version: 1\n  replacements:\n    - path: main.go\n      provider: root\n      oldID: body\n      newID: next\n"
					files["main.go.tmpl"] = []byte("package fixture\n// tplater:managed-begin id=next provider=root\nfunc f(){ }\n// tplater:managed-end id=next\n")
				}
				if suffix != "target" {
					extra = ""
				}
				return managedNewWriteNativeSourceFiles(t, root, suffix, output, extra, files)
			}
			f := managedNativeIntegrationFixtureWithScope(t, "link-update", writer)
			ctx, cancel := context.WithTimeout(context.Background(), 170*time.Second)
			defer cancel()
			r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			homeBase := filepath.Join(f.dir, "process-home")
			home := filepath.Join(homeBase, "tplaiter")
			if err := os.MkdirAll(home, 0o700); err != nil {
				t.Fatal(err)
			}
			source := managedNewSelection(f.source, f.sourceRefs)
			target := managedNewSelection(f.target, f.targetRefs)
			native, err := newcmd.PrepareNativeContext(ctx, newcmd.Options{Ref: f.source.Commit, ProjectName: "Managed", Dir: f.project, Defaults: true, CLIVersion: "v1"}, newcmd.Deps{Runtime: r, Home: home, SourceInput: source})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := newimages.Build(*native)
			if err != nil {
				t.Fatal(err)
			}
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
			}
			linked, err := linkcmd.PrepareManaged(ctx, r, home, linkcmd.Input{Action: "link", Ref: f.source.Commit, Name: "Managed", Source: source, Choices: map[string]string{}, Managed: &linkcmd.ManagedInput{APIVersion: "tplaiter.dev/managed-link-input/v1", ToolSource: source}}, "v1")
			if err != nil {
				t.Fatal(err)
			}
			requests, err := linked.Requests(ctx)
			if err != nil {
				t.Fatal(err)
			}
			approvals := map[string]trustverify.ApprovalRefs{}
			for _, q := range requests {
				approvals[q.RequestSHA256] = managedNewApprove(t, f, q)
			}
			if err := linked.Stage(ctx, approvals); err != nil {
				t.Fatal(err)
			}
			linkPlan, err := linkcmd.Prepare(ctx, r, home, linked.Input(), "v1")
			if err != nil {
				t.Fatal(err)
			}
			tx, err := linktx.Begin(ctx, linkPlan, linkPlan.Fingerprint(), "v1")
			if err != nil {
				if tx != nil {
					tx.Release()
				}
				t.Fatal(err)
			}
			err = tx.Commit(ctx)
			tx.Release()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.project, "main.go")
			old, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ours := bytes.ReplaceAll(old, []byte("func f() {}"), []byte("func f() { println(1) }"))
			if bytes.Equal(ours, old) {
				t.Fatal("missing local edit")
			}
			if err := os.WriteFile(path, ours, 0o644); err != nil {
				t.Fatal(err)
			}
			lockRaw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/root-template.lock.json"))
			if err != nil {
				t.Fatal(err)
			}
			sourceLock, err := provenance.DecodeRootTemplateLock(lockRaw)
			if err != nil {
				t.Fatal(err)
			}
			blocksRaw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/managed-blocks.json"))
			if err != nil {
				t.Fatal(err)
			}
			blocks, err := managedblocks.ParseBaseline(blocksRaw)
			if err != nil {
				t.Fatal(err)
			}
			render := renderref.Input{Repo: "pinned", Values: settings.Values{"label": "ok"}, Project: manifest.ProjectInfo{Name: "Managed", Slug: "managed"}}
			targetSnapshot, err := operationtrust.PrepareSnapshot(ctx, r, operationtrust.PrepareSnapshotInput{SourceInput: target, Render: render, RendererVersion: "v1"})
			if err != nil {
				t.Fatal(err)
			}
			d := managedblocks.Decision{Action: action, Path: "main.go", Provider: "root", OldID: "body", SourceRootLockSHA256: sourceLock.RootLockSHA256, TargetRootLockSHA256: targetSnapshot.RootLock().RootLockSHA256, BaselineBodySHA256: blocks.Files["main.go"].Blocks["body"].BodySHA256, ObservedFileSHA256: evidencecas.Digest(ours)}
			if action == "rename" {
				d.NewID = "next"
				formatted, err := format.Source(targetSnapshot.Rendered().Files["main.go"])
				if err != nil {
					t.Fatal(err)
				}
				doc, err := managedblocks.Parse("main.go", formatted)
				if err != nil {
					t.Fatal(err)
				}
				d.TargetBodySHA256 = evidencecas.Digest(doc.ByID["next"].Body)
			}
			decisionRaw, err := canonicaljson.Canonical(managedblocks.Decisions{APIVersion: managedblocks.DecisionsAPIVersion, Decisions: []managedblocks.Decision{d}})
			if err != nil {
				t.Fatal(err)
			}

			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			base := f.dir
			registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
			registrationRaw := managedNewJSON(t, registration)
			registrationPath := filepath.Join(base, "registration.json")
			if err := os.WriteFile(registrationPath, registrationRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(base, "tplaiter")
			build := exec.CommandContext(ctx, testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=v1 -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+evidencecas.Digest(registrationRaw), "-o", binary, ".")
			build.Dir = filepath.Join("..", "..")
			build.Env = append(testBuildEnv(homeBase), "PYTHONDONTWRITEBYTECODE=1")
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("installed build: %v %s", err, out)
			}
			image, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("actual installed Update image=%s registration=%s channel=%s", evidencecas.Digest(image), evidencecas.Digest(registrationRaw), channel)
			targetPath := filepath.Join(base, "update-target.json")
			decisionPath := filepath.Join(base, "update-decisions.json")
			formatPath := filepath.Join(base, "update-format.json")
			for path, raw := range map[string][]byte{targetPath: target, decisionPath: decisionRaw} {
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			tool, err := operationtrust.DecodeSourceSelection(source)
			if err != nil {
				t.Fatal(err)
			}
			controls := FormatInput{APIVersion: FormatInputAPIVersion, ToolSource: *tool, Approvals: []FormatApproval{}}
			writeControls := func(path string, v FormatInput) {
				t.Helper()
				if err := os.WriteFile(path, managedNewJSON(t, v), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeControls(formatPath, controls)
			runRaw := func(args ...string) (resultdto.Result, error) {
				c := exec.CommandContext(ctx, binary, args...)
				c.Dir = base
				c.Env = append(testProcessEnv(homeBase), "PYTHONDONTWRITEBYTECODE=1")
				out, runErr := c.Output()
				var env resultdto.Result
				if err := json.Unmarshal(out, &env); err != nil {
					t.Fatalf("installed envelope: %v %s run=%v", err, out, runErr)
				}
				if runErr != nil {
					for _, d := range env.Diagnostics {
						t.Logf("actual refusal %s: %s", d.Code, d.Message)
					}
				}
				return env, runErr
			}
			runCLI := func(phase, format string) (resultdto.Result, error) {
				args := []string{"update", "--dir", f.project, "--to", f.target.Commit, "--source-input", targetPath, "--format-input", format, "--decisions-input", decisionPath, "--json"}
				if phase != "" {
					args = append(args, "--"+phase)
				}
				env, err := runRaw(args...)
				t.Logf("actual Update CLI phase=%s status=%s", phase, env.Status)
				return env, err
			}
			call := runCLI
			if channel == "mcp" {
				server := exec.CommandContext(ctx, binary, "mcp-server")
				server.Dir = base
				server.Env = append(testProcessEnv(homeBase), "PYTHONDONTWRITEBYTECODE=1")
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

				if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); err != nil {
					t.Fatal(err)
				}
				call = func(phase string, path string) (resultdto.Result, error) {
					args := map[string]any{"to": f.target.Commit, "dir": f.project, "sourceInput": targetPath, "formatInput": path, "decisionsInput": decisionPath}
					if phase == "prepare" {
						args["prepare"] = true
					}
					if phase == "format-stage" {
						args["formatStage"] = true
					}
					raw := request("tools/call", map[string]any{"name": "update", "arguments": args})
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
					t.Logf("MCP phase=%s operation=%s status=%s diagnostics=%v", phase, env.Operation, env.Status, env.Diagnostics)
					if result.IsError {
						return env, fmt.Errorf("MCP application refusal")
					}
					return env, nil
				}
			}

			if _, err := call("", formatPath); err == nil {
				t.Fatal("publication before real formatter effects admitted")
			}
			for _, want := range []string{"clean-target", "merged-candidate"} {
				env, err := call("prepare", formatPath)
				if err != nil {
					t.Fatal(err)
				}
				var requests []trustverify.ExecutionRequest
				phase := ""
				for _, d := range env.Diagnostics {
					if d.Code == "TPL-I-MANAGED-UPDATE-PHASE" {
						phase, _ = d.Details["phase"].(string)
						if err := json.Unmarshal(managedNewJSON(t, d.Details["requests"]), &requests); err != nil {
							t.Fatal(err)
						}
					}
				}
				if phase != want || len(requests) != 2 || requests[0].Action.ID == requests[1].Action.ID {
					t.Fatal("actual Update phase/request mismatch", phase, len(requests))
				}
				if _, err := call("format-stage", formatPath); err == nil {
					t.Fatal("missing approvals accepted")
				}
				approved := controls
				for _, q := range requests {
					if q.Scope != "update" {
						t.Fatal("foreign purpose")
					}
					ref := managedNewApprove(t, f, q)
					approved.Approvals = append(approved.Approvals, FormatApproval{RequestSHA256: q.RequestSHA256, ApprovalCAS: ref.ApprovalCAS})
				}
				stagePath := filepath.Join(base, "update-stage-"+want+".json")
				writeControls(stagePath, approved)
				if _, err := call("format-stage", stagePath); err != nil {
					t.Fatal(err)
				}
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, ours) {
					t.Fatal("formatter stage published project", err)
				}
			}
			observedRuntime, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: bootstrap.ClockFunc(time.Now)})
			if err != nil {
				t.Fatal(err)
			}
			backend, err := updateplan.New(observedRuntime, home, "v1")
			if err != nil {
				t.Fatal(err)
			}
			input := updateplan.Input{SourceInput: source, TargetInput: target, Managed: &updateplan.ManagedInput{ToolSource: source, Decisions: decisionRaw}}
			effects, err := backend.PrepareManagedEffects(ctx, input, *input.Managed)
			if err != nil {
				t.Fatal(err)
			}
			phase, pending, err := effects.PhaseRequests(ctx)
			if err != nil || phase != "complete" || len(pending) != 0 {
				t.Fatal("completed actual effects pending", err)
			}
			report, err := effects.Report(ctx)
			if err != nil {
				t.Fatal(err)
			}
			type retained struct {
				raw  []byte
				info os.FileInfo
			}
			records := map[string]retained{}
			for _, refs := range []map[string]formatproof.Reference{report.CleanFrames, report.CandidateFrames} {
				for _, ref := range refs {
					for ordinal := 1; ordinal <= 2; ordinal++ {
						name := filepath.Join(observedRuntime.ScratchRoot(), "formatter-evidence", strings.TrimPrefix(ref.FrameSHA256, "sha256:"), fmt.Sprintf("pass-%d-completed.json", ordinal))
						raw, err := os.ReadFile(name)
						if err != nil {
							t.Fatal(err)
						}
						info, err := os.Stat(name)
						if err != nil {
							t.Fatal(err)
						}
						records[name] = retained{raw, info}
					}
				}
			}
			expectedID := ""
			if channel == "cold-cli" {
				plan, err := backend.Prepare(ctx, input)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := projecttransaction.BeginUpdate(ctx, plan, plan.Fingerprint())
				if err != nil {
					if tx != nil {
						tx.Release()
					}
					t.Fatal(err)
				}
				expectedID = tx.ID()
				tx.Release()
			}
			if err := observedRuntime.Close(); err != nil {
				t.Fatal(err)
			}
			var published resultdto.Result
			if channel == "cold-cli" {
				published, err = runRaw("update", "continue", expectedID, "--dir", f.project, "--json")
			} else {
				published, err = call("", formatPath)
			}
			if err != nil {
				t.Fatal("actual publication", err)
			}
			if published.TransactionID == nil || *published.TransactionID == "" || expectedID != "" && *published.TransactionID != expectedID {
				t.Fatal("actual transaction ID missing/changed")
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, report.CandidateFiles["main.go"]) {
				t.Fatal("actual candidate publication", err)
			}
			for name, old := range records {
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(name)
				if err != nil || !bytes.Equal(raw, old.raw) || !os.SameFile(info, old.info) || !info.ModTime().Equal(old.info.ModTime()) {
					t.Fatal("completed formatter effect replaced/rerun", err)
				}
			}
			for _, args := range [][]string{{"settings", "list", "--dir", f.project, "--json"}, {"diff", "--dir", f.project, "--json"}} {
				if _, err := runRaw(args...); err != nil {
					t.Fatal("actual postupdate installed reader", args[0], err)
				}
			}
			t.Logf("actual installed %s Update: clean/merged native two-pass phases, signed rename, project/registry commit SAME-ID=%s and authenticated readers; completed effect bytes/inodes/timestamps unchanged; synthetic operator authority", channel, *published.TransactionID)
		})
	}
}

// Recovery consumes the actual sealed owner carrier in a fresh installed process.
// Both attempts reuse completed native effects; abort and continue have distinct
// operation IDs, each retained unchanged across its own cold boundary.
func TestContextManagedNewInstalledRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 290*time.Second)
	defer cancel()
	f := newContextFixture(t, nil)
	r := f.runtime
	target := r.ProjectContext().RootPath
	base := filepath.Dir(f.policyPath)
	processHome := filepath.Join(base, "process-home")
	home := filepath.Join(processHome, "tplaiter")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r.ProjectContext().RootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
	registrationRaw := managedNewJSON(t, registration)
	registrationPath := filepath.Join(base, "registration.json")
	if err := os.WriteFile(registrationPath, registrationRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(base, "tplaiter")
	build := exec.CommandContext(ctx, testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=1.0.0 -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+evidencecas.Digest(registrationRaw), "-o", binary, ".")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(testBuildEnv(processHome), "PYTHONDONTWRITEBYTECODE=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("installed recovery build: %v %s", err, out)
	}
	image, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("installed recovery image=%s registration=%s", evidencecas.Digest(image), evidencecas.Digest(registrationRaw))
	leaf := f.proofs["leaf"]
	tool := operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: leaf.Subject, Evidence: leaf.Evidence, Dependencies: []string{}}
	input := formatproof.NewCleanInput{APIVersion: "tplaiter.dev/managed-new-clean-input/v2", Home: home, Ref: f.input.Root.Subject.Commit, SourceInput: contextJSON(t, f.input), ToolSource: contextJSON(t, tool), Render: renderref.Input{Repo: "pinned", Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}, Runtime: manifest.ProjectRuntime{Port: 8080}}, RendererVersion: "1.0.0", Origins: map[string]survey.Source{}}
	p, err := formatproof.PrepareNewClean(ctx, r, input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var policy trustverify.ExecutionPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	owner := &managedNewIntegrationFixture{policy: policy, approver: ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123")), evidence: filepath.Join(base, "evidence")}
	approvals := map[string]trustverify.ApprovalRefs{}
	for _, request := range p.Requests() {
		approvals[request.RequestSHA256] = managedNewApprove(t, owner, request)
	}
	clean, err := formatproof.StageNewClean(ctx, p, approvals)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := formatproof.BuildNewPublication(ctx, p, clean)
	if err != nil {
		t.Fatal(err)
	}
	reference := pub.Reference()
	type effect struct {
		raw  []byte
		info os.FileInfo
	}
	effects := map[string]effect{}
	for _, ref := range p.References() {
		for ordinal := 1; ordinal <= 2; ordinal++ {
			path := filepath.Join(r.ScratchRoot(), "formatter-evidence", strings.TrimPrefix(ref.FrameSHA256, "sha256:"), fmt.Sprintf("pass-%d-completed.json", ordinal))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			effects[path] = effect{raw, info}
		}
	}
	for _, operation := range []string{"abort", "continue"} {
		if pub == nil {
			pub, err = formatproof.OpenNewPublication(ctx, r, reference)
			if err != nil {
				t.Fatal(err)
			}
		}
		tx, projection, err := newtransaction.BeginManagedPublication(ctx, r, pub)
		if err != nil {
			t.Fatal(err)
		}
		id := tx.ID()
		for name, raw := range projection.Images {
			path := filepath.Join(tx.Workspace(), filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				tx.Release()
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				tx.Release()
				t.Fatal(err)
			}
		}
		if err := tx.SealOutputs(); err != nil {
			tx.Release()
			t.Fatal(err)
		}
		plan := newtransaction.RegistryPlan{Home: projection.Home, Before: projection.RegistryBefore, After: projection.RegistryAfter}
		if operation == "abort" {
			altered := plan
			altered.After = append(append([]byte(nil), plan.After...), ' ')
			if err := tx.PrepareRegistry(altered); err == nil {
				tx.Release()
				t.Fatal("returned projection bypassed exact registry publication binding")
			}
		}
		if err := tx.PrepareRegistry(plan); err != nil {
			tx.Release()
			t.Fatal(err)
		}
		tx.Release()
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		c := exec.CommandContext(ctx, binary, "new", operation, id, "--json")
		c.Dir = base
		c.Env = append(testProcessEnv(processHome), "PYTHONDONTWRITEBYTECODE=1")
		out, runErr := c.Output()
		var env resultdto.Result
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatalf("cold envelope: %v %s run=%v", err, out, runErr)
		}
		if runErr != nil {
			t.Fatalf("cold %s: %v diagnostics=%v", operation, runErr, env.Diagnostics)
		}
		if env.TransactionID == nil || *env.TransactionID != id {
			t.Fatal("cold recovery changed transaction ID")
		}
		if _, err := newtransaction.Load(home, id); !errors.Is(err, newtransaction.ErrNoActive) {
			t.Fatalf("terminal carrier cleanup: %v", err)
		}
		for path, old := range effects {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || !bytes.Equal(raw, old.raw) || !os.SameFile(info, old.info) || !info.ModTime().Equal(old.info.ModTime()) {
				t.Fatal("completed native effect replaced/rerun", err)
			}
		}
		if operation == "continue" {
			for name, want := range projection.Images {
				actual, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(name)))
				if err != nil || !bytes.Equal(actual, want) {
					t.Fatalf("cold published image %s: %v", name, err)
				}
			}
		}
		t.Logf("actual installed v2 %s SAME-ID=%s schema3 owner carrier, completed effects bytes/inodes/timestamps unchanged; synthetic operator authority", operation, id)
		if operation == "abort" {
			r, err = trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: contextFixtureClock{}})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			pub = nil
		}
	}
}
