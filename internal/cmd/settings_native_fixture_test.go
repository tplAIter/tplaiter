package cmd

import (
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// Synthetic signed native settings use public test keys and the actual
// installed registration/provisioning path. Conditional files and transitive
// requires exercise same-version changes without repository discovery.
func nativeSettingsFixture(t *testing.T, targetExtra ...string) t5FFixture {
	t.Helper()
	options := t5FFixtureOptions{Now: time.Now().UTC()}
	base := "/private/tmp"
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
	_, source := nativeSettingsSource(t, filepath.Join(dir, "objects"), "source", targetExtra...)
	_, target := nativeSettingsSource(t, filepath.Join(dir, "objects"), "target", targetExtra...)
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

func nativeSettingsSource(t *testing.T, root, suffix string, extra ...string) ([]byte, trustverify.Subject) {
	t.Helper()
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: settings-" + suffix + "\n  version: 1.0.0\n  description: fixture\nengine:\n  type: gotemplate\n  root: files\n" + `settings:
  - group: label
    title: Label
    type: string
    default: alpha
  - group: tls
    title: TLS
    type: toggle
    default: false
  - group: storage
    title: Storage
    type: select
    default: none
    options:
      - id: none
        title: None
      - id: postgres
        title: PostgreSQL
        requires: ["tls=true"]
  - group: feature
    title: Feature
    type: select
    default: basic
    options:
      - id: basic
        title: Basic
      - id: advanced
        title: Advanced
        requires: ["storage=postgres"]
  - group: database
    title: Database
    type: select
    default: postgres
    options:
      - {id: none, title: None}
      - {id: postgres, title: PostgreSQL}
generators:
  - kind: entity
    snippet: generators/entity.tmpl
    target: entity.txt
`)
	for _, raw := range extra {
		manifest = append(manifest, []byte(raw)...)
	}
	h := sha256.Sum256(manifest)
	contract := []byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"sha256:` + hex.EncodeToString(h[:]) + `","dependencies":[]}`)
	files := map[string][]byte{"files/__if_database=postgres__/schema.sql": []byte("schema clean\n"), "files/__if_database=postgres__/seed.sql": []byte("seed clean\n"), "generators/entity.tmpl": []byte("signed frozen generator\n"), "template.manifest.yaml": manifest, "template.contract.json": contract, "files/hello.txt.tmpl": []byte("base one\n{{ index .Settings \"label\" }}\nbase three\n"), "files/__if_feature=basic__/basic.txt": []byte("old clean\n"), "files/__if_feature=advanced__/advanced.txt": []byte("new advanced\n")}
	objects := map[string][]byte{}
	add := func(kind string, data []byte) string {
		raw := append([]byte(kind+" "+t5FItoa(len(data))+"\x00"), data...)
		sum := sha1.Sum(raw)
		id := hex.EncodeToString(sum[:])
		objects[id] = raw
		return id
	}
	var tree func(string) string
	dirs := map[string]bool{}
	tree = func(prefix string) string {
		var entries []t5FTreeEntry
		children := map[string]bool{}
		for name, data := range files {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			rest := strings.TrimPrefix(name, prefix)
			child, _, nested := strings.Cut(rest, "/")
			if nested {
				if !children[child] {
					children[child] = true
					dirs[prefix+child] = true
					entries = append(entries, t5FTreeEntry{mode: "40000", name: child, oid: tree(prefix + child + "/")})
				}
			} else {
				entries = append(entries, t5FTreeEntry{mode: "100644", name: rest, oid: add("blob", data)})
			}
		}
		return t5FTree(add, entries)
	}
	rootID := tree("")
	commit := add("commit", []byte("tree "+rootID+"\n\nauthor settings <settings@example.test> 0 +0000\n"))
	for id, raw := range objects {
		if err := os.WriteFile(filepath.Join(root, id), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries := []trustverify.SourceEntry{}
	for name, data := range files {
		entries = append(entries, trustverify.SourceEntry{Path: name, Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(data)})
	}
	for name := range dirs {
		entries = append(entries, trustverify.SourceEntry{Path: name, Kind: "directory", Mode: "40000"})
	}
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
