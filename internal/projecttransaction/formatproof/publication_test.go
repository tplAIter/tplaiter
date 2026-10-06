package formatproof

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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/blockformatter"
	"github.com/tplAIter/tplaiter/internal/blockmarkers"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/survey"
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

func TestManagedNewCleanActualSignedSource(t *testing.T) {
	f := managedNewNewIntegrationFixture(t)
	r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	home := filepath.Join(f.dir, "home")
	if err = os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	input := NewCleanInput{APIVersion: "tplaiter.dev/managed-new-clean-input/v1", Home: home, Ref: f.source.Commit, SourceInput: managedNewSelection(f.source, f.sourceRefs), ToolSource: managedNewSelection(f.source, f.sourceRefs), Render: renderref.Input{Values: settings.Values{"label": "ok"}, Project: manifest.ProjectInfo{Name: "Managed", Slug: "managed", Module: "example.test/managed"}, Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: "pinned"}, RendererVersion: "v1", Origins: map[string]survey.Source{"label": survey.SourceDefault}}
	p, err := PrepareNewClean(context.Background(), r, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Requests()) != 2 {
		t.Fatal("missing two actual New requests")
	}
	if pending, err := p.RequiredRequests(context.Background()); err != nil || len(pending) != 2 {
		t.Fatalf("fresh New pending requests: %v %+v", err, pending)
	}
	if _, err = OpenNewClean(context.Background(), p, p.References()); err == nil {
		t.Fatal("absent effects accepted")
	}
	before, err := os.ReadDir(f.project)
	if err != nil || len(before) != 0 {
		t.Fatal("prepare modified project")
	}
	for _, q := range p.Requests() {
		if q.Scope != "new" || q.Action.Kind != "formatter" {
			t.Fatal("wrong actual New scope")
		}
	}
	approvals := map[string]trustverify.ApprovalRefs{}
	for _, request := range p.Requests() {
		approvals[request.RequestSHA256] = managedNewApprove(t, f, request)
	}
	projection, err := StageNewClean(context.Background(), p, approvals)
	if err != nil {
		t.Fatal(err)
	}
	images, err := projection.ImagesFor(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if string(images["main.go"]) == string(p.context.Result.Files["main.go"]) {
		t.Fatal("actual New formatter output missing")
	}
	if bytes.Equal(images[".tplaiter/managed-blocks.json"], []byte(`{"files":{},"schema":1}`)) {
		t.Fatal("managed clean baseline missing")
	}
	cold, err := PrepareNewClean(context.Background(), r, input)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := cold.RequiredRequests(context.Background()); err != nil || len(pending) != 0 {
		t.Fatalf("completed New requests resurrected: %v %+v", err, pending)
	}
	if _, err := StageNewClean(context.Background(), cold, approvals); err == nil {
		t.Fatal("unused completed-pass approval imports accepted")
	}
	// Actual completed pairs reconstruct with no new grant or execution. Hold
	// both completed record identities and bytes across the explicit cold call.
	records := map[string][]byte{}
	identities := map[string]os.FileInfo{}
	for _, path := range cold.paths {
		frame := strings.TrimPrefix(cold.formats[path].digest, "sha256:")
		for ordinal := 1; ordinal <= 2; ordinal++ {
			name := filepath.Join(f.scratch, "formatter-evidence", frame, "pass-"+strconv.Itoa(ordinal)+"-completed.json")
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			records[name], identities[name] = raw, info
		}
	}
	retained, err := StageNewClean(context.Background(), cold, map[string]trustverify.ApprovalRefs{})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range records {
		actual, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(actual, raw) {
			t.Fatal("cold effect replaced", err)
		}
		info, err := os.Stat(name)
		if err != nil || !os.SameFile(info, identities[name]) || !info.ModTime().Equal(identities[name].ModTime()) {
			t.Fatal("cold effect inode changed", err)
		}
	}
	reconstructed, err := retained.ImagesFor(context.Background(), cold)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := canonicaljson.Canonical(images)
	second, _ := canonicaljson.Canonical(reconstructed)
	if !bytes.Equal(first, second) {
		t.Fatal("cold source/formatter projection changed complete image set")
	}
	publication, err := BuildNewPublication(context.Background(), p, projection)
	if err != nil {
		t.Fatal(err)
	}
	publishedImages, err := publication.ImagesFor(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(publishedImages[".tplaiter/managed-lineage.json"]) == 0 {
		t.Fatal("missing authenticated lineage reference")
	}
	if err = publication.RevalidatePublication(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenNewPublication(context.Background(), r, publication.Reference())
	if err != nil {
		t.Fatal(err)
	}
	coldImages, err := reopened.ImagesFor(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	warmCanonical, _ := canonicaljson.Canonical(publishedImages)
	coldCanonical, _ := canonicaljson.Canonical(coldImages)
	if !bytes.Equal(warmCanonical, coldCanonical) {
		t.Fatal("cold managed publication changed complete afterimages")
	}
	entries, err := os.ReadDir(f.project)
	if err != nil || len(entries) != 0 {
		t.Fatal("formatter staging published project")
	}
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

func TestLinkColdWireBindsObservationWithoutCopyingUserBytes(t *testing.T) {
	raw := []byte(`{".":{"directory":true,"inode":11},"main.go":{"data":"b3JpZ2luYWw="}}`)
	in := LinkPublicationInput{APIVersion: "tplaiter.dev/managed-link-publication-input/v1", Native: NewCleanInput{Origins: map[string]survey.Source{}, SourceInput: json.RawMessage(`{}`), ToolSource: json.RawMessage(`{}`), Render: renderref.Input{Values: settings.Values{}}}, BeforeSHA256: evidencecas.Digest(raw), Stamp: "2026-10-06T00:00:00Z"}
	encoded, err := canonicaljson.Canonical(in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("b3JpZ2luYWw=")) || bytes.Contains(encoded, []byte(`"before":`)) {
		t.Fatal("publication duplicated user beforeimages")
	}
	var decoded LinkPublicationInput
	if err := canonicaljson.DecodeStrict(encoded, &decoded); err != nil || decoded.BeforeSHA256 != evidencecas.Digest(raw) {
		t.Fatal("lost observation binding", err)
	}
	old := bytes.Replace(encoded, []byte(`"beforeSHA256":`), []byte(`"before":`), 1)
	if err := canonicaljson.DecodeStrict(old, &decoded); err == nil {
		t.Fatal("legacy raw-before wire accepted")
	}
	for _, bad := range []string{"", "sha256:", strings.ToUpper(in.BeforeSHA256), "sha256:" + strings.Repeat("g", 64), in.BeforeSHA256 + "0"} {
		if validLinkObservationDigest(bad) {
			t.Fatal("invalid digest accepted")
		}
	}
	if !validLinkObservationDigest(in.BeforeSHA256) {
		t.Fatal("canonical observation digest refused")
	}
	if _, err := ProjectLinkPublication(context.Background(), nil, nil, raw, time.Now()); err == nil {
		t.Fatal("digest-bearing data became publication authority")
	}
}

func TestUpdateCleanBindsActualIntentAndNativeEffects(t *testing.T) {
	f := managedNativeIntegrationFixtureWithScope(t, "update", managedNewWriteNativeSource)
	ctx := context.Background()
	r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: managedNewClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	source, target := managedNewSelection(f.source, f.sourceRefs), managedNewSelection(f.target, f.targetRefs)
	render := renderref.Input{Repo: "demo", Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Managed", Slug: "managed"}}
	before := evidencecas.Digest([]byte("actual owner observation fixture"))
	in := operationtrust.PrepareUpdateInput{SourceInput: source, TargetInput: target, Render: render, RendererVersion: "v1", PreimageSHA256: before}
	intent, err := operationtrust.PrepareUpdate(ctx, r, in)
	if err != nil {
		t.Fatal(err)
	}
	decisions := []byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":[]}`)
	p, err := PrepareUpdateClean(ctx, r, intent, source, target, source, render, render, before, evidencecas.Digest(nil), decisions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareUpdateClean(ctx, r, intent, source, target, source, render, render, evidencecas.Digest([]byte("different before")), evidencecas.Digest(nil), decisions); err == nil {
		t.Fatal("different observation bypassed opaque Update base digest")
	}
	if _, err := PrepareUpdateClean(ctx, r, &operationtrust.PreparedUpdate{}, source, target, source, render, render, before, evidencecas.Digest(nil), decisions); err == nil {
		t.Fatal("fabricated Update intent accepted")
	}
	requests, err := p.RequiredRequests(ctx)
	if err != nil || len(requests) != 2 {
		t.Fatal("missing paired Update requests", err)
	}
	for _, request := range requests {
		if request.Scope != "update" || request.Action.Kind != "formatter" || request.OperationInputsSHA256 == intent.OperationInputsSHA256() {
			t.Fatal("calculation base substituted for actual Update action digest")
		}
	}
	if requests[0].RequestSHA256 == requests[1].RequestSHA256 {
		t.Fatal("formatter requests are not distinct")
	}
	if _, err := StageUpdateClean(ctx, p, nil); err == nil {
		t.Fatal("missing signed operator approvals accepted")
	}
	approvals := map[string]trustverify.ApprovalRefs{}
	for _, request := range requests {
		approvals[request.RequestSHA256] = managedNewApprove(t, f, request)
	}
	projected, err := StageUpdateClean(ctx, p, approvals)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := projected.RenderedFor(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(clean.Files["main.go"], []byte("func f()")) || clean.Baseline.Files["main.go"] != strings.TrimPrefix(evidencecas.Digest(clean.Files["main.go"]), "sha256:") {
		t.Fatal("clean target baseline not derived from actual formatter output")
	}
	if err := projected.RevalidatePublication(ctx, p); err != nil {
		t.Fatal(err)
	}
	pending, err := p.RequiredRequests(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatal("completed Update effects still request approvals", err)
	}
	if _, err := StageUpdateClean(ctx, p, approvals); err == nil {
		t.Fatal("unused completed-effect approvals accepted")
	}
	cold, err := PrepareUpdateClean(ctx, r, intent, source, target, source, render, render, before, evidencecas.Digest(nil), decisions)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := StageUpdateClean(ctx, cold, map[string]trustverify.ApprovalRefs{})
	if err != nil {
		t.Fatal(err)
	}
	again, err := retained.RenderedFor(ctx, cold)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clean.Files["main.go"], again.Files["main.go"]) {
		t.Fatal("retained clean target changed")
	}
	candidate := bytes.ReplaceAll(clean.Files["main.go"], []byte("func f() {}"), []byte("func f() { println(1) }"))
	merged, err := PrepareUpdateMerged(ctx, cold, retained, map[string][]byte{"main.go": candidate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareUpdateMerged(ctx, cold, &UpdateCleanProjection{}, map[string][]byte{"main.go": candidate}); err == nil {
		t.Fatal("unverified clean predecessor accepted")
	}
	if _, err := PrepareUpdateMerged(ctx, cold, retained, map[string][]byte{"foreign.go": candidate}); err == nil {
		t.Fatal("foreign candidate path accepted")
	}
	mergedRequests, err := merged.RequiredRequests(ctx)
	if err != nil || len(mergedRequests) != 2 {
		t.Fatal("missing real candidate pair", err)
	}
	mergedApprovals := map[string]trustverify.ApprovalRefs{}
	for _, request := range mergedRequests {
		for _, cleanRequest := range requests {
			if request.RequestSHA256 == cleanRequest.RequestSHA256 {
				t.Fatal("clean approval reused as candidate approval")
			}
		}
		mergedApprovals[request.RequestSHA256] = managedNewApprove(t, f, request)
	}
	if _, err := StageUpdateMerged(ctx, merged, approvals); err == nil {
		t.Fatal("clean approvals authorized candidate")
	}
	mergedProjection, err := StageUpdateMerged(ctx, merged, mergedApprovals)
	if err != nil {
		t.Fatal(err)
	}
	files, err := mergedProjection.FilesFor(ctx, merged)
	if err != nil || !bytes.Contains(files["main.go"], []byte("println(1)")) {
		t.Fatal("actual candidate formatter output missing", err)
	}
	if bytes.Equal(files["main.go"], clean.Files["main.go"]) {
		t.Fatal("candidate replaced clean target baseline")
	}
	if err := mergedProjection.RevalidatePublication(ctx, merged); err != nil {
		t.Fatal(err)
	}
	if _, err := StageUpdateMerged(ctx, merged, mergedApprovals); err == nil {
		t.Fatal("surplus completed candidate approvals accepted")
	}
	reopenedMerged, err := PrepareUpdateMerged(ctx, cold, retained, map[string][]byte{"main.go": candidate})
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := reopenedMerged.RequiredRequests(ctx); err != nil || len(pending) != 0 {
		t.Fatal("completed candidate ordinals requested again", err)
	}
	if _, err := StageUpdateMerged(ctx, reopenedMerged, map[string]trustverify.ApprovalRefs{}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(f.project)
	if err != nil || len(entries) != 0 {
		t.Fatal("calculation/effects published project state", err)
	}
	t.Log("actual signed Update intent -> native clean pair -> distinct predecessor-bound candidate pair -> retained zero-repeat reopening; no Update transaction publication claim")
}

// This public synthetic four-source fixture uses actual installed admission.
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
	return newContextFixtureScopes(t, alter, []string{"new"})
}

// Scopes are fixture-authored before enrollment; no live policy is changed.
func newContextFixtureScopes(t *testing.T, alter func(string, map[string][]byte), scopesForFixture []string) *contextFixture {
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
	policy.Approvers[0].Scopes = nil
	for _, scope := range scopesForFixture {
		if scope != "new" && scope != "update" {
			t.Fatal("unsupported synthetic fixture scope")
		}
		policy.Approvers[0].Scopes = append(policy.Approvers[0].Scopes, trustverify.ApprovalScope{ProjectID: "project-t6b", OperationScope: scope, ActionKind: "formatter", Origin: origin, TemplatePath: "root"})
	}
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

func TestContextNewNativeFormattingAndPublication(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	home := filepath.Join(filepath.Dir(f.policyPath), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	leaf := f.proofs["leaf"]
	tool := operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: leaf.Subject, Evidence: leaf.Evidence, Dependencies: []string{}}
	input := NewCleanInput{APIVersion: "tplaiter.dev/managed-new-clean-input/v2", Home: home, Ref: f.input.Root.Subject.Commit, SourceInput: contextJSON(t, f.input), ToolSource: contextJSON(t, tool), Render: renderref.Input{Repo: "", Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}, RendererVersion: "1.0.0", Origins: map[string]survey.Source{}}
	if _, err := contextsource.DecodeSourceSelectionV2(input.SourceInput); err != nil {
		t.Fatal("selection decoder", err)
	}
	for _, proof := range append([]contextsource.ContextSourceProof{f.input.Root}, f.input.Sources...) {
		sel := operationtrust.SourceSelection{Subject: proof.Subject, Evidence: proof.Evidence}
		if _, err := f.runtime.TrustRuntime().VerifySubject(ctx, sel.TrustSubject(), sel.EvidenceRefs()); err != nil {
			t.Fatal("source admission", proof.Subject.TemplatePath, err)
		}
	}
	standalone, err := contextsource.PrepareContextSources(ctx, f.runtime, input.SourceInput)
	if err != nil {
		t.Fatal("DAG admission", err)
	}
	standalone.Close()
	// The actual immutable locator defines the display alias.
	rootSource, err := sourceadapter.ResolveContextSources(ctx, f.runtime, home, input.Ref, input.SourceInput)
	if err != nil {
		t.Fatal(err)
	}
	display, err := rootSource.Root(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	input.Render.Repo = display.Alias
	rootSource.Close()
	p, err := PrepareNewClean(ctx, f.runtime, input)
	if err != nil {
		t.Fatal("native v2 prepare", err)
	}
	requests, err := p.RequiredRequests(ctx)
	if err != nil || len(requests) != 2 {
		t.Fatalf("actual requests %d: %v", len(requests), err)
	}
	if requests[0].RequestSHA256 == requests[1].RequestSHA256 {
		t.Fatal("collapsed action requests")
	}
	for _, prepared := range p.formats {
		if prepared.frame.APIVersion != "tplaiter.dev/formatter-frame/v2" {
			t.Fatal("legacy frame")
		}
	}
	if _, err := StageNewClean(ctx, p, nil); err == nil {
		t.Fatal("missing approvals accepted")
	}
	var policy trustverify.ExecutionPolicy
	if err := json.Unmarshal(mustContextRead(t, f.policyPath), &policy); err != nil {
		t.Fatal(err)
	}
	approvalOwner := &managedNewIntegrationFixture{policy: policy, approver: ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123")), evidence: filepath.Join(filepath.Dir(f.policyPath), "evidence")}
	approvals := map[string]trustverify.ApprovalRefs{}
	for _, request := range requests {
		approvals[request.RequestSHA256] = managedNewApprove(t, approvalOwner, request)
	}
	clean, err := StageNewClean(ctx, p, approvals)
	if err != nil {
		t.Fatal("native pair", err)
	}
	images, err := clean.ImagesFor(ctx, p)
	if err != nil || !bytes.Contains(images["main.go"], []byte("func F() int { return 1 }")) {
		t.Fatalf("actual formatted image: %s %v", images["main.go"], err)
	}
	pending, err := p.RequiredRequests(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("completed pair rerun: %d %v", len(pending), err)
	}
	pub, err := BuildNewPublication(ctx, p, clean)
	if err != nil {
		t.Fatal("publication", err)
	}
	if pub.Reference().APIVersion != "tplaiter.dev/managed-publication-reference/v2" {
		t.Fatal("legacy publication")
	}
	fresh, err := OpenNewPublication(ctx, f.runtime, pub.Reference())
	if err != nil {
		t.Fatal("retained publication", err)
	}
	again, err := fresh.ImagesFor(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := canonicaljson.Canonical(images)
	// Lineage is added only by the actual publication owner.
	delete(again, newLineagePath)
	actual, _ := canonicaljson.Canonical(again)
	if !bytes.Equal(expected, actual) {
		t.Fatal("publication changed rendered images")
	}
	wrong := pub.Reference()
	wrong.APIVersion = "tplaiter.dev/managed-publication-reference/v1"
	if _, err := OpenNewPublication(ctx, f.runtime, wrong); err == nil {
		t.Fatal("v2 frame entered v1 reference")
	}
	p.nativeIntent.Close()
	if _, err := p.RequiredRequests(ctx); err == nil {
		t.Fatal("closed intent accepted")
	}
	t.Log("actual signed DAG=4, real formatter requests=2, retained pair=complete; no project publication claimed")
}

func mustContextRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestContextNativeFormatterMaterialActualSourceAndRefusals(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	home := filepath.Join(filepath.Dir(f.policyPath), "material-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := contextJSON(t, f.input)
	source, err := sourceadapter.ResolveContextSources(ctx, f.runtime, home, f.input.Root.Subject.Commit, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	rootSource, err := source.Root(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := source.Sources(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := contextsource.PrepareManagedNativeNew(ctx, f.runtime, admitted, contextsource.NativeNewInput{Render: renderref.Input{Repo: rootSource.Alias, Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}, RendererVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	defer intent.Close()
	closure, err := intent.FormatterSources(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	result, err := intent.Rendered(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	root, err := intent.RootLock(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	deps, err := intent.DependencyLock(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := intent.ContextDigest(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := closure.SourceGraph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	graphDigest, err := bootstrap.DomainDigest("tplaiter.dev/managed-formatter-source-graph/v2", graph)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := intent.OperationBase(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	leaf := f.proofs["leaf"]
	toolSelection := operationtrust.SourceSelection{Subject: leaf.Subject, Evidence: leaf.Evidence}
	tool, err := f.runtime.TrustRuntime().VerifySubject(ctx, toolSelection.TrustSubject(), toolSelection.EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.runtime.TrustRuntime().VerifiedSnapshot(tool)
	if err != nil {
		t.Fatal(err)
	}
	recordRaw, ok := snapshot.Blob("formatter/tool.json")
	if !ok {
		t.Fatal("actual tool record missing")
	}
	var record struct {
		APIVersion      string `json:"apiVersion"`
		Adapter         string `json:"adapter"`
		ToolID          string `json:"toolID"`
		ToolVersion     string `json:"toolVersion"`
		BinarySHA256    string `json:"binarySHA256"`
		VersionEvidence struct {
			Kind     string `json:"kind"`
			Identity string `json:"identity"`
		} `json:"versionEvidence"`
		NativeEnvelope string `json:"nativeEnvelope"`
	}
	if err := canonicaljson.DecodeStrict(recordRaw, &record); err != nil {
		t.Fatal(err)
	}
	input := result.Files["main.go"]
	markers, err := blockmarkers.Validate(blockmarkers.LanguageGo, "main.go", input)
	if err != nil || len(markers) == 0 {
		t.Fatal("actual managed inventory", err)
	}
	options := []string{}
	optionsDigest, err := trustverify.ComputeToolOptionsSHA256(options)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := blockformatter.BuildPlan(blockformatter.PlanInput{Path: "main.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: trustverify.Tool{ID: record.ToolID, Version: record.ToolVersion, BinarySHA256: record.BinarySHA256, OptionsSHA256: optionsDigest}, Options: options, InputMode: "100644", Markers: markers, TimeoutMillis: 5000, OutputLimitBytes: 16 << 20, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	contextData := operationtrust.ContextNewFormatterContext{APIVersion: "tplaiter.dev/managed-formatter-context/v2", Role: "clean-target", SourceRootLockSHA256: root.RootLockSHA256, TargetRootLockSHA256: root.RootLockSHA256, ReplacementDeclarationsSHA256: evidencecas.Digest([]byte(`{"replacements":[],"version":1}`)), DecisionsSHA256: evidencecas.Digest([]byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":[]}`)), ObservedProjectSHA256: evidencecas.Digest(nil), ObservedRegistrySHA256: evidencecas.Digest(nil), RendererAnswersSHA256: operation.AnswersSHA256, DependencyLockSHA256: deps.LockSHA256, SourceGraphSHA256: graphDigest, NativeContextSHA256: contextDigest}
	contextRaw, err := canonicaljson.Canonical(contextData)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := blockformatter.NewRuntimeAdapter(f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	calculation, err := operationtrust.PrepareContextNewFormatterCalculation(ctx, f.runtime, closure, renderref.Input{Repo: rootSource.Alias, Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}, "1.0.0")
	if err != nil {
		t.Fatal("owned calculation", err)
	}
	selection, err := adapter.SelectContextNativeNew(ctx, calculation, tool, plan, input, contextRaw)
	if err != nil {
		t.Fatal("actual native material selection", err)
	}
	operation.Actions = selection.Actions()
	if len(operation.Subjects) != 4 || len(operation.Actions) != 2 {
		t.Fatal("actual full DAG/actions missing")
	}
	bound, err := adapter.BindContextNativeNew(ctx, selection, operation)
	if err != nil {
		t.Fatal("actual native material bind", err)
	}
	requests := bound.Requests()
	if len(requests) != 2 || requests[0].RequestSHA256 == requests[1].RequestSHA256 || requests[0].Action.ID == requests[1].Action.ID {
		t.Fatal("actual distinct requests missing")
	}
	for _, request := range requests {
		if request.Scope != "new" || request.VerifyRequestSHA256() != nil {
			t.Fatal("actual request scope/digest")
		}
	}
	if _, err := adapter.Bind(ctx, selection, operation); err == nil {
		t.Fatal("v2 selection entered legacy binding")
	}
	for _, mutate := range []func(*trustverify.OperationInputs){func(op *trustverify.OperationInputs) { op.Actions = nil }, func(op *trustverify.OperationInputs) { op.Subjects = op.Subjects[:len(op.Subjects)-1] }, func(op *trustverify.OperationInputs) { op.Scope = "update" }, func(op *trustverify.OperationInputs) {
		op.AnswersSHA256 = evidencecas.Digest([]byte("foreign answers"))
	}} {
		candidate := operation
		candidate.Subjects = append([]trustverify.Provider(nil), operation.Subjects...)
		candidate.Actions = append([]trustverify.ActionMaterial(nil), operation.Actions...)
		mutate(&candidate)
		if _, err := adapter.BindContextNativeNew(ctx, selection, candidate); err == nil {
			t.Fatal("mismatched operation material accepted")
		}
	}
	for name, mutate := range map[string]func(*operationtrust.ContextNewFormatterContext){
		"dependency-lock": func(c *operationtrust.ContextNewFormatterContext) {
			c.DependencyLockSHA256 = evidencecas.Digest([]byte("foreign lock"))
		},
		"root-lock": func(c *operationtrust.ContextNewFormatterContext) {
			c.SourceRootLockSHA256 = evidencecas.Digest([]byte("foreign root"))
			c.TargetRootLockSHA256 = c.SourceRootLockSHA256
		},
		"native-context": func(c *operationtrust.ContextNewFormatterContext) {
			c.NativeContextSHA256 = evidencecas.Digest([]byte("foreign native"))
		},
		"answers": func(c *operationtrust.ContextNewFormatterContext) {
			c.RendererAnswersSHA256 = evidencecas.Digest([]byte("foreign answers"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := contextData
			mutate(&changed)
			badRaw := contextJSON(t, changed)
			// Recompute the actual canonical content closure and both action identities;
			// refusal cannot be explained by binding stale actions from the positive.
			planRaw := contextJSON(t, plan)
			content := []trustverify.ContentEntry{{Root: "project", Path: plan.Path, Mode: plan.InputMode, ContentSHA256: evidencecas.Digest(input)}, {Root: "project", Path: "formatter/plan.json", Mode: "100644", ContentSHA256: evidencecas.Digest(planRaw)}, {Root: "project", Path: "formatter/tool.json", Mode: "100644", ContentSHA256: evidencecas.Digest(recordRaw)}, {Root: "project", Path: "formatter/context.json", Mode: "100644", ContentSHA256: evidencecas.Digest(badRaw)}}
			sort.Slice(content, func(i, j int) bool {
				return content[i].Root+"\x00"+content[i].Path < content[j].Root+"\x00"+content[j].Path
			})
			closureDigest, err := trustverify.ComputeContentClosureSHA256(content)
			if err != nil {
				t.Fatal(err)
			}
			candidate := operation
			candidate.Actions = selection.Actions()
			candidate.AnswersSHA256 = changed.RendererAnswersSHA256
			id := strings.TrimPrefix(evidencecas.Digest(append(append([]byte(nil), planRaw...), badRaw...)), "sha256:")
			for i := range candidate.Actions {
				candidate.Actions[i].Action.ID = fmt.Sprintf("format-%s-%d", id, i+1)
				candidate.Actions[i].Action.ContentClosureSHA256 = closureDigest
			}
			if _, err := trustverify.ComputeOperationInputsSHA256(candidate); err != nil {
				t.Fatal("recomputed operation", err)
			}
			if reflect.DeepEqual(candidate.Actions, operation.Actions) {
				t.Fatal("negative retained stale actions")
			}
			if _, err := adapter.SelectContextNativeNew(ctx, calculation, tool, plan, input, badRaw); err == nil {
				t.Fatal("foreign context selected")
			}
			rawInput := operationtrust.FormatterInput{Path: plan.Path, Mode: plan.InputMode, Bytes: input, PlanJSON: planRaw, ContextJSON: badRaw}
			if _, err := operationtrust.ResolveContextNewFormatterComposition(ctx, f.runtime, calculation, tool, candidate, candidate.Actions[0], rawInput); err == nil {
				t.Fatal("recomputed foreign context bound")
			}
		})
	}

	t.Log("actual four-source installed closure and independent source-bound tool: two action-specific native material requests; missing actions/subjects, answers, scope, dependency lock and legacy route refused; no execution/publication claim")
}

func TestContextUpdateFormatterMaterialActualRecordedClosuresAndRefusals(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	home := filepath.Join(filepath.Dir(f.policyPath), "material-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := contextJSON(t, f.input)
	source, err := sourceadapter.ResolveContextSources(ctx, f.runtime, home, f.input.Root.Subject.Commit, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	rootSource, err := source.Root(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := source.Sources(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	targetAdmitted, err := contextsource.PrepareContextSources(ctx, f.runtime, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer targetAdmitted.Close()
	render := renderref.Input{Repo: rootSource.Alias, Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}
	observed := evidencecas.Digest([]byte("actual synthetic project observation"))
	intent, err := contextsource.PrepareNativeUpdate(ctx, f.runtime, admitted, targetAdmitted, contextsource.NativeUpdateInput{SourceRender: render, TargetRender: render, SourceRecordedValues: settings.Values{}, TargetRecordedValues: settings.Values{}, RendererVersion: "1.0.0", PreimageSHA256: observed})
	if err != nil {
		t.Fatal(err)
	}
	defer intent.Close()
	targetSnapshot, err := intent.TargetSnapshot(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	sourceSnapshot, err := intent.SourceSnapshot(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	sourceClosure, err := sourceSnapshot.FormatterSources(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	closure, err := targetSnapshot.FormatterSources(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	result, err := intent.Rendered(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := intent.OperationBase(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	leaf := f.proofs["leaf"]
	toolSelection := operationtrust.SourceSelection{Subject: leaf.Subject, Evidence: leaf.Evidence}
	tool, err := f.runtime.TrustRuntime().VerifySubject(ctx, toolSelection.TrustSubject(), toolSelection.EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.runtime.TrustRuntime().VerifiedSnapshot(tool)
	if err != nil {
		t.Fatal(err)
	}
	recordRaw, ok := snapshot.Blob("formatter/tool.json")
	if !ok {
		t.Fatal("actual tool record missing")
	}
	var record struct {
		APIVersion      string `json:"apiVersion"`
		Adapter         string `json:"adapter"`
		ToolID          string `json:"toolID"`
		ToolVersion     string `json:"toolVersion"`
		BinarySHA256    string `json:"binarySHA256"`
		VersionEvidence struct {
			Kind     string `json:"kind"`
			Identity string `json:"identity"`
		} `json:"versionEvidence"`
		NativeEnvelope string `json:"nativeEnvelope"`
	}
	if err := canonicaljson.DecodeStrict(recordRaw, &record); err != nil {
		t.Fatal(err)
	}
	input := result.Files["main.go"]
	markers, err := blockmarkers.Validate(blockmarkers.LanguageGo, "main.go", input)
	if err != nil || len(markers) == 0 {
		t.Fatal("actual managed inventory", err)
	}
	options := []string{}
	optionsDigest, err := trustverify.ComputeToolOptionsSHA256(options)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := blockformatter.BuildPlan(blockformatter.PlanInput{Path: "main.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: trustverify.Tool{ID: record.ToolID, Version: record.ToolVersion, BinarySHA256: record.BinarySHA256, OptionsSHA256: optionsDigest}, Options: options, InputMode: "100644", Markers: markers, TimeoutMillis: 5000, OutputLimitBytes: 16 << 20, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operationtrust.PrepareContextUpdateFormatterCalculation(ctx, f.runtime, closure, closure, render, render, settings.Values{}, settings.Values{}, "1.0.0", observed, evidencecas.Digest(nil), []byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":[]}`)); err == nil {
		t.Fatal("same admitted source closure accepted for both formatter roles")
	}
	calculation, err := operationtrust.PrepareContextUpdateFormatterCalculation(ctx, f.runtime, sourceClosure, closure, render, render, settings.Values{}, settings.Values{}, "1.0.0", observed, evidencecas.Digest(nil), []byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":[]}`))
	if err != nil {
		t.Fatal("owned recorded calculation", err)
	}
	contextData, err := calculation.Context(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	contextRaw, err := canonicaljson.Canonical(contextData)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := blockformatter.NewRuntimeAdapter(f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := adapter.SelectContextNativeUpdate(ctx, calculation, tool, plan, input, contextRaw)
	if err != nil {
		t.Fatal("actual native material selection", err)
	}
	operation.Actions = selection.Actions()
	if len(operation.Subjects) != 4 || len(operation.Actions) != 2 {
		t.Fatal("actual full DAG/actions missing")
	}
	bound, err := adapter.BindContextNativeUpdate(ctx, selection, operation)
	if err != nil {
		t.Fatal("actual native material bind", err)
	}
	requests := bound.Requests()
	if len(requests) != 2 || requests[0].RequestSHA256 == requests[1].RequestSHA256 || requests[0].Action.ID == requests[1].Action.ID {
		t.Fatal("actual distinct requests missing")
	}
	for _, request := range requests {
		if request.Scope != "update" || request.VerifyRequestSHA256() != nil {
			t.Fatal("actual request scope/digest")
		}
	}
	if _, err := adapter.Bind(ctx, selection, operation); err == nil {
		t.Fatal("v2 selection entered legacy binding")
	}
	for _, mutate := range []func(*trustverify.OperationInputs){func(op *trustverify.OperationInputs) { op.Actions = nil }, func(op *trustverify.OperationInputs) { op.Subjects = op.Subjects[:len(op.Subjects)-1] }, func(op *trustverify.OperationInputs) { op.Scope = "new" }, func(op *trustverify.OperationInputs) {
		op.AnswersSHA256 = evidencecas.Digest([]byte("foreign answers"))
	}} {
		candidate := operation
		candidate.Subjects = append([]trustverify.Provider(nil), operation.Subjects...)
		candidate.Actions = append([]trustverify.ActionMaterial(nil), operation.Actions...)
		mutate(&candidate)
		if _, err := adapter.BindContextNativeUpdate(ctx, selection, candidate); err == nil {
			t.Fatal("mismatched operation material accepted")
		}
	}
	for name, mutate := range map[string]func(*operationtrust.ContextUpdateFormatterContext){
		"dependency-lock": func(c *operationtrust.ContextUpdateFormatterContext) {
			c.TargetDependencyLockSHA256 = evidencecas.Digest([]byte("foreign lock"))
		},
		"root-lock": func(c *operationtrust.ContextUpdateFormatterContext) {
			c.SourceRootLockSHA256 = evidencecas.Digest([]byte("foreign root"))
			c.TargetRootLockSHA256 = c.SourceRootLockSHA256
		},
		"native-context": func(c *operationtrust.ContextUpdateFormatterContext) {
			c.TargetNativeContextSHA256 = evidencecas.Digest([]byte("foreign native"))
		},
		"answers": func(c *operationtrust.ContextUpdateFormatterContext) {
			c.RendererAnswersSHA256 = evidencecas.Digest([]byte("foreign answers"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := contextData
			mutate(&changed)
			badRaw := contextJSON(t, changed)
			// Recompute the actual canonical content closure and both action identities;
			// refusal cannot be explained by binding stale actions from the positive.
			planRaw := contextJSON(t, plan)
			content := []trustverify.ContentEntry{{Root: "project", Path: plan.Path, Mode: plan.InputMode, ContentSHA256: evidencecas.Digest(input)}, {Root: "project", Path: "formatter/plan.json", Mode: "100644", ContentSHA256: evidencecas.Digest(planRaw)}, {Root: "project", Path: "formatter/tool.json", Mode: "100644", ContentSHA256: evidencecas.Digest(recordRaw)}, {Root: "project", Path: "formatter/context.json", Mode: "100644", ContentSHA256: evidencecas.Digest(badRaw)}}
			sort.Slice(content, func(i, j int) bool {
				return content[i].Root+"\x00"+content[i].Path < content[j].Root+"\x00"+content[j].Path
			})
			closureDigest, err := trustverify.ComputeContentClosureSHA256(content)
			if err != nil {
				t.Fatal(err)
			}
			candidate := operation
			candidate.Actions = selection.Actions()
			candidate.AnswersSHA256 = changed.RendererAnswersSHA256
			id := strings.TrimPrefix(evidencecas.Digest(append(append([]byte(nil), planRaw...), badRaw...)), "sha256:")
			for i := range candidate.Actions {
				candidate.Actions[i].Action.ID = fmt.Sprintf("format-%s-%d", id, i+1)
				candidate.Actions[i].Action.ContentClosureSHA256 = closureDigest
			}
			if _, err := trustverify.ComputeOperationInputsSHA256(candidate); err != nil {
				t.Fatal("recomputed operation", err)
			}
			if reflect.DeepEqual(candidate.Actions, operation.Actions) {
				t.Fatal("negative retained stale actions")
			}
			if _, err := adapter.SelectContextNativeUpdate(ctx, calculation, tool, plan, input, badRaw); err == nil {
				t.Fatal("foreign context selected")
			}
			rawInput := operationtrust.FormatterInput{Path: plan.Path, Mode: plan.InputMode, Bytes: input, PlanJSON: planRaw, ContextJSON: badRaw}
			if _, err := operationtrust.ResolveContextUpdateFormatterComposition(ctx, f.runtime, calculation, tool, candidate, candidate.Actions[0], rawInput); err == nil {
				t.Fatal("recomputed foreign context bound")
			}
		})
	}

	t.Log("actual independently admitted recorded source/target closures and signed tool: two action-specific Update material requests; recalculated foreign locks/native facts/answers/scope/subjects refuse; no execution/publication claim")
}

func TestContextUpdateFormatterRejectsSameAdmittedClosure(t *testing.T) {
	f := newContextFixtureScopes(t, nil, []string{"new", "update"})
	ctx := context.Background()
	home := filepath.Join(filepath.Dir(f.policyPath), "same-closure-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := contextJSON(t, f.input)
	admitted, err := sourceadapter.ResolveContextSources(ctx, f.runtime, home, f.input.Root.Subject.Commit, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Close()
	sources, err := admitted.Sources(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	render := renderref.Input{Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}
	snapshot, err := contextsource.PrepareRecordedNativeSnapshot(ctx, f.runtime, sources, contextsource.RecordedNativeSnapshotInput{Render: render, RendererVersion: "1.0.0", RecordedValues: settings.Values{}})
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	closure, err := snapshot.FormatterSources(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operationtrust.PrepareContextUpdateFormatterCalculation(ctx, f.runtime, closure, closure, render, render, settings.Values{}, settings.Values{}, "1.0.0", evidencecas.Digest([]byte("actual same-closure observation")), evidencecas.Digest([]byte("actual same-closure registry")), []byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":[]}`)); err == nil {
		t.Fatal("same actual admitted closure accepted for both formatter roles")
	}
}

func TestContextUpdateCleanMergedActualEffectsAndRetainedNoRepeat(t *testing.T) {
	started := time.Now()
	f := newContextFixtureScopes(t, nil, []string{"new", "update"})
	ctx := context.Background()
	t.Logf("fixture enrolled at %s; actual v2 source/target admission", time.Since(started))
	raw := contextJSON(t, f.input)
	source, err := contextsource.PrepareContextSources(ctx, f.runtime, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := contextsource.PrepareContextSources(ctx, f.runtime, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	render := renderref.Input{Repo: "root", Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}
	before := evidencecas.Digest([]byte("bounded synthetic observed project"))
	intent, err := contextsource.PrepareNativeUpdate(ctx, f.runtime, source, target, contextsource.NativeUpdateInput{SourceRender: render, TargetRender: render, SourceRecordedValues: settings.Values{}, TargetRecordedValues: settings.Values{}, RendererVersion: "1.0.0", PreimageSHA256: before})
	if err != nil {
		t.Fatal(err)
	}
	defer intent.Close()
	leaf := f.proofs["leaf"]
	tool := operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: leaf.Subject, Evidence: leaf.Evidence, Dependencies: []string{}}
	decisions := []byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":[]}`)
	clean, err := PrepareContextUpdateClean(ctx, f.runtime, intent, contextJSON(t, tool), render, render, settings.Values{}, settings.Values{}, before, evidencecas.Digest(nil), decisions)
	if err != nil {
		t.Fatal("clean preparation", err)
	}
	requests, err := clean.RequiredRequests(ctx)
	if err != nil || len(requests) != 2 {
		t.Fatalf("actual clean requests %d: %v", len(requests), err)
	}
	for _, ref := range clean.References() {
		if ref.APIVersion != "tplaiter.dev/formatter-reference/v3" {
			t.Fatal("legacy clean frame")
		}
	}
	if _, err := StageUpdateClean(ctx, clean, nil); err == nil {
		t.Fatal("missing clean approvals accepted")
	}
	var policy trustverify.ExecutionPolicy
	if err := json.Unmarshal(mustContextRead(t, f.policyPath), &policy); err != nil {
		t.Fatal(err)
	}
	owner := &managedNewIntegrationFixture{policy: policy, approver: ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123")), evidence: filepath.Join(filepath.Dir(f.policyPath), "evidence")}
	approvals := map[string]trustverify.ApprovalRefs{}
	for _, request := range requests {
		approvals[request.RequestSHA256] = managedNewApprove(t, owner, request)
	}
	t.Logf("actual two clean formatter actions start at %s", time.Since(started))
	projection, err := StageUpdateClean(ctx, clean, approvals)
	if err != nil {
		t.Fatal("clean effects", err)
	}
	result, err := projection.RenderedFor(ctx, clean)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual clean actions completed at %s", time.Since(started))
	t.Run("CleanRetained", func(t *testing.T) {
		pending, err := clean.RequiredRequests(ctx)
		if err != nil || len(pending) != 0 {
			t.Fatal("completed clean ordinals pending", err)
		}
		if _, err := StageUpdateClean(ctx, clean, approvals); err == nil {
			t.Fatal("unused approvals accepted for completed effects")
		}
		retained, err := StageUpdateClean(ctx, clean, map[string]trustverify.ApprovalRefs{})
		if err != nil {
			t.Fatal("clean retained pair", err)
		}
		again, err := retained.RenderedFor(ctx, clean)
		if err != nil || !bytes.Equal(again.Files["main.go"], result.Files["main.go"]) {
			t.Fatal("retained clean image changed", err)
		}
		if result.Baseline.Files["main.go"] != strings.TrimPrefix(evidencecas.Digest(result.Files["main.go"]), "sha256:") {
			t.Fatal("clean baseline not actual output")
		}
		refs := clean.References()
		ref := refs["main.go"]
		ref.APIVersion = "tplaiter.dev/formatter-reference/v1"
		refs["main.go"] = ref
		if _, err := OpenUpdateClean(ctx, clean, refs); err == nil {
			t.Fatal("downgraded frame accepted")
		}
		t.Logf("actual v3 clean pair and retained zero-repeat reopening complete at %s; no merged, transaction or installed CLI claim", time.Since(started))
	})
	t.Run("Merged", func(t *testing.T) {
		candidate := append(bytes.Clone(result.Files["main.go"]), []byte("\n// local unmanaged comment\n")...)
		if _, err := PrepareUpdateMerged(ctx, clean, &UpdateCleanProjection{}, map[string][]byte{"main.go": candidate}); err == nil {
			t.Fatal("fabricated clean predecessor accepted")
		}
		merged, err := PrepareUpdateMerged(ctx, clean, projection, map[string][]byte{"main.go": candidate})
		if err != nil {
			t.Fatal("merged preparation", err)
		}
		mergedRequests, err := merged.RequiredRequests(ctx)
		if err != nil || len(mergedRequests) != 2 {
			t.Fatalf("actual merged requests %d: %v", len(mergedRequests), err)
		}
		mergedApprovals := map[string]trustverify.ApprovalRefs{}
		for _, request := range mergedRequests {
			for _, cleanRequest := range requests {
				if request.RequestSHA256 == cleanRequest.RequestSHA256 {
					t.Fatal("clean action reused")
				}
			}
			mergedApprovals[request.RequestSHA256] = managedNewApprove(t, owner, request)
		}
		if _, err := StageUpdateMerged(ctx, merged, approvals); err == nil {
			t.Fatal("clean approvals accepted for candidate")
		}
		t.Log("actual two predecessor-bound merged formatter actions")
		completed, err := StageUpdateMerged(ctx, merged, mergedApprovals)
		if err != nil {
			t.Fatal("merged effects", err)
		}
		files, err := completed.FilesFor(ctx, merged)
		if err != nil || !bytes.Contains(files["main.go"], []byte("// local unmanaged comment")) {
			t.Fatal("candidate lost local span", err)
		}
		for _, ref := range merged.References() {
			if ref.APIVersion != "tplaiter.dev/formatter-reference/v3" {
				t.Fatal("legacy merged frame")
			}
		}
		if pending, err := merged.RequiredRequests(ctx); err != nil || len(pending) != 0 {
			t.Fatal("completed effects still request execution", err)
		}
		retained, err := StageUpdateMerged(ctx, merged, map[string]trustverify.ApprovalRefs{})
		if err != nil {
			t.Fatal("retained completed pair", err)
		}
		again, err := retained.FilesFor(ctx, merged)
		if err != nil || !bytes.Equal(again["main.go"], files["main.go"]) {
			t.Fatal("retained output changed", err)
		}
		t.Log("actual 2+2 formatter actions; retained same-runtime reopening has zero pending ordinals; no Update transaction, installed CLI or fresh-runtime cold claim")
	})
}

func TestContextNewRecordedProjectionActualOwnerAndPurpose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Second)
	defer cancel()
	f := newContextFixture(t, nil)
	home := filepath.Join(filepath.Dir(f.policyPath), "recorded-read-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	leaf := f.proofs["leaf"]
	tool := operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: leaf.Subject, Evidence: leaf.Evidence, Dependencies: []string{}}
	input := NewCleanInput{APIVersion: "tplaiter.dev/managed-new-clean-input/v2", Home: home, Ref: f.input.Root.Subject.Commit, SourceInput: contextJSON(t, f.input), ToolSource: contextJSON(t, tool), Render: renderref.Input{Repo: "pinned", Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}, RendererVersion: "1.0.0", Origins: map[string]survey.Source{}}
	prep, err := PrepareNewClean(ctx, f.runtime, input)
	if err != nil {
		t.Fatal(err)
	}
	var policy trustverify.ExecutionPolicy
	if err := json.Unmarshal(mustContextRead(t, f.policyPath), &policy); err != nil {
		t.Fatal(err)
	}
	owner := &managedNewIntegrationFixture{policy: policy, approver: ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123")), evidence: filepath.Join(filepath.Dir(f.policyPath), "evidence")}
	signed := map[string]trustverify.ApprovalRefs{}
	for _, q := range prep.Requests() {
		signed[q.RequestSHA256] = managedNewApprove(t, owner, q)
	}
	clean, err := StageNewClean(ctx, prep, signed)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := BuildNewPublication(ctx, prep, clean)
	if err != nil {
		t.Fatal(err)
	}
	// Access this package-private fresh owner only to assert exact reader bytes;
	// the production entry still reopens the real immutable publication record.
	want := pub.images
	projection, images, err := ReconstructRootPublication(ctx, f.runtime, home, "1.0.0", want[newLineagePath], "new")
	if err != nil || projection == nil {
		t.Fatal("actual owner reconstruction", err)
	}
	a, _ := canonicaljson.Canonical(want)
	b, _ := canonicaljson.Canonical(images)
	if !bytes.Equal(a, b) {
		t.Fatal("authenticated projection changed")
	}
	images["main.go"][0] = 'X'
	if bytes.Equal(images["main.go"], pub.images["main.go"]) {
		t.Fatal("caller mutation escaped into retained owner")
	}
	if _, _, err := ReconstructRootPublication(ctx, f.runtime, home, "1.0.0", want[newLineagePath], "link"); err == nil {
		t.Fatal("wrong literal purpose accepted")
	}
	var locator newLineage
	if err := canonicaljson.DecodeStrict(want[newLineagePath], &locator); err != nil {
		t.Fatal(err)
	}
	locator.Publication.APIVersion = "tplaiter.dev/managed-publication-reference/v1"
	raw, err := canonicaljson.Canonical(locator)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReconstructRootPublication(ctx, f.runtime, home, "1.0.0", raw, "new"); err == nil {
		t.Fatal("downgraded reference accepted")
	}
	t.Log("fresh signed native-v2 New owner read: exact detached projection, foreign purpose and downgraded reference refused; no transaction publication or cold claim")
}
