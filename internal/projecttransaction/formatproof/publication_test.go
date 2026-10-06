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
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
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
