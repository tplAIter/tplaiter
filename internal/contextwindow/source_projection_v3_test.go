package contextwindow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1" // Git object format in public synthetic source fixtures.
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

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
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, b, 0600); e != nil {
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
		if e := os.Mkdir(p, 0700); e != nil {
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
	policy = trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "t6b-policy", Profile: "oss", MinimumProfile: "oss", Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Principals: []trustverify.Principal{{ID: "principal:approver"}, {ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []trustverify.IssuerPrincipal{{Issuer: "publisher-1", PrincipalID: "principal:publisher"}}, SourceRules: []trustverify.SourceRule{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: origin, TemplatePath: ".", Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"}}, Approvers: []trustverify.Approver{{ID: "t6b-approver", PrincipalID: "principal:approver", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(approverPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(approverPub), Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Scopes: []trustverify.ApprovalScope{{ProjectID: "project-t6b", OperationScope: "run", ActionKind: "command", Origin: origin, TemplatePath: "."}, {ProjectID: "project-t6b", OperationScope: "run", ActionKind: "formatter", Origin: origin, TemplatePath: "."}}}}, AllowInvocationHuman: false, MaxTimeoutMillis: 5000}
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

// This fixture uses real signed simulated source evidence and the installed
// loader. It is library acceptance, not a normal New or live operator claim.
func sourceSignedProjection(t *testing.T) (*Selection, *contextFixture) {
	t.Helper()
	f := newContextFixture(t, nil)
	ctx := context.Background()
	prepared, e := contextsource.PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(prepared.Close)
	pins, e := prepared.Pins(ctx)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../testdata/knowledge/catalog.json")
	if e != nil {
		t.Fatal(e)
	}
	d, e := knowledge.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	template := d.Items[2]
	d.Sources = []knowledge.Source{}
	d.Items = []knowledge.Item{}
	d.Edges = []knowledge.Edge{}
	bindings := []contextindex.Binding{}
	for _, pin := range pins {
		r, e := prepared.Resolution(ctx, pin.Alias)
		if e != nil {
			t.Fatal(e)
		}
		sub, ev := r.Subject(), r.Evidence()
		sourceID := "context:source:" + pin.Alias
		d.Sources = append(d.Sources, knowledge.Source{ID: sourceID, Pin: pin, Anchor: provenance.RootSubject{Origin: sub.Origin, TemplatePath: sub.TemplatePath, RequestedRef: sub.RequestedRef, Commit: sub.Commit, TreeSHA256: sub.TreeSHA256, ContractSHA256: sub.ContractSHA256, StatementCAS: ev.StatementCAS, SignatureCAS: ev.SignatureCAS, KeyFingerprint: ev.KeyFingerprint, CheckpointCAS: ev.CheckpointCAS, InclusionProofCAS: ev.InclusionProofCAS}})
		it := template
		it.ID = "context:resource:" + pin.Alias
		it.SourceID = sourceID
		it.SourcePath = "docs/notes.md"
		it.ContentSHA256 = evidencecas.Digest(f.files[pin.Alias][it.SourcePath])
		it.Export = nil
		it.Ownership.OwnerID = "context:owner:" + pin.Alias
		it.Requires = []string{}
		it.Produces = []string{}
		it.Inputs.ContextFloor = []string{}
		for _, dep := range pin.Dependencies {
			it.Requires = append(it.Requires, "context:resource:"+dep)
		}
		d.Items = append(d.Items, it)
		bindings = append(bindings, contextindex.Binding{SourceID: sourceID, Runtime: f.runtime.TrustRuntime(), Resolution: r})
	}
	index, e := contextindex.New(contextJSON(t, d), nil)
	if e != nil {
		t.Fatal(e)
	}
	request := contextindex.Request{Query: contextindex.Query{ID: "context:resource:root", One: true}, MaxBytes: 32768, IncludeExcerpts: true, MaxExcerptBytes: 2048}
	selected, e := Select(ctx, index, request, bindings)
	if e != nil {
		t.Fatal(e)
	}
	return selected, f
}
func TestSourceProjectionV3AuthenticatedClosureAndFreshness(t *testing.T) {
	original, f := sourceSignedProjection(t)
	ctx := context.Background()
	projected, e := FactorProjectSelectionV3(ctx, original)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(projected.raw, original.raw) || projected.index != original.index || projected.query != original.query || len(projected.bindings) != 4 {
		t.Fatal("projection replaced owned facts/bindings")
	}
	for i := range original.bindings {
		if projected.bindings[i] != original.bindings[i] {
			t.Fatal("binding identity lost")
		}
	}
	packet, e := contextindex.DecodeSourceFactsV3(projected.deliveryBytes())
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(contextJSON(t, packet), original.raw) || len(packet.RequiredFloor) != 8 || len(packet.SourceEvidence) != 4 || len(packet.Excerpts) != 4 {
		t.Fatal("shared DAG floor/evidence lost")
	}
	adapter, _ := NewByteAdapter(Scope{Session: "v3", Model: "unknown"}, baseEnvelope())
	host := adapter.Host()
	defer host.Revoke()
	held, plan, e := host.Reserve(ctx, observation(t, host), Request{ID: "v3", Selection: projected, MaxBytes: 32768, OutputByteReserve: 64})
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := adapter.Deliver(ctx, held, exchangeFunc(func(_ context.Context, raw []byte, max int) ([]byte, error) {
		if !bytes.Equal(raw, plan.Envelope) || max != 64 {
			t.Fatal("unmeasured frame")
		}
		return []byte("complete multi-source facts consumed"), nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	if e = host.Finish(ctx, held, receipt); e != nil {
		t.Fatal(e)
	}
	t.Logf("signed simulated installed loader -> same-runtime four concrete resolutions -> C03 shared DAG floor=8, excerpts=4 -> C04 Reserve/Deliver/Finish; logical=%d facts=%d frame=%d", len(original.raw), len(projected.wire), len(plan.Envelope))
	// Whole projected mandatory facts refuse one byte below the measured
	// input-plus-output floor; no optional context can hide that refusal.
	boundaryAdapter, _ := NewByteAdapter(Scope{Session: "boundary", Model: "unknown"}, baseEnvelope())
	boundaryHost := boundaryAdapter.Host()
	defer boundaryHost.Revoke()
	observed := observation(t, boundaryHost)
	request := Request{ID: "edge", Selection: projected, OutputByteReserve: 64}
	preview, e := boundaryHost.Preview(ctx, observed, request)
	if e != nil {
		t.Fatal(e)
	}
	request.MaxBytes = preview.Bytes - 1
	if _, _, e = boundaryHost.Reserve(ctx, observed, request); e == nil {
		t.Fatal("one-below mandatory floor accepted")
	}
	request.MaxBytes = preview.Bytes
	boundaryHeld, boundaryPlan, e := boundaryHost.Reserve(ctx, observed, request)
	if e != nil {
		t.Fatal(e)
	}
	if boundaryPlan.Bytes != preview.Bytes {
		t.Fatal("boundary measurement changed")
	}
	boundaryReceipt, e := boundaryAdapter.Deliver(ctx, boundaryHeld, exchangeFunc(func(_ context.Context, raw []byte, _ int) ([]byte, error) {
		if !bytes.Equal(raw, boundaryPlan.Envelope) {
			t.Fatal("boundary truncation")
		}
		return []byte("complete"), nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	if e = boundaryHost.Finish(ctx, boundaryHeld, boundaryReceipt); e != nil {
		t.Fatal(e)
	}
	t.Logf("actual measured whole C04 minimum=%d; one-below refuses without truncation", preview.Bytes)
	// Actual object mutation must invalidate even a previously factored selection.
	paths, e := os.ReadDir(f.objectRoot)
	if e != nil || len(paths) == 0 {
		t.Fatal(e)
	}
	p := filepath.Join(f.objectRoot, paths[0].Name())
	before, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	contextWrite(t, p, []byte("tampered source object"))
	if e = selectionFresh(ctx, projected); e == nil {
		t.Fatal("stale actual source accepted")
	}
	contextWrite(t, p, before)
}
func TestSourceProjectionV3MissingForeignDuplicateAndCancel(t *testing.T) {
	s, _ := sourceSignedProjection(t)
	ctx := context.Background()
	metadataReq := s.request
	metadataReq.IncludeExcerpts = false
	metadata, e := Select(ctx, s.index, metadataReq, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = FactorProjectSelectionV3(ctx, metadata); e == nil {
		t.Fatal("metadata minted projection")
	}
	missing := *s.selectionRecord
	missing.bindings = missing.bindings[:3]
	if _, e = FactorProjectSelectionV3(ctx, &Selection{&missing}); e == nil {
		t.Fatal("missing source binding accepted")
	}
	duplicate := *s.selectionRecord
	duplicate.bindings = append([]contextindex.Binding(nil), s.bindings...)
	duplicate.bindings[1] = duplicate.bindings[0]
	if _, e = FactorProjectSelectionV3(ctx, &Selection{&duplicate}); e == nil {
		t.Fatal("duplicate source binding accepted")
	}
	foreign, _ := sourceSignedProjection(t)
	changed := *s.selectionRecord
	changed.bindings = append([]contextindex.Binding(nil), s.bindings...)
	changed.bindings[0].Resolution = foreign.bindings[0].Resolution
	if _, e = FactorProjectSelectionV3(ctx, &Selection{&changed}); e == nil {
		t.Fatal("foreign resolution accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = FactorProjectSelectionV3(canceled, s); e == nil {
		t.Fatal("canceled projection accepted")
	}
	projected, e := FactorProjectSelectionV3(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	projected.wire[0] = '!'
	if e = selectionFresh(ctx, projected); e == nil {
		t.Fatal("altered projected facts accepted")
	}
}
