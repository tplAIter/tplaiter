package contextsource

import (
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
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type contextFixtureClock struct{}

func (contextFixtureClock) Now() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }

type contextFixture struct {
	runtime    *trustload.Runtime
	selection  trustload.LaunchSelection
	input      ContextSourceSelection
	objectRoot string
	policyPath string
	proofs     map[string]ContextSourceProof
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
	f := &contextFixture{objectRoot: filepath.Join(dir, "objects"), policyPath: filepath.Join(dir, "policy.json"), proofs: map[string]ContextSourceProof{}, files: map[string]map[string][]byte{}}
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
		refs := []ContextDependency{}
		associations := []ContextDependencyBinding{}
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
			refs = append(refs, ContextDependency{Alias: dep, Origin: s.Origin, TemplatePath: s.TemplatePath, CommitAlgorithm: "sha1", Commit: s.Commit, TreeDigest: s.TreeSHA256, ContractDigest: s.ContractSHA256})
			associations = append(associations, ContextDependencyBinding{Alias: dep, ProviderID: "provider." + dep, Parameters: parameters})
			requirements = append(requirements, exports.ExportRequirement{Selector: dep + ".block.notes", ContractDigest: s.ContractSHA256, CompatibleRange: ">=1.0.0 <2.0.0"})
		}
		manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: context-" + alias + "\n  version: 1.0.0\n  description: Public task context\nengine:\n  type: gotemplate\n  root: files\nsettings: []\n")
		var contract []byte
		if alias == "leaf" {
			contract = contextJSON(t, operationtrust.NativeContract{APIVersion: operationtrust.NativeContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: []string{}})
		} else {
			contract = contextJSON(t, NativeContextContract{APIVersion: NativeContextContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: refs})
		}
		binding := ContextSourceBindings{APIVersion: ContextSourceBindingsAPIVersion, Kind: "ContextSourceBindings", Source: ContextCatalogBinding{Alias: alias, ProviderID: "provider." + alias, Parameters: parameters, EntriesPath: "catalog/entries.json", PayloadDirectory: "catalog/payloads", ToolPath: "catalog/tool.md"}, Dependencies: associations}
		content := []byte("Complete inert procedure for " + alias + ". Read every required prerequisite; no tool execution.\n")
		payload := contextJSON(t, exports.ExportPayload{APIVersion: exports.ExportPayloadAPIVersion, ExportID: "notes", Files: []exports.PayloadFile{{SourcePath: "docs/notes.md", TargetPath: "context/" + alias + ".md", Mode: "100644", ContentSHA256: evidencecas.Digest(content)}}, Slots: []exports.PayloadSlot{}, Blocks: []exports.PayloadBlock{}})
		tool := []byte("Inert file context only.\n")
		domain := "block"
		if alias == "root" {
			domain = "skill"
		}
		entry := exports.ExportEntry{ID: "notes", Domain: domain, Name: "notes", Version: "1.0.0", ContentDigest: evidencecas.Digest(payload), ToolDigest: evidencecas.Digest(tool), Parameters: []exports.ScalarParameter{}, Requires: requirements}
		files := map[string][]byte{"template.manifest.yaml": manifest, "template.contract.json": contract, ContextSourceBindingsPath: contextJSON(t, binding), "catalog/entries.json": contextJSON(t, []exports.ExportEntry{entry}), "catalog/tool.md": tool, "catalog/payloads/notes.json": payload, "docs/notes.md": content, "files/hello.txt.tmpl": []byte("Hello public project.\n")}
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
		f.proofs[alias] = ContextSourceProof{Subject: operationtrust.SelectionSubject{Origin: subject.Origin, TemplatePath: subject.TemplatePath, RequestedRef: subject.Commit, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}, Evidence: refs}
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
	f.input = ContextSourceSelection{APIVersion: ContextSourceSelectionAPIVersion, Root: f.proofs["root"], Sources: []ContextSourceProof{f.proofs["a"], f.proofs["b"], f.proofs["leaf"]}}
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
	f.input = ContextSourceSelection{APIVersion: ContextSourceSelectionAPIVersion, Root: f.proofs["root"], Sources: []ContextSourceProof{f.proofs["a"], f.proofs["b"], f.proofs["leaf"]}}
	f.runtime = runtime
	t.Cleanup(func() { runtime.Close() })
	return f
}

func TestInstalledContextSourceClosure(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	if _, err := DecodeSourceSelectionV2(contextJSON(t, f.input)); err != nil {
		t.Fatalf("selection decode: %s %v", contextJSON(t, f.input), err)
	}
	for alias, files := range f.files {
		if _, err := DecodeContextSourceBindingsV2(files[ContextSourceBindingsPath]); err != nil {
			t.Fatalf("binding %s: %v", alias, err)
		}
		if alias != "leaf" {
			if _, err := DecodeNativeContextContractV2(files["template.contract.json"], files["template.manifest.yaml"]); err != nil {
				t.Fatalf("contract %s: %s %v", alias, files["template.contract.json"], err)
			}
		}
	}
	p, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	pins, err := p.Pins(ctx)
	if err != nil || len(pins) != 4 {
		t.Fatalf("pins: %v %v", pins, err)
	}
	graph, err := p.SourceGraph(ctx)
	if err != nil || len(graph.Nodes) != 4 || len(graph.Edges) != 4 {
		t.Fatalf("graph: %v %v", graph, err)
	}
	catalogs, err := p.Catalogs(ctx)
	if err != nil || len(catalogs) != 4 {
		t.Fatal(err)
	}
	plain := []exports.Catalog{}
	for _, c := range catalogs {
		plain = append(plain, c.Catalog)
	}
	request := func(s string) exports.Selection {
		return exports.Selection{APIVersion: exports.SelectionAPIVersion, Selector: s, Bindings: []exports.ScalarParameter{}}
	}
	selected, err := exports.ResolveSelections([]exports.Selection{request("root.skill.notes")}, &graph, plain)
	if err != nil || len(selected.Selected) != 4 || len(selected.Edges) != 4 {
		t.Fatalf("selection: %+v %v", selected, err)
	}
	for _, s := range selected.Selected {
		if s.Provider == "provider.leaf" && len(s.Chains) != 2 {
			t.Fatalf("missing shared leaf chains: %+v", s)
		}
	}
	first, err := exports.ResolveSelections([]exports.Selection{request("a.block.notes"), request("b.block.notes")}, &graph, plain)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := exports.ResolveSelections([]exports.Selection{request("b.block.notes"), request("a.block.notes")}, &graph, plain)
	if err != nil || first.Digest != reverse.Digest {
		t.Fatalf("permutation: %v", err)
	}
	for _, requests := range [][]exports.Selection{{request("unknown.block.notes")}, {request("a.block.notes"), request("a.block.notes")}} {
		if _, err := exports.ResolveSelections(requests, &graph, plain); err == nil {
			t.Fatal("invalid selection accepted")
		}
	}
	material := exports.MaterializeInput{Sources: []exports.MaterialSource{}, TargetInventory: []exports.InventoryEntry{}, Owned: []exports.OwnedPreimage{}, Managed: []exports.ManagedCandidate{}, Current: []exports.FileState{}, Operations: []exports.MaterialOperation{}}
	for _, s := range selected.Selected {
		for _, c := range catalogs {
			if c.Catalog.Source != s.Source || c.Catalog.Provider != s.Provider {
				continue
			}
			index := len(material.Sources)
			material.Sources = append(material.Sources, exports.MaterialSource{Selected: s, Payload: c.Payloads[0].Raw, Blobs: c.Blobs})
			payload, err := exports.ParseExportPayload(c.Payloads[0].Raw)
			if err != nil {
				t.Fatal(err)
			}
			file := payload.Files[0]
			material.Current = append(material.Current, exports.FileState{Path: file.TargetPath})
			material.Operations = append(material.Operations, exports.MaterialOperation{Kind: "add", Path: file.TargetPath, AfterOwner: exports.MaterialOwner{Provider: s.Provider, RuleID: s.ID, ExportID: s.ID}, SourceIndex: index, EntryIndex: 0})
		}
	}
	output, err := exports.Materialize(material)
	if err != nil || len(output.Images) != 4 || len(output.Conflicts) != 0 {
		t.Fatalf("materialization: %+v %v", output, err)
	}
	for _, image := range output.Images {
		alias := strings.TrimSuffix(strings.TrimPrefix(image.Path, "context/"), ".md")
		if string(image.After.Content) != string(f.files[alias]["docs/notes.md"]) {
			t.Fatalf("wrong exact image %s", image.Path)
		}
	}
	t.Logf("actual closure: sources=%d sourceEdges=%d exports=%d exportEdges=%d graph=%s images=%d", len(pins), len(graph.Edges), len(selected.Selected), len(selected.Edges), selected.Digest, len(output.Images))
	// Returned data cannot alter any retained pin, graph, payload or image.
	cyclic, _ := contextCopy(pins)
	for i := range cyclic {
		if cyclic[i].Alias == "leaf" {
			cyclic[i].Dependencies = []string{"root"}
		}
	}
	if _, err := deps.BuildSourceGraph(cyclic); err == nil {
		t.Fatal("source graph cycle accepted")
	}
	pins[0].Parameters[0].Value[0] = 'x'
	graph.Nodes[0].Provenance[0].Alias = "changed"
	catalogs[0].Blobs[0].Content[0] = 'x'
	data, err := p.CatalogData(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	data.Blobs[0].Content[0] = 'x'
	data.Payloads[0].Raw[0] = 'x'
	again, err := p.CatalogData(ctx, "root")
	if err != nil || again.Blobs[0].Content[0] == 'x' || again.Payloads[0].Raw[0] != '{' {
		t.Fatal("copy escaped", err)
	}
	againPins, err := p.Pins(ctx)
	if err != nil || string(againPins[0].Parameters[0].Value) != `"plain"` {
		t.Fatal("pin copy escaped", err)
	}
	resolution, err := p.Resolution(ctx, "root")
	if err != nil || !resolution.ValidFor(f.runtime.TrustRuntime(), f.runtime.TrustRuntime().Binding()) {
		t.Fatal("resolution admission", err)
	}
	foreign, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: contextFixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if resolution.ValidFor(foreign.TrustRuntime(), foreign.TrustRuntime().Binding()) || p.RecheckFor(ctx, foreign) == nil {
		t.Fatal("foreign runtime accepted")
	}
	if err := p.RecheckFor(ctx, f.runtime); err != nil {
		t.Fatal(err)
	}
	root, err := p.RootPin(ctx)
	if err != nil || root.Alias != "root" || len(root.Dependencies) != 2 {
		t.Fatal("authenticated root", err)
	}
	foreignResolution, err := foreign.TrustRuntime().VerifySubject(ctx, contextSubject(f.input.Root), contextEvidence(f.input.Root))
	if err != nil {
		t.Fatal(err)
	}
	record := p.records["root"]
	originalRecord := record
	record.resolution = foreignResolution
	p.records["root"] = record
	if p.Recheck(ctx) == nil {
		t.Fatal("foreign opaque carrier replay accepted")
	}
	p.records["root"] = originalRecord
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if p.Recheck(canceled) == nil {
		t.Fatal("cancellation ignored")
	}
	if _, err = p.CatalogData(ctx, "missing"); err == nil {
		t.Fatal("missing alias accepted")
	}
	p.Close()
	if p.Recheck(ctx) == nil {
		t.Fatal("closed preparation accepted")
	}
}

func TestInstalledContextSourceSignedAssociationRefusals(t *testing.T) {
	for _, name := range []string{"provider", "parameters", "alias", "pin", "catalog", "payload", "duplicate-record", "self-reference"} {
		t.Run(name, func(t *testing.T) {
			f := newContextFixture(t, func(alias string, files map[string][]byte) {
				if alias != "root" {
					return
				}
				switch name {
				case "provider", "parameters", "alias":
					var b ContextSourceBindings
					if err := json.Unmarshal(files[ContextSourceBindingsPath], &b); err != nil {
						t.Fatal(err)
					}
					switch name {
					case "provider":
						b.Dependencies[0].ProviderID = "provider.wrong"
					case "parameters":
						b.Dependencies[0].Parameters[0].Value = json.RawMessage(`"other"`)
					case "alias":
						b.Dependencies[0].Alias = "absent"
					}
					files[ContextSourceBindingsPath] = contextJSON(t, b)
				case "pin":
					var c NativeContextContract
					json.Unmarshal(files["template.contract.json"], &c)
					c.Dependencies[0].TreeDigest = "sha256:" + strings.Repeat("a", 64)
					files["template.contract.json"] = contextJSON(t, c)
				case "duplicate-record":
					var entries []exports.ExportEntry
					if err := json.Unmarshal(files["catalog/entries.json"], &entries); err != nil {
						t.Fatal(err)
					}
					entries = append(entries, entries[0])
					files["catalog/entries.json"] = contextJSON(t, entries)
				case "self-reference":
					var c NativeContextContract
					json.Unmarshal(files["template.contract.json"], &c)
					c.Dependencies[0].Alias = "root"
					var b ContextSourceBindings
					json.Unmarshal(files[ContextSourceBindingsPath], &b)
					b.Dependencies[0].Alias = "root"
					files["template.contract.json"] = contextJSON(t, c)
					files[ContextSourceBindingsPath] = contextJSON(t, b)
				case "catalog":
					files["catalog/entries.json"] = []byte(`[{"id":"notes","id":"changed"}]`)
				case "payload":
					files["docs/notes.md"] = []byte("changed signed source bytes without payload digest update")
				}
			})
			if p, err := PrepareContextSources(context.Background(), f.runtime, contextJSON(t, f.input)); err == nil {
				p.Close()
				t.Fatal("signed invalid association admitted")
			}
		})
	}
}

func TestInstalledContextSourceFreshnessAndInputRefusals(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	for _, name := range []string{"missing", "duplicate", "evidence", "signature", "subject", "unreachable"} {
		t.Run(name, func(t *testing.T) {
			in, _ := contextCopy(f.input)
			switch name {
			case "unreachable":
				in.Root = f.proofs["a"]
				in.Sources = []ContextSourceProof{f.proofs["root"], f.proofs["b"], f.proofs["leaf"]}
			case "missing":
				in.Sources = in.Sources[:2]
			case "duplicate":
				in.Sources = append(in.Sources, in.Root)
			case "signature":
				in.Sources[0].Evidence.SignatureCAS = in.Sources[1].Evidence.SignatureCAS
			case "evidence":
				in.Sources[0].Evidence.StatementCAS = in.Sources[1].Evidence.StatementCAS
			case "subject":
				in.Sources[0].Subject.TreeSHA256 = "sha256:" + strings.Repeat("a", 64)
			}
			if p, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, in)); err == nil {
				p.Close()
				t.Fatal("invalid input admitted")
			}
		})
	}
	p, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	file := filepath.Join(f.objectRoot, f.input.Root.Subject.Commit)
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	contextWrite(t, file, append(original, 'x'))
	if p.Recheck(ctx) == nil {
		t.Fatal("tampered source accepted")
	}
	contextWrite(t, file, original)
	if err = p.Recheck(ctx); err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	contextWrite(t, f.policyPath, append(policy, ' '))
	if p.Recheck(ctx) == nil {
		t.Fatal("stale fixed input accepted")
	}
	contextWrite(t, f.policyPath, policy)
	if err = p.Recheck(ctx); err != nil {
		t.Fatal(err)
	}
	f.runtime.Close()
	if p.Recheck(ctx) == nil {
		t.Fatal("closed runtime accepted")
	}
	if new(PreparedContextSources).Recheck(ctx) == nil {
		t.Fatal("zero carrier accepted")
	}
}

func TestInstalledContextSourceCrossSourceTopology(t *testing.T) {
	for _, target := range []string{"context/a.md", "CONTEXT/A.md", "context/a.md/child"} {
		t.Run(target, func(t *testing.T) {
			f := newContextFixture(t, func(alias string, files map[string][]byte) {
				if alias != "b" {
					return
				}
				var payload exports.ExportPayload
				if err := json.Unmarshal(files["catalog/payloads/notes.json"], &payload); err != nil {
					t.Fatal(err)
				}
				payload.Files[0].TargetPath = target
				files["catalog/payloads/notes.json"] = contextJSON(t, payload)
				var entries []exports.ExportEntry
				json.Unmarshal(files["catalog/entries.json"], &entries)
				entries[0].ContentDigest = evidencecas.Digest(files["catalog/payloads/notes.json"])
				files["catalog/entries.json"] = contextJSON(t, entries)
			})
			ctx := context.Background()
			p, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			graph, err := p.SourceGraph(ctx)
			if err != nil {
				t.Fatal(err)
			}
			catalogs, err := p.Catalogs(ctx)
			if err != nil {
				t.Fatal(err)
			}
			plain := []exports.Catalog{}
			for _, c := range catalogs {
				plain = append(plain, c.Catalog)
			}
			selected, err := exports.ResolveSelections([]exports.Selection{{APIVersion: exports.SelectionAPIVersion, Selector: "root.skill.notes", Bindings: []exports.ScalarParameter{}}}, &graph, plain)
			if err != nil {
				t.Fatal(err)
			}
			in := exports.MaterializeInput{Sources: []exports.MaterialSource{}, TargetInventory: []exports.InventoryEntry{}, Current: []exports.FileState{}, Owned: []exports.OwnedPreimage{}, Operations: []exports.MaterialOperation{}, Managed: []exports.ManagedCandidate{}}
			for _, s := range selected.Selected {
				for _, c := range catalogs {
					if s.Source != c.Catalog.Source || s.Provider != c.Catalog.Provider {
						continue
					}
					index := len(in.Sources)
					in.Sources = append(in.Sources, exports.MaterialSource{Selected: s, Payload: c.Payloads[0].Raw, Blobs: c.Blobs})
					payload, err := exports.ParseExportPayload(c.Payloads[0].Raw)
					if err != nil {
						t.Fatal(err)
					}
					file := payload.Files[0]
					in.Current = append(in.Current, exports.FileState{Path: file.TargetPath})
					in.Operations = append(in.Operations, exports.MaterialOperation{Kind: "add", Path: file.TargetPath, AfterOwner: exports.MaterialOwner{Provider: s.Provider, RuleID: s.ID, ExportID: s.ID}, SourceIndex: index, EntryIndex: 0})
				}
			}
			output, err := exports.Materialize(in)
			typed, ok := err.(*exports.MaterialError)
			if !ok || typed.Code != "MATERIAL_TARGET_CONFLICT" || len(output.Images) != 0 {
				t.Fatalf("cross-source topology refusal: output=%+v error=%v", output, err)
			}
			t.Logf("target=%s error=%s images=%d", target, typed.Code, len(output.Images))
		})
	}
}

func TestInstalledContextSourceConcurrentCopies(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	p, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			pins, err := p.Pins(ctx)
			if err == nil {
				pins[0].Alias = "changed"
			}
			errs <- err
		}()
	}
	for i := 0; i < 4; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	pins, err := p.Pins(ctx)
	if err != nil || pins[0].Alias == "changed" {
		t.Fatal("concurrent copy escaped", err)
	}
	if _, err := os.Stat(f.runtime.ProjectContext().RootPath); !os.IsNotExist(err) {
		t.Fatalf("source preparation wrote project root: %v", err)
	}
}

func TestInstalledContextSourceAggregateBound(t *testing.T) {
	for _, mode := range []string{"one-source", "complete-closure"} {
		t.Run(mode, func(t *testing.T) {
			f := newContextFixture(t, func(alias string, files map[string][]byte) {
				count := 4
				if mode == "one-source" {
					if alias != "root" {
						return
					}
					count = 17
				}
				var payload exports.ExportPayload
				json.Unmarshal(files["catalog/payloads/notes.json"], &payload)
				for i := 0; i < count; i++ {
					name := fmt.Sprintf("docs/bounded-%02d.md", i)
					raw := []byte(strings.Repeat("x", 1<<20))
					files[name] = raw
					payload.Files = append(payload.Files, exports.PayloadFile{SourcePath: name, TargetPath: fmt.Sprintf("context/%s-bounded-%02d.md", alias, i), Mode: "100644", ContentSHA256: evidencecas.Digest(raw)})
				}
				files["catalog/payloads/notes.json"] = contextJSON(t, payload)
				var entries []exports.ExportEntry
				json.Unmarshal(files["catalog/entries.json"], &entries)
				entries[0].ContentDigest = evidencecas.Digest(files["catalog/payloads/notes.json"])
				files["catalog/entries.json"] = contextJSON(t, entries)
			})
			if p, err := PrepareContextSources(context.Background(), f.runtime, contextJSON(t, f.input)); err != errContextSourceLimit {
				if p != nil {
					p.Close()
				}
				t.Fatalf("complete context size refusal: %v", err)
			}
		})
	}
}

func TestInstalledContextSourceEmptyLeafAndNoMutation(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	before := map[string]string{}
	if err := filepath.WalkDir(f.objectRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		before[path] = evidencecas.Digest(raw)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	in := ContextSourceSelection{APIVersion: ContextSourceSelectionAPIVersion, Root: f.proofs["leaf"], Sources: []ContextSourceProof{}}
	p, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, in))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	pins, err := p.Pins(ctx)
	if err != nil || len(pins) != 1 || len(pins[0].Dependencies) != 0 {
		t.Fatal("empty leaf", err)
	}
	for path, digest := range before {
		raw, err := os.ReadFile(path)
		if err != nil || evidencecas.Digest(raw) != digest {
			t.Fatalf("retained objects changed: %s %v", path, err)
		}
	}
	if _, err := os.Stat(f.runtime.ProjectContext().RootPath); !os.IsNotExist(err) {
		t.Fatalf("project changed: %v", err)
	}
}
