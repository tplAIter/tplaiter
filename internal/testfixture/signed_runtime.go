// Package testfixture builds enrolled, signed local trust evidence for tests.
package testfixture

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
	"os/exec" //nolint:depguard // test fixture builds and runs signed helper binaries
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type t6BClock struct{}

func (t6BClock) Now() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }

type Fixture struct {
	dir, scratch, project, evidence string
	selection                       trustload.LaunchSelection
	policy                          trustverify.ExecutionPolicy
	anchor, publisher, approver     ed25519.PrivateKey
	subject                         trustverify.Subject
	refs                            trustverify.EvidenceRefs
	tool, stdin                     []byte
}

func NewGofmtFixture(t *testing.T) *Fixture {
	toolMode, sourceVariant := "gofmt", "gofmt"
	t.Helper()
	// The enrolled loader pins canonical paths; Darwin's default TMPDIR can
	// traverse a /var alias before resolving to /private/var.
	base := "/private/var/tmp"
	if _, err := os.Stat(base); err != nil {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "tplaiter-gofmt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &Fixture{dir: dir, scratch: filepath.Join(dir, "scratch"), project: filepath.Join(dir, "project"), evidence: filepath.Join(dir, "evidence"), anchor: ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901")), publisher: ed25519.NewKeyFromSeed([]byte("12345678901234567890123456789012")), approver: ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123")), stdin: []byte("literal signed stdin\n")}
	for _, p := range []string{f.scratch, f.project, f.evidence, filepath.Join(dir, "objects"), filepath.Join(dir, "home")} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.tool = t6BBuildHelper(t, dir, toolMode)
	if sourceVariant == "oversize-tool" {
		f.tool = bytes.Repeat([]byte{'t'}, 16<<20+1)
	}
	if sourceVariant == "oversize-stdin" {
		f.stdin = bytes.Repeat([]byte{'s'}, 1<<20+1)
	}
	f.subject = t6BWriteSource(t, filepath.Join(dir, "objects"), f.tool, f.stdin, sourceVariant)
	evidence := map[string][]byte{}
	put := func(b []byte) string { d := evidencecas.Digest(b); evidence[d] = append([]byte(nil), b...); return d }
	anchorPub, publisherPub := f.anchor.Public().(ed25519.PublicKey), f.publisher.Public().(ed25519.PublicKey)
	rootRef := put([]byte(bootstrap.EncodePublicKey(publisherPub)))
	env := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: "t6b-authority", Sequence: 1, Validity: bootstrap.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(publisherPub), PublicKeyCAS: rootRef, Issuer: "publisher-1", Status: "active"}}, Threshold: 1, RevocationEpoch: 0, Revocations: []bootstrap.Revocation{}}
	if env.PayloadSHA256, err = env.ComputePayloadSHA256(); err != nil {
		t.Fatal(err)
	}
	payload, _ := hex.DecodeString(env.PayloadSHA256[7:])
	env.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchorPub), SignatureCAS: put([]byte(bootstrap.EncodeSignature(ed25519.Sign(f.anchor, payload))))}}
	envRef := put(t6BJSON(t, env))
	f.refs = t6BPublisherEvidence(t, evidence, f.publisher, f.subject)
	leaf0, leaf1 := bootstrap.HashLeaf([]byte(env.PayloadSHA256)), bootstrap.HashLeaf([]byte(f.refs.StatementCAS))
	root := bootstrap.HashChildren(leaf0, leaf1)
	checkpointRef := put(t6BJSON(t, bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: env.AuthorityID, TreeSize: 2, RootHash: "sha256:" + hex.EncodeToString(root[:])}))
	f.refs.CheckpointCAS = checkpointRef
	f.refs.InclusionProofCAS = put(t6BJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 1, TreeSize: 2, Hashes: []string{"sha256:" + hex.EncodeToString(leaf0[:])}}))
	envProof := put(t6BJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 2, Hashes: []string{"sha256:" + hex.EncodeToString(leaf1[:])}}))
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: env.AuthorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, TreeSize: 2, CheckpointDigest: checkpointRef}
	if receipt.ReceiptDigest, err = receipt.ComputeDigest(); err != nil {
		t.Fatal(err)
	}
	receiptRef := put(t6BJSON(t, receipt))
	desc := bootstrap.DescriptorDocument{APIVersion: bootstrap.DescriptorAPIVersion, Profile: bootstrap.ProfileOSS, AuthorityID: env.AuthorityID, Anchors: []bootstrap.DescriptorAnchor{{Fingerprint: bootstrap.Fingerprint(anchorPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(anchorPub)}}, Threshold: 1, AllowedPolicyOrigins: []string{"https://example.test/policy"}, PublisherScopes: []bootstrap.PublisherScope{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", SourceOrigin: f.subject.Origin, TemplatePath: ".", Predicate: "https://example.test/predicate", Usage: "template-source"}}}
	desc.DescriptorSHA256 = desc.ComputedSHA256()
	opRecord := trustload.OperatorPinRecord{APIVersion: trustload.OperatorPinRecordAPIVersion, Method: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256}
	opRaw := t6BJSON(t, opRecord)
	prov := bootstrap.ProvisioningRecord{APIVersion: bootstrap.ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256, AuthenticationEvidenceSHA256: evidencecas.Digest(opRaw), EvidenceClass: bootstrap.EvidenceSimulated}
	prov.ProvisioningSHA256 = prov.ComputedSHA256()
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: desc.DescriptorSHA256, ProvisioningSHA256: prov.ProvisioningSHA256, AuthorityID: env.AuthorityID, Sequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, ReceiptDigest: receipt.ReceiptDigest, TreeSize: 2, CheckpointDigest: checkpointRef}
	state.StateSHA256 = state.ComputedSHA256()
	approverPub := f.approver.Public().(ed25519.PublicKey)
	f.policy = trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "t6b-policy", Profile: "oss", MinimumProfile: "oss", Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Principals: []trustverify.Principal{{ID: "principal:approver"}, {ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []trustverify.IssuerPrincipal{{Issuer: "publisher-1", PrincipalID: "principal:publisher"}}, SourceRules: []trustverify.SourceRule{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: f.subject.Origin, TemplatePath: ".", Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"}}, Approvers: []trustverify.Approver{{ID: "t6b-approver", PrincipalID: "principal:approver", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(approverPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(approverPub), Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Scopes: []trustverify.ApprovalScope{{ProjectID: "project-t6b", OperationScope: "run", ActionKind: "command", Origin: f.subject.Origin, TemplatePath: "."}, {ProjectID: "project-t6b", OperationScope: "run", ActionKind: "formatter", Origin: f.subject.Origin, TemplatePath: "."}}}}, AllowInvocationHuman: false, MaxTimeoutMillis: 5000}
	if f.policy.PolicySHA256, err = f.policy.ComputePolicySHA256(); err != nil {
		t.Fatal(err)
	}
	descRaw, provRaw, policyRaw := t6BJSON(t, desc), t6BJSON(t, prov), t6BJSON(t, f.policy)
	for p, b := range map[string][]byte{filepath.Join(dir, "descriptor.json"): descRaw, filepath.Join(dir, "provisioning.json"): provRaw, filepath.Join(dir, "operator.json"): opRaw, filepath.Join(dir, "policy.json"): policyRaw, filepath.Join(dir, "state.json"): t6BJSON(t, state)} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := trustload.StoredBundle{APIVersion: "tplaiter.dev/stored-bootstrap-bundle/v1", EnvelopeCAS: envRef, ReceiptCAS: receiptRef, Transparency: trustload.StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: envProof}}
	bundleRaw := t6BJSON(t, bundle)
	bundleDigest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	install := trustload.RuntimeInstall{APIVersion: trustload.RuntimeInstallAPIVersion, InstallationID: "t6b-install", Profile: bootstrap.ProfileOSS, MinimumProfile: bootstrap.ProfileOSS, Descriptor: t6BPin(filepath.Join(dir, "descriptor.json"), descRaw), Provisioning: t6BPin(filepath.Join(dir, "provisioning.json"), provRaw), OperatorRecord: t6BPin(filepath.Join(dir, "operator.json"), opRaw), ExecutionPolicy: t6BPin(filepath.Join(dir, "policy.json"), policyRaw), ProjectContexts: []trustload.ProjectContext{{Key: "project", ProjectID: "project-t6b", SubmitterPrincipalID: "principal:submitter", MinimumProfile: bootstrap.ProfileOSS, RootPath: f.project}}, ObjectOrigins: []trustload.ObjectOrigin{{Origin: f.subject.Origin, RootPath: filepath.Join(dir, "objects")}}, EvidenceRoot: f.evidence, ScratchRoot: f.scratch, OSS: &trustload.OSSInstall{StorePath: filepath.Join(dir, "store"), InitialStatePath: filepath.Join(dir, "state.json"), InitialStateSHA256: state.StateSHA256, InitialBundlePath: filepath.Join(dir, "bundle.json"), InitialBundleSHA256: bundleDigest}}
	installRaw := t6BJSON(t, install)
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
		return bootstrap.NewVerifier(r, t6BClock{}, nil, 0)
	}
	if err := trustload.Enroll(context.Background(), f.selection, factory, t6BJSON(t, state), bundleRaw, evidence); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return f
}

func t6BBuildHelper(t *testing.T, dir, mode string) []byte {
	t.Helper()
	src, out := filepath.Join(dir, "native-helper.go"), filepath.Join(dir, "native-tool")
	var raw []byte
	switch mode {
	case "gofmt":
		raw = []byte("package main\n")
	case "normal":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){if _,ok:=syscall.Getenv(\"T6B_EXEC_CANARY\");ok{syscall.Write(1,[]byte(\"inherited-env\"));return};b:=make([]byte,1024);n,_:=syscall.Read(0,b);syscall.Write(1,append([]byte(\"approved:\"),b[:n]...))}\n")
	case "fail":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){syscall.Exit(3)}\n")
	case "overflow":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){b:=make([]byte,32768);for i:=0;i<64;i++{syscall.Write(1,b)}}\n")
	case "stderr":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){b:=make([]byte,32768);for i:=0;i<3;i++{syscall.Write(2,b)}}\n")
	case "hang":
		raw = []byte("package main\nfunc main(){for {}}\n")
	case "descendant":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){p,e:=syscall.ForkExec(\"/bin/sleep\",[]string{\"sleep\",\"30\"},&syscall.ProcAttr{Files:[]uintptr{0,1,2}});if e==nil{var b [24]byte;i:=len(b)-1;b[i]='\\n';for p>0{i--;b[i]=byte('0'+p%10);p/=10};syscall.Write(1,b[i:])};for {}}\n")
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"build", "-trimpath", "-o", out, src}
	if mode == "gofmt" {
		args = []string{"build", "-trimpath", "-o", out, "cmd/gofmt"}
	}
	cache := filepath.Join(dir, "cache")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(GoBinary(t), args...)
	cmd.Env = []string{"HOME=" + filepath.Join(dir, "home"), "GOMODCACHE=" + filepath.Join(dir, "modcache"), "GOCACHE=" + cache, "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GO111MODULE=off", "CGO_ENABLED=0", "PATH=" + filepath.Join(GoRoot(t), "bin") + ":/usr/bin:/bin"}
	cmd.Env = append(cmd.Env, NativeTargetEnv()...)
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper build: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func t6BWriteSource(t *testing.T, root string, tool, stdin []byte, variant string) trustverify.Subject {
	t.Helper()
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: t6b\n  version: 1.0.0\n  description: fixture\nengine:\n  type: gotemplate\n  root: files\nsettings:\n  - group: label\n    title: Label\n    type: string\n    default: ok\n")
	h := sha256.Sum256(manifest)
	contract := []byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"sha256:` + hex.EncodeToString(h[:]) + `","dependencies":[]}`)
	objects := map[string][]byte{}
	add := func(kind string, data []byte) string {
		raw := append([]byte(kind+" "+t6BItoa(len(data))+"\x00"), data...)
		sum := sha1.Sum(raw)
		id := hex.EncodeToString(sum[:])
		objects[id] = raw
		return id
	}
	blob := func(b []byte) string { return add("blob", b) }
	files := t6BTree(add, []t6BTreeEntry{{"100644", "hello.txt.tmpl", blob([]byte("hello\n"))}})
	execTree := []t6BTreeEntry{{"100755", "native-tool", blob(tool)}, {"100644", "stdin", blob(stdin)}}
	execEntries := []trustverify.SourceEntry{{Path: ".tplaiter-execution", Kind: "directory", Mode: "40000"}, {Path: ".tplaiter-execution/native-tool", Kind: "file", Mode: "100755", ContentSHA256: evidencecas.Digest(tool)}, {Path: ".tplaiter-execution/stdin", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(stdin)}}
	var formatterTree string
	var formatterEntries []trustverify.SourceEntry
	if variant == "gofmt" {
		info, err := buildinfo.Read(bytes.NewReader(tool))
		if err != nil {
			t.Fatal(err)
		}
		record, err := canonicaljson.Canonical(map[string]any{"apiVersion": "tplaiter.dev/formatter-tool/v1", "adapter": "gofmt-stdin-v1", "toolID": "gofmt", "toolVersion": strings.TrimPrefix(info.GoVersion, "go"), "binarySHA256": evidencecas.Digest(tool), "versionEvidence": map[string]any{"kind": "go-buildinfo", "identity": info.GoVersion}, "nativeEnvelope": FormatterNativeEnvelope()})
		if err != nil {
			t.Fatal(err)
		}
		formatterTree = t6BTree(add, []t6BTreeEntry{{"100755", "native-tool", blob(tool)}, {"100644", "tool.json", blob(record)}})
		formatterEntries = []trustverify.SourceEntry{{Path: "formatter", Kind: "directory", Mode: "40000"}, {Path: "formatter/native-tool", Kind: "file", Mode: "100755", ContentSHA256: evidencecas.Digest(tool)}, {Path: "formatter/tool.json", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(record)}}
	}
	includeExec := true
	switch variant {
	case "normal", "oversize-tool", "oversize-stdin", "gofmt":
	case "absent":
		includeExec, execTree, execEntries = false, nil, nil
	case "extra":
		execTree = append(execTree, t6BTreeEntry{"100644", "extra", blob([]byte("extra"))})
		execEntries = append(execEntries, trustverify.SourceEntry{Path: ".tplaiter-execution/extra", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte("extra"))})
	case "nested":
		nested := t6BTree(add, []t6BTreeEntry{{"100644", "child", blob([]byte("child"))}})
		execTree = append(execTree, t6BTreeEntry{"40000", "nested", nested})
		execEntries = append(execEntries, trustverify.SourceEntry{Path: ".tplaiter-execution/nested", Kind: "directory", Mode: "40000"}, trustverify.SourceEntry{Path: ".tplaiter-execution/nested/child", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte("child"))})
	case "alias":
		execTree = append(execTree, t6BTreeEntry{"100644", "native_tool", blob([]byte("alias"))})
		execEntries = append(execEntries, trustverify.SourceEntry{Path: ".tplaiter-execution/native_tool", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte("alias"))})
	case "tool-mode":
		execTree[0].mode, execEntries[1].Mode = "100644", "100644"
	case "stdin-mode":
		execTree[1].mode, execEntries[2].Mode = "100755", "100755"
	case "dir-mode":
		execEntries[0].Mode = "40755"
	case "missing-tool":
		execTree, execEntries = execTree[1:], []trustverify.SourceEntry{execEntries[0], execEntries[2]}
	case "missing-stdin":
		execTree, execEntries = execTree[:1], execEntries[:2]
	case "symlink":
		execTree[0].mode, execEntries[1].Mode = "120000", "120000"
	default:
		t.Fatalf("unknown source variant %q", variant)
	}
	rootEntries := []t6BTreeEntry{{"40000", "files", files}, {"100644", "template.contract.json", blob(contract)}, {"100644", "template.manifest.yaml", blob(manifest)}}
	if formatterTree != "" {
		rootEntries = append(rootEntries, t6BTreeEntry{"40000", "formatter", formatterTree})
	}
	if includeExec {
		execDir := t6BTree(add, execTree)
		rootEntries = append(rootEntries, t6BTreeEntry{"40000", ".tplaiter-execution", execDir})
	}
	rootID := t6BTree(add, rootEntries)
	commit := add("commit", []byte("tree "+rootID+"\n\nauthor t6b <t6b@example.test> 0 +0000\n"))
	for id, raw := range objects {
		if err := os.WriteFile(filepath.Join(root, id), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries := execEntries
	entries = append(entries, formatterEntries...)
	entries = append(entries, trustverify.SourceEntry{Path: "files", Kind: "directory", Mode: "40000"}, trustverify.SourceEntry{Path: "files/hello.txt.tmpl", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte("hello\n"))}, trustverify.SourceEntry{Path: "template.contract.json", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(contract)}, trustverify.SourceEntry{Path: "template.manifest.yaml", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(manifest)})
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
	return trustverify.Subject{Origin: "https://example.test/source", TemplatePath: ".", RequestedRef: commit, Commit: commit, TreeSHA256: treeDigest, ContractSHA256: contractDigest}
}

func (f *Fixture) formatterRecord() ([]byte, bool) {
	info, err := buildinfo.Read(bytes.NewReader(f.tool))
	if err != nil {
		return nil, false
	}
	record, err := canonicaljson.Canonical(map[string]any{"apiVersion": "tplaiter.dev/formatter-tool/v1", "adapter": "gofmt-stdin-v1", "toolID": "gofmt", "toolVersion": strings.TrimPrefix(info.GoVersion, "go"), "binarySHA256": evidencecas.Digest(f.tool), "versionEvidence": map[string]any{"kind": "go-buildinfo", "identity": info.GoVersion}, "nativeEnvelope": FormatterNativeEnvelope()})
	return record, err == nil
}

func (f *Fixture) persistentApproval(t *testing.T, r trustverify.ExecutionRequest) trustverify.ApprovalRefs {
	t.Helper()
	a := trustverify.ExecutionApproval{APIVersion: trustverify.ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: r.RequestSHA256, ProfileBindingSHA256: r.ProfileBindingSHA256, OperationInputsSHA256: r.OperationInputsSHA256, ProjectID: r.ProjectID, Scope: r.Scope, ApproverID: f.policy.Approvers[0].ID, IdentityClass: f.policy.Approvers[0].IdentityClass, ExecutionPolicySHA256: f.policy.PolicySHA256, Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, KeyFingerprint: f.policy.Approvers[0].KeyFingerprint}
	var err error
	if a.GrantSHA256, err = a.ComputeGrantSHA256(); err != nil {
		t.Fatal(err)
	}
	grant, _ := hex.DecodeString(a.GrantSHA256[7:])
	sig := []byte(bootstrap.EncodeSignature(ed25519.Sign(f.approver, grant)))
	a.SignatureCAS = evidencecas.Digest(sig)
	raw := t6BJSON(t, a)
	t6BWriteCAS(t, f.evidence, a.SignatureCAS, sig)
	approval := evidencecas.Digest(raw)
	t6BWriteCAS(t, f.evidence, approval, raw)
	return trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: approval}
}

type t6BTreeEntry struct{ mode, name, oid string }

func t6BTree(add func(string, []byte) string, entries []t6BTreeEntry) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var raw []byte
	for _, e := range entries {
		id, _ := hex.DecodeString(e.oid)
		raw = append(raw, []byte(e.mode+" "+e.name+"\x00")...)
		raw = append(raw, id...)
	}
	return add("tree", raw)
}

func t6BItoa(v int) string {
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

func t6BJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func t6BPin(path string, raw []byte) trustload.FilePin {
	return trustload.FilePin{Path: path, SHA256: evidencecas.Digest(raw)}
}

func t6BWriteCAS(t *testing.T, root, digest string, raw []byte) {
	t.Helper()
	x := strings.TrimPrefix(digest, "sha256:")
	dir := filepath.Join(root, "sha256", x[:2])
	if e := os.MkdirAll(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, x[2:]), raw, 0o600); e != nil {
		t.Fatal(e)
	}
}

func t6BPublisherEvidence(t *testing.T, store map[string][]byte, key ed25519.PrivateKey, s trustverify.Subject) trustverify.EvidenceRefs {
	t.Helper()
	put := func(b []byte) string { d := evidencecas.Digest(b); store[d] = append([]byte(nil), b...); return d }
	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Predicate: "https://example.test/predicate", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}}
	raw := t6BJSON(t, statement)
	d, e := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := hex.DecodeString(d[7:])
	return trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: put(raw), SignatureCAS: put([]byte(bootstrap.EncodeSignature(ed25519.Sign(key, hash)))), KeyFingerprint: bootstrap.Fingerprint(key.Public().(ed25519.PublicKey))}
}

func (f *Fixture) Open(t *testing.T) (*trustload.Runtime, *trustverify.VerifiedResolution) {
	t.Helper()
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t6BClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	resolution, err := runtime.TrustRuntime().VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, resolution
}
func (f *Fixture) Tool() []byte   { return append([]byte(nil), f.tool...) }
func (f *Fixture) Record() []byte { raw, _ := f.formatterRecord(); return raw }
func (f *Fixture) Approval(t *testing.T, request trustverify.ExecutionRequest) trustverify.ApprovalRefs {
	return f.persistentApproval(t, request)
}
func (f *Fixture) Scratch() string { return f.scratch }
func (f *Fixture) Project() string { return f.project }

// CorruptSignedToolRecord changes the object behind the signed source commit.
// A retained resolution still has its original bytes, while a fresh source
// verification must reject the changed object before execution.
func (f *Fixture) CorruptSignedToolRecord(t *testing.T) {
	t.Helper()
	record := f.Record()
	raw := append([]byte("blob "+t6BItoa(len(record))+"\x00"), record...)
	sum := sha1.Sum(raw)
	path := filepath.Join(f.dir, "objects", hex.EncodeToString(sum[:]))
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
