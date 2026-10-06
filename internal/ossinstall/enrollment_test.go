package ossinstall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// Test keys are generated here only, never exported as private fixture material.
func signedPackage(t *testing.T, origin string, mutate func(map[string][]byte)) (Publisher, SourcePackage) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"hello.txt": []byte("hello\n"), "template.manifest.yaml": []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: enrolled\n  version: 1.0.0\nengine:\n  type: gotemplate\n  root: .\n")}
	contract, _ := json.Marshal(operationtrust.NativeContract{APIVersion: operationtrust.NativeContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(files["template.manifest.yaml"]), Dependencies: []string{}})
	files["template.contract.json"] = contract
	if mutate != nil {
		mutate(files)
	}
	objects := map[string][]byte{}
	add := func(kind string, data []byte) string {
		raw := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(data))), data...)
		h := sha1.Sum(raw)
		id := hex.EncodeToString(h[:])
		objects[id] = raw
		return id
	}
	entries := []trustverify.SourceEntry{}
	var tree func(string) string
	tree = func(prefix string) string {
		nested := map[string]bool{}
		for name := range files {
			if strings.HasPrefix(name, prefix) {
				part, _, directory := strings.Cut(strings.TrimPrefix(name, prefix), "/")
				nested[part] = nested[part] || directory
			}
		}
		names := []string{}
		for name := range nested {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool {
			a, b := names[i], names[j]
			if nested[a] {
				a += "/"
			}
			if nested[b] {
				b += "/"
			}
			return a < b
		})
		raw := []byte{}
		for _, name := range names {
			mode, kind, id, digest := "100644", "file", "", ""
			if nested[name] {
				mode, kind = "40000", "directory"
				id = tree(prefix + name + "/")
			} else {
				id = add("blob", files[prefix+name])
				digest = evidencecas.Digest(files[prefix+name])
			}
			oid, _ := hex.DecodeString(id)
			raw = append(raw, []byte(mode+" "+name+"\x00")...)
			raw = append(raw, oid...)
			entries = append(entries, trustverify.SourceEntry{Path: prefix + name, Kind: kind, Mode: mode, ContentSHA256: digest})
		}
		return add("tree", raw)
	}
	treeID := tree("")
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	commit := add("commit", []byte("tree "+treeID+"\n\ntest only\n"))
	treeHash, err := bootstrap.DomainDigest("tplaiter.dev/source-content-tree/v1", struct {
		APIVersion string                    `json:"apiVersion"`
		Entries    []trustverify.SourceEntry `json:"entries"`
	}{"tplaiter.dev/source-content-tree/v1", entries})
	if err != nil {
		t.Fatal(err)
	}
	contractHash, err := bootstrap.DomainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", evidencecas.Digest(files["template.contract.json"])})
	if err != nil {
		t.Fatal(err)
	}
	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: localPolicyOrigin, Issuer: "test-publisher-" + strings.TrimPrefix(origin, "https://example.test/"), Predicate: localPredicate, Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: origin, TemplatePath: ".", Commit: commit, TreeSHA256: treeHash, ContractSHA256: contractHash}}
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	return Publisher{Issuer: statement.Issuer, PublicKeyBase64: base64.StdEncoding.EncodeToString(public), SourceOrigin: origin, TemplatePath: "."}, SourcePackage{APIVersion: SourcePackageAPIVersion, Statement: raw, Signature: bootstrap.EncodeSignature(ed25519.Sign(private, msg)), KeyFingerprint: bootstrap.Fingerprint(public), Objects: objects}
}

func enrollmentOptions(t *testing.T) Options {
	t.Helper()
	root := tempRoot(t)
	a, pa := signedPackage(t, "https://example.test/a", nil)
	b, pb := signedPackage(t, "https://example.test/b", nil)
	return Options{Root: root, Publishers: []Publisher{a, b}, SourcePackages: []SourcePackage{pa, pb}, ProjectContexts: []trustload.ProjectContext{{Key: "a", ProjectID: "project-a", SubmitterPrincipalID: operatorPrincipal, MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(filepath.Dir(root), "project-a")}, {Key: "b", ProjectID: "project-b", SubmitterPrincipalID: operatorPrincipal, MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(filepath.Dir(root), "project-b")}}}
}

func enrollGenerated(t *testing.T, result Result) (*Registration, []operationtrust.SourceSelection) {
	t.Helper()
	reg := loadRegistration(t, result)
	loaded, err := trustload.Load(context.Background(), reg.Selection())
	if err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(loaded.Install.OSS.InitialStatePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(loaded.Install.OSS.InitialBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := trustload.DecodeStoredBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := evidencecas.NewFSReader(loaded.Install.EvidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	refs := []string{stored.EnvelopeCAS, stored.ReceiptCAS, stored.Transparency.CheckpointCAS, stored.Transparency.InclusionProofCAS}
	evidence := map[string][]byte{}
	// Same bootstrap-only evidence closure as stock trust provision: sources
	// must resolve from the installed FS CAS, not privileged test store inserts.
	for i := 0; i < len(refs); i++ {
		ref := refs[i]
		if _, ok := evidence[ref]; ok {
			continue
		}
		raw, err := reader.Read(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		evidence[ref] = raw
		if ref == stored.EnvelopeCAS {
			envelope, err := bootstrap.DecodeEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range envelope.RootKeys {
				refs = append(refs, key.PublicKeyCAS)
			}
			for _, sig := range envelope.Signatures {
				refs = append(refs, sig.SignatureCAS)
			}
		}
	}
	factory := func(reader evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(reader, bootstrap.ClockFunc(time.Now), nil, 0)
	}
	if err := trustload.Enroll(context.Background(), reg.Selection(), factory, state, bundle, evidence); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(result.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var selections []operationtrust.SourceSelection
	if err := json.Unmarshal(raw, &selections); err != nil {
		t.Fatal(err)
	}
	return reg, selections
}

func TestInitialEnrollmentTwoProjectsAndSources(t *testing.T) {
	o := enrollmentOptions(t)
	result, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range o.ProjectContexts {
		if _, err := os.Stat(p.RootPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("project enrollment created content: %v", err)
		}
	}
	reg, sels := enrollGenerated(t, result)
	if len(sels) != 2 {
		t.Fatal("missing selections")
	}
	runtimes := []*trustload.Runtime{}
	for _, p := range o.ProjectContexts {
		r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: reg.Selection(), ProjectKey: p.Key, Clock: bootstrap.ClockFunc(time.Now)})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		runtimes = append(runtimes, r)
		if r.ProjectContext() != p {
			t.Fatal("incorrect finite context")
		}
		for _, sel := range sels {
			raw, _ := json.Marshal(sel)
			decoded, err := operationtrust.DecodeSourceSelection(raw)
			if err != nil {
				t.Fatal(err)
			}
			resolution, err := r.TrustRuntime().VerifySubject(context.Background(), decoded.TrustSubject(), decoded.EvidenceRefs())
			if err != nil {
				t.Fatal(err)
			}
			if !resolution.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
				t.Fatal("invalid resolution")
			}
		}
	}
	if runtimes[0].TrustRuntime().Binding().Equal(runtimes[1].TrustRuntime().Binding()) {
		t.Fatal("contexts share binding")
	}
	resolution, err := runtimes[0].TrustRuntime().VerifySubject(context.Background(), sels[0].TrustSubject(), sels[0].EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	if resolution.ValidFor(runtimes[1].TrustRuntime(), runtimes[1].TrustRuntime().Binding()) {
		t.Fatal("cross-project resolution replay")
	}
	if _, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: reg.Selection(), ProjectKey: "unknown", Clock: bootstrap.ClockFunc(time.Now)}); err == nil {
		t.Fatal("unknown key accepted")
	}
	before, _ := os.ReadFile(result.RegistrationPath)
	reuse, err := Generate(o)
	if err != nil || !reuse.Reused {
		t.Fatalf("exact reuse: %v", err)
	}
	o.ProjectContexts[0].ProjectID = "different"
	if _, err := Generate(o); !errors.Is(err, ErrEnrollmentChanged) {
		t.Fatalf("changed context accepted: %v", err)
	}
	o.Rotate = true
	if _, err := Generate(o); !errors.Is(err, ErrEnrollmentChanged) {
		t.Fatalf("enrolled store reset: %v", err)
	}
	after, _ := os.ReadFile(result.RegistrationPath)
	if !bytes.Equal(before, after) {
		t.Fatal("registration changed on refusal")
	}
	store, err := trustload.OpenReadOnly(context.Background(), reg.Selection())
	if err != nil {
		t.Fatal("prior store lost", err)
	}
	_ = store.Close()
}

func TestInitialEnrollmentRejectsPackageBeforePublication(t *testing.T) {
	cases := map[string]func(*Options){
		"wrong-key":       func(o *Options) { o.SourcePackages[0].KeyFingerprint = "sha256:" + strings.Repeat("a", 64) },
		"wrong-signature": func(o *Options) { o.SourcePackages[0].Signature = bootstrap.EncodeSignature(make([]byte, 64)) },
		"malformed-frame": func(o *Options) {
			for id := range o.SourcePackages[0].Objects {
				o.SourcePackages[0].Objects[id] = []byte("blob 3\x00bad")
				break
			}
		},
		"wrong-oid": func(o *Options) {
			for id, raw := range o.SourcePackages[0].Objects {
				delete(o.SourcePackages[0].Objects, id)
				o.SourcePackages[0].Objects[strings.Repeat("a", 40)] = raw
				break
			}
		},
		"missing-object": func(o *Options) {
			for id := range o.SourcePackages[0].Objects {
				delete(o.SourcePackages[0].Objects, id)
				break
			}
		},
		"extra-object": func(o *Options) {
			raw := []byte("blob 6\x00orphan")
			h := sha1.Sum(raw)
			o.SourcePackages[0].Objects[hex.EncodeToString(h[:])] = raw
		},
		"wrong-scope": func(o *Options) { o.Publishers[0].TemplatePath = "other" },
		"package-count": func(o *Options) {
			for len(o.SourcePackages) < 33 {
				o.SourcePackages = append(o.SourcePackages, o.SourcePackages[0])
			}
		},
		"external-root": func(o *Options) { o.Publishers[0].ObjectRoot = filepath.Dir(o.Root) },
		"wrong-tree-digest": func(o *Options) {
			var s bootstrap.PublisherStatement
			_ = json.Unmarshal(o.SourcePackages[0].Statement, &s)
			s.Subject.TreeSHA256 = evidencecas.Digest(nil)
			o.SourcePackages[0].Statement, _ = json.Marshal(s)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := enrollmentOptions(t)
			mutate(&o)
			if _, err := Generate(o); err == nil {
				t.Fatal("invalid package accepted")
			}
			if _, err := os.Stat(o.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failure published root: %v", err)
			}
		})
	}
	for _, name := range []string{"bad-manifest-hash", "missing-contract", "action"} {
		t.Run(name, func(t *testing.T) {
			o := enrollmentOptions(t)
			pub, p := signedPackage(t, "https://example.test/a", func(files map[string][]byte) {
				switch name {
				case "bad-manifest-hash":
					files["template.manifest.yaml"] = append(files["template.manifest.yaml"], []byte("# changed\n")...)
				case "missing-contract":
					delete(files, "template.contract.json")
				case "action":
					files["template.manifest.yaml"] = append(files["template.manifest.yaml"], []byte("hooks:\n  postCreate:\n    - run: echo unsafe\n")...)
					var c operationtrust.NativeContract
					_ = json.Unmarshal(files["template.contract.json"], &c)
					c.ManifestSHA256 = evidencecas.Digest(files["template.manifest.yaml"])
					files["template.contract.json"], _ = json.Marshal(c)
				}
			})
			o.Publishers[0] = pub
			o.SourcePackages[0] = p
			if _, err := Generate(o); err == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
}

func TestInitialEnrollmentRejectsProjects(t *testing.T) {
	cases := map[string]func(*Options){"duplicate-id": func(o *Options) { o.ProjectContexts[1].ProjectID = o.ProjectContexts[0].ProjectID }, "duplicate-key": func(o *Options) { o.ProjectContexts[1].Key = o.ProjectContexts[0].Key }, "duplicate-root": func(o *Options) { o.ProjectContexts[1].RootPath = o.ProjectContexts[0].RootPath }, "nested-root": func(o *Options) {
		_ = os.Mkdir(o.ProjectContexts[0].RootPath, 0o700)
		o.ProjectContexts[1].RootPath = filepath.Join(o.ProjectContexts[0].RootPath, "child")
	}, "trust-overlap": func(o *Options) { o.ProjectContexts[0].RootPath = o.Root }, "downgrade": func(o *Options) { o.ProjectContexts[0].MinimumProfile = bootstrap.ProfileDevelopment }, "submitter": func(o *Options) { o.ProjectContexts[0].SubmitterPrincipalID = "principal:unknown" }, "symlink-parent": func(o *Options) {
		link := filepath.Join(filepath.Dir(o.Root), "link")
		_ = os.Symlink(filepath.Dir(o.Root), link)
		o.ProjectContexts[0].RootPath = filepath.Join(link, "target")
	}}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := enrollmentOptions(t)
			mutate(&o)
			if _, err := Generate(o); err == nil {
				t.Fatal("invalid project accepted")
			}
		})
	}
}

func TestConfinedImmutablePublicationAndVacancy(t *testing.T) {
	root := filepath.Dir(tempRoot(t))
	raw := []byte("verified bytes")
	digest := evidencecas.Digest(raw)
	if err := writeCAS(root, digest, raw); err != nil {
		t.Fatal(err)
	}
	x := strings.TrimPrefix(digest, "sha256:")
	path := filepath.Join(root, "sha256", x[:2], x[2:])
	if err := os.WriteFile(path, []byte("collision"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCAS(root, digest, raw); err == nil {
		t.Fatal("collision overwritten")
	}
	assertTestFile(t, path, "collision")
	_ = os.Remove(path)
	target := filepath.Join(root, "target")
	writeTestFile(t, target, "preserve")
	_ = os.Symlink(target, path)
	if err := writeCAS(root, digest, raw); err == nil {
		t.Fatal("symlink overwritten")
	}
	assertTestFile(t, target, "preserve")
	stage := filepath.Join(root, "stage")
	_ = os.Mkdir(stage, 0o700)
	writeTestFile(t, filepath.Join(stage, RegistrationFile), "candidate")
	prior := filepath.Join(root, "prior")
	writeTestFile(t, filepath.Join(prior, "foreign"), "prior")
	if err := publishInstallation(stage, prior); err == nil {
		t.Fatal("nonvacant install replaced")
	}
	assertTestFile(t, filepath.Join(prior, "foreign"), "prior")
	if _, err := DecodeSourcePackages([]byte(`[{"apiVersion":"x","publicKey":"self-authority"}]`)); err == nil {
		t.Fatal("package supplied authority accepted")
	}
	if _, err := DecodeSourcePackages([]byte(`[] {}`)); err == nil {
		t.Fatal("trailing document accepted")
	}
}

func TestMerkleEnrollmentOddTreesAndDenials(t *testing.T) {
	for _, size := range []int{1, 2, 3, 5, 33} {
		g := &generator{evidence: map[string][]byte{}}
		leaves := []string{}
		for i := 0; i < size; i++ {
			leaves = append(leaves, fmt.Sprintf("leaf-%d", i))
		}
		cp, proofs, err := g.checkpoint("authority", leaves)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := bootstrap.DecodeCheckpoint(g.evidence[cp])
		h, _ := hex.DecodeString(strings.TrimPrefix(c.RootHash, "sha256:"))
		var root bootstrap.MerkleHash
		copy(root[:], h)
		for i, ref := range proofs {
			p, _ := bootstrap.DecodeInclusionProof(g.evidence[ref])
			hashes := []bootstrap.MerkleHash{}
			for _, v := range p.Hashes {
				b, _ := hex.DecodeString(strings.TrimPrefix(v, "sha256:"))
				var h bootstrap.MerkleHash
				copy(h[:], b)
				hashes = append(hashes, h)
			}
			if err := bootstrap.VerifyInclusion([]byte(leaves[i]), p.LeafIndex, p.TreeSize, root, hashes); err != nil {
				t.Fatal(size, i, err)
			}
			if err := bootstrap.VerifyInclusion([]byte("unpublished-source"), p.LeafIndex, p.TreeSize, root, hashes); err == nil {
				t.Fatal("absent leaf accepted")
			}
		}
	}
}

func TestOneLeafAndIndependentCheckpointDenyOrphanCAS(t *testing.T) {
	o := enrollmentOptions(t)
	source := o.SourcePackages[0]
	o.SourcePackages = nil
	result, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := enrollGenerated(t, result)
	loaded, err := trustload.Load(context.Background(), reg.Selection())
	if err != nil {
		t.Fatal(err)
	}
	statement, _ := bootstrap.DecodePublisherStatement(source.Statement)
	root := ""
	for _, origin := range loaded.Install.ObjectOrigins {
		if origin.Origin == statement.Subject.Origin {
			root = origin.RootPath
		}
	}
	for id, raw := range source.Objects {
		if err := publishImmutable(root, id, raw); err != nil {
			t.Fatal(err)
		}
	}
	statementCAS := evidencecas.Digest(source.Statement)
	signatureCAS := evidencecas.Digest([]byte(source.Signature))
	for _, raw := range [][]byte{source.Statement, []byte(source.Signature)} {
		if err := writeCAS(loaded.Install.EvidenceRoot, evidencecas.Digest(raw), raw); err != nil {
			t.Fatal(err)
		}
	}
	bundleRaw, _ := os.ReadFile(loaded.Install.OSS.InitialBundlePath)
	bundle, _ := trustload.DecodeStoredBundle(bundleRaw)
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: reg.Selection(), ProjectKey: "a", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	refs := trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: statementCAS, SignatureCAS: signatureCAS, KeyFingerprint: source.KeyFingerprint, CheckpointCAS: bundle.Transparency.CheckpointCAS, InclusionProofCAS: bundle.Transparency.InclusionProofCAS}
	if _, err := runtime.TrustRuntime().VerifySubject(context.Background(), statementSubject(statement), refs); err == nil {
		t.Fatal("empty one-leaf source log accepted orphan")
	}
	g := &generator{evidence: map[string][]byte{}}
	cp, proofs, err := g.checkpoint("independent-authority", []string{statementCAS})
	if err != nil {
		t.Fatal(err)
	}
	for digest, raw := range g.evidence {
		if err := writeCAS(loaded.Install.EvidenceRoot, digest, raw); err != nil {
			t.Fatal(err)
		}
	}
	refs.CheckpointCAS, refs.InclusionProofCAS = cp, proofs[0]
	if _, err := runtime.TrustRuntime().VerifySubject(context.Background(), statementSubject(statement), refs); err == nil {
		t.Fatal("independent checkpoint accepted")
	}
}

func TestImportFailurePreservesPriorAndSourceContract(t *testing.T) {
	o := enrollmentOptions(t)
	result, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := enrollGenerated(t, result)
	before, _ := os.ReadFile(result.RegistrationPath)
	oldSignature := o.SourcePackages[0].Signature
	o.SourcePackages[0].Signature = bootstrap.EncodeSignature(make([]byte, 64))
	if _, err := Generate(o); err == nil {
		t.Fatal("changed package reused")
	}
	o.SourcePackages[0].Signature = oldSignature
	if _, err := Generate(Options{Root: o.Root, Rotate: true}); !errors.Is(err, ErrEnrollmentChanged) {
		t.Fatalf("omitted contract reset enrollment: %v", err)
	}
	after, _ := os.ReadFile(result.RegistrationPath)
	if !bytes.Equal(before, after) {
		t.Fatal("prior registration damaged")
	}
	store, err := trustload.OpenReadOnly(context.Background(), reg.Selection())
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	loaded, err := trustload.Load(context.Background(), reg.Selection())
	if err != nil {
		t.Fatal(err)
	}
	statement, _ := bootstrap.DecodePublisherStatement(o.SourcePackages[0].Statement)
	for _, origin := range loaded.Install.ObjectOrigins {
		if origin.Origin == statement.Subject.Origin {
			for id := range o.SourcePackages[0].Objects {
				if err := os.WriteFile(filepath.Join(origin.RootPath, id), []byte("corrupt"), 0o600); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
	}
	if _, err := Generate(o); err == nil {
		t.Fatal("corrupted imported objects silently reused")
	}
}

func TestRawTreeSymlinkGitlinkAndObjectBounds(t *testing.T) {
	for _, mode := range []string{"120000", "160000"} {
		t.Run(mode, func(t *testing.T) {
			o := enrollmentOptions(t)
			p := &o.SourcePackages[0]
			statement, _ := bootstrap.DecodePublisherStatement(p.Statement)
			commitRaw := p.Objects[statement.Subject.Commit]
			commitObj, err := rawObject(statement.Subject.Commit, commitRaw)
			if err != nil {
				t.Fatal(err)
			}
			treeID := strings.TrimPrefix(strings.Split(string(commitObj.Data), "\n")[0], "tree ")
			treeObj, err := rawObject(treeID, p.Objects[treeID])
			if err != nil {
				t.Fatal(err)
			}
			data := bytes.Replace(treeObj.Data, []byte("100644 "), []byte(mode+" "), 1)
			raw := append([]byte(fmt.Sprintf("tree %d\x00", len(data))), data...)
			hash := sha1.Sum(raw)
			newTree := hex.EncodeToString(hash[:])
			delete(p.Objects, treeID)
			p.Objects[newTree] = raw
			data = bytes.Replace(commitObj.Data, []byte(treeID), []byte(newTree), 1)
			raw = append([]byte(fmt.Sprintf("commit %d\x00", len(data))), data...)
			hash = sha1.Sum(raw)
			newCommit := hex.EncodeToString(hash[:])
			delete(p.Objects, statement.Subject.Commit)
			p.Objects[newCommit] = raw
			statement.Subject.Commit = newCommit
			p.Statement, _ = json.Marshal(statement)
			if _, err := Generate(o); err == nil {
				t.Fatal("unsupported Git mode imported")
			}
		})
	}
	o := enrollmentOptions(t)
	for len(o.SourcePackages[0].Objects) < 8193 {
		o.SourcePackages[0].Objects[fmt.Sprintf("%040x", len(o.SourcePackages[0].Objects))] = nil
	}
	if _, err := Generate(o); err == nil {
		t.Fatal("object count bound ignored")
	}
}

func TestInstalledEnrollmentProvisionProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("installed process proof")
	}
	o := enrollmentOptions(t)
	result, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(filepath.Dir(o.Root), "tplaiter")
	moduleRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	flags := "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath=" + result.RegistrationPath + " -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=" + result.RegistrationSHA256
	build := exec.Command("go", "build", "-buildvcs=false", "-ldflags", flags, "-o", binary, ".")
	build.Dir = moduleRoot
	build.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("installed build: %v\n%s", err, output)
	}
	home := filepath.Join(filepath.Dir(o.Root), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"trust", "provision"}, {"trust", "inspect", "--json"}} {
		command := exec.Command(binary, args...)
		command.Dir = home
		command.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("installed %v: %v\n%s", args, err, output)
		}
		if args[1] == "inspect" && !bytes.Contains(output, []byte("publisher-verified")) {
			t.Fatalf("inspect missing authority: %s", output)
		}
	}
	reg := loadRegistration(t, result)
	raw, err := os.ReadFile(result.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var selections []operationtrust.SourceSelection
	if err := json.Unmarshal(raw, &selections); err != nil {
		t.Fatal(err)
	}
	for _, p := range o.ProjectContexts {
		runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: reg.Selection(), ProjectKey: p.Key, Clock: bootstrap.ClockFunc(time.Now)})
		if err != nil {
			t.Fatal(err)
		}
		for _, sel := range selections {
			if _, err := runtime.TrustRuntime().VerifySubject(context.Background(), sel.TrustSubject(), sel.EvidenceRefs()); err != nil {
				_ = runtime.Close()
				t.Fatal(err)
			}
		}
		_ = runtime.Close()
	}
}

func TestEnrollmentContractBindsDefaultKeyAndRawStatementCAS(t *testing.T) {
	o := enrollmentOptions(t)
	before, err := contractFor(o)
	if err != nil {
		t.Fatal(err)
	}
	o.ProjectContexts[0], o.ProjectContexts[1] = o.ProjectContexts[1], o.ProjectContexts[0]
	after, err := contractFor(o)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("default selection omitted from contract")
	}
	o.ProjectContexts[0], o.ProjectContexts[1] = o.ProjectContexts[1], o.ProjectContexts[0]
	o.SourcePackages[0].Statement = append([]byte(" "), o.SourcePackages[0].Statement...)
	after, err = contractFor(o)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("raw statement CAS omitted from contract")
	}
	o.SourcePackages = []SourcePackage{}
	if _, err := Generate(o); err == nil {
		t.Fatal("explicit empty package input accepted")
	}
}

func TestLocalProviderZeroInputKeepsEnrollmentDigest(t *testing.T) {
	plain := Options{}
	legacy, err := contractFor(plain)
	if err != nil {
		t.Fatal(err)
	}
	plain.LocalProviders = []LocalProviderSpec{}
	empty, err := contractFor(plain)
	if err != nil || legacy != empty {
		t.Fatal("zero input changed legacy digest", err)
	}
	if _, err := DecodeLocalProviders([]byte(`[{"registrationID":"synthetic","installationID":"caller"}]`)); err == nil {
		t.Fatal("caller installation authority")
	}
}

func TestAuthenticatedContentImporterUsesCompleteIndex(t *testing.T) {
	for _, bad := range []bool{false, true} {
		o := contentExternalOptions(t, func(p *exports.ExportPayload, _ map[string][]byte) {
			if bad {
				p.Files = p.Files[1:]
			}
		})
		entropy := &recordingRand{}
		o.Rand = entropy
		result, err := Generate(o)
		if bad {
			if err == nil || entropy.next != 0 {
				t.Fatal("authenticated signature bypassed incomplete index")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_, selections := enrollGenerated(t, result)
		if len(selections) != 2 {
			t.Fatal("content source omitted")
		}
	}
}
