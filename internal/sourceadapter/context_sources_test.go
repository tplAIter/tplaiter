package sourceadapter_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func encodeNew(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func writeNew(t *testing.T, p string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func gitNew(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("/usr/bin/git", append([]string{"-C", dir}, args...)...)
	// This is a newly created test repository only. No machine identity, credential
	// profile or inherited Git configuration is read by fixture Git commands.
	cmd.Env = []string{"PATH=/usr/bin:/bin:/opt/homebrew/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=Public Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=Public Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("fixture Git %v: %v %s", args, err, stderr.Bytes())
	}
	return strings.TrimSpace(string(raw))
}

type normalNewFixture struct {
	runtime                          *trustload.Runtime
	registration                     *ossinstall.Registration
	raw                              []byte
	input                            contextsource.ContextSourceSelection
	home, install, rootRepo, project string
	rootObjects                      map[string][]byte
}

// Captured ordinary Git sources, real configured publisher signatures and normal
// Generate/provision/OpenRuntime are used. No lock or authority snapshot is made.
func normalNew(t *testing.T, alter func(string, map[string][]byte)) *normalNewFixture {
	t.Helper()
	ctx := context.Background()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &normalNewFixture{home: filepath.Join(dir, "home"), install: filepath.Join(dir, "install"), project: filepath.Join(dir, "project")}
	if err := os.MkdirAll(filepath.Join(f.home, "repos"), 0700); err != nil {
		t.Fatal(err)
	}
	subjects := map[string]trustverify.Subject{}
	options := ossinstall.Options{Root: f.install, ProjectContexts: []trustload.ProjectContext{{Key: "project", ProjectID: "project:example", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: f.project}}}
	parameters := []deps.Parameter{{Name: "flavor", Value: json.RawMessage(`"plain"`)}}
	for _, alias := range []string{"leaf", "a", "b", "root"} {
		refs := []contextsource.ContextDependency{}
		associations := []contextsource.ContextDependencyBinding{}
		requires := []exports.ExportRequirement{}
		children := []string{}
		if alias == "a" || alias == "b" {
			children = []string{"leaf"}
		}
		if alias == "root" {
			children = []string{"a", "b"}
		}
		for _, child := range children {
			s := subjects[child]
			refs = append(refs, contextsource.ContextDependency{Alias: child, Origin: s.Origin, TemplatePath: s.TemplatePath, CommitAlgorithm: "sha1", Commit: s.Commit, TreeDigest: s.TreeSHA256, ContractDigest: s.ContractSHA256})
			associations = append(associations, contextsource.ContextDependencyBinding{Alias: child, ProviderID: "provider." + child, Parameters: parameters})
			requires = append(requires, exports.ExportRequirement{Selector: child + ".block.notes", ContractDigest: s.ContractSHA256, CompatibleRange: ">=1.0.0 <2.0.0"})
		}
		rawManifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: context-" + alias + "\n  version: 1.0.0\nengine:\n  type: gotemplate\n  root: files\nsettings:\n  - group: greeting\n    title: Greeting\n    type: string\n    default: Hello\ngenerators:\n  - kind: entity\n    snippet: generators/entity.tmpl\n    target: internal/{{ .Name.Snake }}/entity.go\n")
		contract := encodeNew(t, contextsource.NativeContextContract{APIVersion: contextsource.NativeContextContractAPIVersion, Kind: "NativeTemplate", ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(rawManifest), Dependencies: refs})
		if alias == "leaf" {
			contract = encodeNew(t, operationtrust.NativeContract{APIVersion: operationtrust.NativeContractAPIVersion, Kind: "NativeTemplate", ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(rawManifest), Dependencies: []string{}})
		}
		binding := contextsource.ContextSourceBindings{APIVersion: contextsource.ContextSourceBindingsAPIVersion, Kind: "ContextSourceBindings", Source: contextsource.ContextCatalogBinding{Alias: alias, ProviderID: "provider." + alias, Parameters: parameters, EntriesPath: "catalog/entries.json", PayloadDirectory: "catalog/payloads", ToolPath: "catalog/tool.md"}, Dependencies: associations}
		content := []byte("Complete inert context for " + alias + ". Read prerequisites before action.\n")
		tool := []byte("Inert content; no execution.\n")
		payload := encodeNew(t, exports.ExportPayload{APIVersion: exports.ExportPayloadAPIVersion, ExportID: "notes", Files: []exports.PayloadFile{{SourcePath: "docs/notes.md", TargetPath: "context/" + alias + ".md", Mode: "100644", ContentSHA256: evidencecas.Digest(content)}}, Slots: []exports.PayloadSlot{}, Blocks: []exports.PayloadBlock{}})
		domain := "block"
		if alias == "root" {
			domain = "skill"
		}
		files := map[string][]byte{"template.manifest.yaml": rawManifest, "template.contract.json": contract, contextsource.ContextSourceBindingsPath: encodeNew(t, binding), "files/hello.txt.tmpl": []byte("{{ .Settings.greeting }} {{ .Project.Name }}\n"), "generators/entity.tmpl": []byte("Inert entity image for " + alias + ".\n"), "docs/notes.md": content, "catalog/tool.md": tool, "catalog/payloads/notes.json": payload, "catalog/entries.json": encodeNew(t, []exports.ExportEntry{{ID: "notes", Domain: domain, Name: "notes", Version: "1.0.0", ContentDigest: evidencecas.Digest(payload), ToolDigest: evidencecas.Digest(tool), Parameters: []exports.ScalarParameter{}, Requires: requires}})}
		if alter != nil {
			alter(alias, files)
		}
		repoDir := filepath.Join(dir, "source-"+alias)
		if alias == "root" {
			repoDir = filepath.Join(f.home, "repos", "fixture")
			f.rootRepo = repoDir
		}
		if err := os.MkdirAll(repoDir, 0700); err != nil {
			t.Fatal(err)
		}
		gitNew(t, repoDir, "init", "--initial-branch=main")
		for name, raw := range files {
			writeNew(t, filepath.Join(repoDir, filepath.FromSlash(name)), raw)
		}
		gitNew(t, repoDir, "add", "--all")
		tree := gitNew(t, repoDir, "write-tree")
		commit := gitNew(t, repoDir, "commit-tree", tree, "-m", "Public generic fixture")
		gitNew(t, repoDir, "update-ref", "refs/heads/main", commit)
		origin := "https://example.test/" + alias
		captured, err := sourcepackage.Capture(ctx, sourcepackage.CaptureInput{RepositoryPath: repoDir, Origin: origin, TemplatePath: ".", Commit: commit})
		if err != nil {
			t.Fatal(err)
		}
		subjects[alias] = captured.Subject
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		issuer := "publisher." + alias
		statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://local.tplaiter.invalid/policy", Issuer: issuer, Predicate: "https://local.tplaiter.invalid/predicate/template-source", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: origin, TemplatePath: ".", Commit: commit, TreeSHA256: captured.Subject.TreeSHA256, ContractSHA256: captured.Subject.ContractSHA256}}
		digest, err := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
		if err != nil {
			t.Fatal(err)
		}
		message, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
		if err != nil {
			t.Fatal(err)
		}
		options.Publishers = append(options.Publishers, ossinstall.Publisher{Issuer: issuer, PublicKeyBase64: base64.StdEncoding.EncodeToString(public), SourceOrigin: origin, TemplatePath: "."})
		options.SourcePackages = append(options.SourcePackages, ossinstall.SourcePackage{APIVersion: ossinstall.SourcePackageAPIVersion, Statement: encodeNew(t, statement), Signature: bootstrap.EncodeSignature(ed25519.Sign(private, message)), KeyFingerprint: bootstrap.Fingerprint(public), Objects: captured.Objects})
		if alias == "root" {
			f.rootObjects = captured.Objects
		}
	}
	result, err := ossinstall.Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	registrationRaw, err := os.ReadFile(result.RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	f.registration, err = ossinstall.DecodeRegistration(registrationRaw)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := trustload.Load(ctx, f.registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	stateRaw, err := os.ReadFile(loaded.Install.OSS.InitialStatePath)
	if err != nil {
		t.Fatal(err)
	}
	bundleRaw, err := os.ReadFile(loaded.Install.OSS.InitialBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := trustload.DecodeStoredBundle(bundleRaw)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := evidencecas.NewFSReader(loaded.Install.EvidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	evidence := map[string][]byte{}
	refs := []string{bundle.EnvelopeCAS, bundle.ReceiptCAS, bundle.Transparency.CheckpointCAS, bundle.Transparency.InclusionProofCAS}
	for i := 0; i < len(refs); i++ {
		ref := refs[i]
		if _, ok := evidence[ref]; ok {
			continue
		}
		raw, err := reader.Read(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		evidence[ref] = raw
		if ref == bundle.EnvelopeCAS {
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
	factory := func(r evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(r, bootstrap.ClockFunc(time.Now), nil, 0)
	}
	if err := trustload.Enroll(ctx, f.registration.Selection(), factory, stateRaw, bundleRaw, evidence); err != nil {
		t.Fatal(err)
	}
	f.runtime, err = trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.registration.Selection(), ProjectKey: "project", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.runtime.Close() })
	entries, err := os.ReadDir(filepath.Join(f.install, "config/context-source-selections"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(f.install, "config/context-source-selections", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		input, err := contextsource.DecodeSourceSelectionV2(raw)
		if err != nil {
			t.Fatal(err)
		}
		if input.Root.Subject.Origin == "https://example.test/root" {
			f.raw = raw
			f.input = input
		}
	}
	if len(f.raw) == 0 {
		t.Fatal("normal producer omitted root")
	}
	cfg := state.DefaultConfig()
	cfg.Repos = []state.RepoRef{{Alias: "fixture", URL: f.input.Root.Subject.Origin, Branch: "main", Type: state.RepoKindGit}}
	if err := state.SaveConfig(f.home, cfg); err != nil {
		t.Fatal(err)
	}
	index := state.NewIndex(time.Now())
	index.Repos["fixture"] = []state.TemplateEntry{{Name: "context-root", Version: "1.0.0", Path: ".", Ref: "main"}}
	if err := state.SaveIndex(f.home, index); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNormalContextNativeNewInstalledRenderLocksResources(t *testing.T) {
	f := normalNew(t, nil)
	ctx := context.Background()
	for _, ref := range []string{f.input.Root.Subject.Commit, "fixture/context-root@latest"} {
		source, err := sourceadapter.ResolveContextSources(ctx, f.runtime, f.home, ref, f.raw)
		if err != nil {
			t.Fatal(err)
		}
		rootData, err := source.Root(ctx, f.runtime)
		if err != nil {
			t.Fatal(err)
		}
		rootData.Input[0] = 'X'
		detached := rootData.Snapshot.(fstest.MapFS)
		detached["files/hello.txt.tmpl"].Data = []byte("forged detached grant\n")

		carrier, err := source.Sources(ctx, f.runtime)
		if err != nil {
			t.Fatal(err)
		}
		in := contextsource.NativeNewInput{Render: renderref.Input{Values: settings.Values{"greeting": "Welcome"}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}, Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: rootData.Alias}, RendererVersion: "1.0.0"}
		prepared, err := contextsource.PrepareNativeNew(ctx, f.runtime, carrier, in)
		if err != nil {
			t.Fatal(err)
		}
		rendered, err := prepared.Rendered(ctx, f.runtime)
		if err != nil || len(rendered.Files) != 1 || string(rendered.Files["hello.txt"]) != "Welcome Example\n" {
			t.Fatalf("root-only normal render: %+v %v", rendered, err)
		}
		root, err := prepared.RootLock(ctx, f.runtime)
		if err != nil {
			t.Fatal(err)
		}
		ledger, err := prepared.DependencyLock(ctx, f.runtime)
		if err != nil || len(ledger.Dependencies) != 3 || provenance.ValidateLockPair(root, ledger) != nil {
			t.Fatalf("complete locks: %+v %v", ledger, err)
		}
		expected := map[string]contextsource.ContextSourceProof{f.input.Root.Subject.Origin: f.input.Root}
		for _, proof := range f.input.Sources {
			expected[proof.Subject.Origin] = proof
		}
		check := func(s provenance.RootSubject) {
			proof := expected[s.Origin]
			if s.Subject() != proofSubject(proof) || s.StatementCAS != proof.Evidence.StatementCAS || s.SignatureCAS != proof.Evidence.SignatureCAS || s.KeyFingerprint != proof.Evidence.KeyFingerprint || s.CheckpointCAS != proof.Evidence.CheckpointCAS || s.InclusionProofCAS != proof.Evidence.InclusionProofCAS {
				t.Fatal("lost source/evidence pin")
			}
		}
		check(root.Root)
		for _, s := range ledger.Dependencies {
			check(provenance.RootSubject(s))
		}
		images, err := resources.PlanContextNativeGeneratorImages(ctx, f.runtime, prepared)
		if err != nil || len(images.Files) != 1 || len(images.Lock.Artifacts) != 1 {
			t.Fatalf("complete root resource: %+v %v", images, err)
		}
		name := ".tplaiter/generators/generators/entity.tmpl"
		if string(images.Files[name]) != "Inert entity image for root.\n" {
			t.Fatal("empty or dependency resource substituted")
		}
		if err := images.Validate(root); err != nil {
			t.Fatal(err)
		}
		resolution, err := prepared.RootResolution(ctx, f.runtime)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := resources.PlanNativeGeneratorImages(f.runtime.TrustRuntime(), resolution, root); err == nil {
			t.Fatal("v1 resource guard weakened")
		}
		if _, err := operationtrust.PrepareNew(ctx, f.runtime, operationtrust.PrepareNewInput{SourceInput: f.raw, Render: in.Render, RendererVersion: in.RendererVersion}); err == nil {
			t.Fatal("v1 preparation guard weakened")
		}
		operation, err := prepared.OperationInputsSHA256(ctx, f.runtime)
		if err != nil || operation == "" {
			t.Fatal("missing operation identity")
		}
		identity, err := prepared.ContextDigest(ctx, f.runtime)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("normal operator capture/enrollment ref=%s dependencies=%d rendered=%d rootResources=%d rootLock=%s dependencyLock=%s operation=%s intent=%s", ref, len(ledger.Dependencies), len(rendered.Files), len(images.Files), root.RootLockSHA256, ledger.LockSHA256, operation, identity)
		invalid := in
		invalid.Render.Values = settings.Values{"greeting": 42}
		if bad, err := contextsource.PrepareNativeNew(ctx, f.runtime, carrier, invalid); err == nil {
			bad.Close()
			t.Fatal("fresh typed setting accepted malformed value")
		}
		invalid.RendererVersion = "../invalid renderer"
		if bad, err := contextsource.PrepareNativeNew(ctx, f.runtime, carrier, invalid); err == nil {
			bad.Close()
			t.Fatal("invalid renderer accepted")
		}
		changed := in
		changed.Render.Runtime.Port++
		other, err := contextsource.PrepareNativeNew(ctx, f.runtime, carrier, changed)
		if err != nil {
			t.Fatal(err)
		}
		otherIdentity, err := other.ContextDigest(ctx, f.runtime)
		if err != nil || identity == otherIdentity {
			t.Fatal("render coordinates not bound")
		}
		other.Close()
		rendered.Files["hello.txt"][0] = 'X'
		rendered.Template.Metadata.Name = "foreign"
		ledger.Dependencies[0].Commit = "changed"
		images.Files[name][0] = 'X'
		again, err := prepared.Rendered(ctx, f.runtime)
		if err != nil || string(again.Files["hello.txt"]) != "Welcome Example\n" || again.Template.Metadata.Name == "foreign" {
			t.Fatal("returned data altered intent")
		}
		if images.Validate(root) == nil {
			t.Fatal("image hash mismatch accepted")
		}
		foreign, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.registration.Selection(), ProjectKey: "project", Clock: bootstrap.ClockFunc(time.Now)})
		if err != nil {
			t.Fatal(err)
		}
		if source.RecheckFor(ctx, foreign) == nil || prepared.RecheckFor(ctx, foreign) == nil {
			t.Fatal("foreign runtime accepted")
		}
		if _, err := resources.PlanContextNativeGeneratorImages(ctx, foreign, prepared); err == nil {
			t.Fatal("foreign projection accepted")
		}
		foreign.Close()
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := resources.PlanContextNativeGeneratorImages(cancelled, f.runtime, prepared); err == nil {
			t.Fatal("cancel ignored")
		}
		loaded, err := trustload.Load(ctx, f.registration.Selection())
		if err != nil {
			t.Fatal(err)
		}
		objectPath := ""
		for _, o := range loaded.Install.ObjectOrigins {
			if o.Origin == f.input.Root.Subject.Origin {
				objectPath = filepath.Join(o.RootPath, f.input.Root.Subject.Commit)
			}
		}
		original, err := os.ReadFile(objectPath)
		if err != nil {
			t.Fatal(err)
		}
		writeNew(t, objectPath, []byte("stale immutable source"))
		if prepared.RecheckFor(ctx, f.runtime) == nil {
			t.Fatal("stale carrier accepted")
		}
		if _, err := resources.PlanContextNativeGeneratorImages(ctx, f.runtime, prepared); err == nil {
			t.Fatal("stale resources accepted")
		}
		writeNew(t, objectPath, original)
		source.Close()
		if prepared.RecheckFor(ctx, f.runtime) == nil {
			t.Fatal("closed source accepted")
		}
		prepared.Close()
	}
	if _, err := os.Lstat(f.project); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview wrote project: %v", err)
	}
	scratch := f.runtime.ScratchRoot()
	entries, err := os.ReadDir(scratch)
	if err != nil || len(entries) != 0 {
		t.Fatalf("scratch leaked: %v %v", entries, err)
	}
	t.Logf("actualGeneratedRootInput=%s", f.raw)
}

func proofSubject(p contextsource.ContextSourceProof) trustverify.Subject {
	s := p.Subject
	return trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}

func TestNormalContextSourceInputAndLocatorRefusals(t *testing.T) {
	f := normalNew(t, nil)
	ctx := context.Background()
	for _, name := range []string{"missing", "duplicate", "unknown", "bad-proof", "malformed-v2", "v1-root"} {
		t.Run(name, func(t *testing.T) {
			input := f.input
			input.Sources = append([]contextsource.ContextSourceProof(nil), f.input.Sources...)
			switch name {
			case "missing":
				input.Sources = input.Sources[1:]
			case "duplicate":
				input.Sources = append(input.Sources, input.Sources[0])
			case "unknown":
				input.Sources[0].Subject.Commit = strings.Repeat("a", 40)
				input.Sources[0].Subject.RequestedRef = input.Sources[0].Subject.Commit
			case "bad-proof":
				input.Root.Evidence.InclusionProofCAS = input.Sources[0].Evidence.InclusionProofCAS
			case "v1-root":
				for _, p := range input.Sources {
					if p.Subject.Origin == "https://example.test/leaf" {
						input.Root = p
						break
					}
				}
				input.Sources = []contextsource.ContextSourceProof{}
			}
			raw := encodeNew(t, input)
			if name == "malformed-v2" {
				raw = append(raw[:len(raw)-1], []byte(`,"trusted":true}`)...)
			}
			if s, err := sourceadapter.ResolveContextSources(ctx, f.runtime, f.home, input.Root.Subject.Commit, raw); err == nil {
				s.Close()
				t.Fatal("invalid source input admitted")
			}
		})
	}
	config, err := state.LoadConfig(f.home)
	if err != nil {
		t.Fatal(err)
	}
	index, err := state.LoadIndex(f.home)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"origin", "duplicate-origin", "path", "name", "commit"} {
		t.Run(name, func(t *testing.T) {
			cfg := config
			cfg.Repos = append([]state.RepoRef(nil), config.Repos...)
			idx := state.NewIndex(index.GeneratedAt)
			idx.Repos["fixture"] = append([]state.TemplateEntry(nil), index.Repos["fixture"]...)
			switch name {
			case "origin":
				cfg.Repos[0].URL = "https://example.test/foreign"
			case "duplicate-origin":
				cfg.Repos = append(cfg.Repos, cfg.Repos[0])
			case "path":
				idx.Repos["fixture"][0].Path = "nested"
			case "name":
				idx.Repos["fixture"][0].Name = "other"
			case "commit":
				tree := gitNew(t, f.rootRepo, "rev-parse", "main^{tree}")
				commit := gitNew(t, f.rootRepo, "commit-tree", tree, "-m", "Changed immutable fixture")
				gitNew(t, f.rootRepo, "update-ref", "refs/heads/main", commit)
			}
			if err := state.SaveConfig(f.home, cfg); err != nil {
				t.Fatal(err)
			}
			if err := state.SaveIndex(f.home, idx); err != nil {
				t.Fatal(err)
			}
			ref := "fixture/context-root@latest"
			if name == "name" {
				ref = "fixture/other@latest"
			}
			if s, err := sourceadapter.ResolveContextSources(ctx, f.runtime, f.home, ref, f.raw); err == nil {
				s.Close()
				t.Fatal("mismatched locator admitted")
			}
			if err := state.SaveConfig(f.home, config); err != nil {
				t.Fatal(err)
			}
			if err := state.SaveIndex(f.home, index); err != nil {
				t.Fatal(err)
			}
			if name == "commit" {
				gitNew(t, f.rootRepo, "update-ref", "refs/heads/main", f.input.Root.Subject.Commit)
			}
		})
	}
	// A normally enrolled v1 leaf still resolves through the unchanged v1 API.
	for _, p := range f.input.Sources {
		if p.Subject.Origin == "https://example.test/leaf" {
			legacy := operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: p.Subject, Evidence: p.Evidence, Dependencies: []string{}}
			source, err := sourceadapter.Resolve(ctx, f.runtime, f.home, p.Subject.Commit, encodeNew(t, legacy))
			if err != nil || source.Name != "context-leaf" {
				t.Fatalf("v1 parity: %+v %v", source, err)
			}
		}
	}
}

func TestNormalContextNativeNewRefusesCapturedGeneratorTamper(t *testing.T) {
	f := normalNew(t, nil)
	ctx := context.Background()
	source, err := sourceadapter.ResolveContextSources(ctx, f.runtime, f.home, f.input.Root.Subject.Commit, f.raw)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	carrier, err := source.Sources(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := contextsource.PrepareNativeNew(ctx, f.runtime, carrier, contextsource.NativeNewInput{Render: renderref.Input{Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example"}}, RendererVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	loaded, err := trustload.Load(ctx, f.registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	objectRoot := ""
	for _, o := range loaded.Install.ObjectOrigins {
		if o.Origin == f.input.Root.Subject.Origin {
			objectRoot = o.RootPath
		}
	}
	// Change the actual retained declared generator blob, not the caller's copy.
	id := ""
	for object, raw := range f.rootObjects {
		if bytes.HasSuffix(raw, []byte("Inert entity image for root.\n")) {
			id = object
		}
	}
	if id == "" {
		t.Fatal("declared captured blob absent")
	}
	name := filepath.Join(objectRoot, id)
	original, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	writeNew(t, name, []byte("blob 4\x00evil"))
	if _, err := resources.PlanContextNativeGeneratorImages(ctx, f.runtime, prepared); err == nil {
		t.Fatal("generator tamper accepted")
	}
	writeNew(t, name, original)
	if _, err := resources.PlanContextNativeGeneratorImages(ctx, f.runtime, prepared); err != nil {
		t.Fatalf("restored exact blob: %v", err)
	}
}
