//go:build darwin || linux

package ossinstall

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func localOptions(t *testing.T) Options {
	t.Helper()
	root := tempRoot(t)
	repo := filepath.Join(filepath.Dir(root), "repo")
	dir := filepath.Join(repo, ".git")
	_, p := signedPackage(t, "https://example.test/local", nil)
	statement, err := bootstrap.DecodePublisherStatement(p.Statement)
	if err != nil {
		t.Fatal(err)
	}
	for id, raw := range p.Objects {
		path := filepath.Join(dir, "objects", id[:2], id[2:])
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		z := zlib.NewWriter(f)
		if _, err = z.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(dir, "config"), "[core]\nrepositoryformatversion=0\nbare=false\n")
	return Options{Root: root, LocalSources: []sourcepackage.CaptureInput{{RepositoryPath: repo, Origin: statement.Subject.Origin, TemplatePath: ".", Commit: statement.Subject.Commit}}, ProjectContexts: []trustload.ProjectContext{{Key: "a", ProjectID: "project-local", SubmitterPrincipalID: operatorPrincipal, MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(filepath.Dir(root), "project")}}}
}

func TestLocalPublisherSignedEnrollmentPublicRecordAndDenials(t *testing.T) {
	o := localOptions(t)
	entropy := &recordingRand{}
	o.Rand = entropy
	result, err := GenerateWithContext(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if result.PublicationState != "committed" || len(entropy.seeds) != 2 {
		t.Fatal("expected distinct source and anchor keys and committed result")
	}
	reg, selections := enrollGenerated(t, result)
	raw, err := os.ReadFile(filepath.Join(result.Root, "config", "local-publisher.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record LocalPublication
	if err := canonicaljson.DecodeStrict(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Issuer != "local-operator-"+strings.TrimPrefix(record.KeyFingerprint, "sha256:") || record.Mode != "local-operator" || bytes.Contains(raw, []byte(o.LocalSources[0].RepositoryPath)) {
		t.Fatal("untruthful operator provenance record")
	}
	var contract enrollmentContract
	enrollmentRaw, err := os.ReadFile(filepath.Join(result.Root, "config", "enrollment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := canonicaljson.DecodeStrict(enrollmentRaw, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.LocalPublisherSHA256 != localRecordDigest(raw) || contract.Digest != reg.InitialEnrollmentSHA256 {
		t.Fatal("public record not bound to enrollment registration")
	}
	loaded, err := trustload.Load(context.Background(), reg.Selection())
	if err != nil {
		t.Fatal(err)
	}
	descriptorRaw, err := os.ReadFile(loaded.Install.Descriptor.Path)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor bootstrap.DescriptorDocument
	if err := json.Unmarshal(descriptorRaw, &descriptor); err != nil {
		t.Fatal(err)
	}
	if descriptor.Anchors[0].Fingerprint == record.KeyFingerprint {
		t.Fatal("source key reused as anchor")
	}
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: reg.Selection(), ProjectKey: "a", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	selection := selections[0]
	s := selection.Subject
	subject := trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
	e := selection.Evidence
	refs := trustverify.EvidenceRefs{Format: e.Format, StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint, CheckpointCAS: e.CheckpointCAS, InclusionProofCAS: e.InclusionProofCAS}
	if _, err := runtime.TrustRuntime().VerifySubject(context.Background(), subject, refs); err != nil {
		t.Fatal(err)
	}
	wrong := refs
	bundleRaw, _ := os.ReadFile(loaded.Install.OSS.InitialBundlePath)
	bundle, _ := trustload.DecodeStoredBundle(bundleRaw)
	wrong.InclusionProofCAS = bundle.Transparency.InclusionProofCAS
	if _, err := runtime.TrustRuntime().VerifySubject(context.Background(), subject, wrong); err == nil {
		t.Fatal("envelope proof accepted for source")
	}
	wrong = refs
	wrong.CheckpointCAS = "sha256:" + strings.Repeat("0", 64)
	if _, err := runtime.TrustRuntime().VerifySubject(context.Background(), subject, wrong); err == nil {
		t.Fatal("false checkpoint accepted")
	}
	// Retained test secrets remain process local. Scan every published file without
	// ever rendering private bytes, even on failure.
	var needles [][]byte
	for _, seed := range entropy.seeds {
		private := ed25519.NewKeyFromSeed(seed)
		for _, secret := range [][]byte{seed, private} {
			needles = append(needles, secret, []byte(base64.StdEncoding.EncodeToString(secret)), []byte(base64.RawURLEncoding.EncodeToString(secret)), []byte(hex.EncodeToString(secret)))
		}
	}
	err = filepath.WalkDir(result.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, needle := range needles {
			if bytes.Contains(raw, needle) {
				t.Fatal("private key material persisted")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	selectionPin := reg.Selection()
	selectionPin.RuntimeConfig.SHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err := trustload.Load(context.Background(), selectionPin); err == nil {
		t.Fatal("tampered install pin accepted")
	}
}

func TestLocalModeRefusalBeforeEntropy(t *testing.T) {
	for _, name := range []string{"empty-root", "existing-root", "rotate", "external-publishers", "empty-publishers", "external-packages", "two-sources", "nil-contexts", "publisher-submitter", "missing-object", "invalid-origin", "origin-with-query", "origin-with-userinfo", "origin-uppercase-host", "invalid-subject-path", "invalid-subject-commit", "invalid-scope"} {
		t.Run(name, func(t *testing.T) {
			o := localOptions(t)
			entropy := &recordingRand{}
			o.Rand = entropy
			switch name {
			case "empty-root":
				if err := os.Mkdir(o.Root, 0o700); err != nil {
					t.Fatal(err)
				}
			case "existing-root":
				writeTestFile(t, filepath.Join(o.Root, "foreign"), "preserve")
			case "rotate":
				o.Rotate = true
			case "external-publishers":
				o.Publishers = []Publisher{{Issuer: "upstream"}}
			case "empty-publishers":
				o.Publishers = []Publisher{}
			case "external-packages":
				o.SourcePackages = []SourcePackage{}
			case "two-sources":
				o.LocalSources = append(o.LocalSources, o.LocalSources[0])
			case "nil-contexts":
				o.ProjectContexts = nil
			case "publisher-submitter":
				o.ProjectContexts[0].SubmitterPrincipalID = publisherPrincipal
			case "invalid-origin":
				o.LocalSources[0].Origin = "not-an-origin"
			case "origin-with-query":
				o.LocalSources[0].Origin = "https://example.test/source?unapproved=1"
			case "origin-with-userinfo":
				o.LocalSources[0].Origin = "https://user@example.test/source"
			case "origin-uppercase-host":
				o.LocalSources[0].Origin = "https://EXAMPLE.test/source"
			case "invalid-subject-path":
				o.LocalSources[0].TemplatePath = "../unapproved"
			case "invalid-subject-commit":
				o.LocalSources[0].Commit = "main"
			case "invalid-scope":
				o.Publishers = []Publisher{{SourceOrigin: "not-an-origin", TemplatePath: "../unapproved", Issuer: "upstream"}}
			case "missing-object":
				o.LocalSources[0].Commit = strings.Repeat("a", 40)
			}
			result, err := Generate(o)
			if err == nil || result.RegistrationSHA256 != "" || len(entropy.seeds) != 0 || entropy.next != 0 {
				t.Fatal("invalid local input reached signing/publication")
			}
			if name == "existing-root" {
				assertTestFile(t, filepath.Join(o.Root, "foreign"), "preserve")
			}
		})
	}
}

func TestGenerationCancellationCommitBoundary(t *testing.T) {
	for _, name := range []string{"pre-cancel", "pre-rename", "post-rename", "parent-sync", "final-load", "concurrent-empty", "project-parent-replaced"} {
		t.Run(name, func(t *testing.T) {
			o := localOptions(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("test finalization failure")
			switch name {
			case "pre-cancel":
				cancel()
			case "pre-rename":
				installationPublicationHook = cancel
			case "post-rename":
				installationCommittedHook = cancel
			case "parent-sync":
				installationParentSyncHook = func() error { return failure }
			case "final-load":
				publicationFinalizationHook = func() error { return failure }
			case "project-parent-replaced":
				// A project leaf can become a symlink after staging; the immediate
				// publication-boundary revalidation must refuse it.
				installationPublicationHook = func() {
					if err := os.Symlink(o.LocalSources[0].RepositoryPath, o.ProjectContexts[0].RootPath); err != nil {
						t.Fatal(err)
					}
				}
			case "concurrent-empty":
				installationPublicationHook = func() {
					if err := os.Mkdir(o.Root, 0o750); err != nil {
						t.Fatal(err)
					}
				}
			}
			defer func() {
				installationPublicationHook = nil
				installationCommittedHook = nil
				installationParentSyncHook = nil
				publicationFinalizationHook = nil
			}()
			result, err := GenerateWithContext(ctx, o)
			switch name {
			case "pre-cancel", "pre-rename":
				if !errors.Is(err, context.Canceled) || result.RegistrationSHA256 != "" {
					t.Fatal("precommit cancellation emitted pins")
				}
				if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("precommit cancellation published root")
				}
			case "post-rename":
				if err != nil || result.PublicationState != "committed" {
					t.Fatal("postcommit cancellation discarded committed result")
				}
				if _, err := trustload.Load(context.Background(), mustSelection(result)); err != nil {
					t.Fatal(err)
				}
			case "parent-sync", "final-load":
				if !errors.Is(err, ErrPublicationCommitted) || !errors.Is(err, failure) || result.PublicationState != "committed-unconfirmed" {
					t.Fatal("committed failure not reported distinctly")
				}
				if _, err := os.Stat(result.RegistrationPath); err != nil {
					t.Fatal("committed install removed")
				}
			case "project-parent-replaced":
				if err == nil || result.RegistrationSHA256 != "" {
					t.Fatal("changed project path published")
				}
				if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("invalid project root installation committed")
				}
			case "concurrent-empty":
				if !errors.Is(err, ErrInstallRootForeign) || result.RegistrationSHA256 != "" {
					t.Fatal("competing destination replaced")
				}
				entries, err := os.ReadDir(o.Root)
				if err != nil || len(entries) != 0 {
					t.Fatal("foreign empty root modified")
				}
			}
			stages, err := filepath.Glob(filepath.Join(filepath.Dir(o.Root), ".tplaiter-initial-*"))
			if err != nil || len(stages) != 0 {
				t.Fatal("owned staging leaked")
			}
		})
	}
}

func TestExternalEnrollmentRefusesExistingEmptyRoot(t *testing.T) {
	o := enrollmentOptions(t)
	if err := os.Mkdir(o.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(o.Root)
	if _, err := Generate(o); !errors.Is(err, ErrInstallRootForeign) {
		t.Fatal(err)
	}
	after, _ := os.Stat(o.Root)
	if !os.SameFile(before, after) {
		t.Fatal("existing empty destination inode replaced")
	}
}

func TestDecodeLocalSourcesClosedOptIn(t *testing.T) {
	for _, raw := range []string{`[]`, `null`, `[{"repositoryPath":"/repo","origin":"x","templatePath":".","commit":"main"}]`, `[{"repositoryPath":"/repo","origin":"x","templatePath":".","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issuer":"upstream"}]`} {
		if _, err := DecodeLocalSources([]byte(raw)); err == nil {
			t.Fatal("invalid opt-in input accepted")
		}
	}
}

type cancellingEntropy struct {
	cancel context.CancelFunc
	source *recordingRand
}

func (r cancellingEntropy) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.cancel()
	return n, err
}

func TestLocalEntropyCancellationAndFailure(t *testing.T) {
	for _, name := range []string{"cancel-during-key", "failure-after-source-key", "nil-context"} {
		t.Run(name, func(t *testing.T) {
			o := localOptions(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entropy := &recordingRand{}
			switch name {
			case "cancel-during-key":
				o.Rand = cancellingEntropy{cancel: cancel, source: entropy}
			case "failure-after-source-key":
				o.Rand = io.LimitReader(entropy, ed25519.SeedSize)
			case "nil-context":
				ctx = nil
			}
			result, err := GenerateWithContext(ctx, o)
			if err == nil || result.RegistrationSHA256 != "" {
				t.Fatal("entropy/context failure emitted success")
			}
			if name == "cancel-during-key" && !errors.Is(err, context.Canceled) {
				t.Fatal("key-read cancellation not propagated")
			}
			if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("entropy/context failure published root")
			}
			stages, _ := filepath.Glob(filepath.Join(filepath.Dir(o.Root), ".tplaiter-initial-*"))
			if len(stages) != 0 {
				t.Fatal("entropy failure leaked staging")
			}
		})
	}
}
