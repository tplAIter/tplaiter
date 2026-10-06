//go:build darwin || linux

package ossinstall

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func contentPackage(t *testing.T, origin string, alter func(*exports.ExportPayload, map[string][]byte)) (Publisher, SourcePackage) {
	t.Helper()
	return signedPackage(t, origin, func(files map[string][]byte) {
		delete(files, "template.manifest.yaml")
		files["LICENSE"] = []byte("synthetic public test license\n")
		files["nested/README.md"] = []byte("synthetic inert content\n")
		names := []string{}
		for name := range files {
			if name != "template.contract.json" {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		p := exports.ExportPayload{APIVersion: exports.ExportPayloadAPIVersion, ExportID: "generic.library", Files: []exports.PayloadFile{}, Slots: []exports.PayloadSlot{}, Blocks: []exports.PayloadBlock{}}
		for _, name := range names {
			p.Files = append(p.Files, exports.PayloadFile{SourcePath: name, TargetPath: name, Mode: "100644", ContentSHA256: evidencecas.Digest(files[name])})
		}
		if alter != nil {
			alter(&p, files)
		}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		files["template.contract.json"] = raw
	})
}

func capturedPackageInput(t *testing.T, base, name string, p SourcePackage) sourcepackage.CaptureInput {
	t.Helper()
	repo := filepath.Join(base, name)
	for id, raw := range p.Objects {
		path := filepath.Join(repo, ".git", "objects", id[:2], id[2:])
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
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
	writeTestFile(t, filepath.Join(repo, ".git", "config"), "[core]\nrepositoryformatversion=0\nbare=false\n")
	statement, err := bootstrap.DecodePublisherStatement(p.Statement)
	if err != nil {
		t.Fatal(err)
	}
	return sourcepackage.CaptureInput{RepositoryPath: repo, Origin: statement.Subject.Origin, TemplatePath: statement.Subject.TemplatePath, Commit: statement.Subject.Commit}
}

func localBundleOptions(t *testing.T, alter func(*exports.ExportPayload, map[string][]byte)) Options {
	t.Helper()
	o := localOptions(t)
	_, p := contentPackage(t, "https://example.test/content", alter)
	o.LocalSourceBundle = []sourcepackage.CaptureInput{o.LocalSources[0], capturedPackageInput(t, filepath.Dir(o.Root), "content", p)}
	o.LocalSources = nil
	return o
}

func TestContentBundleSignedRuntimeAndReader(t *testing.T) {
	o := localBundleOptions(t, nil)
	entropy := &recordingRand{}
	o.Rand = entropy
	result, err := GenerateWithContext(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(entropy.seeds) != 3 {
		t.Fatal("expected two distinct source keys and anchor")
	}
	reg, selections := enrollGenerated(t, result)
	if len(selections) != 2 {
		t.Fatal("generic selection dropped")
	}
	raw, err := os.ReadFile(filepath.Join(result.Root, "config/local-publisher.json"))
	if err != nil {
		t.Fatal(err)
	}
	var records []LocalPublication
	if err = json.Unmarshal(raw, &records); err != nil || len(records) != 2 {
		t.Fatal("bundle record shape", err)
	}
	for _, in := range o.LocalSourceBundle {
		if bytes.Contains(raw, []byte(in.RepositoryPath)) {
			t.Fatal("locator persisted")
		}
	}
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: reg.Selection(), ProjectKey: "a", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	reader, err := deps.NewSourceReader(runtime.TrustRuntime())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range selections {
		e := s.Evidence
		subject := trustverify.Subject{Origin: s.Subject.Origin, TemplatePath: s.Subject.TemplatePath, RequestedRef: s.Subject.RequestedRef, Commit: s.Subject.Commit, TreeSHA256: s.Subject.TreeSHA256, ContractSHA256: s.Subject.ContractSHA256}
		refs := trustverify.EvidenceRefs{Format: e.Format, StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint, CheckpointCAS: e.CheckpointCAS, InclusionProofCAS: e.InclusionProofCAS}
		resolution, err := runtime.TrustRuntime().VerifySubject(context.Background(), subject, refs)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := runtime.TrustRuntime().VerifiedSnapshot(resolution)
		if err != nil {
			t.Fatal(err)
		}
		content, err := deps.SnapshotContentDigest(snapshot.Entries())
		if err != nil {
			t.Fatal(err)
		}
		pin := deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: "content", ProviderID: "public.git", Origin: subject.Origin, TemplatePath: subject.TemplatePath, RequestedRef: subject.RequestedRef, CommitAlgorithm: "sha1", Commit: subject.Commit, TreeDigest: subject.TreeSHA256, ContentDigest: content, ContractDigest: subject.ContractSHA256, EvidenceDigest: e.StatementCAS, Parameters: []deps.Parameter{}, Dependencies: []string{}}
		verified, err := reader.Read(context.Background(), resolution, pin)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(verified.ContractBytes(), snapshot.ContractBytes()) {
			t.Fatal("contract bytes changed")
		}
		if strings.HasSuffix(subject.Origin, "/content") {
			if err := validateNativeSnapshot(snapshot); err == nil {
				t.Fatal("content became native")
			}
			body, ok := verified.Blob("nested/README.md")
			if !ok || string(body) != "synthetic inert content\n" {
				t.Fatal("reader bytes differ")
			}
			pin.EvidenceDigest = content
			if _, err := reader.Read(context.Background(), resolution, pin); err == nil {
				t.Fatal("report/content digest accepted as statement CAS")
			}
		}
	}
	if _, err := Generate(o); !errors.Is(err, ErrInstallRootForeign) {
		t.Fatal("local bundle reused root", err)
	}
}

func TestContentBundleIndexRefusalsBeforeEntropy(t *testing.T) {
	cases := map[string]func(*exports.ExportPayload, map[string][]byte){
		"missing":   func(p *exports.ExportPayload, _ map[string][]byte) { p.Files = p.Files[1:] },
		"reordered": func(p *exports.ExportPayload, _ map[string][]byte) { p.Files[0], p.Files[1] = p.Files[1], p.Files[0] },
		"self-index": func(p *exports.ExportPayload, _ map[string][]byte) {
			p.Files = append(p.Files, exports.PayloadFile{SourcePath: "template.contract.json", TargetPath: "template.contract.json", Mode: "100644", ContentSHA256: "sha256:" + strings.Repeat("0", 64)})
		},
		"mode": func(p *exports.ExportPayload, _ map[string][]byte) { p.Files[0].Mode = "100755" },
		"hash": func(p *exports.ExportPayload, _ map[string][]byte) {
			p.Files[0].ContentSHA256 = "sha256:" + strings.Repeat("0", 64)
		},
		"mapping": func(p *exports.ExportPayload, _ map[string][]byte) { p.Files[0].TargetPath = "elsewhere" },
		"slot": func(p *exports.ExportPayload, _ map[string][]byte) {
			p.Slots = append(p.Slots, exports.PayloadSlot{TargetPath: "extra.json", Pointer: "/a", Value: "1"})
		},
		"block": func(p *exports.ExportPayload, _ map[string][]byte) {
			p.Blocks = append(p.Blocks, exports.PayloadBlock{SourcePath: "extra", ContentSHA256: "sha256:" + strings.Repeat("0", 64)})
		},
		"unindexed": func(_ *exports.ExportPayload, files map[string][]byte) { files["extra"] = []byte("extra") },
		"id":        func(p *exports.ExportPayload, _ map[string][]byte) { p.ExportID = "bad/id" },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			o := localBundleOptions(t, alter)
			entropy := &recordingRand{}
			o.Rand = entropy
			if _, err := Generate(o); err == nil || entropy.next != 0 {
				t.Fatal("invalid index reached entropy")
			}
			if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid index created root")
			}
		})
	}
}

func TestContentBundleCountIdentityAndCancellation(t *testing.T) {
	for _, name := range []string{"no-native", "two-native", "duplicate", "too-many", "mixed-mode", "empty-publishers", "no-context", "existing-empty", "cancel"} {
		t.Run(name, func(t *testing.T) {
			o := localBundleOptions(t, nil)
			entropy := &recordingRand{}
			o.Rand = entropy
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "no-native":
				_, p := contentPackage(t, "https://example.test/other-content", nil)
				o.LocalSourceBundle[0] = capturedPackageInput(t, filepath.Dir(o.Root), "other-content", p)
			case "two-native":
				_, p := signedPackage(t, "https://example.test/other-native", nil)
				o.LocalSourceBundle[1] = capturedPackageInput(t, filepath.Dir(o.Root), "other-native", p)
			case "duplicate":
				o.LocalSourceBundle = append(o.LocalSourceBundle, o.LocalSourceBundle[1])
			case "too-many":
				for len(o.LocalSourceBundle) < 17 {
					o.LocalSourceBundle = append(o.LocalSourceBundle, o.LocalSourceBundle[1])
				}
			case "mixed-mode":
				o.LocalSources = o.LocalSourceBundle[:1]
			case "empty-publishers":
				o.Publishers = []Publisher{}
			case "no-context":
				o.ProjectContexts = nil
			case "existing-empty":
				if err := os.Mkdir(o.Root, 0700); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			if _, err := GenerateWithContext(ctx, o); err == nil || entropy.next != 0 {
				t.Fatal("invalid bundle reached entropy")
			}
		})
	}
}

func TestDecodeContentBundleClosedBounded(t *testing.T) {
	o := localBundleOptions(t, nil)
	raw, _ := json.Marshal(o.LocalSourceBundle)
	if _, err := DecodeLocalSourceBundle(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLocalSources(raw); err == nil {
		t.Fatal("old exact one-source decoder widened")
	}
	for _, raw := range [][]byte{[]byte("null"), []byte("[]"), bytes.Repeat([]byte(" "), MaxLocalSourceInputBytes+1), bytes.Replace(raw, []byte(`"origin":`), []byte(`"kind":"native","origin":`), 1)} {
		if _, err := DecodeLocalSourceBundle(raw); err == nil {
			t.Fatal("unclosed input accepted")
		}
	}
}

// Ensure signed external packages use the same typed index admission, not a
// privilege supplied by local-bundle JSON or by a test-only constructor.
func contentExternalOptions(t *testing.T, alter func(*exports.ExportPayload, map[string][]byte)) Options {
	t.Helper()
	o := enrollmentOptions(t)
	pub, p := contentPackage(t, "https://example.test/content", alter)
	o.Publishers = o.Publishers[:1]
	o.SourcePackages = o.SourcePackages[:1]
	o.Publishers = append(o.Publishers, pub)
	o.SourcePackages = append(o.SourcePackages, p)
	return o
}

func TestContentBundleMaximumGenericSources(t *testing.T) {
	o := localBundleOptions(t, nil)
	for i := 2; i < 16; i++ {
		name := fmt.Sprintf("content-%02d", i)
		_, p := contentPackage(t, "https://example.test/"+name, func(p *exports.ExportPayload, _ map[string][]byte) { p.ExportID = name })
		o.LocalSourceBundle = append(o.LocalSourceBundle, capturedPackageInput(t, filepath.Dir(o.Root), name, p))
	}
	result, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	_, selections := enrollGenerated(t, result)
	if len(selections) != 16 {
		t.Fatal("maximum bundle lost source selection")
	}
}
