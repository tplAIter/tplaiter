//go:build darwin || linux

package runtimeassembly_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/tplAIter/tplaiter/internal/execx"

	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"

	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const publicGoCommit = "d0179547cd2e47b7564b0011bc5045799fc036bd"

func strconvItoa(v int) string { return strconv.Itoa(v) }

type noNativeResourceSpawn struct{ t *testing.T }

func (r noNativeResourceSpawn) Run(context.Context, string, []string, execx.Options) (execx.Result, error) {
	r.t.Fatal("unexpected command execution")
	return execx.Result{}, errors.New("spawn refused")
}

func (r noNativeResourceSpawn) LookPath(string) (string, error) {
	r.t.Fatal("unexpected tool probe")
	return "", errors.New("probe refused")
}

func nativeGoSource(t *testing.T, root, _, _, _ string) ([]byte, trustverify.Subject) {
	t.Helper()
	var fixture struct {
		Commit  string            `json:"commit"`
		Origin  string            `json:"origin"`
		Objects map[string][]byte `json:"objects"`
	}
	raw, err := os.ReadFile("../../newcmd/testdata/nativecreationfixtures/template-go-d017.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != publicGoCommit || fixture.Origin != "https://github.com/tplAIter/template-go" {
		t.Fatal("wrong public fixture")
	}
	object := func(kind, id string) []byte {
		raw, ok := fixture.Objects[id]
		if !ok {
			t.Fatalf("missing fixture object %s", id)
		}
		header, data, ok := bytes.Cut(raw, []byte{0})
		if !ok || string(header) != kind+" "+strconv.Itoa(len(data)) {
			t.Fatal("bad fixture frame")
		}
		return data
	}

	put := func(kind, id string) []byte {
		b := object(kind, id)
		raw := append([]byte(kind+" "+strconvItoa(len(b))+"\x00"), b...)
		if err := os.WriteFile(filepath.Join(root, id), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return b
	}
	commit := put("commit", publicGoCommit)
	tree := strings.TrimPrefix(strings.SplitN(string(commit), "\n", 2)[0], "tree ")
	put("tree", tree)
	var entries []trustverify.SourceEntry
	var contract []byte
	var walk func(string, string)
	walk = func(treeID, prefix string) {
		data := object("tree", treeID)
		for len(data) > 0 {
			header, rest, ok := bytes.Cut(data, []byte{0})
			if !ok || len(rest) < 20 {
				t.Fatal("bad Git tree")
			}
			mode, name, ok := strings.Cut(string(header), " ")
			if !ok {
				t.Fatal("bad tree entry")
			}
			oid := hex.EncodeToString(rest[:20])
			data = rest[20:]
			kind := "blob"
			entry := trustverify.SourceEntry{Path: prefix + name, Kind: "file", Mode: mode}
			if mode == "40000" {
				kind = "tree"
				entry.Kind = "directory"
			}
			b := put(kind, oid)
			if kind == "blob" {
				entry.ContentSHA256 = evidencecas.Digest(b)
			}
			if entry.Path == "template.contract.json" {
				contract = b
			}
			entries = append(entries, entry)
			if kind == "tree" {
				walk(oid, prefix+name+"/")
			}
		}
	}
	walk(tree, "")

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
	return contract, trustverify.Subject{Origin: "https://github.com/tplAIter/template-go", TemplatePath: ".", RequestedRef: publicGoCommit, Commit: publicGoCommit, TreeSHA256: treeDigest, ContractSHA256: contractDigest}
}

func nativeSignedProject(t *testing.T) (*trustload.Runtime, string, string) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rawObjects := filepath.Join(base, "raw")
	if err := os.Mkdir(rawObjects, 0o700); err != nil {
		t.Fatal(err)
	}
	_, publicSubject := nativeGoSource(t, rawObjects, "", "", "")
	repository := filepath.Join(base, "source")
	entries, err := os.ReadDir(rawObjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		id := entry.Name()
		raw, err := os.ReadFile(filepath.Join(rawObjects, id))
		if err != nil {
			t.Fatal(err)
		}
		objectPath := filepath.Join(repository, ".git", "objects", id[:2], id[2:])
		if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(objectPath)
		if err != nil {
			t.Fatal(err)
		}
		writer := zlib.NewWriter(file)
		if _, err := writer.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repository, ".git", "config"), []byte("[core]\nrepositoryformatversion=0\nbare=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "project")
	result, err := ossinstall.GenerateWithContext(ctx, ossinstall.Options{
		Root:            filepath.Join(base, "installation"),
		LocalSources:    []sourcepackage.CaptureInput{{RepositoryPath: repository, Origin: publicSubject.Origin, TemplatePath: ".", Commit: publicGoCommit}},
		ProjectContexts: []trustload.ProjectContext{{Key: "go", ProjectID: "project-local-go", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: target}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PublicationState != "committed" {
		t.Fatalf("installation publication: %s", result.PublicationState)
	}
	registrationRaw, err := os.ReadFile(result.RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	if evidencecas.Digest(registrationRaw) != result.RegistrationSHA256 {
		t.Fatal("registration raw pin mismatch")
	}
	registration, err := ossinstall.DecodeRegistration(registrationRaw)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := trustload.Load(ctx, registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	// Enroll only the ordinary bootstrap closure. Source CAS remains in the
	// published installation; it is not injected as privileged store material.
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
	refs := []string{bundle.EnvelopeCAS, bundle.ReceiptCAS, bundle.Transparency.CheckpointCAS, bundle.Transparency.InclusionProofCAS}
	evidence := map[string][]byte{}
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
			for _, signature := range envelope.Signatures {
				refs = append(refs, signature.SignatureCAS)
			}
		}
	}
	factory := func(r evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(r, bootstrap.ClockFunc(time.Now), nil, 0)
	}
	if err := trustload.Enroll(ctx, registration.Selection(), factory, stateRaw, bundleRaw, evidence); err != nil {
		t.Fatal(err)
	}
	runtime, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: registration.Selection(), ProjectKey: "go", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	selectionsRaw, err := os.ReadFile(result.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var selections []operationtrust.SourceSelection
	if err := canonicaljson.DecodeStrict(selectionsRaw, &selections); err != nil || len(selections) != 1 {
		t.Fatalf("selection: %v %v", selections, err)
	}
	selected := selections[0]
	if selected.TrustSubject() != publicSubject {
		t.Fatal("capture changed exact public subject")
	}
	resolution, err := runtime.TrustRuntime().VerifySubject(ctx, selected.TrustSubject(), selected.EvidenceRefs())
	if err != nil {
		t.Fatal(err)
	}
	if !resolution.ValidFor(runtime.TrustRuntime(), runtime.TrustRuntime().Binding()) {
		t.Fatal("source capability not runtime-bound")
	}
	recordRaw, err := os.ReadFile(filepath.Join(result.Root, "config", "local-publisher.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record ossinstall.LocalPublication
	if err := canonicaljson.DecodeStrict(recordRaw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Issuer != "local-operator-"+strings.TrimPrefix(record.KeyFingerprint, "sha256:") || record.Mode != "local-operator" || record.Subject.Commit != publicGoCommit || record.Subject.TreeSHA256 != publicSubject.TreeSHA256 || record.Subject.ContractSHA256 != publicSubject.ContractSHA256 || record.KeyFingerprint != selected.Evidence.KeyFingerprint || bytes.Contains(recordRaw, []byte(repository)) {
		t.Fatal("local operator publication tuple mismatch")
	}
	// Once verified, removal of the input object repository cannot affect new.
	if err := os.RemoveAll(repository); err != nil {
		t.Fatal(err)
	}
	sourceInput, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	d := newcmd.Deps{Runtime: runtime, Home: home, SourceInput: sourceInput, Runner: noNativeResourceSpawn{t}, Out: &bytes.Buffer{}}
	opts := newcmd.Options{Ref: publicGoCommit, ProjectName: "Local Go", Dir: target, Module: "example.test/neutral", Defaults: true, NoHooks: true, NoDepsCheck: true, CLIVersion: "v1.0.0"}
	if err := newcmd.Run(ctx, opts, d); err != nil {
		t.Fatal(err)
	}
	launch, err := json.Marshal(registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "fixture-launch.json"), launch, 0o600); err != nil {
		t.Fatal(err)
	}
	return runtime, home, target
}
