//go:build darwin || linux

package engine

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/ownership"
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
	raw, err := os.ReadFile("../../../newcmd/testdata/nativecreationfixtures/template-go-d017.json")
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
	bridge := startFixtureBridge(t, fixtureBridgeRequest{Selection: registration.Selection(), ProjectKey: "go", Home: home, Project: target, Name: "Local Go", Module: "example.test/neutral", Ref: publicGoCommit, Renderer: "v1.0.0", Source: sourceInput})
	bridge.call("create", nil)
	bridge.Close()
	launch, err := json.Marshal(registration.Selection())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "fixture-launch.json"), launch, 0o600); err != nil {
		t.Fatal(err)
	}
	return runtime, home, target
}

func nativePlan(t *testing.T, r *trustload.Runtime, home string) *gen.NativePlan {
	t.Helper()
	p, err := gen.PlanNative(context.Background(), r, home, []gen.NativeOperation{{Kind: "entity", Name: "Widget", Provided: nil}})
	if _, ok := any(r.TrustRuntime()).(interface {
		CheckProjectIdentity(context.Context, string, string) error
	}); !ok {
		if !errors.Is(err, gen.ErrNativeIdentityUnavailable) {
			t.Fatalf("missing identity API did not refuse: %v", err)
		}
		t.Skip("accepted identity API not integrated in base; test its fail-closed boundary")
	}
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Simulates the exact durable crash boundary using the real signed project:
// sealed intent and atomic publication exist, completion receipt does not.
func TestNativeSignedIntentColdRecovery(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(strconv.FormatBool(rollback), func(t *testing.T) {
			r, home, root := nativeSignedProject(t)
			p := nativePlan(t, r, home)
			tx, err := beginSignedNative(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			tx.state.Phase = "applying"
			s := &tx.state.Steps[0]
			s.Intent = true
			if err := tx.save(); err != nil {
				t.Fatal(err)
			}
			_, exists := tx.plan.Material.Before[s.Path]
			if err := tx.publish(*s, exists); err != nil {
				t.Fatal(err)
			}
			// No completion flag is written. Release only relinquishes the live lease.
			id := tx.ID()
			tx.Release()
			cold, err := openSignedNative(context.Background(), r, home, id)
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Release()
			if rollback {
				err = cold.Rollback(context.Background())
			} else {
				err = cold.Commit(context.Background())
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(root); err != nil {
				t.Fatal("root missing")
			}
			for _, name := range p.Result().CreatedFiles {
				_, err := os.Stat(filepath.Join(root, name))
				if rollback {
					if !os.IsNotExist(err) {
						t.Fatal("rollback left output")
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func signedMaterial(m gen.NativeMaterial) (Material, error) {
	intent, err := canonicaljson.Canonical(m)
	if err != nil {
		return Material{}, err
	}
	convert := func(in map[string]gen.NativeFile) map[string]File {
		out := map[string]File{}
		for name, f := range in {
			out[name] = File{Data: append(Bytes{}, f.Data...), Mode: f.Mode, Directory: f.Directory, Device: f.Device, Inode: f.Inode}
		}
		return out
	}
	readonly := []string{}
	for name := range m.Before {
		if name == ".tplaiter/project.yaml" || name == ".tplaiter/root-template.lock.json" || name == ".tplaiter/template.lock.json" || name == ".tplaiter/resources.lock.json" || strings.HasPrefix(name, ".tplaiter/generators/") {
			readonly = append(readonly, name)
		}
	}
	sort.Strings(readonly)
	return Material{Root: m.Root, Home: m.Home, ProjectID: m.ProjectID, Binding: m.Binding, Before: convert(m.Before), After: convert(m.After), Fingerprint: m.Fingerprint, ReadOnlyPaths: readonly, Intent: intent}, nil
}

func beginSignedNative(ctx context.Context, p *gen.NativePlan) (*Transaction, error) {
	m, r, err := p.TransactionMaterial(ctx)
	if err != nil {
		return nil, err
	}
	draft, err := signedMaterial(m)
	if err != nil {
		return nil, err
	}
	tx, err := Acquire(ctx, r, NativeGeneratorKind, draft)
	if err != nil {
		return nil, err
	}
	m, _, err = p.TransactionMaterialAfterLease(ctx)
	if err != nil {
		tx.Release()
		return nil, err
	}
	if err := gen.AuthenticateNativeMaterial(ctx, r, m); err != nil {
		tx.Release()
		return nil, err
	}
	material, err := signedMaterial(m)
	if err != nil {
		tx.Release()
		return nil, err
	}
	if err := tx.Seal(ctx, material); err != nil {
		tx.Release()
		return nil, err
	}
	return tx, nil
}

func openSignedNative(ctx context.Context, r *trustload.Runtime, home, id string) (*Transaction, error) {
	tx, err := Open(ctx, r, NativeGeneratorKind, home, id)
	if err != nil {
		return nil, err
	}
	var m gen.NativeMaterial
	if err := canonicaljson.DecodeStrict(tx.Material().Intent, &m); err != nil {
		tx.Release()
		return nil, err
	}
	if err := gen.AuthenticateNativeMaterial(ctx, r, m); err != nil {
		tx.Release()
		return nil, err
	}
	if err := tx.Admit(ctx); err != nil {
		tx.Release()
		return nil, err
	}
	return tx, nil
}

// The context arms only after every real Apply step and durable completion
// receipt. Its first later Err call is the final Commit authentication boundary.
type finalCommitContext struct {
	context.Context
	once  sync.Once
	tx    *Transaction
	fault func()
}

func (c *finalCommitContext) Err() error {
	// SQL can call Err asynchronously. Observe the atomically published receipt,
	// not the engine's mutable in-memory progress. No MAC/key is read by this hook.
	raw, err := os.ReadFile(filepath.Join(c.tx.dir, "state.json"))
	var record envelope
	var receipt progress
	if err == nil && json.Unmarshal(raw, &record) == nil && json.Unmarshal(record.Payload, &receipt) == nil {
		done := receipt.Phase == "applying" && len(receipt.Steps) > 0
		for _, step := range receipt.Steps {
			done = done && step.Done
		}
		if done {
			c.once.Do(c.fault)
		}
	}
	return c.Context.Err()
}

func signedModeProject(t *testing.T) (*trustload.Runtime, string, string) {
	t.Helper()
	r, home, root := nativeSignedProject(t)
	anchor := filepath.Join(root, "cmd/service/main.go")
	if err := os.Chmod(anchor, 0o600); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, ".tplaiter/ownership.json")
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var inv ownership.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	for i := range inv.Artifacts {
		if inv.Artifacts[i].Path == "cmd/service/main.go" {
			inv.Artifacts[i].Mode = 0o600
		}
	}
	raw, err = canonicaljson.Canonical(inv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return r, home, root
}

func assertOriginalImages(t *testing.T, tx *Transaction, foreign string) {
	t.Helper()
	root, err := os.Stat(tx.plan.Material.Root)
	if err != nil || fileID(root) != tx.plan.RootIdentity {
		t.Fatal("original root not visible")
	}
	for name, image := range tx.plan.Material.Before {
		if name == foreign {
			continue
		}
		if err := checkPath(filepath.Join(tx.plan.Material.Root, name), image, Identity{image.Device, image.Inode}); err != nil {
			t.Fatalf("original bytes/mode/inode not restored: %s: %v", name, err)
		}
	}
	for name := range tx.plan.Material.After {
		if _, existed := tx.plan.Material.Before[name]; existed || name == foreign {
			continue
		}
		if _, err := os.Lstat(filepath.Join(tx.plan.Material.Root, name)); !os.IsNotExist(err) {
			t.Fatalf("new path survived rollback: %s", name)
		}
	}
}

func freshSignedRuntime(t *testing.T, r *trustload.Runtime, home string) *trustload.Runtime {
	t.Helper()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, "fixture-launch.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selection trustload.LaunchSelection
	if err := json.Unmarshal(raw, &selection); err != nil {
		t.Fatal(err)
	}
	fresh, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: selection, ProjectKey: "go", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	return fresh
}

func TestSignedFinalCommitRollback(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(strconv.FormatBool(foreign), func(t *testing.T) {
			r, home, root := signedModeProject(t)
			p := nativePlan(t, r, home)
			tx, err := beginSignedNative(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Release()
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			fired := false
			var foreignInfo os.FileInfo
			const anchor = "cmd/service/main.go"
			ctx := &finalCommitContext{Context: base, tx: tx}
			ctx.fault = func() {
				fired = true
				if !foreign {
					cancel()
					return
				}
				name := filepath.Join(root, anchor)
				replacement := name + ".foreign"
				if err := os.WriteFile(replacement, []byte("foreign final target"), 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, name); err != nil {
					t.Fatal(err)
				}
				foreignInfo, _ = os.Stat(name)
			}
			err = tx.Commit(ctx)
			if !fired {
				t.Fatal("final boundary not reached")
			}
			if foreign {
				if !errors.Is(err, ErrConflict) {
					t.Fatalf("foreign original cause: %v", err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel original cause: %v", err)
			}
			skip := ""
			if foreign {
				skip = anchor
			}
			assertOriginalImages(t, tx, skip)
			if foreign {
				actual, err := os.ReadFile(filepath.Join(root, anchor))
				info, other := os.Stat(filepath.Join(root, anchor))
				if err != nil || other != nil || string(actual) != "foreign final target" || info.Mode().Perm() != 0o640 || !os.SameFile(info, foreignInfo) {
					t.Fatal("foreign bytes/mode/inode changed")
				}
				for _, step := range tx.state.Steps {
					if step.Path == anchor {
						before := tx.plan.Material.Before[anchor]
						if err := checkPath(filepath.Join(tx.images, step.Slot), before, Identity{before.Device, before.Inode}); err != nil {
							t.Fatal("original anchor beforeimage lost")
						}
					}
				}
			}
			var disk progress
			if err := tx.readSigned("state.json", &disk); err != nil || disk.Phase == "committed" {
				t.Fatalf("failed final check committed: %v %s", err, disk.Phase)
			}
		})
	}
}

func TestSignedTerminalReceiptFailure(t *testing.T) {
	for _, published := range []bool{false, true} {
		for _, coldRecovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("published-%v/cold-%v", published, coldRecovery), func(t *testing.T) {
				r, home, root := signedModeProject(t)
				p := nativePlan(t, r, home)
				tx, err := beginSignedNative(context.Background(), p)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Release()
				tx.commitFault = commitWriteBeforePublish
				if published {
					tx.commitFault = commitWriteAfterPublish
				}
				err = tx.Commit(context.Background())
				if !errors.Is(err, errCommitWriteFault) {
					t.Fatalf("original storage cause: %v", err)
				}
				if tx.state.Phase == "committed" {
					t.Fatal("unconfirmed in-memory success")
				}
				if _, err := os.Stat(root); err != nil {
					t.Fatal("root disappeared")
				}
				for _, step := range tx.state.Steps {
					if err := tx.checkTarget(step, tx.plan.Material.After[step.Path], step.AfterIdentity); err != nil {
						t.Fatal("published image lost")
					}
					if before, ok := tx.plan.Material.Before[step.Path]; ok {
						if err := checkPath(filepath.Join(tx.images, step.Slot), before, Identity{before.Device, before.Inode}); err != nil {
							t.Fatal("original bytes/mode/inode lost")
						}
					}
				}
				var disk progress
				if err := tx.readSigned("state.json", &disk); err != nil {
					t.Fatal(err)
				}
				expected := "applying"
				if published {
					expected = "committed"
				}
				if disk.Phase != expected {
					t.Fatalf("actual durable phase=%s want=%s", disk.Phase, expected)
				}
				if published {
					if err := tx.Rollback(context.Background()); !errors.Is(err, ErrCommitUncertain) {
						t.Fatalf("uncertain published receipt rollback: %v", err)
					}
					// Lose access to the actual receipt temporarily: retry MUST NOT report nil
					// just because a committed candidate was published or cached.
					journal := filepath.Join(tx.dir, "state.json")
					held := journal + ".held"
					if err := os.Rename(journal, held); err != nil {
						t.Fatal(err)
					}
					if err := tx.Commit(context.Background()); err == nil {
						t.Fatal("missing receipt reported success")
					}
					if err := os.Rename(held, journal); err != nil {
						t.Fatal(err)
					}
				} else {
					// The same deterministic prepublication storage failure must fail again;
					// the first candidate phase may never become an in-memory shortcut.
					if err := tx.Commit(context.Background()); !errors.Is(err, errCommitWriteFault) {
						t.Fatalf("false retry success: %v", err)
					}
				}
				id := tx.ID()
				tx.commitFault = commitWriteOK
				if coldRecovery {
					tx.Release()
					if err := r.Close(); err != nil {
						t.Fatal(err)
					}
					executable, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					child := exec.Command(executable, "-test.run=^TestSignedCommitRecoveryChild$", "-test.timeout=45s")
					child.Env = []string{"TPLAITER_COMMIT_RECOVERY_HOME=" + home, "TPLAITER_COMMIT_RECOVERY_ID=" + id}
					if output, err := child.CombinedOutput(); err != nil {
						t.Fatalf("fresh process recovery: %v: %s", err, output)
					}
					r = freshSignedRuntime(t, r, home)
					tx, err = openSignedNative(context.Background(), r, home, id)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Release()
				}
				if err := tx.Commit(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := tx.readSigned("state.json", &disk); err != nil || disk.Phase != "committed" {
					t.Fatalf("success without terminal receipt: %v %s", err, disk.Phase)
				}
				if err := tx.Commit(context.Background()); err != nil {
					t.Fatal("confirmed retry failed", err)
				}
			})
		}
	}
}

// Only the exact owned test executable is started by the boundary regression.
// No production formatter/build/hook or generic execution adapter is enabled.
func TestSignedCommitRecoveryChild(t *testing.T) {
	home := os.Getenv("TPLAITER_COMMIT_RECOVERY_HOME")
	if home == "" {
		return
	}
	id := os.Getenv("TPLAITER_COMMIT_RECOVERY_ID")
	raw, err := os.ReadFile(filepath.Join(home, "fixture-launch.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selection trustload.LaunchSelection
	if err := json.Unmarshal(raw, &selection); err != nil {
		t.Fatal(err)
	}
	r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: selection, ProjectKey: "go", Clock: bootstrap.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	tx, err := openSignedNative(context.Background(), r, home, id)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	var receipt progress
	if err := tx.readSigned("state.json", &receipt); err != nil || receipt.Phase != "committed" {
		t.Fatalf("child terminal receipt: %v %s", err, receipt.Phase)
	}
	root, err := os.Stat(tx.plan.Material.Root)
	if err != nil || fileID(root) != tx.plan.RootIdentity {
		t.Fatal("child root identity lost")
	}
	for _, step := range tx.state.Steps {
		if err := tx.checkTarget(step, tx.plan.Material.After[step.Path], step.AfterIdentity); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSignedReadPreservesDecodeCause(t *testing.T) {
	r, home, _ := nativeSignedProject(t)
	tx, err := beginSignedNative(context.Background(), nativePlan(t, r, home))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	// Use the actual admitted runtime's existing private writer; no injected key.
	if err := tx.writeSigned("cause.json", struct {
		Number string `json:"number"`
	}{Number: "invalid"}, true); err != nil {
		t.Fatal(err)
	}
	var value struct {
		Number int `json:"number"`
	}
	err = tx.readSigned("cause.json", &value)
	var typeCause *json.UnmarshalTypeError
	if !errors.Is(err, ErrAuthentication) || !errors.As(err, &typeCause) {
		t.Fatalf("payload cause missing: %v", err)
	}
	name := filepath.Join(tx.dir, "cause.json")
	if err := os.WriteFile(name, []byte(`{"payload":!}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = tx.readSigned("cause.json", &value)
	var syntaxCause *json.SyntaxError
	if !errors.Is(err, ErrAuthentication) || !errors.As(err, &syntaxCause) {
		t.Fatalf("envelope cause missing: %v", err)
	}
}
