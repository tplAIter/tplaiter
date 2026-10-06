package ossinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func contextEnrollmentOptions(t *testing.T, alter func(string, map[string][]byte)) Options {
	t.Helper()
	o := enrollmentOptions(t)
	o.Publishers = nil
	o.SourcePackages = nil
	subjects := map[string]bootstrap.SubjectIdentity{}
	encode := func(v any) []byte {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	parameters := []deps.Parameter{{Name: "flavor", Value: json.RawMessage(`"plain"`)}}
	for _, alias := range []string{"leaf", "a", "b", "root"} {
		alias := alias
		refs := []contextsource.ContextDependency{}
		associations := []contextsource.ContextDependencyBinding{}
		requires := []exports.ExportRequirement{}
		names := []string{}
		if alias == "a" || alias == "b" {
			names = []string{"leaf"}
		}
		if alias == "root" {
			names = []string{"a", "b"}
		}
		for _, name := range names {
			s := subjects[name]
			refs = append(refs, contextsource.ContextDependency{Alias: name, Origin: s.Origin, TemplatePath: s.TemplatePath, CommitAlgorithm: "sha1", Commit: s.Commit, TreeDigest: s.TreeSHA256, ContractDigest: s.ContractSHA256})
			associations = append(associations, contextsource.ContextDependencyBinding{Alias: name, ProviderID: "provider." + name, Parameters: parameters})
			requires = append(requires, exports.ExportRequirement{Selector: name + ".block.notes", ContractDigest: s.ContractSHA256, CompatibleRange: ">=1.0.0 <2.0.0"})
		}
		pub, pkg := signedPackage(t, "https://example.test/"+alias, func(files map[string][]byte) {
			manifest := files["template.manifest.yaml"]
			if alias != "leaf" {
				files["template.contract.json"] = encode(contextsource.NativeContextContract{APIVersion: contextsource.NativeContextContractAPIVersion, Kind: "NativeTemplate", ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifest), Dependencies: refs})
			}
			binding := contextsource.ContextSourceBindings{APIVersion: contextsource.ContextSourceBindingsAPIVersion, Kind: "ContextSourceBindings", Source: contextsource.ContextCatalogBinding{Alias: alias, ProviderID: "provider." + alias, Parameters: parameters, EntriesPath: "catalog/entries.json", PayloadDirectory: "catalog/payloads", ToolPath: "catalog/tool.md"}, Dependencies: associations}
			files[contextsource.ContextSourceBindingsPath] = encode(binding)
			content := []byte("Complete procedure for " + alias + ". Read all prerequisites before acting. This source is inert.\n")
			files["docs/notes.md"] = content
			payload := encode(exports.ExportPayload{APIVersion: exports.ExportPayloadAPIVersion, ExportID: "notes", Files: []exports.PayloadFile{{SourcePath: "docs/notes.md", TargetPath: "context/" + alias + ".md", Mode: "100644", ContentSHA256: evidencecas.Digest(content)}}, Slots: []exports.PayloadSlot{}, Blocks: []exports.PayloadBlock{}})
			tool := []byte("Inert task context; no execution.\n")
			domain := "block"
			if alias == "root" {
				domain = "skill"
			}
			files["catalog/entries.json"] = encode([]exports.ExportEntry{{ID: "notes", Domain: domain, Name: "notes", Version: "1.0.0", ContentDigest: evidencecas.Digest(payload), ToolDigest: evidencecas.Digest(tool), Parameters: []exports.ScalarParameter{}, Requires: requires}})
			files["catalog/payloads/notes.json"] = payload
			files["catalog/tool.md"] = tool
			if alter != nil {
				alter(alias, files)
			}
		})
		statement, err := bootstrap.DecodePublisherStatement(pkg.Statement)
		if err != nil {
			t.Fatal(err)
		}
		subjects[alias] = statement.Subject
		o.Publishers = append(o.Publishers, pub)
		o.SourcePackages = append(o.SourcePackages, pkg)
	}
	return o
}

func TestContextSourceEnrollmentInstalledClosure(t *testing.T) {
	ctx := context.Background()
	o := contextEnrollmentOptions(t, nil)
	result, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range o.ProjectContexts {
		if _, err := os.Lstat(p.RootPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("project content created: %v", err)
		}
	}
	reg, legacy := enrollGenerated(t, result)
	if len(legacy) != 1 || legacy[0].Subject.Origin != "https://example.test/leaf" {
		t.Fatal("v2 source exposed through legacy input")
	}
	records, err := contextEnrollmentSources(ctx, o.SourcePackages)
	if err != nil {
		t.Fatal(err)
	}
	name, err := contextSelectionName(records[3].subject)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(result.Root, contextSelectionDirectory, name)
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	input, err := contextsource.DecodeSourceSelectionV2(raw)
	if err != nil || len(input.Sources) != 3 {
		t.Fatalf("closed generated input: %+v %v", input, err)
	}
	t.Logf("generatedRootInput=%s", raw)
	loaded, err := trustload.Load(ctx, reg.Selection())
	if err != nil {
		t.Fatal(err)
	}
	objectPath := ""
	for _, origin := range loaded.Install.ObjectOrigins {
		if origin.Origin == records[3].subject.Origin {
			objectPath = filepath.Join(origin.RootPath, records[3].subject.Commit)
		}
	}
	if objectPath == "" {
		t.Fatal("missing generated object origin")
	}
	originalObject, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, project := range o.ProjectContexts {
		r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: reg.Selection(), ProjectKey: project.Key, Clock: bootstrap.ClockFunc(time.Now)})
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := contextsource.PrepareContextSources(ctx, r, raw)
		if err != nil {
			r.Close()
			t.Fatal(err)
		}
		graph, err := prepared.SourceGraph(ctx)
		if err != nil || len(graph.Nodes) != 4 || len(graph.Edges) != 4 {
			t.Fatalf("DAG: %+v %v", graph, err)
		}
		pins, err := prepared.Pins(ctx)
		if err != nil || len(pins) != 4 {
			t.Fatal(err)
		}
		for _, pin := range pins {
			found := false
			for _, record := range records {
				if record.pin.Alias == pin.Alias {
					a, _ := json.Marshal(record.pin)
					b, _ := json.Marshal(pin)
					if !bytes.Equal(a, b) {
						t.Fatalf("source pin mismatch %s", pin.Alias)
					}
					found = true
				}
			}
			if !found {
				t.Fatal("foreign pin")
			}
		}
		catalogs, err := prepared.Catalogs(ctx)
		if err != nil || len(catalogs) != 4 {
			t.Fatal(err)
		}
		plain := []exports.Catalog{}
		for _, c := range catalogs {
			plain = append(plain, c.Catalog)
		}
		selected, err := exports.ResolveSelections([]exports.Selection{{APIVersion: exports.SelectionAPIVersion, Selector: "root.skill.notes", Bindings: []exports.ScalarParameter{}}}, &graph, plain)
		if err != nil || len(selected.Selected) != 4 || len(selected.Edges) != 4 {
			t.Fatalf("required selection: %+v %v", selected, err)
		}
		material := exports.MaterializeInput{Sources: []exports.MaterialSource{}, TargetInventory: []exports.InventoryEntry{}, Owned: []exports.OwnedPreimage{}, Managed: []exports.ManagedCandidate{}, Current: []exports.FileState{}, Operations: []exports.MaterialOperation{}}
		for _, s := range selected.Selected {
			for _, c := range catalogs {
				if c.Catalog.Source != s.Source || c.Catalog.Provider != s.Provider {
					continue
				}
				payload, err := exports.ParseExportPayload(c.Payloads[0].Raw)
				if err != nil {
					t.Fatal(err)
				}
				file := payload.Files[0]
				index := len(material.Sources)
				material.Sources = append(material.Sources, exports.MaterialSource{Selected: s, Payload: c.Payloads[0].Raw, Blobs: c.Blobs})
				material.Current = append(material.Current, exports.FileState{Path: file.TargetPath})
				material.Operations = append(material.Operations, exports.MaterialOperation{Kind: "add", Path: file.TargetPath, AfterOwner: exports.MaterialOwner{Provider: s.Provider, RuleID: s.ID, ExportID: s.ID}, SourceIndex: index, EntryIndex: 0})
			}
			if s.Provider == "provider.leaf" && len(s.Chains) != 2 {
				t.Fatal("shared leaf chains lost")
			}
		}
		images, err := exports.Materialize(material)
		if err != nil || len(images.Images) != 4 || len(images.Conflicts) != 0 {
			t.Fatalf("material: %+v %v", images, err)
		}
		for _, image := range images.Images {
			alias := strings.TrimSuffix(strings.TrimPrefix(image.Path, "context/"), ".md")
			want := []byte("Complete procedure for " + alias + ". Read all prerequisites before acting. This source is inert.\n")
			if !bytes.Equal(image.After.Content, want) {
				t.Fatalf("wrong whole image %s", image.Path)
			}
		}
		t.Logf("normal Generate/provision/installed carrier project=%s sources=%d edges=%d catalogs=%d selected=%d images=%d graph=%s", project.Key, len(pins), len(graph.Edges), len(catalogs), len(selected.Selected), len(images.Images), selected.Digest)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := contextsource.PrepareContextSources(cancelled, r, raw); err == nil {
			t.Fatal("cancelled admission")
		}
		foreign, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: reg.Selection(), ProjectKey: project.Key, Clock: bootstrap.ClockFunc(time.Now)})
		if err != nil {
			t.Fatal(err)
		}
		if prepared.RecheckFor(ctx, foreign) == nil {
			t.Fatal("foreign runtime reused carrier")
		}
		foreign.Close()
		// Retained metadata is not a waiver for a changed installed Git object.
		if err := os.WriteFile(objectPath, []byte("tampered immutable object"), 0600); err != nil {
			t.Fatal(err)
		}
		if prepared.Recheck(ctx) == nil {
			t.Fatal("stale source carrier accepted")
		}
		if _, err := contextsource.PrepareContextSources(ctx, r, raw); err == nil {
			t.Fatal("tampered source admitted")
		}
		if err := os.WriteFile(objectPath, originalObject, 0600); err != nil {
			t.Fatal(err)
		}
		if err := prepared.Recheck(ctx); err != nil {
			t.Fatalf("restored exact source: %v", err)
		}
		// Each generated v2 root is independently consumable, not only root's
		// full closure. Nothing is obtained from a hand-authored selection.
		dirEntries, err := os.ReadDir(filepath.Dir(inputPath))
		if err != nil {
			t.Fatal(err)
		}
		if len(dirEntries) != 3 {
			t.Fatal("wrong v2 root inventory")
		}
		for _, entry := range dirEntries {
			inputBytes, err := os.ReadFile(filepath.Join(filepath.Dir(inputPath), entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			individual, err := contextsource.PrepareContextSources(ctx, r, inputBytes)
			if err != nil {
				t.Fatal(err)
			}
			rootPin, err := individual.RootPin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			individualPins, err := individual.Pins(ctx)
			if err != nil {
				t.Fatal(err)
			}
			expected := 2
			if rootPin.Alias == "root" {
				expected = 4
			}
			if len(individualPins) != expected {
				t.Fatalf("incomplete generated root %s", rootPin.Alias)
			}
			individual.Close()
		}
		prepared.Close()
		if _, err := prepared.Pins(ctx); err == nil {
			t.Fatal("closed carrier")
		}
		r.Close()
	}
	before := snapshotInstall(t, result.Root)
	reused, err := Generate(o)
	if err != nil || !reused.Reused {
		t.Fatalf("exact reuse: %v", err)
	}
	// The existing enrollment contract treats source sets as order independent.
	for i, j := 0, len(o.SourcePackages)-1; i < j; i, j = i+1, j-1 {
		o.SourcePackages[i], o.SourcePackages[j] = o.SourcePackages[j], o.SourcePackages[i]
	}
	if _, err := Generate(o); err != nil {
		t.Fatalf("permuted reuse: %v", err)
	}
	after := snapshotInstall(t, result.Root)
	if !bytes.Equal(before, after) {
		t.Fatal("idempotent generation mutated install")
	}
	for _, mutation := range []string{"missing", "bytes", "extra", "proof", "subject", "duplicate", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			extra := filepath.Join(filepath.Dir(inputPath), "extra.json")
			changed := append([]byte(nil), raw...)
			switch mutation {
			case "missing":
				if err := os.Remove(inputPath); err != nil {
					t.Fatal(err)
				}
			case "bytes":
				changed = append(changed, ' ')
				if err := os.WriteFile(inputPath, changed, 0600); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(extra, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(inputPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(result.SelectionsPath, inputPath); err != nil {
					t.Fatal(err)
				}
			default:
				c := input
				c.Sources = append([]contextsource.ContextSourceProof(nil), input.Sources...)
				if mutation == "proof" {
					c.Root.Evidence.InclusionProofCAS = c.Sources[0].Evidence.InclusionProofCAS
				}
				if mutation == "subject" {
					c.Root.Subject.Commit = strings.Repeat("a", 40)
					c.Root.Subject.RequestedRef = c.Root.Subject.Commit
				}
				if mutation == "duplicate" {
					c.Sources = append(c.Sources, c.Sources[0])
				}
				changed, _ = marshal(c)
				if err := os.WriteFile(inputPath, changed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			state := snapshotInstall(t, result.Root)
			if _, err := Generate(o); err == nil {
				t.Fatal("tampered output reused")
			}
			if !bytes.Equal(state, snapshotInstall(t, result.Root)) {
				t.Fatal("refusal changed installed content")
			}
			os.Remove(extra)
			os.Remove(inputPath)
			if err := os.WriteFile(inputPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Record file bytes and modes without following symlinks or reading any host
// secrets. The only root is this test's generated temporary installation.
func snapshotInstall(t *testing.T, root string) []byte {
	t.Helper()
	out := []byte{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		out = append(out, []byte(relative+":"+info.Mode().String()+"\n")...)
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			out = append(out, []byte(target)...)
		} else {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out = append(out, raw...)
		}
		out = append(out, 0)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestContextSourceEnrollmentClosureRefusals(t *testing.T) {
	for _, name := range []string{"missing-source", "provider", "parameters", "subject", "bindings", "unknown-contract", "duplicate-package", "signature"} {
		t.Run(name, func(t *testing.T) {
			o := contextEnrollmentOptions(t, func(alias string, files map[string][]byte) {
				if alias != "root" {
					return
				}
				switch name {
				case "bindings":
					delete(files, contextsource.ContextSourceBindingsPath)
				case "unknown-contract":
					raw := files["template.contract.json"]
					files["template.contract.json"] = append(raw[:len(raw)-1], []byte(`,"trusted":true}`)...)
				case "subject":
					var c contextsource.NativeContextContract
					json.Unmarshal(files["template.contract.json"], &c)
					c.Dependencies[0].TreeDigest = "sha256:" + strings.Repeat("a", 64)
					files["template.contract.json"], _ = json.Marshal(c)
				case "provider", "parameters":
					var b contextsource.ContextSourceBindings
					json.Unmarshal(files[contextsource.ContextSourceBindingsPath], &b)
					if name == "provider" {
						b.Dependencies[0].ProviderID = "foreign.provider"
					} else {
						b.Dependencies[0].Parameters[0].Value = json.RawMessage(`"other"`)
					}
					files[contextsource.ContextSourceBindingsPath], _ = json.Marshal(b)
				}
			})
			if name == "missing-source" {
				o.SourcePackages = o.SourcePackages[1:]
			}
			if name == "duplicate-package" {
				o.SourcePackages = append(o.SourcePackages, o.SourcePackages[0])
			}
			if name == "signature" {
				o.SourcePackages[3].Signature = o.SourcePackages[0].Signature
			}
			if _, err := Generate(o); err == nil {
				t.Fatal("ineligible closure published")
			}
			if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refusal published installation: %v", err)
			}
		})
	}
}

func TestContextSourceEnrollmentV1ByteParity(t *testing.T) {
	o := enrollmentOptions(t)
	result, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	_, selections := enrollGenerated(t, result)
	raw, err := os.ReadFile(result.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := marshal(selections)
	if err != nil || !bytes.Equal(raw, expected) {
		t.Fatal("legacy wire differs")
	}
	records, err := contextEnrollmentSources(context.Background(), o.SourcePackages)
	if err != nil {
		t.Fatal(err)
	}
	legacy, documents, err := contextEnrollmentDocuments(context.Background(), records, selections)
	if err != nil || len(documents) != 0 {
		t.Fatal("legacy install emits v2")
	}
	encoded, _ := marshal(legacy)
	if !bytes.Equal(expected, encoded) {
		t.Fatal("legacy transport changed")
	}
	if _, err := os.Lstat(filepath.Join(result.Root, contextSelectionDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("v1 layout changed")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	before := snapshotInstall(t, result.Root)
	if _, err := GenerateWithContext(cancelled, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel ignored: %v", err)
	}
	if !bytes.Equal(before, snapshotInstall(t, result.Root)) {
		t.Fatal("cancel mutated install")
	}
}

func TestContextSourceEnrollmentDefensiveCycle(t *testing.T) {
	o := contextEnrollmentOptions(t, nil)
	result, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	records, err := contextEnrollmentSources(context.Background(), o.SourcePackages)
	if err != nil {
		t.Fatal(err)
	}
	selections := []operationtrust.SourceSelection{}
	rawLegacy, err := os.ReadFile(result.SelectionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var old []operationtrust.SourceSelection
	if err := json.Unmarshal(rawLegacy, &old); err != nil {
		t.Fatal(err)
	}
	proofBySubject := map[operationtrust.SelectionSubject]operationtrust.SelectionEvidence{}
	for _, s := range old {
		proofBySubject[s.Subject] = s.Evidence
	}
	files, err := os.ReadDir(filepath.Join(result.Root, contextSelectionDirectory))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(result.Root, contextSelectionDirectory, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		input, err := contextsource.DecodeSourceSelectionV2(raw)
		if err != nil {
			t.Fatal(err)
		}
		proofBySubject[input.Root.Subject] = input.Root.Evidence
	}
	for _, r := range records {
		selections = append(selections, operationtrust.SourceSelection{Subject: r.subject, Evidence: proofBySubject[r.subject]})
	}
	root := records[3].pin
	// A private pure-builder counter: an internally inconsistent cyclic set of
	// records is rejected. This is not a claim of a captured cyclic Git source.
	records[0].contract.Dependencies = []contextsource.ContextDependency{{Alias: root.Alias, Origin: root.Origin, TemplatePath: root.TemplatePath, CommitAlgorithm: root.CommitAlgorithm, Commit: root.Commit, TreeDigest: root.TreeDigest, ContractDigest: root.ContractDigest}}
	records[0].binding.Dependencies = []contextsource.ContextDependencyBinding{{Alias: root.Alias, ProviderID: root.ProviderID, Parameters: root.Parameters}}
	records[0].pin.Dependencies = []string{root.Alias}
	if _, _, err := contextEnrollmentDocuments(context.Background(), records, selections); err == nil {
		t.Fatal("cycle accepted")
	}
}

func TestInertContentExcludedFromNativeAssociations(t *testing.T) {
	o := contentExternalOptions(t, nil)
	records, err := contextEnrollmentSources(context.Background(), o.SourcePackages)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].inert || !records[1].inert || records[1].v2 || records[1].pin.Alias != "" || records[1].contract.APIVersion != "" {
		t.Fatal("inert content gained native association")
	}
	// No classification flag is accepted: a signed invalid index still refuses.
	bad := contentExternalOptions(t, func(p *exports.ExportPayload, _ map[string][]byte) { p.Files = p.Files[1:] })
	if _, err := contextEnrollmentSources(context.Background(), bad.SourcePackages); err == nil {
		t.Fatal("native association path skipped invalid content")
	}
}
