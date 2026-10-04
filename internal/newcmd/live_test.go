package newcmd

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"gopkg.in/yaml.v3"
)

func liveFixture(t *testing.T, extra ...string) (*t5DIntegrationFixture, Options, Deps) {
	t.Helper()
	testfixture.RequireTrustStore(t)
	f := t5DNewIntegrationFixture(t, extra...)
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	home := filepath.Join(f.dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return f, Options{Ref: f.source.Commit, ProjectName: "Demo Service", Dir: f.project, Defaults: true, NoHooks: true, CLIVersion: "v1.0.0"}, Deps{Runtime: runtime, Home: home, SourceInput: t5DSelection(f.source, f.sourceRefs), Out: &bytes.Buffer{}, Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }}
}

func assertLiveProject(t *testing.T, f *t5DIntegrationFixture, d Deps) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.project, "hello.txt"))
	if err != nil || string(raw) != "hello source\n" {
		t.Fatalf("render: %q %v", raw, err)
	}
	raw, err = os.ReadFile(filepath.Join(f.project, ".tplaiter/project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(raw, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.ID != d.Runtime.ProjectContext().ProjectID || marker.Template.ResolvedCommit != f.source.Commit || marker.State != stateledger.StandardPointers() || marker.Project["module"] != "example.com/demo_service" {
		t.Fatalf("marker: %+v", marker)
	}
	rootRaw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/root-template.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := provenance.DecodeRootTemplateLock(rootRaw)
	if err != nil || root.Root.Commit != f.source.Commit {
		t.Fatalf("root lock: %v", err)
	}
	depRaw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/template.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(depRaw, []byte(`"dependencies":[]`)) {
		t.Fatalf("not explicitly empty: %s", depRaw)
	}
	if _, err := stateledger.VerifyStable(context.Background(), f.project, d.Runtime.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		t.Fatalf("stable state: %v", err)
	}
	ownershipRaw, err := os.ReadFile(filepath.Join(f.project, ownership.InventoryRelPath))
	if err != nil {
		t.Fatal(err)
	}
	var inventory ownership.Inventory
	if err := json.Unmarshal(ownershipRaw, &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Version != 1 || len(inventory.Artifacts) != 1 || inventory.Artifacts[0].Path != "hello.txt" || inventory.Artifacts[0].SHA256 != strings.TrimPrefix(evidencecas.Digest([]byte("hello source\n")), "sha256:") {
		t.Fatalf("ownership: %+v", inventory)
	}
	projects, err := state.LoadProjects(d.Home)
	if err != nil || len(projects.Items) != 1 || projects.Items[0].ID != marker.ID || projects.Items[0].Path != f.project {
		t.Fatalf("registry: %+v %v", projects, err)
	}
	journals, err := newtransaction.List(d.Home)
	if err != nil || len(journals) != 0 {
		t.Fatalf("pending journal: %+v %v", journals, err)
	}
}

func TestLiveNewSignedTransactionAndRepeat(t *testing.T) {
	f, opts, d := liveFixture(t)
	opts.Sets = []string{"label=chosen"}
	if err := Run(context.Background(), opts, d); err != nil {
		t.Fatal(err)
	}
	assertLiveProject(t, f, d)
	registry, _ := os.ReadFile(state.ProjectsPath(d.Home))
	marker, _ := os.ReadFile(filepath.Join(f.project, ".tplaiter/project.yaml"))
	if err := Run(context.Background(), opts, d); err == nil {
		t.Fatal("repeated new overwrote project")
	}
	after, _ := os.ReadFile(state.ProjectsPath(d.Home))
	if !bytes.Equal(after, registry) {
		t.Fatal("repeat mutated registry")
	}
	after, _ = os.ReadFile(filepath.Join(f.project, ".tplaiter/project.yaml"))
	if !bytes.Equal(after, marker) {
		t.Fatal("repeat mutated marker")
	}
	if !bytes.Contains(marker, []byte("chosen")) {
		t.Fatal("answer not persisted")
	}
}

func TestLiveNewSealedAfterimageRefusesPublicationDrift(t *testing.T) {
	for _, point := range []string{"commit.before_journal", "commit.before_staging_publish"} {
		for _, name := range []string{"hello.txt", ".tplaiter/project.yaml", ".tplaiter/root-template.lock.json", "foreign.txt"} {
			t.Run(point+"/"+name, func(t *testing.T) {
				f, opts, d := liveFixture(t)
				var before newtransaction.Journal
				var original []byte
				err := runLive(context.Background(), opts, d, func(p string) error {
					if p != point {
						return nil
					}
					journals, err := newtransaction.List(d.Home)
					if err != nil || len(journals) != 1 {
						t.Fatalf("journal before drift: %v %v", journals, err)
					}
					before = journals[0]
					original, _ = os.ReadFile(filepath.Join(before.Staging, name))
					return os.WriteFile(filepath.Join(before.Staging, name), []byte("unsigned replacement\n"), 0o644)
				})
				if !errors.Is(err, newtransaction.ErrOwnershipUncertain) {
					t.Fatalf("drift accepted: %v", err)
				}
				if _, err := os.Lstat(f.project); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unsigned afterimage published: %v", err)
				}
				if _, err := os.Stat(state.ProjectsPath(d.Home)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("registry published drift")
				}
				tx, err := newtransaction.Load(d.Home, before.ID)
				if err != nil || tx.Journal().TargetAfterSHA != before.TargetAfterSHA {
					t.Fatalf("recaptured drift as authority: %v", err)
				}
				if err := newtransaction.Continue(d.Home, before.ID, d.Home); err == nil {
					t.Fatal("recovery published drift")
				}
				wantAbort := newtransaction.ErrOwnershipUncertain
				if point == "commit.before_staging_publish" {
					// Publishing has crossed the journal boundary; abort is
					// forbidden even though the directory has not moved yet.
					wantAbort = newtransaction.ErrCommitted
				}
				if err := newtransaction.AbortByID(d.Home, before.ID); !errors.Is(err, wantAbort) {
					t.Fatalf("abort destroyed ambiguous afterimage: %v", err)
				}
				if raw, err := os.ReadFile(filepath.Join(before.Staging, name)); err != nil || string(raw) != "unsigned replacement\n" {
					t.Fatalf("refusal destroyed ambiguous bytes: %q %v", raw, err)
				}
				assertLiveUncertainJournal(t, d.Home, before.ID)
				// Repair back to the caller-derived bytes, never adopt the changed
				// bytes. The original sealed recovery authority can then finish.
				path := filepath.Join(before.Staging, name)
				if original == nil {
					err = os.Remove(path)
				} else {
					err = os.WriteFile(path, original, 0o644)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := newtransaction.Continue(d.Home, before.ID, d.Home); err != nil {
					t.Fatal(err)
				}
				assertLiveProject(t, f, d)
			})
		}
	}
}

func assertLiveUncertainJournal(t *testing.T, home, id string) {
	t.Helper()
	items, err := newtransaction.Inventory(home)
	if err != nil || len(items) != 1 || items[0].ID != id || items[0].Status != "ownership_uncertain" || items[0].Reason == "" {
		t.Fatalf("uncertain journal not inspectable: %+v %v", items, err)
	}
	plan, err := newtransaction.PlanGC(home, time.Now().Add(365*24*time.Hour), false)
	if err != nil || len(plan.IDs) != 0 {
		t.Fatalf("uncertain evidence became GC candidate: %+v %v", plan, err)
	}
}

func TestLiveNewConcurrentForeignFileSurvivesRefusal(t *testing.T) {
	for _, point := range []string{"begin.before_journal", "begin.after_stage", "begin.after_marker"} {
		t.Run(point, func(t *testing.T) {
			f, opts, d := liveFixture(t)
			foreignPath := ""
			err := runLive(context.Background(), opts, d, func(p string) error {
				if p != point {
					return nil
				}
				root := f.project
				if point != "begin.before_journal" {
					matches, err := filepath.Glob(filepath.Join(filepath.Dir(f.project), "."+filepath.Base(f.project)+".tplaiter-new-*"))
					if err != nil || len(matches) != 1 {
						t.Fatalf("staging: %v %v", matches, err)
					}
					root = matches[0]
				}
				foreignPath = filepath.Join(root, "hello.txt")
				return os.WriteFile(foreignPath, []byte("concurrent foreign content\n"), 0o644)
			})
			if raw, readErr := os.ReadFile(foreignPath); readErr != nil || string(raw) != "concurrent foreign content\n" {
				t.Fatalf("failed new destroyed concurrent foreign content: %q %v", raw, readErr)
			}
			if !errors.Is(err, newtransaction.ErrOwnershipUncertain) {
				t.Fatalf("foreign content accepted: %v", err)
			}
			journals, err := newtransaction.List(d.Home)
			if err != nil || len(journals) != 1 {
				t.Fatalf("lost recovery journal: %+v %v", journals, err)
			}
			id := journals[0].ID
			if err := newtransaction.AbortByID(d.Home, id); !errors.Is(err, newtransaction.ErrOwnershipUncertain) {
				t.Fatalf("abort accepted ambiguous ownership: %v", err)
			}
			if err := newtransaction.Continue(d.Home, id, d.Home); err == nil {
				t.Fatal("recovery published foreign content")
			}
			raw, err := os.ReadFile(foreignPath)
			if err != nil || string(raw) != "concurrent foreign content\n" {
				t.Fatalf("foreign content destroyed: %q %v", raw, err)
			}
			if _, err := os.Stat(state.ProjectsPath(d.Home)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("registry published foreign content")
			}
			assertLiveUncertainJournal(t, d.Home, id)
		})
	}
}

func TestLiveNewScriptedAndDryRun(t *testing.T) {
	f, opts, d := liveFixture(t)
	opts.Defaults, opts.Interactive, opts.DryRun = false, true, true
	prompt := &survey.ScriptedPrompter{Answers: []settings.Values{{"label": "interactive"}}}
	d.Prompter = prompt
	if err := Run(context.Background(), opts, d); err != nil {
		t.Fatal(err)
	}
	if len(prompt.AskCalls) == 0 {
		t.Fatal("did not prompt")
	}
	entries, _ := os.ReadDir(f.project)
	if len(entries) != 0 {
		t.Fatal("dry-run wrote target")
	}
	if _, err := os.Stat(state.ProjectsPath(d.Home)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry-run wrote registry")
	}
	opts.DryRun = false
	d.Prompter = &survey.ScriptedPrompter{Answers: []settings.Values{{"label": "interactive"}}}
	if err := Run(context.Background(), opts, d); err != nil {
		t.Fatal(err)
	}
	assertLiveProject(t, f, d)
}

func TestLiveNewRefusalsHaveNoTargetOrRegistryWrites(t *testing.T) {
	for _, name := range []string{"unsigned", "wrong-target", "cancelled", "hook-even-nohooks", "tool-even-nodeps", "version", "occupied", "symlink"} {
		t.Run(name, func(t *testing.T) {
			extra := ""
			if name == "hook-even-nohooks" {
				extra = "hooks:\n  postCreate:\n    - run: exit 0\n"
			}
			if name == "tool-even-nodeps" {
				extra = "requires:\n  tools:\n    - name: git\n"
			}
			if name == "version" {
				extra = "requires:\n  tplaiter: '>=99.0.0'\n"
			}
			f, opts, d := liveFixture(t, extra)
			ctx := context.Background()
			switch name {
			case "unsigned":
				var selection operationtrust.SourceSelection
				_ = json.Unmarshal(d.SourceInput, &selection)
				selection.Evidence.SignatureCAS = "sha256:" + strings.Repeat("0", 64)
				d.SourceInput, _ = json.Marshal(selection)
			case "wrong-target":
				opts.Dir = filepath.Join(f.dir, "elsewhere")
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "tool-even-nodeps":
				opts.NoDepsCheck = true
			case "occupied":
				if err := os.WriteFile(filepath.Join(f.project, "sentinel"), []byte("keep"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(f.project); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(f.scratch, f.project); err != nil {
					t.Fatal(err)
				}
			}
			if err := Run(ctx, opts, d); err == nil {
				t.Fatal("refusal accepted")
			}
			if _, err := os.Stat(state.ProjectsPath(d.Home)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("registry wrote: %v", err)
			}
			journals, err := newtransaction.List(d.Home)
			if err != nil || len(journals) != 0 {
				t.Fatalf("refusal started transaction: %v %v", journals, err)
			}
			entries, _ := os.ReadDir(f.project)
			if name == "occupied" {
				if len(entries) != 1 {
					t.Fatal("occupied target changed")
				}
			} else if len(entries) != 0 {
				t.Fatal("target changed")
			}
		})
	}
}

func TestLiveNewRecoverPublicationCrashes(t *testing.T) {
	for _, point := range []string{"commit.before_staging_publish", "commit.after_staging_publish", "commit.after_registry", "commit.before_marker_remove", "finalize.before_journal"} {
		t.Run(point, func(t *testing.T) {
			f, opts, d := liveFixture(t)
			err := runLive(context.Background(), opts, d, func(p string) error {
				if p == point {
					return newtransaction.ErrInjectedCrash
				}
				return nil
			})
			if !errors.Is(err, newtransaction.ErrInjectedCrash) {
				t.Fatalf("crash = %v", err)
			}
			journals, err := newtransaction.List(d.Home)
			if err != nil || len(journals) != 1 {
				t.Fatalf("journal: %+v %v", journals, err)
			}
			if err := newtransaction.Continue(d.Home, journals[0].ID, d.Home); err != nil {
				t.Fatal(err)
			}
			assertLiveProject(t, f, d)
		})
	}
}

func TestLiveNewRecoveryRefusesSwappedTargetAndAbortRestoresEmpty(t *testing.T) {
	for _, swap := range []bool{false, true} {
		t.Run(map[bool]string{false: "abort", true: "swap"}[swap], func(t *testing.T) {
			f, opts, d := liveFixture(t)
			err := runLive(context.Background(), opts, d, func(p string) error {
				if (swap && p == "commit.before_staging_publish") || (!swap && p == "begin.after_marker") {
					return newtransaction.ErrInjectedCrash
				}
				return nil
			})
			if !errors.Is(err, newtransaction.ErrInjectedCrash) {
				t.Fatal(err)
			}
			journals, _ := newtransaction.List(d.Home)
			id := journals[0].ID
			if swap {
				if err := os.Symlink(f.scratch, f.project); err != nil {
					t.Fatal(err)
				}
				if err := newtransaction.Continue(d.Home, id, d.Home); err == nil {
					t.Fatal("recovery accepted swapped target")
				}
				if err := newtransaction.AbortByID(d.Home, id); err == nil {
					t.Fatal("abort accepted swapped target")
				}
			} else {
				if err := newtransaction.AbortByID(d.Home, id); err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(f.project)
				if err != nil || len(entries) != 0 {
					t.Fatalf("abort before image: %v %v", entries, err)
				}
				if _, err := os.Stat(state.ProjectsPath(d.Home)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("abort published registry")
				}
			}
		})
	}
}

// Register an actual local ref while keeping render objects in the installed
// runtime's separate confined store. No clone, checkout or network is needed.
func registerLiveSource(t *testing.T, f *t5DIntegrationFixture, d Deps) {
	t.Helper()
	clone := filepath.Join(d.Home, "repos", "fixture")
	if err := os.MkdirAll(clone, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, clone, "init", "-b", "main")
	objects, _ := os.ReadDir(filepath.Join(f.dir, "objects"))
	for _, object := range objects {
		id := object.Name()
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(f.dir, "objects", id))
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(clone, ".git", "objects", id[:2])
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(filepath.Join(dir, id[2:]))
		if err != nil {
			t.Fatal(err)
		}
		writer := zlib.NewWriter(file)
		_, err = writer.Write(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, clone, "update-ref", "refs/tags/v1.0.0", f.source.Commit)
	if err := state.SaveConfig(d.Home, state.Config{Version: state.ConfigVersion, Repos: []state.RepoRef{{Alias: "fixture", URL: f.source.Origin, Type: state.RepoKindGit}}}); err != nil {
		t.Fatal(err)
	}
	index := state.NewIndex(time.Now())
	index.Repos["fixture"] = []state.TemplateEntry{{Name: "t5d-source", Path: ".", Ref: "main", Tags: []string{"v1.0.0"}}}
	if err := state.SaveIndex(d.Home, index); err != nil {
		t.Fatal(err)
	}
}

func TestLiveNewRegisteredRepoAdapterAndRefDrift(t *testing.T) {
	f, opts, d := liveFixture(t)
	registerLiveSource(t, f, d)
	opts.Ref = "fixture/t5d-source@v1.0.0"
	selected, err := sourceadapter.Resolve(context.Background(), d.Runtime, d.Home, opts.Ref, d.SourceInput)
	if err != nil || selected.Alias != "fixture" {
		t.Fatalf("adapter: %+v %v", selected, err)
	}
	clone := filepath.Join(d.Home, "repos", "fixture")
	runGit(t, clone, "update-ref", "refs/tags/v1.0.0", f.target.Commit)
	if err := Run(context.Background(), opts, d); !errors.Is(err, sourceadapter.ErrMismatch) {
		t.Fatalf("moved ref: %v", err)
	}
	runGit(t, clone, "update-ref", "refs/tags/v1.0.0", f.source.Commit)
	if err := Run(context.Background(), opts, d); err != nil {
		t.Fatal(err)
	}
	assertLiveProject(t, f, d)
}

func TestLiveNewCreatesAbsentTargetAndPreservesExistingFile(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "file"}[occupied], func(t *testing.T) {
			f, opts, d := liveFixture(t)
			if err := os.Remove(f.project); err != nil {
				t.Fatal(err)
			}
			if occupied {
				if err := os.WriteFile(f.project, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := Run(context.Background(), opts, d); err == nil {
					t.Fatal("file overwritten")
				}
				raw, err := os.ReadFile(f.project)
				if err != nil || string(raw) != "keep" {
					t.Fatalf("file changed: %q %v", raw, err)
				}
			} else {
				if err := Run(context.Background(), opts, d); err != nil {
					t.Fatal(err)
				}
				assertLiveProject(t, f, d)
			}
		})
	}
}
