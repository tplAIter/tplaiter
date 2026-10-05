package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/adoption"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"gopkg.in/yaml.v3"
)

// Build one registered binary from neutral public signed fixture builders.
// Validate the writers' original marker bytes, never a substituted schema ID.
func TestInstalledProjectMarkerIDContract(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeLinkCLIFixture(t, false)
	base := filepath.Dir(f.projectRoot)
	home := filepath.Join(base, "marker-home")
	ledgerHome := filepath.Join(home, "tplaiter")
	if err := os.MkdirAll(ledgerHome, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.selection.RuntimeConfig.Path)
	if err != nil {
		t.Fatal(err)
	}
	var install trustload.RuntimeInstall
	if err := json.Unmarshal(raw, &install); err != nil {
		t.Fatal(err)
	}
	contexts := []trustload.ProjectContext{install.ProjectContexts[0]}
	for _, tc := range []struct{ key, id string }{
		{"normal", "project-new"}, {"dot", "."}, {"dotdot", ".."}, {"unicode", "项目-é"},
	} {
		pc := contexts[0]
		pc.Key, pc.ProjectID = tc.key, tc.id
		// Root paths deliberately derive from keys, never project IDs.
		pc.RootPath = filepath.Join(base, "root-"+tc.key)
		contexts = append(contexts, pc)
	}
	install.ProjectContexts = contexts
	if err := install.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "bad id", "bad/id", "bad\\id", "bad\x00id", "bad\rid", "bad\nid", "bad\tid", string([]byte{0xff})} {
		bad := install
		bad.ProjectContexts = append([]trustload.ProjectContext(nil), contexts...)
		bad.ProjectContexts[0].ProjectID = id
		if bad.Validate() == nil {
			t.Fatal("invalid installed ID admitted")
		}
	}
	if err := os.WriteFile(f.selection.RuntimeConfig.Path, t5FJSON(t, install), 0o600); err != nil {
		t.Fatal(err)
	}
	f.selection.RuntimeConfig.SHA256, err = install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
	raw = t5FJSON(t, registration)
	reg := filepath.Join(base, "marker-registration.json")
	if err := os.WriteFile(reg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "marker-cli")
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version=dev -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+reg+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+evidencecas.Digest(raw), "-o", bin, ".")
	build.Dir, build.Env = filepath.Join("..", ".."), testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env, cmd.Dir = testProcessEnv(home), base
		return cmd.CombinedOutput()
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision: %v %s", err, out)
	}
	selection := filepath.Join(base, "marker-selection.json")
	if err := os.WriteFile(selection, t5FSelection(f.target, f.targetRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "schema", "state-ledger-project.v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(f.projectRoot, "go.mod")
	userBytes := []byte("module example.test/user-owned\ngo 1.26\n")
	if err := os.WriteFile(userPath, userBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	userInfo, err := os.Stat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, pc := range contexts {
		t.Run(pc.Key, func(t *testing.T) {
			action := "new"
			extra := []string{"--defaults", "--no-hooks"}
			if pc.Key == "project" {
				action = "adopt"
				extra = []string{"--ownership=go.mod=user-owned", "--ownership=added.txt=user-owned"}
			}
			args := []string{action, f.target.Commit, "Marker", "--project-context=" + pc.Key, "--dir=" + pc.RootPath, "--source-input=" + selection, "--module=example.test/marker", "--json"}
			out, err := run(append(args, extra...)...)
			if err != nil {
				t.Fatalf("%s: %v %s", action, err, out)
			}
			var result struct{ Project struct{ ID, Root string } }
			if err := json.Unmarshal(out, &result); err != nil || result.Project.ID != pc.ProjectID || result.Project.Root != pc.RootPath {
				t.Fatalf("writer result identity: %v %s", err, out)
			}
			path := filepath.Join(pc.RootPath, stateledger.StateDir, "project.yaml")
			markerBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := yaml.Unmarshal(markerBytes, &wire); err != nil {
				t.Fatal(err)
			}
			wireJSON, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(wireJSON))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(value); err != nil {
				t.Fatalf("original installed marker rejected: %v", err)
			}
			var marker stateledger.ProjectV2
			if err := yaml.Unmarshal(markerBytes, &marker); err != nil || marker.ID != pc.ProjectID {
				t.Fatal("marker/context mismatch", err)
			}
			registry, err := state.LoadProjects(ledgerHome)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, item := range registry.Items {
				if item.ID == pc.ProjectID {
					found = item.Path == pc.RootPath
				}
			}
			if !found {
				t.Fatal("registry/context mismatch")
			}
			r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: pc.Key, Clock: f.clock})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			before := linkNegativeSnapshot(t, pc.RootPath, ledgerHome, r.ScratchRoot())
			authority := r.TrustRuntime()
			if r.ProjectContext() != pc || authority.CheckProjectIdentity(ctx, pc.RootPath, pc.ProjectID) != nil {
				t.Fatal("exact installed identity refused")
			}
			if authority.CheckProjectIdentity(ctx, pc.RootPath, "foreign-project") == nil ||
				authority.CheckProjectIdentity(ctx, base, pc.ProjectID) == nil {
				t.Fatal("foreign ID or root gained authority")
			}
			if _, err := stateledger.VerifyStable(ctx, pc.RootPath, authority, stateledger.StableVerifyOptions{}); err != nil {
				t.Fatal("original marker runtime validation", err)
			}
			if action == "adopt" {
				policy, err := adoptionpolicy.Parse(marker.Ownership)
				if err != nil || policy == nil || policy.Origin.ProjectID != pc.ProjectID || !policy.Origin.Binding.Equal(authority.Binding()) {
					t.Fatal("origin/context/binding mismatch", err)
				}
				if _, err := adoption.Read(ctx, r, ledgerHome, policy); err != nil {
					t.Fatal("authenticated origin", err)
				}
				after, err := os.Stat(userPath)
				b, readErr := os.ReadFile(userPath)
				if err != nil || readErr != nil || !os.SameFile(userInfo, after) || userInfo.Mode() != after.Mode() || !bytes.Equal(b, userBytes) {
					t.Fatal("adopt changed user-owned file")
				}
				if _, err := os.Lstat(filepath.Join(pc.RootPath, "added.txt")); !os.IsNotExist(err) {
					t.Fatal("adopt created excluded missing file", err)
				}
			}
			assertLinkNegativeSnapshot(t, before, pc.RootPath, ledgerHome, r.ScratchRoot())
			// Syntax remains valid; replacing the ID must fail at authority.
			marker.ID = "foreign-project"
			foreign, err := yaml.Marshal(marker)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, foreign, 0o644); err != nil {
				t.Fatal(err)
			}
			before = linkNegativeSnapshot(t, pc.RootPath, ledgerHome, r.ScratchRoot())
			if _, err := stateledger.VerifyStable(ctx, pc.RootPath, authority, stateledger.StableVerifyOptions{}); !errors.Is(err, stateledger.ErrProjectIdentity) {
				t.Fatal("foreign marker did not fail at identity authority", err)
			}
			if out, err := run("verify", "--project-context="+pc.Key, "--dir="+pc.RootPath, "--json"); err == nil {
				t.Fatalf("installed foreign marker admitted: %s", out)
			}
			if out, err := run("verify", "--project-context=foreign", "--dir="+pc.RootPath, "--json"); err == nil {
				t.Fatalf("unauthorized context admitted: %s", out)
			}
			assertLinkNegativeSnapshot(t, before, pc.RootPath, ledgerHome, r.ScratchRoot())
			t.Logf("%s original marker schema PASS; exact identity and foreign-ID/root refusal PASS; opaque ID=%q", action, pc.ProjectID)
		})
	}
}
