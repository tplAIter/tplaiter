package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestNewLiveSignedCLIJSONMaterializesProject(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := t5FTrustFixture(t)
	home := filepath.Join(filepath.Dir(f.projectRoot), "home")
	t.Setenv(state.HomeEnv, home)
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	provision := newTrustRootCommand(in)
	provision.SetOut(&bytes.Buffer{})
	provision.SetErr(&bytes.Buffer{})
	provision.SetArgs([]string{"trust", "provision"})
	if err := provision.Execute(); err != nil {
		t.Fatal(err)
	}
	sourceInput := filepath.Join(filepath.Dir(f.projectRoot), "selection.json")
	if err := os.WriteFile(sourceInput, t5FSelection(f.source, f.sourceRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	cmd := newTrustRootCommand(in)
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", sourceInput, "--defaults", "--no-hooks", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("new: %v %s", err, stderr.String())
	}
	var envelope struct {
		APIVersion string                    `json:"apiVersion"`
		Status     string                    `json:"status"`
		Project    struct{ ID, Root string } `json:"project"`
		Data       struct {
			DryRun bool `json:"dryRun"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("JSON: %v %s", err, out.String())
	}
	if envelope.Project.ID != "project-t5f" || envelope.Project.Root != f.projectRoot || envelope.Data.DryRun {
		t.Fatalf("result: %s", out.String())
	}
	raw, err := os.ReadFile(filepath.Join(f.projectRoot, "hello.txt"))
	if err != nil || string(raw) != "hello source\n" {
		t.Fatalf("actual materialization: %q %v", raw, err)
	}
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if _, err := stateledger.VerifyStable(context.Background(), f.projectRoot, runtime.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	projects, err := state.LoadProjects(home)
	if err != nil || len(projects.Items) != 1 || projects.Items[0].ID != envelope.Project.ID {
		t.Fatalf("registry: %+v %v", projects, err)
	}
}
