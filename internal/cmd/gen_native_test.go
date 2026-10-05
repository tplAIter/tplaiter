package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
)

func executeNativeGenCLI(in invocation, args ...string) (string, error) {
	c := newTrustRootCommand(in)
	var out, stderr bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&stderr)
	c.SetArgs(args)
	err := c.Execute()
	return out.String(), err
}

func installedNativeGenCLI(t *testing.T) (invocation, string) {
	t.Helper()
	testfixture.RequireTrustStore(t)
	f := nativeGenCLIFixture(t)
	home := filepath.Join(filepath.Dir(f.projectRoot), "home")
	t.Setenv(state.HomeEnv, home)
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	if _, err := executeNativeGenCLI(in, "trust", "provision"); err != nil {
		t.Fatal(err)
	}
	selection := filepath.Join(filepath.Dir(f.projectRoot), "source.json")
	if err := os.WriteFile(selection, t5FSelection(f.source, f.sourceRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := executeNativeGenCLI(in, "new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", selection, "--defaults", "--no-hooks", "--json"); err != nil {
		t.Fatalf("new: %v %s", err, out)
	}
	return in, f.projectRoot
}

func nativeGenTree(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			result[rel] = "dir"
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[rel] = string(raw)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNativeGenCLISignedRunBatchList(t *testing.T) {
	in, root := installedNativeGenCLI(t)
	// Legacy CWD is deliberately unrelated to the registered project.
	t.Chdir(t.TempDir())
	out, err := executeNativeGenCLI(in, "gen", "list", "--project-context", "project", "--dir", root, "--json")
	if err != nil {
		t.Fatal(err)
	}
	envelope := decodeOne(t, out)
	if envelope.Operation != resultdto.OperationGenList || envelope.Project.ID != "project-t5f" || envelope.Project.Root != root {
		t.Fatalf("list: %s", out)
	}
	var list resultdto.GenListData
	if err := json.Unmarshal(envelope.Data, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Generators) != 1 || list.Generators[0].Kind != "note" || !list.Generators[0].Available {
		t.Fatalf("list: %+v", list)
	}
	out, err = executeNativeGenCLI(in, "gen", "note", "FirstNote", "--label", "hello", "--project-context=project", "--dir", root, "--no-build", "--json")
	if err != nil {
		t.Fatalf("gen: %v %s", err, out)
	}
	envelope = decodeOne(t, out)
	if envelope.Operation != resultdto.OperationGenRun || envelope.Status != resultdto.StatusChanges || envelope.Project.Root != root {
		t.Fatalf("run: %s", out)
	}
	var data resultdto.GenRunData
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		t.Fatal(err)
	}
	if !data.NoBuild || !reflect.DeepEqual(data.Created, []string{"notes/first_note.txt"}) || len(data.Edited) != 0 || len(envelope.Changes) != 1 {
		t.Fatalf("run data: %s", out)
	}
	raw, err := os.ReadFile(filepath.Join(root, "notes/first_note.txt"))
	if err != nil || string(raw) != "FirstNote:hello:ok\n" {
		t.Fatalf("render: %q %v", raw, err)
	}
	out, err = executeNativeGenCLI(in, "gen", "batch", "--operations", `[{"kind":"note","name":"SecondNote","params":{"label":"two"}},{"kind":"note","name":"ThirdNote","params":{"label":"three"}}]`, "--no-build", "--json")
	if err != nil {
		t.Fatalf("batch: %v %s", err, out)
	}
	envelope = decodeOne(t, out)
	if envelope.Operation != resultdto.OperationGenBatch || envelope.Status != resultdto.StatusChanges {
		t.Fatalf("batch: %s", out)
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Created) != 2 || !data.NoBuild {
		t.Fatalf("batch data: %s", out)
	}
	for _, name := range []string{"notes/second_note.txt", "notes/third_note.txt"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := composeRuntimeForProject(withInvocation(context.Background(), in), "project")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := stateledger.VerifyStable(context.Background(), root, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeGenCLIRefusesBeforeEffects(t *testing.T) {
	in, root := installedNativeGenCLI(t)
	tests := []struct {
		name        string
		args        []string
		unavailable bool
	}{
		{"default build", []string{"gen", "note", "Default", "--label=ok", "--json"}, true},
		{"format", []string{"gen", "note", "Format", "--label=ok", "--no-build", "--format", "--json"}, true},
		{"hooks", []string{"gen", "batch", "--operations", `[{"kind":"note","name":"Hook","params":{"label":"ok"}}]`, "--no-build", "--hooks", "--json"}, true},
		{"pattern", []string{"gen", "note", "Pattern", "--label=bad;value", "--no-build", "--json"}, false},
		{"reserved control", []string{"gen", "batch", "--operations", `[{"kind":"note","name":"Control","params":{"json":"true","label":"ok"}}]`, "--no-build", "--json"}, false},
		{"batch collision", []string{"gen", "batch", "--operations", `[{"kind":"note","name":"Same","params":{"label":"one"}},{"kind":"note","name":"Same","params":{"label":"two"}}]`, "--no-build", "--json"}, false},
		{"foreign context", []string{"gen", "note", "Foreign", "--label=ok", "--no-build", "--project-context=missing", "--json"}, false},
		{"foreign dir", []string{"gen", "note", "Dir", "--label=ok", "--no-build", "--dir", filepath.Dir(root), "--json"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := nativeGenTree(t, root)
			out, err := executeNativeGenCLI(in, tc.args...)
			if err == nil || out != "" {
				t.Fatalf("expected refusal without success output: %v %s", err, out)
			}
			if tc.unavailable && exitCodeFor(err) != resultdto.ExitUnavailable {
				t.Fatalf("typed unavailable: %v", err)
			}
			if !reflect.DeepEqual(before, nativeGenTree(t, root)) {
				t.Fatal("refusal changed project tree")
			}
		})
	}
}

func TestNativeGenCLIListRejectsResourceDrift(t *testing.T) {
	in, root := installedNativeGenCLI(t)
	resource := filepath.Join(root, ".tplaiter/generators/generators/note.txt.tmpl")
	if err := os.WriteFile(resource, []byte("foreign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := nativeGenTree(t, root)
	out, err := executeNativeGenCLI(in, "gen", "list", "--json")
	if err == nil || out != "" {
		t.Fatalf("drift accepted: %s %v", out, err)
	}
	if !reflect.DeepEqual(before, nativeGenTree(t, root)) {
		t.Fatal("list wrote files")
	}
}

func TestNativeGenControlsAndParams(t *testing.T) {
	c := newGenCmd()
	controls, rest, err := parseNativeGenControls(c, []string{"--label", "hello", "--json", "--no-build", "--project-context=project", "--dir", "/fixed/root"})
	if err != nil {
		t.Fatal(err)
	}
	if !controls.noBuild || controls.key != "project" || controls.dir != "/fixed/root" || !jsonMode(c) || !reflect.DeepEqual(rest, []string{"--label", "hello"}) {
		t.Fatalf("controls: %+v %v", controls, rest)
	}
	g := &manifest.Generator{Kind: "note", Params: []manifest.Param{{Name: "label", Type: "string"}}}
	provided, err := parseNativeGenParams(c, g, rest)
	if err != nil || !reflect.DeepEqual(provided, map[string]string{"label": "hello"}) {
		t.Fatalf("params: %v %v", provided, err)
	}
	for _, name := range []string{"json", "no-build", "dir", "project-context", "help", "format", "hooks", "operations"} {
		g.Params = []manifest.Param{{Name: name, Type: "string"}}
		if _, err := parseNativeGenParams(c, g, nil); err == nil {
			t.Fatalf("reserved --%s accepted", name)
		}
	}
	if _, _, err := parseNativeGenControls(c, []string{"--project-context", "--json"}); err == nil {
		t.Fatal("missing control value accepted")
	}
	if _, err := parseNativeGenParams(c, &manifest.Generator{Kind: "note"}, []string{"--bogus=x"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	out, err := executeNativeGenCLI(invocation{}, "gen", "note", "Help", "--help")
	if err != nil || !strings.Contains(out, "gen") {
		t.Fatalf("help requires authentication: %v", err)
	}
}

func TestNativeGenConfiguredActionsRefuse(t *testing.T) {
	for _, tpl := range []*manifest.Template{
		{Hooks: manifest.Hooks{PostCreate: []manifest.Hook{{Run: "echo hook"}}}},
		{Hooks: manifest.Hooks{PostUpdate: []manifest.Hook{{Run: "echo hook"}}}},
	} {
		err := nativeGenActionPolicy(tpl, nativeGenControls{noBuild: true})
		if !errors.Is(err, gen.ErrExecutionUnavailable) || exitCodeFor(err) != resultdto.ExitUnavailable {
			t.Fatalf("action silently skipped: %v", err)
		}
	}
}

func TestNativeGenBatchBoundsBeforeAuthentication(t *testing.T) {
	operations := make([]genBatchInput, 257)
	for i := range operations {
		operations[i] = genBatchInput{Kind: "note", Name: "Note"}
	}
	raw, err := json.Marshal(operations)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{string(raw), strings.Repeat(" ", 1<<20) + "[]"} {
		out, err := executeNativeGenCLI(invocation{}, "gen", "batch", "--operations", input, "--no-build", "--json")
		if err == nil || out != "" || (!strings.Contains(err.Error(), "256 operations") && !strings.Contains(err.Error(), "exceeds 1 MiB")) {
			t.Fatalf("unbounded batch reached authentication: %v", err)
		}
	}
}
