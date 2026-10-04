package mcpsrv

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func TestProjectNewFiniteTargetChildContract(t *testing.T) {
	cwd := t.TempDir()
	for _, target := range []string{"../absent-target", filepath.Join(cwd, "absent-absolute"), ""} {
		t.Run(target, func(t *testing.T) {
			runner := execx.NewRecordingRunner()
			abs := target
			if abs == "" {
				abs = filepath.Join(cwd, "different_display")
			} else if !filepath.IsAbs(abs) {
				abs = filepath.Join(cwd, abs)
			}
			argv := withJSONFlag(argvProjectNewInvocation(projectNewInvocation{Ref: "full-commit", Name: "Different Display", ProjectContext: "b", TargetDir: abs, SourceInput: "/public/source.json", Defaults: true}))
			runner.On(fakeExe, argv, execx.Response{Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationProjectNew, func(r *resultdto.Result) { r.Project = &resultdto.Project{ID: "installed-b", Root: abs} })}})
			c := newTestClient(t, runner)
			listed, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
			if err != nil {
				t.Fatal(err)
			}
			for _, tool := range listed.Tools {
				if tool.Name == "project_new" {
					for _, field := range []string{"dir", "targetDir", "projectContext"} {
						p, ok := tool.InputSchema.Properties[field].(map[string]any)
						if !ok || p["type"] != "string" {
							t.Fatalf("missing string schema %s", field)
						}
					}
				}
			}
			res := callTool(t, c, "project_new", map[string]any{"ref": "full-commit", "name": "Different Display", "projectContext": "b", "dir": cwd, "targetDir": target, "sourceInput": "/public/source.json", "defaults": true})
			if res.IsError {
				t.Fatalf("contract: %s", resultText(t, res))
			}
			if len(runner.Calls) != 1 || runner.Calls[0].Opts.Dir != cwd || !reflect.DeepEqual(runner.Calls[0].Args, argv) {
				t.Fatalf("child contract: %+v", runner.Calls)
			}
			if _, err := os.Lstat(abs); !os.IsNotExist(err) {
				t.Fatalf("MCP handler created target: %v", err)
			}
		})
	}
}

// Pin the changed input contract separately from the unchanged tool-name list.
func TestProjectNewInputSchemaGolden(t *testing.T) {
	tool := New("/nonexistent/tplaiter", "test", nil).MCP().ListTools()["project_new"].Tool
	got, err := json.MarshalIndent(tool.InputSchema, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "project_new.input.golden.json")
	if os.Getenv("TPLAITER_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("project_new input schema differs from %s: %s", path, got)
	}
}
