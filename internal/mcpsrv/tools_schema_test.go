package mcpsrv

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// toolOperations maps every tool to the result/v1 operations it can return.
// A tool added without an entry fails TestEveryToolHasOutputSchema.
var toolOperations = map[string][]resultdto.Operation{
	"context":               {resultdto.OperationContextQuery},
	"project_link":          {resultdto.OperationProjectLink, resultdto.OperationProjectAdopt},
	"graph_source":          {resultdto.OperationGraphSource},
	"dependency_graph":      {resultdto.OperationGraphSource},
	"graph_exports":         {resultdto.OperationGraphExports},
	"graph_ast":             {resultdto.OperationGraphAST},
	"graph_stats":           {resultdto.OperationGraphStats},
	"project_diff":          {resultdto.OperationProjectDiff},
	"project_verify":        {resultdto.OperationProjectVerify},
	"project_check":         {resultdto.OperationProjectCheck},
	"deps_verify":           {resultdto.OperationDepsVerify},
	"trust_inspect":         {resultdto.OperationTrustInspect},
	"repo_add":              {resultdto.OperationRepoAdd},
	"repo_list":             {resultdto.OperationRepoList},
	"repo_update":           {resultdto.OperationRepoUpdate},
	"repo_remove":           {resultdto.OperationRepoRemove},
	"template_list":         {resultdto.OperationTemplateList},
	"template_show":         {resultdto.OperationTemplateShow},
	"project_new":           {resultdto.OperationProjectNew},
	"run":                   {resultdto.OperationProjectRun},
	"run_batch":             {resultdto.OperationProjectRunBatch},
	"update":                updateOperations,
	"stats":                 {resultdto.OperationProjectStats},
	"doctor":                {resultdto.OperationDoctorCheck},
	"ai_gen":                {resultdto.OperationAIGen},
	"settings_list":         {resultdto.OperationSettingsShow},
	"settings_edit":         {resultdto.OperationSettingsReanswer},
	"settings_set":          {resultdto.OperationSettingsSet},
	"gen":                   {resultdto.OperationGenRun},
	"gen_batch":             {resultdto.OperationGenBatch},
	"gen_list":              {resultdto.OperationGenList},
	"workspace_add_service": {resultdto.OperationWorkspaceAddService},
	"lint_template":         {resultdto.OperationTemplateLint},
	"init_template":         {resultdto.OperationTemplateInit},
	"projects_list":         {resultdto.OperationProjectsList},
	"env_setup":             {resultdto.OperationEnvSetup},
}

// TestEveryToolHasOutputSchema: every registered tool declares a compilable
// result/v1 outputSchema that pins its operation(s), and every envelope the
// server itself can synthesize for that tool (transport failures, argument
// failures, contract failures) conforms to it.
func TestEveryToolHasOutputSchema(t *testing.T) {
	srv := New("/nonexistent/tplaiter", "test", nil)
	tools := srv.MCP().ListTools()
	if len(tools) != len(toolOperations) {
		t.Fatalf("%d tools registered, %d mapped in toolOperations", len(tools), len(toolOperations))
	}
	for name, st := range tools {
		t.Run(name, func(t *testing.T) {
			ops, ok := toolOperations[name]
			if !ok {
				t.Fatalf("tool %q has no entry in toolOperations", name)
			}
			raw := st.Tool.RawOutputSchema
			if len(raw) == 0 {
				t.Fatalf("tool %q has no outputSchema", name)
			}
			encoded, err := json.Marshal(st.Tool)
			if err != nil {
				t.Fatal(err)
			}
			var listed struct {
				OutputSchema map[string]any `json:"outputSchema"`
			}
			if err := json.Unmarshal(encoded, &listed); err != nil || listed.OutputSchema["type"] != "object" {
				t.Fatalf("tools/list outputSchema of %q is not an object schema: %s", name, encoded)
			}
			schema := compileToolSchema(t, raw)
			for _, op := range ops {
				for label, res := range map[string]*mcp.CallToolResult{
					"timeout":  srv.transportFailure(op, "MCP_TIMEOUT", 1500*time.Millisecond),
					"cancel":   srv.transportFailure(op, "MCP_CANCELLED", 10*time.Millisecond),
					"argument": srv.argumentFailure(op, "dir"),
				} {
					validateStructured(t, schema, res, label)
				}
				ok := resultdto.New(op, "test")
				if scope, _ := resultdto.ScopeForOperation(op); scope == resultdto.ScopeProject {
					ok.Project = &resultdto.Project{ID: "p", Root: "/work/p"}
				}
				validateStructured(t, schema, structuredResult(ok, false), "success")
			}
			foreign := resultdto.OperationProjectVerify
			for _, op := range ops {
				if op == foreign {
					foreign = resultdto.OperationProjectCheck
				}
			}
			other := resultdto.New(foreign, "test")
			other.Project = &resultdto.Project{ID: "p", Root: "/work/p"}
			if res := structuredResult(other, false); validateAgainst(schema, res) == nil {
				t.Fatalf("tool %q schema accepts a foreign operation", name)
			}
		})
	}
}

func compileToolSchema(t *testing.T, raw []byte) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("tool.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("tool.schema.json")
	if err != nil {
		t.Fatalf("outputSchema does not compile: %v", err)
	}
	return schema
}

func validateStructured(t *testing.T, schema *jsonschema.Schema, res *mcp.CallToolResult, label string) {
	t.Helper()
	if err := validateAgainst(schema, res); err != nil {
		t.Fatalf("%s envelope violates the tool outputSchema: %v", label, err)
	}
}

func validateAgainst(schema *jsonschema.Schema, res *mcp.CallToolResult) error {
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return err
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return schema.Validate(value)
}

func TestCompactSummaryIsBounded(t *testing.T) {
	env := resultdto.New(resultdto.OperationTemplateLint, "test")
	env.Status = resultdto.StatusFailed
	for i := 0; i < 50; i++ {
		env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: "TPL-E-LINT-" + string(rune('A'+i%26)), Severity: "error", Message: "m", Details: map[string]any{}})
	}
	if err := env.SetData(map[string]any{"failed": true}); err != nil {
		t.Fatal(err)
	}
	summary := compactSummary(env)
	if n := len(bytes.Split([]byte(summary), []byte("\n"))); n > maxSummaryLines {
		t.Fatalf("summary has %d lines, bound is %d:\n%s", n, maxSummaryLines, summary)
	}
}

func TestLocalPreviewKeepsAllNativeOutputSchemas(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	if len(s.MCP().ListTools()) != 30 {
		t.Fatal("native tool inventory")
	}
	for name, tool := range s.MCP().ListTools() {
		if len(tool.Tool.RawOutputSchema) == 0 {
			t.Fatal("output contract removed", name)
		}
		_ = compileToolSchema(t, tool.Tool.RawOutputSchema)
	}
}

// TestRunActionCompiledMetadataGolden checks the actual registered metadata,
// without invoking any tool, source acquisition, installation or process.
func TestRunActionCompiledMetadataGolden(t *testing.T) {
	srv := New("/nonexistent/tplaiter", "test", nil)
	tools := srv.MCP().ListTools()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "testdata", "mcp", "tools.schema.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden []map[string]any
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if len(tools) != 36 || len(golden) != 36 {
		t.Fatalf("expected original35 + batch descriptors, got %d/%d", len(tools), len(golden))
	}
	seen := make(map[string]bool)
	for _, want := range golden {
		name, ok := want["name"].(string)
		if !ok || seen[name] {
			t.Fatal("invalid/duplicate golden name")
		}
		seen[name] = true
		tool, ok := tools[name]
		if !ok {
			t.Fatalf("missing compiled tool %s", name)
		}
		body, err := json.Marshal(tool.Tool)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if name == "run" {
			// Optional test-only capture is an observation of real compiled metadata.
			// It cannot update the oracle or confer source/execution authority.
			if dest := os.Getenv("TPLAITER_RUN_METADATA_CAPTURE"); dest != "" {
				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "  ")
				if err := enc.Encode(got); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dest, buf.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			compileToolSchema(t, tool.Tool.RawOutputSchema)
			props := got["inputSchema"].(map[string]any)["properties"].(map[string]any)
			if props["parameters"] == nil || props["command"].(map[string]any)["description"] != "Authenticated declared native command name" {
				t.Fatal("missing named action metadata")
			}
		}
		actual, _ := json.Marshal(got)
		expected, _ := json.Marshal(want)
		if !bytes.Equal(actual, expected) {
			t.Errorf("compiled metadata differs from exact golden: %s", name)
		}
	}
}
