package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// ── gen ──────────────────────────────────────────────────────────────────

type genArgs struct {
	Prepare       bool              `json:"prepare"`
	ApprovalCAS   string            `json:"approvalCAS"`
	ApprovalInput string            `json:"approvalInput"`
	Dir           string            `json:"dir"`
	Kind          string            `json:"kind"`
	Name          string            `json:"name"`
	Params        map[string]string `json:"params"`
	NoBuild       bool              `json:"noBuild"`
}

type genBatchArgs struct {
	Prepare       bool                `json:"prepare"`
	ApprovalCAS   string              `json:"approvalCAS"`
	ApprovalInput string              `json:"approvalInput"`
	Dir           string              `json:"dir"`
	Operations    []genBatchOperation `json:"operations"`
	NoBuild       bool                `json:"noBuild"`
}

func (s *Server) addGenTools() {
	s.mcp.AddTool(mcp.NewTool(
		"gen",
		mcp.WithDescription("Generate files and anchor insertions from the project's sealed native generator sources. Default build uses a signed exact projected-input request and persistent operator approval through the approved Go runner; noBuild requests file-only generation. Formatter and hooks remain refused."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithString("kind", mcp.Required(), mcp.Description("Type of scaffold (see gen_list)")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of entity to create")),
		mcp.WithObject("params", mcp.Description("Generator parameters: key→string value (serialized as dynamic CLI flags --<param>)")),
		mcp.WithBoolean("prepare", mcp.Description("Prepare exact default-build request without effects")),
		mcp.WithString("approvalCAS", mcp.Description("Persistent signed gen-build approval digest")),
		mcp.WithString("approvalInput", mcp.Description("Public signed gen-build approval JSON path")),
		mcp.WithBoolean("noBuild", mcp.Description("Skip build-gate after generation (--no-build)"), mcp.DefaultBool(false)),
		outputSchema(resultdto.OperationGenRun),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a genArgs) (*mcp.CallToolResult, error) {
		if hasReservedGenParam(a.Params) {
			return s.argumentFailure(resultdto.OperationGenRun, "params"), nil
		}
		cwd, failure := s.workDir(resultdto.OperationGenRun, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		argv := append(argvGen(a.Kind, a.Name, a.Params, a.NoBuild), "--dir", cwd)
		argv = appendGenApproval(argv, a.Prepare, a.ApprovalCAS, a.ApprovalInput)
		return s.callStructured(ctx, resultdto.OperationGenRun, cwd, argv, longCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"gen_batch",
		mcp.WithDescription("Atomically generate files and anchor insertions from sealed native generator sources. Default build uses a signed exact projected-input request and persistent operator approval through the approved Go runner; noBuild requests file-only generation. Formatter and hooks remain refused."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithArray(
			"operations",
			mcp.Required(),
			mcp.MinItems(1),
			mcp.Description("Operations {kind, name, params}; params are string values of generator parameters"),
			mcp.Items(map[string]any{
				"type":     "object",
				"required": []string{"kind", "name"},
				"properties": map[string]any{
					"kind": map[string]any{
						"type":        "string",
						"description": "Generator type from template.manifest.yaml",
						"minLength":   1,
					},
					"name": map[string]any{
						"type":        "string",
						"description": "Name of entity/vertical to create",
						"minLength":   1,
					},
					"params": map[string]any{
						"type":                 "object",
						"description":          "Generator parameters in string CLI representation",
						"additionalProperties": map[string]any{"type": "string"},
					},
				},
				"additionalProperties": false,
			}),
		),
		mcp.WithBoolean("prepare", mcp.Description("Prepare exact default-build request without effects")),
		mcp.WithString("approvalCAS", mcp.Description("Persistent signed gen-build approval digest")),
		mcp.WithString("approvalInput", mcp.Description("Public signed gen-build approval JSON path")),
		mcp.WithBoolean("noBuild", mcp.Description("Skip the final build-gate"), mcp.DefaultBool(false)),
		outputSchema(resultdto.OperationGenBatch),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a genBatchArgs) (*mcp.CallToolResult, error) {
		if len(a.Operations) == 0 {
			return s.argumentFailure(resultdto.OperationGenBatch, "operations"), nil
		}
		for _, operation := range a.Operations {
			if hasReservedGenParam(operation.Params) {
				return s.argumentFailure(resultdto.OperationGenBatch, "operations"), nil
			}
		}
		cwd, failure := s.workDir(resultdto.OperationGenBatch, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		argv := append(argvGenBatch(a.Operations, a.NoBuild), "--dir", cwd)
		argv = appendGenApproval(argv, a.Prepare, a.ApprovalCAS, a.ApprovalInput)
		return s.callStructured(ctx, resultdto.OperationGenBatch, cwd, argv, longCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"gen_list",
		mcp.WithDescription("List available generator kinds from the project's sealed native generator sources."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithReadOnlyHintAnnotation(true),
		outputSchema(resultdto.OperationGenList),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationGenList, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		argv := append(argvGenList(), "--dir", cwd)
		return s.callStructured(ctx, resultdto.OperationGenList, cwd, argv, shortCall), nil
	}))
}

var reservedGenCLIControls = map[string]struct{}{
	"prepare":         {},
	"approval-cas":    {},
	"approval-input":  {},
	"project-context": {},
	"dir":             {},
	"no-build":        {},
	"format":          {},
	"hooks":           {},
	"json":            {},
	"help":            {},
	"operations":      {},
}

func hasReservedGenParam(params map[string]string) bool {
	for name := range params {
		if _, reserved := reservedGenCLIControls[name]; reserved {
			return true
		}
	}
	return false
}

func appendGenApproval(argv []string, prepare bool, cas, input string) []string {
	if prepare {
		argv = append(argv, "--prepare")
	}
	if cas != "" {
		argv = append(argv, "--approval-cas", cas)
	}
	if input != "" {
		argv = append(argv, "--approval-input", input)
	}
	return argv
}
