package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

// ── gen ──────────────────────────────────────────────────────────────────

type genArgs struct {
	Dir     string            `json:"dir"`
	Kind    string            `json:"kind"`
	Name    string            `json:"name"`
	Params  map[string]string `json:"params"`
	NoBuild bool              `json:"noBuild"`
}

type genBatchArgs struct {
	Dir        string              `json:"dir"`
	Operations []genBatchOperation `json:"operations"`
	NoBuild    bool                `json:"noBuild"`
}

func (s *Server) addGenTools() {
	s.mcp.AddTool(mcp.NewTool(
		"gen",
		mcp.WithDescription("Scaffolder: create file(s) of type kind with name according to project manifest generators (dir). After writing, commands.build.run or legacy Go fallback is executed; error rolls back changes. noBuild=true skips build-gate and saves changes."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithString("kind", mcp.Required(), mcp.Description("Type of scaffold (see gen_list)")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of entity to create")),
		mcp.WithObject("params", mcp.Description("Generator parameters: key→string value (serialized as dynamic CLI flags --<param>)")),
		mcp.WithBoolean("noBuild", mcp.Description("Skip build-gate after generation (--no-build)"), mcp.DefaultBool(false)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a genArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvGen(a.Kind, a.Name, a.Params, a.NoBuild), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"gen_batch",
		mcp.WithDescription("Atomically generate multiple scaffolds. All operations are planned before writing, then a single build-gate from manifest commands.build.run (legacy Go fallback: go build ./...) is executed; on error, all batch changes are rolled back."),
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
		mcp.WithBoolean("noBuild", mcp.Description("Skip the final build-gate"), mcp.DefaultBool(false)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a genBatchArgs) (*mcp.CallToolResult, error) {
		if len(a.Operations) == 0 {
			return mcp.NewToolResultError("gen_batch: operations must contain at least one operation"), nil
		}
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		argv := argvGenBatch(a.Operations, a.NoBuild)
		return s.exec(ctx, cwd, argv, longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"gen_list",
		mcp.WithDescription("List of available scaffold types from project template manifest (dir)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvGenList(), defaultTimeout), nil
	}))
}
