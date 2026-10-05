package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// ── workspace ─────────────────────────────────────────────────────────────

type workspaceAddServiceArgs struct {
	ProjectContext string            `json:"projectContext"`
	ServiceContext string            `json:"serviceContext"`
	SourceInput    string            `json:"sourceInput"`
	DryRun         bool              `json:"dryRun"`
	Dir            string            `json:"dir"`
	Name           string            `json:"name"`
	Module         string            `json:"module"`
	Set            map[string]string `json:"set"`
	Defaults       bool              `json:"defaults"`
	NoHooks        bool              `json:"noHooks"`
	NoDepsCheck    bool              `json:"noDepsCheck"`
	Port           int               `json:"port"`
}

func (s *Server) addWorkspaceTools() {
	s.mcp.AddTool(mcp.NewTool(
		"workspace_add_service",
		mcp.WithDescription("Add an independently signed native service under the finite installed workspace and service contexts; atomically register go.work and the project registry."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Exact authenticated workspace root")),
		mcp.WithString("projectContext", mcp.Description("Authenticated installed workspace context; omitted uses registration default")),
		mcp.WithString("serviceContext", mcp.Required(), mcp.Description("Authenticated installed service context at services/<slug>")),
		mcp.WithString("sourceInput", mcp.Required(), mcp.Description("Closed signed service source selection")),
		mcp.WithBoolean("dryRun", mcp.Description("Authenticate and report without changes"), mcp.DefaultBool(false)),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of new service-action")),
		mcp.WithString("module", mcp.Description("Go module of service; default <workspace module>/services/<slug>")),
		mcp.WithObject("set", mcp.Description("Service template settings: group→value; workflow=true is forced by CLI")),
		mcp.WithBoolean("defaults", mcp.Description("Use default values for unspecified groups"), mcp.DefaultBool(true)),
		mcp.WithBoolean("noHooks", mcp.Description("Don't run hooks.postCreate"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noDepsCheck", mcp.Description("Don't check environment tools"), mcp.DefaultBool(false)),
		mcp.WithNumber("port", mcp.Description("Service port; 0 — use template value")),
		outputSchema(resultdto.OperationWorkspaceAddService),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a workspaceAddServiceArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationWorkspaceAddService, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		argv := argvNativeWorkspaceAddService(a, cwd)
		return s.callStructured(ctx, resultdto.OperationWorkspaceAddService, cwd, argv, longCall), nil
	}))
}

func argvNativeWorkspaceAddService(a workspaceAddServiceArgs, cwd string) []string {
	argv := argvWorkspaceAddService(a.Name, a.Module, a.Set, a.Defaults, a.NoHooks, a.NoDepsCheck, a.Port)
	argv = append(argv, "--dir", cwd, "--service-context", a.ServiceContext, "--source-input", a.SourceInput)
	if a.ProjectContext != "" {
		argv = append(argv, "--project-context", a.ProjectContext)
	}
	if a.DryRun {
		argv = append(argv, "--dry-run")
	}
	return argv
}
