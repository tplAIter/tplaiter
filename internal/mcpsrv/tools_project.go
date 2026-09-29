package mcpsrv

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/mark3labs/mcp-go/mcp"
)

// ── project (new / run / stats / update / doctor / ai) ─────────────────────

type projectNewArgs struct {
	Ref         string            `json:"ref"`
	Name        string            `json:"name"`
	Dir         string            `json:"dir"`
	Set         map[string]string `json:"set"`
	Defaults    bool              `json:"defaults"`
	NoHooks     bool              `json:"noHooks"`
	NoDepsCheck bool              `json:"noDepsCheck"`
	NoEnvSetup  bool              `json:"noEnvSetup"`
	Yes         bool              `json:"yes"`
	Port        int               `json:"port"`
	DryRun      bool              `json:"dryRun"`
	SourceInput string            `json:"sourceInput"`
}

type runArgs struct {
	Dir     string   `json:"dir"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type dirArgs struct {
	Dir string `json:"dir"`
}

type updateArgs struct {
	Dir         string `json:"dir"`
	To          string `json:"to"`
	DryRun      bool   `json:"dryRun"`
	Check       bool   `json:"check"`
	SourceInput string `json:"sourceInput"`
}

type doctorArgs struct {
	Dir string `json:"dir"`
}

func (s *Server) addProjectTools() {
	s.mcp.AddTool(mcp.NewTool(
		"project_new",
		mcp.WithDescription("Create a project from a template (always non-interactive). The project is created as <dir>/<slug>. If set is incomplete, the tool will return an error about required groups — or set defaults=true."),
		mcp.WithString("ref", mcp.Required(), mcp.Description("Template reference: repo/name@version or short name")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of the new project")),
		mcp.WithString("dir", mcp.Description("Directory INSIDE which the project is created (must exist); default is the server's cwd")),
		mcp.WithObject("set", mcp.Description("Settings values: group→value (serialized as --set pairs)")),
		mcp.WithBoolean("defaults", mcp.Description("Use default values for unspecified groups"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noHooks", mcp.Description("Skip hooks.postCreate (--no-hooks)"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noDepsCheck", mcp.Description("Skip environment tools check (--no-deps-check)"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noEnvSetup", mcp.Description("Don't offer or run env setup after creation (--no-env-setup)"), mcp.DefaultBool(false)),
		mcp.WithBoolean("yes", mcp.Description("Automatically confirm CLI actions (--yes), including missing tools installation and env setup"), mcp.DefaultBool(false)),
		mcp.WithNumber("port", mcp.Description("Project port (.Runtime.Port); 0 — don't set")),
		mcp.WithBoolean("dryRun", mcp.Description("Prepare a plan without changing files"), mcp.DefaultBool(false)),
		mcp.WithString("sourceInput", mcp.Description("Path to the closed JSON source selection")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a projectNewArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvProjectNew(a.Ref, a.Name, a.Set, a.Defaults, a.NoHooks, a.NoDepsCheck, a.NoEnvSetup, a.Yes, a.Port, strconv.FormatBool(a.DryRun), a.SourceInput), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"run",
		mcp.WithDescription("Execute a template manifest command at the project root (dir). WARNING: long-running commands (dev servers) will be interrupted on timeout."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory (working directory)")),
		mcp.WithString("command", mcp.Required(), mcp.Description("Manifest command name")),
		mcp.WithArray("args", mcp.Description("Additional arguments passed to the command after --"),
			mcp.Items(map[string]any{"type": "string"})),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a runArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		// Building/testing with a clean Go cache easily exceeds 120 seconds, so
		// manifest commands receive the same longer timeout as new/update.
		return s.exec(ctx, cwd, argvRun(a.Command, a.Args), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"update",
		mcp.WithDescription("Update project (dir) to a new template version using 3-way merge. Conflicts produce markers and non-zero return code (isError)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithString("to", mcp.Description("Target template version; empty — latest stable tag")),
		mcp.WithBoolean("dryRun", mcp.Description("Show plan without modifying files"), mcp.DefaultBool(false)),
		mcp.WithBoolean("check", mcp.Description("Check tree for conflict markers (exit code 1 if found)"), mcp.DefaultBool(false)),
		mcp.WithString("sourceInput", mcp.Description("Path to the closed JSON source selection")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a updateArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvUpdate(a.To, a.DryRun, a.Check, a.SourceInput), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"stats",
		mcp.WithDescription("Report of project (dir) drift from template in machine-readable JSON (drift-score, file statuses, updateability classes)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.handleStats(ctx, cwd), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"doctor",
		mcp.WithDescription("Check environment and tools of the active template. dir is optional (default is server's cwd)."),
		mcp.WithString("dir", mcp.Description("Project directory (optional)")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a doctorArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvDoctor(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"ai_gen",
		mcp.WithDescription("Generate AI artifacts (CLAUDE.md, .cursor/**, AGENTS.md, GEMINI.md) to project root (dir)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvAIGen(), defaultTimeout), nil
	}))
}

// handleStats executes `stats --json` and returns parsed (for validation) and
// reformatted JSON. If stdout cannot be parsed as JSON, it is returned as is.
func (s *Server) handleStats(ctx context.Context, cwd string) *mcp.CallToolResult {
	res, runErr := s.runCLI(ctx, cwd, argvStats(), defaultTimeout)
	if failed(res, runErr) {
		return mcp.NewToolResultError(formatFailure(res, runErr))
	}

	var parsed any
	if err := json.Unmarshal([]byte(res.Stdout), &parsed); err != nil {
		return mcp.NewToolResultText(res.Stdout)
	}
	pretty, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return mcp.NewToolResultText(res.Stdout)
	}
	return mcp.NewToolResultText(string(pretty))
}
