package mcpsrv

import (
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// ── project (new / run / stats / update / doctor / ai) ─────────────────────

type projectNewArgs struct {
	Prepare        bool              `json:"prepare"`
	FormatStage    bool              `json:"formatStage"`
	FormatInput    string            `json:"formatInput"`
	Ref            string            `json:"ref"`
	Name           string            `json:"name"`
	Dir            string            `json:"dir"`
	TargetDir      string            `json:"targetDir"`
	ProjectContext string            `json:"projectContext"`
	Set            map[string]string `json:"set"`
	Defaults       bool              `json:"defaults"`
	NoHooks        bool              `json:"noHooks"`
	NoDepsCheck    bool              `json:"noDepsCheck"`
	NoEnvSetup     bool              `json:"noEnvSetup"`
	Yes            bool              `json:"yes"`
	Port           int               `json:"port"`
	DryRun         bool              `json:"dryRun"`
	SourceInput    string            `json:"sourceInput"`
}

type runArgs struct {
	Parameters     string   `json:"parameters"`
	ProjectContext string   `json:"projectContext"`
	Prepare        bool     `json:"prepare"`
	ApprovalCAS    string   `json:"approvalCAS"`
	ApprovalInput  string   `json:"approvalInput"`
	Dir            string   `json:"dir"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
}

type runBatchArgs struct {
	Dir            string   `json:"dir"`
	ProjectContext string   `json:"projectContext"`
	Input          string   `json:"input"`
	Prepare        bool     `json:"prepare"`
	Approvals      []string `json:"approvals"`
	ApprovalInput  string   `json:"approvalInput"`
}

type dirArgs struct {
	Dir string `json:"dir"`
}

type updateArgs struct {
	ProjectContext string `json:"projectContext"`
	Dir            string `json:"dir"`
	To             string `json:"to"`
	DryRun         bool   `json:"dryRun"`
	Check          bool   `json:"check"`
	SourceInput    string `json:"sourceInput"`
	Prepare        bool   `json:"prepare"`
	FormatStage    bool   `json:"formatStage"`
	FormatInput    string `json:"formatInput"`
	DecisionsInput string `json:"decisionsInput"`
}

type doctorArgs struct {
	Dir string `json:"dir"`
}

func (s *Server) addProjectTools() {
	s.mcp.AddTool(mcp.NewTool(
		"run_batch",
		mcp.WithDescription("Prepare or execute a finite ordered authenticated readonly native command batch; ONE operation, complete signed approval vector, no shell or child-process widening."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Authenticated installed project root")),
		mcp.WithString("projectContext", mcp.Description("Exact authenticated installed context key")),
		mcp.WithString("input", mcp.Required(), mcp.Description("Closed run-batch-input/v1 JSON, 1..16 ordered typed steps")),
		mcp.WithBoolean("prepare", mcp.Description("Report finalized requests without import or execution")),
		mcp.WithArray("approvals", mcp.Description("Complete ordered persistent signed approval digest vector"), mcp.Items(map[string]any{"type": "string"})),
		mcp.WithString("approvalInput", mcp.Description("Public signed approval document array path")),
		outputSchema(resultdto.OperationProjectRunBatch),
	), mcp.NewTypedToolHandler(func(ctx context.Context, call mcp.CallToolRequest, a runBatchArgs) (*mcp.CallToolResult, error) {
		if a.Prepare && (len(a.Approvals) != 0 || a.ApprovalInput != "") || len(a.Approvals) != 0 && a.ApprovalInput != "" {
			return s.argumentFailure(resultdto.OperationProjectRunBatch, "approvals"), nil
		}
		cwd, failure := s.workDir(resultdto.OperationProjectRunBatch, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		argv := []string{"run", "--batch-input=" + a.Input, "--dir", cwd}
		if a.ProjectContext != "" {
			argv = append(argv, "--project-context", a.ProjectContext)
		}
		if a.Prepare {
			argv = append(argv, "--prepare")
		}
		if len(a.Approvals) != 0 {
			raw, e := json.Marshal(a.Approvals)
			if e != nil {
				return s.argumentFailure(resultdto.OperationProjectRunBatch, "approvals"), nil
			}
			argv = append(argv, "--batch-approvals="+string(raw))
		}
		if a.ApprovalInput != "" {
			argv = append(argv, "--batch-approval-input", a.ApprovalInput)
		}
		return s.callRunBatchDelivery(ctx, call, argv)
	}))

	s.mcp.AddTool(mcp.NewTool(
		"project_new",
		mcp.WithDescription("Create a project from a template (always non-interactive). Select an authenticated installed projectContext; targetDir must match its root. Omitted targetDir uses <dir>/<slug>. If set is incomplete, the tool will return an error about required groups — or set defaults=true."),
		mcp.WithString("ref", mcp.Required(), mcp.Description("Template reference: repo/name@version or short name")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of the new project")),
		mcp.WithString("dir", mcp.Description("Child working directory (must exist); default is the server's cwd. This is not target authority.")),
		mcp.WithString("targetDir", mcp.Description("Target locator forwarded as --dir; may be absent. Relative paths resolve against child dir. Must equal selected installed root.")),
		mcp.WithString("projectContext", mcp.Description("Exact authenticated installed context key; omitted uses registration default")),
		mcp.WithObject("set", mcp.Description("Settings values: group→value (serialized as --set pairs)")),
		mcp.WithBoolean("defaults", mcp.Description("Use default values for unspecified groups"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noHooks", mcp.Description("Skip hooks.postCreate (--no-hooks)"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noDepsCheck", mcp.Description("Skip environment tools check (--no-deps-check)"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noEnvSetup", mcp.Description("Don't offer or run env setup after creation (--no-env-setup)"), mcp.DefaultBool(false)),
		mcp.WithBoolean("yes", mcp.Description("Automatically confirm CLI actions (--yes), including missing tools installation and env setup"), mcp.DefaultBool(false)),
		mcp.WithNumber("port", mcp.Description("Project port (.Runtime.Port); 0 — don't set")),
		mcp.WithBoolean("dryRun", mcp.Description("Prepare a plan without changing files"), mcp.DefaultBool(false)),
		mcp.WithString("sourceInput", mcp.Description("Path to the closed JSON source selection")),
		mcp.WithBoolean("prepare", mcp.Description("Report source-owned formatter requests without executing or publishing")),
		mcp.WithBoolean("formatStage", mcp.Description("Execute admitted formatting-only stage, without project publication")),
		mcp.WithString("formatInput", mcp.Description("Path to closed formatter tool-source/approval selection JSON")),
		outputSchema(resultdto.OperationProjectNew),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a projectNewArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationProjectNew, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		target := a.TargetDir
		if target == "" {
			slug, err := newcmd.Slugify(a.Name)
			if err != nil {
				return s.argumentFailure(resultdto.OperationProjectNew, "name"), nil //nolint:nilerr // MCP reports argument errors in the result envelope, not as transport errors.
			}
			target = filepath.Join(cwd, slug)
		}
		if target != "" && !filepath.IsAbs(target) {
			target = filepath.Join(cwd, target)
		}
		argv := argvProjectNewInvocation(projectNewInvocation{Ref: a.Ref, Name: a.Name, Prepare: a.Prepare, FormatStage: a.FormatStage, FormatInput: a.FormatInput, Set: a.Set, Defaults: a.Defaults, NoHooks: a.NoHooks, NoDepsCheck: a.NoDepsCheck, NoEnvSetup: a.NoEnvSetup, Yes: a.Yes, Port: a.Port, DryRun: a.DryRun, SourceInput: a.SourceInput, ProjectContext: a.ProjectContext, TargetDir: target})
		return s.callStructured(ctx, resultdto.OperationProjectNew, cwd, argv, longCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"run",
		mcp.WithDescription("Prepare or execute an authenticated signed pure-Go project build with a persistent operator approval; no shell fallback."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory (working directory)")),
		mcp.WithString("command", mcp.Required(), mcp.Description("Authenticated declared native command name")),
		mcp.WithString("parameters", mcp.Description("Closed finite typed action parameters as one JSON object")),
		mcp.WithString("projectContext", mcp.Description("authenticated installed project key")),
		mcp.WithBoolean("prepare", mcp.Description("prepare request without executing")),
		mcp.WithString("approvalCAS", mcp.Description("persistent signed approval digest")),
		mcp.WithString("approvalInput", mcp.Description("public signed approval JSON path")),
		mcp.WithArray("args", mcp.Description("Additional arguments passed to the command after --"),
			mcp.Items(map[string]any{"type": "string"})),
		outputSchema(resultdto.OperationProjectRun),
	), mcp.NewTypedToolHandler(func(ctx context.Context, call mcp.CallToolRequest, a runArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationProjectRun, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		// Building/testing with a clean Go cache easily exceeds the short
		// deadline, so manifest commands receive the same longer timeout as
		// new/update.
		argv := []string{"run", a.Command, "--dir", cwd}
		if len(a.Args) > 0 {
			return s.argumentFailure(resultdto.OperationProjectRun, "args"), nil
		}
		if a.ProjectContext != "" {
			argv = append(argv, "--project-context", a.ProjectContext)
		}
		if a.Prepare {
			argv = append(argv, "--prepare")
		}
		if a.ApprovalCAS != "" {
			argv = append(argv, "--approval-cas", a.ApprovalCAS)
		}
		if a.ApprovalInput != "" {
			argv = append(argv, "--approval-input", a.ApprovalInput)
		}
		if a.Parameters != "" {
			if a.Command == "build" {
				return s.argumentFailure(resultdto.OperationProjectRun, "parameters"), nil
			}
			argv = append(argv, "--parameters="+a.Parameters)
		}
		if a.Command != "build" {
			return s.callAction(ctx, cwd, argv, call), nil
		}
		return s.callStructured(ctx, resultdto.OperationProjectRun, cwd, argv, longCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"update",
		mcp.WithDescription("Update the authenticated native project to its signed pinned target. Conflicting plans preserve project and registry. operation is update.check with check=true, update.plan with dryRun=true, otherwise update.apply."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithString("to", mcp.Description("Exact target commit from sourceInput")),
		mcp.WithString("projectContext", mcp.Description("Exact authenticated installed context key; omitted uses registration default")),
		mcp.WithBoolean("dryRun", mcp.Description("Show plan without modifying files"), mcp.DefaultBool(false)),
		mcp.WithBoolean("check", mcp.Description("Check tree for conflict markers (exit code 1 if found)"), mcp.DefaultBool(false)),
		mcp.WithString("sourceInput", mcp.Description("Path to the closed JSON source selection")),
		mcp.WithBoolean("prepare", mcp.DefaultBool(false)),
		mcp.WithBoolean("formatStage", mcp.DefaultBool(false)),
		mcp.WithString("formatInput", mcp.Description("Closed tool selection and signed approvals")),
		mcp.WithString("decisionsInput", mcp.Description("Closed source/target-bound managed decisions")),
		// The operation depends on the flags, so the schema is the union of
		// the update operations; the envelope itself names the operation.
		mcp.WithRawOutputSchema(updateOutputSchema()),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a updateArgs) (*mcp.CallToolResult, error) {
		op := updateOperation(a.DryRun, a.Check)
		if a.Prepare && !a.Check {
			op = resultdto.OperationUpdatePlan
		}
		cwd, failure := s.workDir(op, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		argv := argvUpdate(a.To, a.DryRun, a.Check, a.SourceInput)
		if a.Prepare {
			argv = append(argv, "--prepare")
		}
		if a.FormatStage {
			argv = append(argv, "--format-stage")
		}
		if a.FormatInput != "" {
			argv = append(argv, "--format-input", a.FormatInput)
		}
		if a.DecisionsInput != "" {
			argv = append(argv, "--decisions-input", a.DecisionsInput)
		}
		argv = append(argv, "--dir", cwd)
		if a.ProjectContext != "" {
			argv = append(argv, "--project-context", a.ProjectContext)
		}
		return s.callStructured(ctx, op, cwd, argv, longCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"stats",
		mcp.WithDescription("Report of project (dir) drift from template (drift-score, file statuses, updateability classes) in data.report."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithReadOnlyHintAnnotation(true),
		outputSchema(resultdto.OperationProjectStats),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationProjectStats, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		return s.callStructured(ctx, resultdto.OperationProjectStats, cwd, argvStats(), shortCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"doctor",
		mcp.WithDescription("Check environment and tools of the active template. dir is optional (default is server's cwd)."),
		mcp.WithString("dir", mcp.Description("Project directory (optional)")),
		mcp.WithReadOnlyHintAnnotation(true),
		outputSchema(resultdto.OperationDoctorCheck),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a doctorArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationDoctorCheck, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		return s.callStructured(ctx, resultdto.OperationDoctorCheck, cwd, argvDoctor(), shortCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"ai_gen",
		mcp.WithDescription("Generate AI artifacts (CLAUDE.md, .cursor/**, AGENTS.md, GEMINI.md) to project root (dir)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		outputSchema(resultdto.OperationAIGen),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationAIGen, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		return s.callStructured(ctx, resultdto.OperationAIGen, cwd, argvAIGen(), shortCall), nil
	}))
}
