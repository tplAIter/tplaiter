package mcpsrv

import (
	"context"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// ── settings ───────────────────────────────────────────────────────────────

type nativeSettingsListArgs struct {
	Dir            string `json:"dir"`
	ProjectContext string `json:"projectContext"`
}

type settingsSetArgs struct {
	Prepare        bool              `json:"prepare"`
	FormatStage    bool              `json:"formatStage"`
	FormatInput    string            `json:"formatInput"`
	DecisionsInput string            `json:"decisionsInput"`
	ProjectContext string            `json:"projectContext"`
	DryRun         bool              `json:"dryRun"`
	Dir            string            `json:"dir"`
	Values         map[string]string `json:"values"`
}

type nativeSettingsEditArgs struct {
	Prepare        bool   `json:"prepare"`
	FormatStage    bool   `json:"formatStage"`
	FormatInput    string `json:"formatInput"`
	DecisionsInput string `json:"decisionsInput"`
	PairsInput     string `json:"pairsInput"`
	Dir            string `json:"dir"`
	ProjectContext string `json:"projectContext"`
	Group          string `json:"group"`
	Value          string `json:"value"`
	DryRun         bool   `json:"dryRun"`
}

func (s *Server) addSettingsTools() {
	s.mcp.AddTool(mcp.NewTool(
		"settings_list",
		mcp.WithDescription("Show current values of project settings (dir) as result/v1 settings.show."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithString("projectContext", mcp.Description("Exact authenticated installed context key; omitted uses registration default")),
		mcp.WithReadOnlyHintAnnotation(true),
		outputSchema(resultdto.OperationSettingsShow),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a nativeSettingsListArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationSettingsShow, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		argv := append(argvSettingsList(), "--dir", cwd)
		if a.ProjectContext != "" {
			argv = append(argv, "--project-context", a.ProjectContext)
		}
		return s.callStructured(ctx, resultdto.OperationSettingsShow, cwd, argv, shortCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"settings_set",
		mcp.WithDescription("Change project (dir) settings using 3-way merge on current template version. Applied without confirmation (--yes)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithString("projectContext", mcp.Description("Exact authenticated installed context key; omitted uses registration default")),
		mcp.WithBoolean("dryRun", mcp.Description("Show signed plan without publication"), mcp.DefaultBool(false)),
		mcp.WithBoolean("prepare", mcp.Description("Report actual managed Settings formatter requests without execution")),
		mcp.WithBoolean("formatStage", mcp.Description("Stage the current managed Settings formatter phase with exact approvals")),
		mcp.WithString("formatInput", mcp.Description("Path to closed formatter selection and approval transport")),
		mcp.WithString("decisionsInput", mcp.Description("Path to canonical typed managed decisions")),
		mcp.WithObject("values", mcp.Required(), mcp.Description("New values: group→value")),
		outputSchema(resultdto.OperationSettingsSet),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a settingsSetArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationSettingsSet, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		for key := range a.Values {
			if key == "" || strings.HasPrefix(strings.TrimSpace(key), "-") || strings.Contains(key, "=") {
				return s.argumentFailure(resultdto.OperationSettingsSet, "values"), nil
			}
		}
		argv := append(argvSettingsSet(a.Values), "--dir", cwd)
		if a.ProjectContext != "" {
			argv = append(argv, "--project-context", a.ProjectContext)
		}
		if a.DryRun {
			argv = append(argv, "--dry-run")
		}
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
		return s.callStructured(ctx, resultdto.OperationSettingsSet, cwd, argv, longCall), nil
	}))
	s.mcp.AddTool(mcp.NewTool(
		"settings_edit",
		mcp.WithDescription("Reanswer one authenticated native settings group on the pinned version using an explicit value; operation is settings.reanswer."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithString("projectContext", mcp.Description("Exact authenticated installed context key; omitted uses registration default")),
		mcp.WithString("group", mcp.Required(), mcp.Description("Signed manifest settings group")),
		mcp.WithString("value", mcp.Description("Explicit answer, validated against the signed group type")),
		mcp.WithBoolean("dryRun", mcp.Description("Show signed plan without publication"), mcp.DefaultBool(false)),
		mcp.WithBoolean("prepare", mcp.Description("Report actual managed Settings formatter requests without execution")),
		mcp.WithBoolean("formatStage", mcp.Description("Stage the current managed Settings formatter phase with exact approvals")),
		mcp.WithString("formatInput", mcp.Description("Path to closed formatter selection and approval transport")),
		mcp.WithString("decisionsInput", mcp.Description("Path to canonical typed managed decisions")),
		mcp.WithString("pairsInput", mcp.Description("Path to captured reanswer intent bound to the unchanged authenticated snapshot")),
		outputSchema(resultdto.OperationSettingsReanswer),
	), mcp.NewTypedToolHandler(func(ctx context.Context, request mcp.CallToolRequest, a nativeSettingsEditArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationSettingsReanswer, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		if a.Group == "" || strings.HasPrefix(strings.TrimSpace(a.Group), "-") || strings.Contains(a.Group, "=") {
			return s.argumentFailure(resultdto.OperationSettingsReanswer, "group"), nil
		}
		_, valuePresent := request.GetArguments()["value"]
		if (a.PairsInput != "") == valuePresent {
			return s.argumentFailure(resultdto.OperationSettingsReanswer, "value/pairsInput"), nil
		}
		argv := []string{"settings", "edit", a.Group, "--yes", "--dir", cwd}
		if a.PairsInput != "" {
			argv = append(argv, "--pairs-input", a.PairsInput)
		} else {
			argv = append(argv, "--value="+a.Value)
		}
		if a.ProjectContext != "" {
			argv = append(argv, "--project-context", a.ProjectContext)
		}
		if a.DryRun {
			argv = append(argv, "--dry-run")
		}
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
		return s.callStructured(ctx, resultdto.OperationSettingsReanswer, cwd, argv, longCall), nil
	}))
}
