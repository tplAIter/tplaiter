package mcpsrv

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func init() {
	toolRegistrars = append(toolRegistrars, (*Server).addLinkTools)
	dataSchemas[resultdto.OperationProjectLink] = schemaOf[resultdto.ProjectLinkData]
	dataSchemas[resultdto.OperationProjectAdopt] = schemaOf[resultdto.ProjectLinkData]
}

type linkToolArgs struct {
	Action         string            `json:"action"`
	Dir            string            `json:"dir"`
	ProjectContext string            `json:"projectContext,omitempty"`
	Ref            string            `json:"ref"`
	Name           string            `json:"name"`
	SourceInput    string            `json:"sourceInput"`
	Module         string            `json:"module,omitempty"`
	Ownership      map[string]string `json:"ownership,omitempty"`
	DryRun         bool              `json:"dryRun,omitempty"`
}

func (s *Server) addLinkTools() {
	data, _ := schemaOf[resultdto.ProjectLinkData]()
	output, _ := resultdto.OperationsSchema([]resultdto.Operation{resultdto.OperationProjectLink, resultdto.OperationProjectAdopt}, data)
	s.mcp.AddTool(mcp.NewTool("project_link",
		mcp.WithDescription("Link/adopt signed state only; preserves user files. Conflicts require explicit ownership path=track or path=user-owned. User-owned adoption preserves full signed baseline lineage and excludes those paths from Update writes. Cold recovery uses qualified CLI commands."),
		mcp.WithString("action", mcp.Required(), mcp.Enum("link", "adopt")), mcp.WithString("dir", mcp.Required()), mcp.WithString("projectContext"), mcp.WithString("ref", mcp.Required()), mcp.WithString("name", mcp.Required()), mcp.WithString("sourceInput", mcp.Required()), mcp.WithString("module"), mcp.WithObject("ownership"), mcp.WithBoolean("dryRun", mcp.DefaultBool(false)),
		mcp.WithReadOnlyHintAnnotation(false), mcp.WithDestructiveHintAnnotation(false), mcp.WithIdempotentHintAnnotation(false), mcp.WithOpenWorldHintAnnotation(false), mcp.WithRawOutputSchema(output),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		raw, err := json.Marshal(request.GetArguments())
		var a linkToolArgs
		op := resultdto.OperationProjectLink
		if err != nil || len(raw) > 16384 || canonicaljson.DecodeStrict(raw, &a) != nil {
			return s.argumentFailure(op, "arguments"), nil
		}
		if a.Action == "adopt" {
			op = resultdto.OperationProjectAdopt
		} else if a.Action != "link" {
			return s.argumentFailure(op, "action"), nil
		}
		if a.Ref == "" || a.Name == "" || a.SourceInput == "" || a.Dir == "" {
			return s.argumentFailure(op, "arguments"), nil
		}
		cwd, fail := s.workDir(op, "dir", a.Dir)
		if fail != nil {
			return fail, nil
		}
		argv := []string{a.Action, a.Ref, a.Name, "--dir=" + cwd, "--source-input=" + a.SourceInput}
		if a.ProjectContext != "" {
			argv = append(argv, "--project-context="+a.ProjectContext)
		}
		if a.Module != "" {
			argv = append(argv, "--module="+a.Module)
		}
		if a.DryRun {
			argv = append(argv, "--dry-run")
		}
		names := make([]string, 0, len(a.Ownership))
		for name := range a.Ownership {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if a.Ownership[name] != "track" && a.Ownership[name] != "user-owned" {
				return s.argumentFailure(op, "ownership"), nil
			}
			argv = append(argv, "--ownership="+name+"="+a.Ownership[name])
		}
		return s.callStructured(ctx, op, cwd, argv, longCall), nil
	})
}
