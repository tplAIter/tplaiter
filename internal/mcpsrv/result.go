package mcpsrv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// maxSummaryLines bounds the compact text summary that accompanies every
// structured result, so that clients that only read text content spend a
// fixed, small number of tokens.
const maxSummaryLines = 12

// callStructured runs the CLI child for op with --json and returns its
// result/v1 envelope as structured content. Transport failures and broken
// child contracts are converted into server-side envelopes, so every call
// returns a document that satisfies the tool's outputSchema.
func (s *Server) callStructured(ctx context.Context, op resultdto.Operation, cwd string, argv []string, class timeoutClass) *mcp.CallToolResult {
	start := time.Now()
	res, runErr := s.runCLI(ctx, cwd, withJSONFlag(argv), s.timeout(class))
	duration := time.Since(start)
	if code := transportCode(res, runErr); code != "" {
		return s.transportFailure(op, code, duration)
	}
	env, err := decodeExpectedResult([]byte(res.Stdout), op, res.ExitCode)
	if err != nil {
		return s.contractFailure(op, res, runErr)
	}
	return structuredResult(env, failed(res, runErr))
}

// withJSONFlag adds --json to argv before a `--` separator (arguments after
// it belong to the child command, not to tplaiter).
func withJSONFlag(argv []string) []string {
	out := make([]string, 0, len(argv)+1)
	for i, arg := range argv {
		if arg == "--" {
			out = append(out, "--json")
			return append(out, argv[i:]...)
		}
		out = append(out, arg)
	}
	return append(out, "--json")
}

// decodeExpectedResult validates a child's stdout at the MCP boundary: it
// must be exactly one result/v1 envelope for the requested operation whose
// status agrees with the child's exit code.
func decodeExpectedResult(data []byte, expected resultdto.Operation, processExit int) (resultdto.Result, error) {
	result, err := resultdto.Decode(data)
	if err != nil {
		return resultdto.Result{}, err
	}
	wantKind, err := resultdto.KindForOperation(expected)
	if err != nil {
		return resultdto.Result{}, err
	}
	if result.Operation != expected || result.Kind != wantKind {
		return resultdto.Result{}, fmt.Errorf("result %s/%s does not match requested %s/%s", result.Kind, result.Operation, wantKind, expected)
	}
	code := resultdto.ExitCode(processExit)
	if !code.Valid() {
		return resultdto.Result{}, fmt.Errorf("child returned unregistered exit status %d", processExit)
	}
	if err := result.ValidateExit(code); err != nil {
		return resultdto.Result{}, err
	}
	return result, nil
}

// transportFailure is the envelope for a call that did not complete: the
// tool deadline expired (MCP_TIMEOUT), the client cancelled
// (MCP_CANCELLED), the child exceeded the output bound (MCP_OUTPUT_LIMIT) or
// could not be started (MCP_UNAVAILABLE). durationMs is the time from launch
// to the moment the child process group was gone.
func (s *Server) transportFailure(op resultdto.Operation, code string, duration time.Duration) *mcp.CallToolResult {
	env := resultdto.New(op, s.version)
	env.Status = resultdto.StatusFailed
	env.Diagnostics = []resultdto.Diagnostic{{
		Code: code, Severity: "error", Message: transportMessage(code),
		Details: map[string]any{"durationMs": duration.Milliseconds()},
	}}
	return structuredResult(env, true)
}

func transportMessage(code string) string {
	switch code {
	case "MCP_TIMEOUT":
		return "the tool deadline expired; the child process group was stopped"
	case "MCP_CANCELLED":
		return "the request was cancelled; the child process group was stopped"
	case "MCP_OUTPUT_LIMIT":
		return "the child exceeded the output limit and was stopped"
	default:
		return "the tplaiter child process is unavailable"
	}
}

// contractFailure is the envelope for a child that completed without a
// valid result/v1 envelope. Raw child output is never forwarded: only a
// whole, fixed trust diagnostic line is recognized (see knownCLIError).
func (s *Server) contractFailure(op resultdto.Operation, res execx.Result, runErr error) *mcp.CallToolResult {
	env := resultdto.New(op, s.version)
	env.Status = resultdto.StatusFailed
	code := "MCP_CONTRACT_INVALID"
	message := "the tplaiter child did not return a valid result/v1 envelope"
	if known := knownCLIError(res.Stderr); known != "" && failed(res, runErr) {
		code, message = known, "the operation was refused by the trust policy"
		env.Status = resultdto.StatusBlocked
	}
	env.Diagnostics = []resultdto.Diagnostic{{
		Code: code, Severity: "error", Message: message,
		Details: map[string]any{"childExitCode": res.ExitCode},
	}}
	return structuredResult(env, true)
}

// structuredResult returns env as structured content plus a compact text
// summary. Content that fails canonical encoding is a server bug and is
// reported as a plain tool error.
func structuredResult(env resultdto.Result, isError bool) *mcp.CallToolResult {
	raw, err := resultdto.MarshalCanonical(env)
	if err != nil {
		return mcp.NewToolResultError("MCP_CONTRACT_INVALID")
	}
	var structured map[string]any
	if err := json.Unmarshal(raw, &structured); err != nil {
		return mcp.NewToolResultError("MCP_CONTRACT_INVALID")
	}
	out := mcp.NewToolResultStructured(structured, compactSummary(env))
	out.IsError = isError
	return out
}

// compactSummary renders at most maxSummaryLines lines: the outcome, the
// counters, and the diagnostic codes. The full envelope is always in the
// structured content.
func compactSummary(env resultdto.Result) string {
	lines := []string{string(env.Operation) + ": " + string(env.Status)}
	if env.Project != nil {
		lines = append(lines, "project: "+env.Project.Root)
	}
	if n := len(env.Changes); n > 0 || env.Summary.FilesChanged > 0 || env.Summary.Conflicts > 0 {
		lines = append(lines, "changes: "+strconv.Itoa(n)+", files changed: "+strconv.Itoa(env.Summary.FilesChanged)+", conflicts: "+strconv.Itoa(env.Summary.Conflicts))
	}
	for i, d := range env.Diagnostics {
		if len(lines) >= maxSummaryLines-2 {
			lines = append(lines, "… "+strconv.Itoa(len(env.Diagnostics)-i)+" more diagnostic(s)")
			break
		}
		lines = append(lines, d.Severity+" "+d.Code+": "+d.Message)
	}
	if len(env.Data) > 0 && len(lines) < maxSummaryLines {
		lines = append(lines, "data: see structured content")
	}
	return strings.Join(lines, "\n")
}

// outputSchema returns the tool option declaring the result/v1 outputSchema
// of op. The schema is generated from the resultdto registry and the Go
// data type registered for op in dataSchemas.
func outputSchema(op resultdto.Operation) mcp.ToolOption {
	raw, err := toolOutputSchema(op)
	if err != nil {
		// A missing schema is caught by TestEveryToolHasOutputSchema; at run
		// time the tool is still registered with the generic envelope.
		raw, _ = resultdto.OperationSchema(op, nil)
	}
	return mcp.WithRawOutputSchema(raw)
}

func toolOutputSchema(op resultdto.Operation) (json.RawMessage, error) {
	data, ok := dataSchemas[op]
	if !ok {
		return nil, fmt.Errorf("no data schema registered for %q", op)
	}
	dataSchema, err := data()
	if err != nil {
		return nil, err
	}
	return resultdto.OperationSchema(op, dataSchema)
}

// dataSchemas maps each operation behind an MCP tool to the JSON schema of
// its data payload, derived from the resultdto data types.
var dataSchemas = map[resultdto.Operation]func() (json.RawMessage, error){
	resultdto.OperationProjectVerify:       schemaOf[resultdto.ProjectVerifyData],
	resultdto.OperationProjectCheck:        schemaOf[resultdto.ProjectCheckData],
	resultdto.OperationDepsVerify:          schemaOf[resultdto.DepsVerifyData],
	resultdto.OperationRepoAdd:             schemaOf[resultdto.RepoListData],
	resultdto.OperationRepoList:            schemaOf[resultdto.RepoListData],
	resultdto.OperationRepoUpdate:          schemaOf[resultdto.RepoListData],
	resultdto.OperationRepoRemove:          schemaOf[resultdto.RepoRemoveData],
	resultdto.OperationTemplateList:        schemaOf[resultdto.TemplateListData],
	resultdto.OperationTemplateShow:        schemaOf[resultdto.TemplateShowData],
	resultdto.OperationTemplateLint:        schemaOf[resultdto.TemplateLintData],
	resultdto.OperationTemplateInit:        schemaOf[resultdto.TemplateInitData],
	resultdto.OperationTrustInspect:        schemaOf[resultdto.TrustInspectData],
	resultdto.OperationProjectsList:        schemaOf[resultdto.ProjectsListData],
	resultdto.OperationProjectStats:        schemaOf[resultdto.ProjectStatsData],
	resultdto.OperationProjectRun:          schemaOf[resultdto.ProjectRunData],
	resultdto.OperationDoctorCheck:         schemaOf[resultdto.DoctorData],
	resultdto.OperationAIGen:               schemaOf[resultdto.AIGenData],
	resultdto.OperationGenRun:              schemaOf[resultdto.GenRunData],
	resultdto.OperationGenBatch:            schemaOf[resultdto.GenRunData],
	resultdto.OperationGenList:             schemaOf[resultdto.GenListData],
	resultdto.OperationWorkspaceAddService: schemaOf[resultdto.WorkspaceAddServiceData],
	resultdto.OperationEnvSetup:            schemaOf[resultdto.EnvSetupData],
	resultdto.OperationProjectNew:          schemaOf[resultdto.ProjectNewData],
	resultdto.OperationUpdatePlan:          schemaOf[resultdto.UpdateData],
	resultdto.OperationUpdateApply:         schemaOf[resultdto.UpdateData],
	resultdto.OperationUpdateCheck:         schemaOf[resultdto.UpdateData],
	resultdto.OperationSettingsShow:        schemaOf[resultdto.SettingsShowData],
	resultdto.OperationSettingsSet:         schemaOf[resultdto.SettingsSetData],
}

// schemaOf derives the JSON schema of T with the same generator mcp-go uses
// for typed output schemas.
func schemaOf[T any]() (json.RawMessage, error) {
	var tool mcp.Tool
	mcp.WithOutputSchema[T]()(&tool)
	if tool.OutputSchema.Type == "" {
		return nil, errors.New("schema generation failed")
	}
	return json.Marshal(tool.OutputSchema)
}

// updateOperation maps update tool flags to the operation the CLI reports.
func updateOperation(dryRun, check bool) resultdto.Operation {
	switch {
	case check:
		return resultdto.OperationUpdateCheck
	case dryRun:
		return resultdto.OperationUpdatePlan
	default:
		return resultdto.OperationUpdateApply
	}
}

// argumentFailure is the envelope for a call rejected before any child
// process starts because an argument is unusable (for example a directory
// that does not exist).
func (s *Server) argumentFailure(op resultdto.Operation, argument string) *mcp.CallToolResult {
	env := resultdto.New(op, s.version)
	env.Status = resultdto.StatusFailed
	env.Diagnostics = []resultdto.Diagnostic{{
		Code: "MCP_INVALID_ARGUMENT", Severity: "error", Message: "the tool argument is invalid",
		Details: map[string]any{"argument": argument},
	}}
	return structuredResult(env, true)
}

// callTrustInspect adapts `trust inspect --json`, which prints the bare
// trust-profile binding, into a trust.inspect envelope. The command itself
// belongs to the trust work package and keeps its established output.
func (s *Server) callTrustInspect(ctx context.Context) *mcp.CallToolResult {
	op := resultdto.OperationTrustInspect
	start := time.Now()
	res, runErr := s.runCLI(ctx, "", argvTrustInspect(), s.timeout(shortCall))
	if code := transportCode(res, runErr); code != "" {
		return s.transportFailure(op, code, time.Since(start))
	}
	if failed(res, runErr) {
		return s.contractFailure(op, res, runErr)
	}
	var binding map[string]any
	if err := json.Unmarshal([]byte(res.Stdout), &binding); err != nil || binding == nil {
		return s.contractFailure(op, res, runErr)
	}
	env := resultdto.New(op, s.version)
	if err := env.SetData(resultdto.TrustInspectData{Binding: binding}); err != nil {
		return s.contractFailure(op, res, runErr)
	}
	return structuredResult(env, false)
}

// updateOperations are the operations the `update` tool can report.
var updateOperations = []resultdto.Operation{resultdto.OperationUpdateApply, resultdto.OperationUpdateCheck, resultdto.OperationUpdatePlan}

// updateOutputSchema is the outputSchema of the `update` tool: the union of
// update.plan, update.apply and update.check with the shared update data.
func updateOutputSchema() json.RawMessage {
	data, err := schemaOf[resultdto.UpdateData]()
	if err == nil {
		if raw, err := resultdto.OperationsSchema(updateOperations, data); err == nil {
			return raw
		}
	}
	raw, _ := resultdto.OperationsSchema(updateOperations, nil)
	return raw
}

// workDir resolves an existing directory argument. On failure it returns the
// MCP_INVALID_ARGUMENT envelope for op instead of a directory.
func (s *Server) workDir(op resultdto.Operation, argument, dir string) (string, *mcp.CallToolResult) {
	abs, err := resolveWorkDir(dir)
	if err != nil {
		return "", s.argumentFailure(op, argument)
	}
	return abs, nil
}

// targetDir resolves a directory argument that may not exist yet (its parent
// must). On failure it returns the MCP_INVALID_ARGUMENT envelope for op.
func (s *Server) targetDir(op resultdto.Operation, argument, dir string) (string, *mcp.CallToolResult) {
	abs, err := resolveTargetDir(dir)
	if err != nil {
		return "", s.argumentFailure(op, argument)
	}
	return abs, nil
}
