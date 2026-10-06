package mcpsrv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
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
	res, capture, runErr := s.runCapturedCLI(ctx, cwd, withJSONFlag(argv), s.timeout(class))
	duration := time.Since(start)
	if code := transportCode(res, runErr); code != "" {
		if env, ok := s.knownActionFrame(capture, op); ok {
			return retainedActionFailure(env, res, code)
		}
		return s.transportFailure(op, code, duration)
	}
	env, err := decodeExpectedResult([]byte(res.Stdout), op, res.ExitCode)
	if err == nil && op == resultdto.OperationProjectRunBatch && len(env.Data) > 0 {
		_, err = decodeClosedBatchData(env.Data)
	}
	if err != nil {
		if retained, ok := s.knownActionFrame(capture, op); ok {
			return retainedActionFailure(retained, res, "MCP_CONTRACT_INVALID")
		}
		return s.contractFailure(op, res, runErr)
	}
	var fields map[string]json.RawMessage
	if op == resultdto.OperationProjectRun && json.Unmarshal(env.Data, &fields) == nil && fields["actionReceipt"] != nil {
		retained, ok := s.knownActionFrame(capture, op)
		if !ok {
			return s.contractFailure(op, res, runErr)
		}
		return structuredResult(retained, failed(res, runErr))
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
	return resultwire.Structured(env, isError)
}
func compactSummary(env resultdto.Result) string { return resultwire.Summary(env) }

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
	resultdto.OperationProjectDiff:         schemaOf[resultdto.ProjectDiffData],
	resultdto.OperationProjectVerify:       schemaOf[resultdto.ProjectVerifyData],
	resultdto.OperationProjectCheck:        schemaOf[resultdto.ProjectCheckData],
	resultdto.OperationDepsVerify:          schemaOf[resultdto.DepsVerifyData],
	resultdto.OperationRepoAdd:             schemaOf[resultdto.RepoListData],
	resultdto.OperationRepoList:            schemaOf[resultdto.RepoListData],
	resultdto.OperationRepoUpdate:          schemaOf[resultdto.RepoListData],
	resultdto.OperationRepoRemove:          schemaOf[resultdto.RepoRemoveData],
	resultdto.OperationTemplateList:        schemaOf[resultdto.TemplateListData],
	resultdto.OperationTemplateDiscover:    discoveryDataSchema,
	resultdto.OperationTemplateShow:        schemaOf[resultdto.TemplateShowData],
	resultdto.OperationTemplateLint:        schemaOf[resultdto.TemplateLintData],
	resultdto.OperationTemplateInit:        schemaOf[resultdto.TemplateInitData],
	resultdto.OperationTrustInspect:        schemaOf[resultdto.TrustInspectData],
	resultdto.OperationProjectsList:        schemaOf[resultdto.ProjectsListData],
	resultdto.OperationProjectStats:        schemaOf[resultdto.ProjectStatsData],
	resultdto.OperationProjectRun:          actionRunDataSchema,
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

// knownActionFrame recognizes only complete canonical factual output of this
// actual installed held-image capture. It is not authority for another action.
func (s *Server) knownActionFrame(c *actionCapture, op resultdto.Operation) (resultdto.Result, bool) {
	fail := func() (resultdto.Result, bool) { return resultdto.Result{}, false }
	if c == nil || s == nil || c.owner != s || !s.installed || c.stage == nil || c.stage != s.stage || !c.complete || op != resultdto.OperationProjectRun {
		return fail()
	}
	raw := []byte(c.result.Stdout)
	if len(raw) == 0 || len(raw) > execx.MaxActionFrame || raw[len(raw)-1] != '\n' {
		return fail()
	}
	raw = raw[:len(raw)-1]
	// Preserve result/v1 canonical struct order; canonicaljson is used here
	// only for strict syntax/duplicate checks. Exact bytes are checked below
	// with the real resultdto canonical encoder.
	_, e := canonicaljson.Canonicalize(raw)
	if e != nil {
		return fail()
	}
	env, e := resultdto.Decode(raw)
	if e != nil || env.Operation != op || env.Kind != "ProjectRun" {
		return fail()
	}
	var data resultdto.ProjectRunData
	if decodeClosedActionData(env.Data, &data) != nil || data.ActionReceipt == nil || data.PreparedRequest != nil || data.ProcessReceipt != nil || data.ActionTransport != nil || data.Command == "" || data.Commands != nil || execx.ValidateActionProcessResult(*data.ActionReceipt) != nil {
		return fail()
	}
	if data.ActionReceipt.ChildExitCode != nil && data.ChildExitCode != *data.ActionReceipt.ChildExitCode || data.ActionReceipt.ChildExitCode == nil && data.ChildExitCode != 0 {
		return fail()
	}
	typed := env
	if typed.SetData(data) != nil {
		return fail()
	}
	roundtrip, e := resultdto.MarshalCanonical(typed)
	if e != nil || !bytes.Equal(roundtrip, raw) {
		return fail()
	}
	return env, true
}

func retainedActionFailure(env resultdto.Result, res execx.Result, code string) *mcp.CallToolResult {
	var data resultdto.ProjectRunData
	if decodeClosedActionData(env.Data, &data) != nil {
		return structuredResult(env, true)
	}
	outer := res.ExitCode
	data.ActionTransport = &resultdto.ActionTransport{StopReason: code, OuterExitCode: &outer, FrameComplete: true}
	_ = env.SetData(data)
	env.Status = resultdto.StatusFailed
	env.Diagnostics = append(env.Diagnostics, resultdto.Diagnostic{Code: code, Severity: "error", Message: "action facts retained after delivery failure", Details: map[string]any{}})
	return structuredResult(env, true)
}

// canonicaljson's generic shape checker treats []byte as arrays, while the
// existing JSON wire uses base64 strings. Keep strict syntax/null/duplicate
// parsing and close this local typed body with encoding/json. Exact casing,
// required presence and base64 spelling are checked by the final v1 re-encode.
func decodeClosedActionData(raw []byte, data *resultdto.ProjectRunData) error {
	var parsed map[string]json.RawMessage
	if len(raw) > execx.MaxActionFrame || canonicaljson.DecodeStrict(raw, &parsed) != nil || parsed == nil {
		return errors.New("MCP_ACTION_FRAME_INVALID")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(data)
}

// encoding/json serializes []byte as base64 strings, including the retained
// action receipt. Correct only those fields; legacy process-receipt fields
// and every other operation keep the generator's existing wire.
func actionRunDataSchema() (json.RawMessage, error) {
	raw, e := schemaOf[resultdto.ProjectRunData]()
	if e != nil {
		return nil, e
	}
	var schema map[string]any
	if json.Unmarshal(raw, &schema) != nil {
		return nil, errors.New("action data schema unavailable")
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil, errors.New("action data properties unavailable")
	}
	receipt, ok := properties["actionReceipt"].(map[string]any)
	if !ok {
		return nil, errors.New("action receipt schema unavailable")
	}
	fields, ok := receipt["properties"].(map[string]any)
	if !ok {
		return nil, errors.New("action receipt properties unavailable")
	}
	for name, limit := range map[string]int{"stdout": 4 * ((128<<10 + 2) / 3), "stderr": 4 * ((16<<10 + 2) / 3)} {
		if _, ok := fields[name]; !ok {
			return nil, errors.New("action output schema unavailable")
		}
		fields[name] = map[string]any{"type": []string{"string", "null"}, "contentEncoding": "base64", "maxLength": limit}
	}
	return json.Marshal(schema)
}

// discoveryDataSchema closes the neutral descriptive wire, including the two
// existing read-only transports. Schema strings cannot confer admission.
func discoveryDataSchema() (json.RawMessage, error) {
	raw, err := schemaOf[resultdto.TemplateDiscoverData]()
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err = json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	kinds := []any{"template", "installable-block", "context", "documentation-recipe", "test-fixture", "skill", "unknown"}
	readiness := []any{"ready", "experimental", "planned", "deprecated", "unknown"}
	digest := map[string]any{"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
	str := func(max int) map[string]any { return map[string]any{"type": "string", "maxLength": max} }
	object := func(props map[string]any, required []string) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": required}
	}
	call := func(tool string, args map[string]any, required []string) map[string]any {
		return object(map[string]any{"tool": map[string]any{"const": tool}, "arguments": object(args, required)}, []string{"tool", "arguments"})
	}
	show := call("template_show", map[string]any{"ref": str(257), "commit": map[string]any{"type": "string", "pattern": "^[0-9a-f]{40}$"}, "manifestSHA256": digest}, []string{"ref", "commit", "manifestSHA256"})
	graph := call("graph_exports", map[string]any{"dir": str(4096), "projectContext": str(256), "sourceInput": str(4096), "expectedDigest": map[string]any{"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"}, "selectors": map[string]any{"type": "array", "minItems": 1, "maxItems": 1, "items": str(512)}, "limit": map[string]any{"const": 1}, "maxBytes": map[string]any{"const": 4096}, "representation": map[string]any{"const": "page"}}, []string{"dir", "projectContext", "sourceInput", "expectedDigest", "selectors", "limit", "maxBytes", "representation"})
	var walk func(map[string]any)
	walk = func(n map[string]any) {
		if types, ok := n["type"].([]any); ok {
			for _, v := range types {
				if v == "array" {
					n["type"] = "array"
				}
			}
		}
		if items, ok := n["items"].(map[string]any); ok {
			walk(items)
		}
		props, _ := n["properties"].(map[string]any)
		for key, value := range props {
			child, ok := value.(map[string]any)
			if !ok {
				continue
			}
			walk(child)
			switch key {
			case "description":
				child["maxLength"] = 512
			case "candidateKind":
				child["enum"] = kinds
			case "readiness":
				child["enum"] = readiness
			case "declarationStatus":
				child["const"] = "metadata-declared"
			case "availability":
				child["enum"] = []any{"metadata-declared", "admitted-record", "unavailable"}
			case "domain":
				child["enum"] = []any{"block", "skill", "approach"}
			case "metadataSHA256", "manifestSHA256", "contentSHA256", "contractSHA256", "catalogSource", "sha256":
				child["pattern"] = "^sha256:[0-9a-f]{64}$"
			case "commit":
				child["pattern"] = "^[0-9a-f]{40}$"
			case "sourcePin":
				child["oneOf"] = []any{map[string]any{"properties": map[string]any{"qualification": map[string]any{"const": "local-observed"}}, "required": []string{"repo", "path", "commit", "manifestSHA256"}, "not": map[string]any{"anyOf": []any{map[string]any{"required": []string{"sourceID"}}, map[string]any{"required": []string{"revision"}}, map[string]any{"required": []string{"contentSHA256"}}}}}, map[string]any{"properties": map[string]any{"qualification": map[string]any{"const": "owner-supplied"}}, "required": []string{"sourceID", "revision", "contentSHA256"}}}
			case "status":
				child["enum"] = []any{"not-requested", "empty", "observed", "unavailable"}
			case "suggestions":
				child["maxItems"] = 20
			case "diagnostics", "blocks", "skills":
				child["maxItems"] = 32
			case "reasons":
				child["maxItems"] = 16
			case "frameworks":
				child["maxItems"] = 8
			case "evidence":
				child["maxItems"] = 3
			case "nextToolCalls":
				child["maxItems"] = 4
				child["items"] = map[string]any{"oneOf": []any{show, graph}}
			}
		}
	}
	walk(root)
	props := root["properties"].(map[string]any)
	props["apiVersion"].(map[string]any)["const"] = "tplaiter.dev/template-discovery/v1"
	props["qualification"].(map[string]any)["const"] = "descriptive-data-only"
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["$id"] = "https://tplaiter.dev/schema/template-discovery.v1.schema.json"
	root["description"] = "Bounded descriptive data only. Source pins and metadata do not grant authority. JSON Schema lengths count characters; the implementation separately enforces UTF8 byte bounds."
	return json.Marshal(root)
}
