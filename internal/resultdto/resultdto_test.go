package resultdto

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validResult() Result {
	r := New(OperationUpdatePlan, "v0.1.0-preview.1")
	// The result must identify its project: update.plan is project scoped.
	r.Project = &Project{ID: "p", Root: "/work/p"}
	r.Changes = []Change{{Path: "z.go", Action: "merge"}, {Path: "a.go", Action: "create"}}
	r.Diagnostics = []Diagnostic{{Code: "TPL-W-TEST-001", Severity: "warning", Message: "warn", Details: map[string]any{}}, {Code: "TPL-E-TEST-001", Severity: "error", Message: "err", Path: "internal/a.go", Details: map[string]any{"x": 1}}}
	r.Artifacts = []Artifact{{Name: "z", Path: "z.json", SHA256: testDigest}, {Name: "a", Path: "a.json", SHA256: testDigest}}
	return r
}

func TestCanonicalSortsAndNormalizes(t *testing.T) {
	r := validResult()
	r.Diagnostics[0].Details = nil
	b, err := MarshalCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"details":{}`) {
		t.Fatalf("details not normalized: %s", b)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Changes[0].Path != "a.go" || got.Diagnostics[0].Code != "TPL-E-TEST-001" || got.Artifacts[0].Path != "a.json" {
		t.Fatalf("not canonical: %#v", got)
	}
}

func TestCanonicalDataBytesAreDeterministic(t *testing.T) {
	a, b := validResult(), validResult()
	a.Data = json.RawMessage(`{"z": 1, "a": {"y": [1, 2], "b": "x"}}`)
	b.Data = json.RawMessage(`{"a":{"b":"x","y":[1,2]},"z":1}`)
	left, err := MarshalCanonical(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := MarshalCanonical(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("data canonical bytes differ\n%s\n%s", left, right)
	}
	a.Data = json.RawMessage(`[1]`)
	if _, err := MarshalCanonical(a); err == nil {
		t.Fatal("non-object data accepted")
	}
	a.Data = json.RawMessage(`{"a":1,"a":2}`)
	if _, err := MarshalCanonical(a); err == nil {
		t.Fatal("duplicate data key accepted")
	}
}

func TestDecodeRejectsUnknownMajorAndSchema(t *testing.T) {
	b, err := MarshalCanonical(validResult())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(string) string{
		func(s string) string { return strings.Replace(s, APIVersion, "tplaiter.dev/result/v2", 1) },
		func(s string) string { return strings.Replace(s, `"schemaVersion":1`, `"schemaVersion":2`, 1) },
	} {
		if _, err := Decode([]byte(mutate(string(b)))); err == nil {
			t.Errorf("accepted %s", mutate(string(b)))
		}
	}
}

func TestDecodeAcceptsAdditiveFields(t *testing.T) {
	b, err := MarshalCanonical(validResult())
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.TrimSuffix(string(b), "}") + `,"future":true}`)
	if _, err := Decode(b); err != nil {
		t.Fatal(err)
	}
}

func TestGoldenRoundTripIsCanonicalAndSchemaValid(t *testing.T) {
	for _, name := range []string{"result.v1.golden.json", "repo.list.golden.json"} {
		t.Run(name, func(t *testing.T) {
			golden, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(golden)
			if err != nil {
				t.Fatalf("Decode golden: %v", err)
			}
			got, err := MarshalCanonical(decoded)
			if err != nil {
				t.Fatalf("MarshalCanonical golden: %v", err)
			}
			var want bytes.Buffer
			if err := json.Compact(&want, golden); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want.Bytes()) {
				t.Fatalf("canonical golden mismatch\n got: %s\nwant: %s", got, want.Bytes())
			}
			if err := resultSchema(t).Validate(decodeJSON(t, got)); err != nil {
				t.Fatalf("golden violates result schema: %v", err)
			}
		})
	}
}

func TestSchemaFileMatchesGenerator(t *testing.T) {
	want, err := GenerateSchema()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; regenerate with: go run ./internal/resultdto/internal/genschema > schema/result.v1.schema.json", schemaPath)
	}
}

func TestDecodeAndSchemaAgreeOnSharedV1Rules(t *testing.T) {
	valid, err := MarshalCanonical(validResult())
	if err != nil {
		t.Fatal(err)
	}
	global := New(OperationRepoList, "v0.1.0-preview.1")
	globalRaw, err := MarshalCanonical(global)
	if err != nil {
		t.Fatal(err)
	}
	blocked := New(OperationSettingsSet, "v0.1.0-preview.1")
	blocked.Status = StatusBlocked
	blockedRaw, err := MarshalCanonical(blocked)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		json string
		ok   bool
	}{
		{name: "valid", json: string(valid), ok: true},
		{name: "additive field", json: strings.TrimSuffix(string(valid), "}") + `,"future":{"v":1}}`, ok: true},
		{name: "global without project", json: string(globalRaw), ok: true},
		{name: "blocked project operation without project", json: string(blockedRaw), ok: true},
		{name: "global with project", json: strings.Replace(string(globalRaw), `"project":null`, `"project":{"id":"p","root":"/p"}`, 1), ok: false},
		{name: "successful project operation without project", json: strings.Replace(string(valid), `"project":{"id":"p","root":"/work/p"}`, `"project":null`, 1), ok: false},
		{name: "missing project key", json: strings.Replace(string(globalRaw), `"project":null,`, ``, 1), ok: false},
		{name: "missing required", json: strings.Replace(string(valid), `,"artifacts":[`, `,"ignoredArtifacts":[`, 1), ok: false},
		{name: "null array", json: strings.Replace(string(valid), `"changes":[`, `"changes":null,"ignoredChanges":[`, 1), ok: false},
		{name: "unknown status", json: strings.Replace(string(valid), `"status":"ok"`, `"status":"future"`, 1), ok: false},
		{name: "unknown operation", json: strings.Replace(string(valid), `"operation":"update.plan"`, `"operation":"future.operation"`, 1), ok: false},
		{name: "kind operation mismatch", json: strings.Replace(string(valid), `"kind":"UpdatePlan"`, `"kind":"ProjectNew"`, 1), ok: false},
		{name: "negative summary", json: strings.Replace(string(valid), `"filesChanged":0`, `"filesChanged":-1`, 1), ok: false},
		{name: "unknown severity", json: strings.Replace(string(valid), `"severity":"error"`, `"severity":"fatal"`, 1), ok: false},
		{name: "unsafe block id", json: strings.Replace(string(valid), `"action":"create"`, `"blockId":"../bad","action":"create"`, 1), ok: false},
		{name: "null optional block id", json: strings.Replace(string(valid), `"action":"create"`, `"blockId":null,"action":"create"`, 1), ok: false},
		{name: "null optional diagnostic path", json: strings.Replace(string(valid), `"details":{"x":1}`, `"path":null,"details":{"x":1}`, 1), ok: false},
		{name: "unsafe change path", json: strings.Replace(string(valid), `"path":"a.go"`, `"path":"../a.go"`, 1), ok: false},
		{name: "relative project root", json: strings.Replace(string(valid), `"root":"/work/p"`, `"root":"work/p"`, 1), ok: false},
		{name: "invalid digest", json: strings.Replace(string(valid), testDigest, `sha256:bad`, 1), ok: false},
		{name: "non-object data", json: strings.TrimSuffix(string(valid), "}") + `,"data":[1]}`, ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, decodeErr := Decode([]byte(tc.json))
			schemaErr := resultSchema(t).Validate(decodeJSON(t, []byte(tc.json)))
			if got := decodeErr == nil; got != tc.ok {
				t.Fatalf("Decode accepted=%v, want %v: %v", got, tc.ok, decodeErr)
			}
			if got := schemaErr == nil; got != tc.ok {
				t.Fatalf("schema accepted=%v, want %v: %v", got, tc.ok, schemaErr)
			}
		})
	}
}

func TestOperationSchemaPinsOperationKindAndData(t *testing.T) {
	dataSchema := json.RawMessage(`{"type":"object","required":["repositories"],"properties":{"repositories":{"type":"array"}}}`)
	for _, op := range Operations() {
		raw, err := OperationSchema(op, dataSchema)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		schema := compileSchema(t, raw)
		r := New(op, "v0.1.0-preview.1")
		if scope, _ := ScopeForOperation(op); scope == ScopeProject {
			r.Project = &Project{ID: "p", Root: "/work/p"}
		}
		if err := r.SetData(map[string]any{"repositories": []any{}}); err != nil {
			t.Fatal(err)
		}
		b, err := MarshalCanonical(r)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if err := schema.Validate(decodeJSON(t, b)); err != nil {
			t.Fatalf("%s: own envelope rejected: %v", op, err)
		}
		other := Operation("repo.list")
		if op == other {
			other = "repo.add"
		}
		wrong := strings.Replace(string(b), `"operation":"`+string(op)+`"`, `"operation":"`+string(other)+`"`, 1)
		if err := schema.Validate(decodeJSON(t, []byte(wrong))); err == nil {
			t.Fatalf("%s: schema accepted operation %s", op, other)
		}
		missingData := strings.Replace(string(b), `"data":{"repositories":[]}`, `"data":{}`, 1)
		if err := schema.Validate(decodeJSON(t, []byte(missingData))); err == nil {
			t.Fatalf("%s: schema accepted data without required fields", op)
		}
	}
	if _, err := OperationSchema("future.op", nil); err == nil {
		t.Fatal("unknown operation schema generated")
	}
}

func TestDecodeRejectsOmittedNullAndDuplicateWireFields(t *testing.T) {
	valid, err := MarshalCanonical(validResult())
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		strings.Replace(string(valid), `"details":{}`, `"details":null`, 1),
		strings.Replace(string(valid), `"transactionId":null,`, "", 1),
		strings.Replace(string(valid), `"apiVersion":"`+APIVersion+`"`, `"apiVersion":"`+APIVersion+`","apiVersion":"`+APIVersion+`"`, 1),
		strings.TrimSuffix(string(valid), "}") + `,"data":null}`,
		string(valid) + `{}`,
	} {
		if _, err := Decode([]byte(data)); err == nil {
			t.Fatalf("Decode accepted invalid wire result: %s", data)
		}
	}
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	if _, err := Decode([]byte(strings.TrimSuffix(string(valid), "}") + `,"future":` + deep + `}`)); err == nil {
		t.Fatal("Decode accepted unbounded nesting")
	}
}

func TestRelativePaths(t *testing.T) {
	r := validResult()
	for _, p := range []string{"/etc/passwd", "../outside", "a\\b", "", "a/../b", "a//b", "./a"} {
		r.Changes[0].Path = p
		if err := r.Validate(); err == nil {
			t.Errorf("accepted path %q", p)
		}
	}
}

func TestBlockIDAndAbsoluteProjectRootSafety(t *testing.T) {
	r := validResult()
	for _, blockID := range []string{"../block", "a/b", strings.Repeat("a", 129)} {
		r.Changes[0].BlockID = blockID
		if err := r.Validate(); err == nil {
			t.Errorf("accepted unsafe block id %q", blockID)
		}
	}
	for _, root := range []string{"", "relative", `C:relative`, `\server`} {
		r = validResult()
		r.Project.Root = root
		if err := r.Validate(); err == nil {
			t.Errorf("accepted non-absolute root %q", root)
		}
	}
	r = validResult()
	r.Project.ID = ""
	if err := r.Validate(); err == nil {
		t.Error("accepted a project without project.id")
	}
}

func TestCanonicalDeepCopiesDetailsAndFullyOrdersDiagnostics(t *testing.T) {
	r := validResult()
	r.Diagnostics = []Diagnostic{
		{Code: "TPL-E-TEST-001", Severity: "error", Message: "same", Details: map[string]any{"z": 1}},
		{Code: "TPL-E-TEST-001", Severity: "error", Message: "same", Details: map[string]any{"a": 1}},
	}
	canonical := r.Canonical()
	canonical.Diagnostics[0].Details["nested"] = map[string]any{"mutated": true}
	canonical.Project.ID = "mutated"
	if _, found := r.Diagnostics[1].Details["nested"]; found {
		t.Fatal("Canonical mutated caller-owned details")
	}
	if r.Project.ID != "p" {
		t.Fatal("Canonical shared the caller-owned project")
	}
	if canonical.Diagnostics[0].Details["a"] == nil {
		t.Fatalf("diagnostics were not deterministically ordered: %#v", canonical.Diagnostics)
	}
}

type typedErr struct{}

func (typedErr) Error() string      { return "anything" }
func (typedErr) ExitCode() ExitCode { return ExitTrust }

func TestClassifyUsesTypedError(t *testing.T) {
	if got := Classify(typedErr{}); got != ExitTrust {
		t.Fatalf("got %d", got)
	}
	if got := Classify(errors.New("trust denied")); got != ExitInternal {
		t.Fatalf("string matched: %d", got)
	}
	if got := Classify(nil); got != ExitSuccess {
		t.Fatalf("nil: %d", got)
	}
	if got := Classify(fmtWrap(typedErr{})); got != ExitTrust {
		t.Fatalf("wrapped typed error: %d", got)
	}
	for input, want := range map[int]int{0: 0, 1: 10, 8: 10, 10: 10, 42: 42, 130: 130} {
		if got := ClassifyChildExit(input); got != want {
			t.Errorf("ClassifyChildExit(%d)=%d, want %d", input, got, want)
		}
	}
}

func TestDiagnosticProjectionFlattensWrappedAndJoinedTypedErrors(t *testing.T) {
	first := NewDiagnosticError(Diagnostic{Code: "TPL-E-Z", Severity: "error", Message: "z", Details: map[string]any{}}, ExitTrust, errors.New("opaque"))
	second := NewDiagnosticError(Diagnostic{Code: "TPL-E-A", Severity: "error", Message: "a", Details: map[string]any{}}, ExitConflict, nil)
	got := ProjectDiagnostics(errors.Join(fmtWrap(first), second, errors.New("unstructured text")))
	if len(got) != 2 || got[0].Code != "TPL-E-A" || got[1].Code != "TPL-E-Z" {
		t.Fatalf("diagnostics=%#v", got)
	}
	if code := Classify(errors.Join(first, second)); code != ExitTrust {
		t.Fatalf("exit=%d, want trust precedence", code)
	}
}

func TestLifecycleErrorDiagnosticDoesNotLeakWrappedText(t *testing.T) {
	secret := "password=do-not-project"
	err := NewError("TPL-E-TRUST-001", ExitTrust, errors.New(secret))
	diagnostics := ProjectDiagnostics(err)
	if len(diagnostics) != 1 || diagnostics[0].Code != "TPL-E-TRUST-001" {
		t.Fatalf("diagnostics=%#v", diagnostics)
	}
	encoded, marshalErr := json.Marshal(diagnostics)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("wrapped secret leaked into diagnostics: %s", encoded)
	}
}

func TestOperationKindRegistryAndStatusExitMatrix(t *testing.T) {
	kinds := map[string]Operation{}
	for _, operation := range Operations() {
		kind, err := KindForOperation(operation)
		if err != nil || kind == "" {
			t.Fatalf("registry %s: %v", operation, err)
		}
		if previous, dup := kinds[kind]; dup {
			t.Fatalf("kind %s registered for both %s and %s", kind, previous, operation)
		}
		kinds[kind] = operation
		if err := ValidateOperationKind(operation, kind); err != nil {
			t.Fatal(err)
		}
		if err := ValidateOperationKind(operation, "wrong"); err == nil {
			t.Fatalf("wrong kind accepted for %s", operation)
		}
		if _, err := ScopeForOperation(operation); err != nil {
			t.Fatal(err)
		}
	}
	for exit := ExitSuccess; exit <= ExitChild; exit++ {
		if err := ValidateStatusExit(StatusForExit(exit), exit); err != nil {
			t.Errorf("StatusForExit(%d)=%s is not allowed by the matrix: %v", exit, StatusForExit(exit), err)
		}
	}
	for exit, status := range map[ExitCode]Status{
		ExitSuccess: StatusOK, ExitFinding: StatusChanges, ExitUsage: StatusFailed, ExitOperational: StatusBlocked,
		ExitConflict: StatusConflicted, ExitTrust: StatusBlocked, ExitTransaction: StatusBlocked,
		ExitIncompatible: StatusBlocked, ExitUnavailable: StatusBlocked, ExitInternal: StatusFailed, ExitChild: StatusFailed,
	} {
		if got := StatusForExit(exit); got != status {
			t.Errorf("StatusForExit(%d)=%s, want %s", exit, got, status)
		}
	}
	if err := ValidateStatusExit(StatusOK, ExitConflict); err == nil {
		t.Fatal("incompatible status/exit accepted")
	}
	if err := ValidateStatusExit(StatusOK, ExitCode(11)); err == nil {
		t.Fatal("unregistered exit accepted")
	}
	r := New(OperationNewStatus, "v")
	r.Status = StatusBlocked
	if err := r.ValidateExit(ExitSuccess); err != nil {
		t.Fatalf("observational status query rejected: %v", err)
	}
}

func TestNormalizeVolatileTouchesOnlyAllowlistedFields(t *testing.T) {
	left := New(OperationSettingsSet, "test")
	left.Project = &Project{ID: "project", Root: "/tmp/cli/project"}
	left.Status = StatusChanges
	left.Summary.FilesChanged = 1
	left.Changes = []Change{{Path: "service.go", Action: "write"}}
	left.Diagnostics = []Diagnostic{{Code: "TPL-W-SETTINGS-001", Severity: "warning", Message: "stable", Details: map[string]any{"durationMs": 5}}}
	leftTx := "tx-cli"
	left.TransactionID = &leftTx
	if err := left.SetData(map[string]any{"updatedAt": "2026-01-01T00:00:00Z", "value": "x"}); err != nil {
		t.Fatal(err)
	}
	right := left.canonicalCollections()
	right.Project.Root = "/tmp/mcp/project"
	rightTx := "tx-mcp"
	right.TransactionID = &rightTx
	right.Diagnostics[0].Details = map[string]any{"durationMs": 9}
	if err := right.SetData(map[string]any{"updatedAt": "2026-02-02T00:00:00Z", "value": "x"}); err != nil {
		t.Fatal(err)
	}
	if !parityEqual(t, left, right, "/tmp/cli", "/tmp/mcp") {
		t.Fatal("allowlisted volatile fields did not normalize")
	}
	for name, mutate := range map[string]func(*Result){
		"summary":     func(r *Result) { r.Summary.FilesChanged++ },
		"diagnostic":  func(r *Result) { r.Diagnostics[0].Message = "changed" },
		"data value":  func(r *Result) { _ = r.SetData(map[string]any{"updatedAt": "x", "value": "y"}) },
		"stable root": func(r *Result) { r.Project.Root = "/elsewhere/project" },
		"status":      func(r *Result) { r.Status = StatusOK },
	} {
		changed := right.canonicalCollections()
		mutate(&changed)
		if parityEqual(t, left, changed, "/tmp/cli", "/tmp/mcp") {
			t.Fatalf("%s was incorrectly normalized", name)
		}
	}
}

func parityEqual(t *testing.T, left, right Result, roots ...string) bool {
	t.Helper()
	l, err := MarshalCanonical(NormalizeVolatile(left, roots...))
	if err != nil {
		t.Fatal(err)
	}
	r, err := MarshalCanonical(NormalizeVolatile(right, roots...))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(l, r)
}

func fmtWrap(err error) error { return errors.Join(errors.New("context"), err) }

const schemaPath = "../../schema/result.v1.schema.json"

func resultSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	return compileSchema(t, data)
}

func compileSchema(t *testing.T, data []byte) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	const resource = "https://tplaiter.dev/schema/test.schema.json"
	if err := compiler.AddResource(resource, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func decodeJSON(t *testing.T, data []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
