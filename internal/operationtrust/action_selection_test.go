package operationtrust

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// These are closed-wire test values, not publisher/operator grants or installed
// execution acceptance. No native process, signer or database is used here.
func actionTestDocument() actionDocument {
	d := evidencecas.Digest([]byte("neutral-fixture"))
	return actionDocument{APIVersion: "tplaiter.dev/template-actions/v1", Actions: []actionDeclaration{{ID: "check", Purpose: "run", Class: ActionClass, Profile: "darwin25G83-native-fd/v1", Version: 1, Kind: "command", Phase: "standalone", Parameters: []actionParameter{{Name: "level", Type: "integer", Values: []json.RawMessage{json.RawMessage(`1`), json.RawMessage(`2`)}}}, Argv: []actionArg{{Kind: "literal", Value: "checker"}, {Kind: "literal", Value: "--level"}, {Kind: "parameter", Value: "level"}}, Inputs: []actionFile{}, Stdin: actionFile{Root: "provider", Path: "input.txt", Mode: "100644", SHA256: d}, Tool: actionToolSelection{Provider: trustverify.Provider{Origin: "https://example.test/tools", TemplatePath: ".", Commit: strings.Repeat("a", 40), TreeSHA256: d, ContractSHA256: d}, Evidence: SelectionEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: d, SignatureCAS: d, KeyFingerprint: d, CheckpointCAS: d, InclusionProofCAS: d}, ID: "checker", Version: "1.0", RecordSHA256: d}, Environment: fixedEnvironment(), WorkingDirectory: trustverify.WorkingDirectoryScope{Root: "provider", Path: ".tplaiter-execution"}, TimeoutMillis: 1000, StdoutLimit: 128 << 10, StderrLimit: 16 << 10}}}
}

func actionTestCanonical(t *testing.T, v any) []byte {
	t.Helper()
	b, e := canonicaljson.Canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestActionMetadataClosedSchemaAndRefusals(t *testing.T) {
	schema, e := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "schema", "template-actions.v1.schema.json"))
	if e != nil {
		t.Fatal(e)
	}
	good := actionTestCanonical(t, actionTestDocument())
	if _, e := decodeActionDocument(good); e != nil {
		t.Fatal(e)
	}
	var value any
	if json.Unmarshal(good, &value) != nil {
		t.Fatal("decode")
	}
	if e := schema.Validate(value); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name   string
		change func(*actionDocument)
	}{
		{"future-purpose", func(d *actionDocument) { d.Actions[0].Purpose = "env" }},
		{"shell", func(d *actionDocument) { d.Actions[0].Shell = true }},
		{"unknown-class", func(d *actionDocument) { d.Actions[0].Class = "arbitrary-native" }},
		{"unknown-profile", func(d *actionDocument) { d.Actions[0].Profile = "darwin-amd64-staged-readonly/v1" }},
		{"version", func(d *actionDocument) { d.Actions[0].Version = 2 }},
		{"phase", func(d *actionDocument) { d.Actions[0].Phase = "after" }},
		{"kind", func(d *actionDocument) { d.Actions[0].Kind = "ansible" }},
		{"timeout", func(d *actionDocument) { d.Actions[0].TimeoutMillis = 5001 }},
		{"stdout", func(d *actionDocument) { d.Actions[0].StdoutLimit++ }},
		{"stderr", func(d *actionDocument) { d.Actions[0].StderrLimit++ }},
		{"ambient-env", func(d *actionDocument) { d.Actions[0].Environment.Inherit = true }},
		{"loader-variable", func(d *actionDocument) { d.Actions[0].Environment.Variables[0].Name = "DYLD_INSERT_LIBRARIES" }},
		{"cwd", func(d *actionDocument) { d.Actions[0].WorkingDirectory.Path = ".." }},
		{"path-escape", func(d *actionDocument) { d.Actions[0].Stdin.Path = "../outside" }},
		{"absolute-path", func(d *actionDocument) { d.Actions[0].Stdin.Path = "/outside" }},
		{"backslash", func(d *actionDocument) { d.Actions[0].Stdin.Path = `a\b` }},
		{"control-namespace", func(d *actionDocument) { d.Actions[0].Stdin.Path = "actions/run/capsule.json" }},
		{"executable-input", func(d *actionDocument) { d.Actions[0].Stdin.Mode = "100755" }},
		{"bad-hash", func(d *actionDocument) { d.Actions[0].Stdin.SHA256 = "sha256:bad" }},
		{"duplicate-id", func(d *actionDocument) { d.Actions = append(d.Actions, d.Actions[0]) }},
		{"duplicate-input", func(d *actionDocument) { d.Actions[0].Inputs = []actionFile{d.Actions[0].Stdin} }},
		{"duplicate-parameter", func(d *actionDocument) {
			d.Actions[0].Parameters = append(d.Actions[0].Parameters, d.Actions[0].Parameters[0])
		}},
		{"wrong-parameter-type", func(d *actionDocument) { d.Actions[0].Parameters[0].Values = []json.RawMessage{json.RawMessage(`"1"`)} }},
		{"fractional-integer", func(d *actionDocument) { d.Actions[0].Parameters[0].Values = []json.RawMessage{json.RawMessage(`1.5`)} }},
		{"duplicate-enum", func(d *actionDocument) {
			d.Actions[0].Parameters[0].Values = []json.RawMessage{json.RawMessage(`1`), json.RawMessage(`1`)}
		}},
		{"unknown-slot", func(d *actionDocument) { d.Actions[0].Argv[2].Value = "executable" }},
		{"tool-from-param", func(d *actionDocument) { d.Actions[0].Argv[0] = actionArg{Kind: "parameter", Value: "level"} }},
		{"nul", func(d *actionDocument) { d.Actions[0].Argv[1].Value = "--x\x00y" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := actionTestDocument()
			tc.change(&d)
			if _, e := decodeActionDocument(actionTestCanonical(t, d)); e == nil {
				t.Fatal("accepted unsafe declaration")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"duplicate-key":     bytes.Replace(good, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"unknown-recursive": bytes.Replace(good, []byte(`"shell":false`), []byte(`"shell":false,"grant":true`), 1),
		"missing-shell":     bytes.Replace(good, []byte(`"shell":false,`), nil, 1),
		"null-inputs":       bytes.Replace(good, []byte(`"inputs":[]`), []byte(`"inputs":null`), 1),
		"noncanonical":      append([]byte(" "), good...),
		"trailing-json":     append(append([]byte(nil), good...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeActionDocument(raw); e == nil {
				t.Fatal("accepted malformed wire")
			}
		})
	}
}

func TestActionTypedParametersDoNotSelectAuthority(t *testing.T) {
	a := actionTestDocument().Actions[0]
	p, argv, e := actionArguments(a, []byte(`{"level":2}`))
	if e != nil || strings.Join(argv, "|") != "checker|--level|2" || string(p["level"]) != "2" {
		t.Fatal(argv, e)
	}
	for _, raw := range []string{`{}`, `{"level":3}`, `{"level":"2"}`, `{"level":true}`, `{"level":2,"tool":"/bin/sh"}`, `{"level":2,"level":2}`, `{"level":null}`, `[]`} {
		if _, _, e := actionArguments(a, []byte(raw)); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	a.Parameters = []actionParameter{{Name: "flag", Type: "boolean", Values: []json.RawMessage{json.RawMessage(`true`), json.RawMessage(`false`)}}, {Name: "text", Type: "string", Values: []json.RawMessage{json.RawMessage(`"literal spaces; $(never-executed)"`)}}}
	a.Argv = []actionArg{{Kind: "literal", Value: "checker"}, {Kind: "parameter", Value: "flag"}, {Kind: "parameter", Value: "text"}}
	_, argv, e = actionArguments(a, []byte(`{"text":"literal spaces; $(never-executed)","flag":false}`))
	if e != nil || len(argv) != 3 || argv[1] != "false" || argv[2] != "literal spaces; $(never-executed)" {
		t.Fatal("split or expanded literal", argv, e)
	}
	a.Argv = make([]actionArg, 5)
	for i := range a.Argv {
		a.Argv[i] = actionArg{Kind: "literal", Value: strings.Repeat("a", 4096)}
	}
	if _, _, e := actionArguments(a, []byte(`{"text":"literal spaces; $(never-executed)","flag":false}`)); e == nil {
		t.Fatal("unbounded aggregate argv")
	}
}

func TestActionCapsuleBoundSemanticsAndDefensiveProjection(t *testing.T) {
	d := evidencecas.Digest([]byte("original"))
	a := actionTestDocument().Actions[0]
	p, argv, e := actionArguments(a, []byte(`{"level":1}`))
	if e != nil {
		t.Fatal(e)
	}
	c := actionCapsule{APIVersion: "tplaiter.dev/action-capsule/v1", Declaration: a, MetadataSHA256: d, ToolRecordSHA256: d, Parameters: p, Argv: argv, Inputs: []trustverify.ContentEntry{}, AnswersSHA256: d, PreimageSHA256: d}
	before := actionTestCanonical(t, c)
	for name, change := range map[string]func(*actionCapsule){"purpose": func(c *actionCapsule) { c.Declaration.Purpose = "other" }, "params": func(c *actionCapsule) { c.Parameters = map[string]json.RawMessage{"level": json.RawMessage(`2`)} }, "tool": func(c *actionCapsule) { c.Declaration.Tool.Provider.Commit = strings.Repeat("b", 40) }, "source": func(c *actionCapsule) { c.MetadataSHA256 = evidencecas.Digest([]byte("changed")) }, "answers": func(c *actionCapsule) { c.AnswersSHA256 = evidencecas.Digest([]byte("changed")) }, "preimage": func(c *actionCapsule) { c.PreimageSHA256 = evidencecas.Digest([]byte("changed")) }} {
		t.Run(name, func(t *testing.T) {
			after := c
			change(&after)
			if bytes.Equal(before, actionTestCanonical(t, after)) {
				t.Fatal("capsule failed to bind semantics")
			}
		})
	}
	s := &ActionSelection{capsule: before, request: trustverify.ExecutionRequest{Action: trustverify.Action{Argv: []string{"checker"}}}, operation: trustverify.OperationInputs{Subjects: []trustverify.Provider{a.Tool.Provider}, Actions: []trustverify.ActionMaterial{{Action: trustverify.Action{Argv: []string{"checker"}}}}}}
	s.Capsule()[0] = '!'
	s.Request().Action.Argv[0] = "changed"
	s.Operation().Actions[0].Action.Argv[0] = "changed"
	if !bytes.Equal(s.Capsule(), before) || s.Request().Action.Argv[0] != "checker" || s.Operation().Actions[0].Action.Argv[0] != "checker" {
		t.Fatal("mutable projection")
	}
	s.Close()
	s.Close()
	if s.Request().RequestSHA256 != "" || s.Capsule() != nil {
		t.Fatal("closed selection exposed content")
	}
}

func TestActionOpaqueRuntimeRefusals(t *testing.T) {
	for _, owner := range []*trustload.Runtime{nil, {}} {
		if _, e := PrepareAction(context.Background(), owner, &trustverify.VerifiedResolution{}, &trustverify.VerifiedResolution{}, ActionInput{Name: "check", ParametersJSON: []byte(`{}`)}); e != ErrActionSelection {
			t.Fatalf("unverified owner accepted: %v", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := PrepareAction(ctx, &trustload.Runtime{}, nil, nil, ActionInput{Name: "check"}); e != ErrActionSelection {
		t.Fatal(e)
	}
	for _, s := range []*ActionSelection{nil, {}} {
		if e := s.Recheck(context.Background(), nil); e != ErrActionSelection {
			t.Fatal("zero selection validated", e)
		}
	}
}

func TestActionHeldFilesRetainOriginalIdentity(t *testing.T) {
	for _, name := range []string{"replace-equal-bytes", "restore-mode", "link-state", "body-change", "symlink", "closed", "cancel"} {
		t.Run(name, func(t *testing.T) {
			root, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			f := filepath.Join(root, "input.txt")
			if e = os.WriteFile(f, []byte("neutral"), 0o644); e != nil {
				t.Fatal(e)
			}
			held, e := openActionFiles(root)
			if e != nil {
				t.Fatal(e)
			}
			defer held.close()
			b, e := held.read(context.Background(), "input.txt", 64)
			if e != nil || string(b) != "neutral" {
				t.Fatal(e)
			}
			if e = held.check(context.Background()); e != nil {
				t.Fatal("initial observation failed", e)
			}
			ctx := context.Background()
			switch name {
			case "replace-equal-bytes":
				if e = os.Rename(f, f+".old"); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(f, b, 0o644); e != nil {
					t.Fatal(e)
				}
			case "restore-mode":
				if e = os.Chmod(f, 0o600); e != nil {
					t.Fatal(e)
				}
				if e = os.Chmod(f, 0o644); e != nil {
					t.Fatal(e)
				}
			case "link-state":
				if e = os.Link(f, f+".alias"); e != nil {
					t.Fatal(e)
				}
			case "body-change":
				if e = os.WriteFile(f, []byte("changed"), 0o644); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e = os.Rename(f, f+".old"); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink(f+".old", f); e != nil {
					t.Fatal(e)
				}
			case "closed":
				held.close()
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if held.check(ctx) == nil {
				t.Fatal("original physical observation replaced by fresh equal fact")
			}
		})
	}
}

func TestActionFileAcquisitionRefusesLinksModesAndBounds(t *testing.T) {
	for _, name := range []string{"symlink", "hardlink", "executable", "special-mode", "oversize", "escape", "parent-symlink"} {
		t.Run(name, func(t *testing.T) {
			root, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			f := filepath.Join(root, "input.txt")
			if e = os.WriteFile(f, []byte("neutral"), 0o644); e != nil {
				t.Fatal(e)
			}
			p := "input.txt"
			limit := 64
			switch name {
			case "symlink":
				if e = os.Symlink("input.txt", filepath.Join(root, "alias")); e != nil {
					t.Fatal(e)
				}
				p = "alias"
			case "hardlink":
				if e = os.Link(f, f+".alias"); e != nil {
					t.Fatal(e)
				}
			case "executable":
				if e = os.Chmod(f, 0o755); e != nil {
					t.Fatal(e)
				}
			case "special-mode":
				if e = os.Chmod(f, 0o644|os.ModeSticky); e != nil {
					t.Fatal(e)
				}
			case "oversize":
				limit = 1
			case "escape":
				p = "../input.txt"
			case "parent-symlink":
				if e = os.Mkdir(filepath.Join(root, "real"), 0o755); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(root, "real", "x"), []byte("x"), 0o644); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink("real", filepath.Join(root, "alias")); e != nil {
					t.Fatal(e)
				}
				p = "alias/x"
			}
			held, e := openActionFiles(root)
			if e != nil {
				t.Fatal(e)
			}
			defer held.close()
			if _, e := held.read(context.Background(), p, limit); e == nil {
				t.Fatal("unsafe file acquired")
			}
		})
	}
}

type actionTestObjects map[trustverify.ObjectID]trustverify.GitObject

func (m actionTestObjects) ReadObject(ctx context.Context, _ trustverify.SourceOrigin, id trustverify.ObjectID) (trustverify.GitObject, error) {
	if e := ctx.Err(); e != nil {
		return trustverify.GitObject{}, e
	}
	o, ok := m[id]
	if !ok {
		return o, fmt.Errorf("missing neutral object")
	}
	return o, nil
}

func TestActionUsesActualGitSnapshotBytesAndModes(t *testing.T) {
	objects := actionTestObjects{}
	put := func(kind string, b []byte) string {
		h := sha1.Sum(append([]byte(fmt.Sprintf("%s %d\x00", kind, len(b))), b...))
		id := hex.EncodeToString(h[:])
		objects[trustverify.ObjectID(id)] = trustverify.GitObject{Kind: kind, Data: append([]byte(nil), b...)}
		return id
	}
	tree := []byte{}
	for _, row := range []struct{ mode, name, body string }{{"100644", "input.txt", "neutral"}, {"100644", "template.contract.json", `{"neutral":true}`}, {"100755", "tool.bin", "inert-not-executable-proof"}} {
		id := put("blob", []byte(row.body))
		oid, _ := hex.DecodeString(id)
		tree = append(tree, []byte(row.mode+" "+row.name+"\x00")...)
		tree = append(tree, oid...)
	}
	commit := put("commit", []byte("tree "+put("tree", tree)+"\n\nneutral fixture\n"))
	captured, e := trustverify.CaptureSource(context.Background(), objects, trustverify.SourceIdentity{Origin: "https://example.test/neutral", TemplatePath: ".", Commit: commit}, trustverify.DefaultSourceLimits())
	if e != nil {
		t.Fatal(e)
	}
	s, e := trustverify.VerifySource(context.Background(), objects, captured.Subject())
	if e != nil {
		t.Fatal(e)
	}
	b, ok := actionSnapshotBlob(s, "input.txt", "100644")
	if !ok || string(b) != "neutral" {
		t.Fatal("actual verified object not consumed")
	}
	b[0] = '!'
	b, ok = actionSnapshotBlob(s, "input.txt", "100644")
	if !ok || string(b) != "neutral" {
		t.Fatal("snapshot bytes not owned")
	}
	if _, ok = actionSnapshotBlob(s, "tool.bin", "100644"); ok {
		t.Fatal("Git executable mode collapsed to readonly")
	}
	if _, ok = actionSnapshotBlob(s, "unknown", "100644"); ok {
		t.Fatal("unknown blob")
	}
	// Capture/VerifySource proves Git bytes only, not a stable publisher resolution.
	if _, e = PrepareAction(context.Background(), &trustload.Runtime{}, &trustverify.VerifiedResolution{}, &trustverify.VerifiedResolution{}, ActionInput{Name: "check", ParametersJSON: []byte(`{}`)}); e == nil {
		t.Fatal("raw object proof treated as runtime grant")
	}
}

func TestActionNativeEnvelopeIsStructuralAndClosed(t *testing.T) {
	linux := make([]byte, 120)
	copy(linux, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(linux[16:], 2)
	binary.LittleEndian.PutUint16(linux[18:], 62)
	binary.LittleEndian.PutUint32(linux[20:], 1)
	binary.LittleEndian.PutUint64(linux[24:], 0x400000)
	binary.LittleEndian.PutUint64(linux[32:], 64)
	binary.LittleEndian.PutUint16(linux[52:], 64)
	binary.LittleEndian.PutUint16(linux[54:], 56)
	binary.LittleEndian.PutUint16(linux[56:], 1)
	binary.LittleEndian.PutUint32(linux[64:], 1)
	binary.LittleEndian.PutUint32(linux[68:], 5)
	binary.LittleEndian.PutUint64(linux[96:], 120)
	binary.LittleEndian.PutUint64(linux[104:], 120)
	if !actionNativeImageFor(linux, "linux-static-fd-go127/v1", "amd64") {
		t.Fatal("static structural fixture")
	}
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{{"interpreter", func(b []byte) { binary.LittleEndian.PutUint32(b[64:], 3) }}, {"dynamic", func(b []byte) { binary.LittleEndian.PutUint32(b[64:], 2) }}, {"write-execute", func(b []byte) { binary.LittleEndian.PutUint32(b[68:], 7) }}, {"wrong-machine", func(b []byte) { binary.LittleEndian.PutUint16(b[18:], 183) }}, {"wrong-size", func(b []byte) { binary.LittleEndian.PutUint64(b[96:], 121) }}} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), linux...)
			tc.change(b)
			if actionNativeImageFor(b, "linux-static-fd-go127/v1", "amd64") {
				t.Fatal("unsupported image")
			}
		})
	}
	if actionNativeImage(linux, "unknown") || actionNativeImage([]byte("shell text"), "darwin25G83-native-fd/v1") {
		t.Fatal("unknown envelope")
	}
}

func TestActionPollProfileVersionBinding(t *testing.T) {
	old, e := ActionProfileDigest("linux-static-fd-go127/v1")
	if e != nil || old != "sha256:c461e9cd59a69b7274c9d6cc993024595eee70ff10c377a2c6661c06646468d0" {
		t.Fatalf("v1 changed: %s %v", old, e)
	}
	fresh, e := ActionProfileDigest("linux-static-fd-go127-poll/v1")
	if e != nil || fresh == old {
		t.Fatal("missing distinct digest", e)
	}
	doc := actionTestDocument()
	doc.Actions[0].Profile = "linux-static-fd-go127-poll/v1"
	if _, e := decodeActionDocument(actionTestCanonical(t, doc)); e != nil {
		t.Fatal(e)
	}
	doc.Actions[0].Profile = "linux-static-fd-go127-poll/v2"
	if _, e := decodeActionDocument(actionTestCanonical(t, doc)); e == nil {
		t.Fatal("unknown version accepted")
	}
}

func TestActionInstalledCurrentWireIsExplicit(t *testing.T) {
	legacy := actionTestCanonical(t, actionTestDocument())
	var current map[string]any
	if json.Unmarshal(legacy, &current) != nil {
		t.Fatal("decode")
	}
	current["apiVersion"] = "tplaiter.dev/template-actions/v2"
	tool := current["actions"].([]any)[0].(map[string]any)["tool"].(map[string]any)
	tool["selection"] = "installed-current/v1"
	evidence := tool["evidence"].(map[string]any)
	delete(evidence, "checkpointCAS")
	delete(evidence, "inclusionProofCAS")
	raw := actionTestCanonical(t, current)
	doc, e := decodeActionDocument(raw)
	if e != nil || doc.APIVersion != "tplaiter.dev/template-actions/v2" || doc.Actions[0].Tool.Evidence.CheckpointCAS != "" {
		t.Fatal(e)
	}
	schema, e := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "schema", "template-actions.v1.schema.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e := schema.Validate(current); e != nil {
		t.Fatal(e)
	}
	actual := trustverify.EvidenceRefs{Format: evidence["format"].(string), StatementCAS: evidence["statementCAS"].(string), SignatureCAS: evidence["signatureCAS"].(string), KeyFingerprint: evidence["keyFingerprint"].(string), CheckpointCAS: evidencecas.Digest([]byte("actual current checkpoint")), InclusionProofCAS: evidencecas.Digest([]byte("actual current proof"))}
	if !actionEvidenceMatches(doc.APIVersion, doc.Actions[0].Tool.Evidence, actual) {
		t.Fatal("immutable mismatch")
	}
	if actionEvidenceMatches("tplaiter.dev/template-actions/v1", actionTestDocument().Actions[0].Tool.Evidence, actual) {
		t.Fatal("legacy fell back")
	}
	actual.KeyFingerprint = evidencecas.Digest([]byte("foreign publisher"))
	if actionEvidenceMatches(doc.APIVersion, doc.Actions[0].Tool.Evidence, actual) {
		t.Fatal("foreign identity")
	}
	for name, bad := range map[string][]byte{
		"legacy-with-current-form": bytes.Replace(raw, []byte("template-actions/v2"), []byte("template-actions/v1"), 1),
		"current-with-legacy-form": bytes.Replace(legacy, []byte("template-actions/v1"), []byte("template-actions/v2"), 1),
		"unknown-selection":        bytes.Replace(raw, []byte("installed-current/v1"), []byte("ambient-current/v1"), 1),
		"extra-checkpoint":         bytes.Replace(raw, []byte(`"evidence":{`), []byte(`"evidence":{"checkpointCAS":"sha256:bad",`), 1),
		"duplicate-selection":      bytes.Replace(raw, []byte(`"selection":"installed-current/v1"`), []byte(`"selection":"installed-current/v1","selection":"installed-current/v1"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeActionDocument(bad); e == nil {
				t.Fatal("accepted mixed wire")
			}
		})
	}
	if restored := actionTestCanonical(t, actionTestDocument()); !bytes.Equal(legacy, restored) {
		t.Fatal("legacy bytes")
	}
}

func TestActionEmptyToolOptionsPreservePreparedDigest(t *testing.T) {
	argv := []string{"checker"}
	prepared, e := trustverify.ComputeToolOptionsSHA256(argv[1:])
	if e != nil {
		t.Fatal(e)
	}
	staged := nativeActionToolOptions(argv)
	actual, e := trustverify.ComputeToolOptionsSHA256(staged)
	if e != nil || staged == nil || actual != prepared {
		t.Fatal("empty options changed", e)
	}
	nonempty := []string{"checker", "--literal"}
	copy := nativeActionToolOptions(nonempty)
	copy[0] = "changed"
	if nonempty[1] != "--literal" {
		t.Fatal("aliased argv")
	}
}
