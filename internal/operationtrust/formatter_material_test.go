package operationtrust

import (
	"bytes"
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestFormatterToolRecordIsClosed(t *testing.T) {
	good := []byte(`{"adapter":"gofmt-stdin-v1","apiVersion":"tplaiter.dev/formatter-tool/v1","binarySHA256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nativeEnvelope":"darwin-arm64-dyld-libsystem-libresolv-v1","toolID":"gofmt","toolVersion":"1.27.1","versionEvidence":{"identity":"go1.27.1","kind":"go-buildinfo"}}`)
	record, err := parseFormatterToolRecord(good)
	if err != nil || record.ToolVersion != "1.27.1" {
		t.Fatalf("parseFormatterToolRecord = %#v, %v", record, err)
	}
	for _, raw := range [][]byte{
		nil,
		[]byte(`{"apiVersion":"tplaiter.dev/formatter-tool/v1"}`),
		[]byte(`{"adapter":"gofmt-stdin-v1","apiVersion":"tplaiter.dev/formatter-tool/v1","binarySHA256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true,"nativeEnvelope":"darwin-arm64-dyld-libsystem-libresolv-v1","toolID":"gofmt","toolVersion":"1.27.1","versionEvidence":{"identity":"go1.27.1","kind":"go-buildinfo"}}`),
	} {
		if _, err := parseFormatterToolRecord(raw); err == nil {
			t.Fatalf("accepted invalid record %s", raw)
		}
	}
}

func TestNormalizeGoVersion(t *testing.T) {
	if got := normalizeGoVersion("go1.27.1"); got != "1.27.1" {
		t.Fatalf("normalizeGoVersion = %q", got)
	}
}

func TestFormatterContentKeepsBytesPairedAfterSort(t *testing.T) {
	entries, values := formatterContent(FormatterInput{Path: "z.go", Mode: "100644", Bytes: []byte("candidate"), PlanJSON: []byte(`{"plan":true}`)}, []byte(`{"tool":true}`))
	if len(entries) != 3 || len(values) != 3 {
		t.Fatalf("closure lengths = %d, %d", len(entries), len(values))
	}
	for i, entry := range entries {
		if entry.ContentSHA256 != evidencecas.Digest(values[i]) {
			t.Fatalf("entry %s lost its paired bytes", entry.Path)
		}
	}
}

func TestManagedFormatterContextClosed(t *testing.T) {
	d := evidencecas.Digest([]byte("x"))
	c := ManagedFormatterContext{APIVersion: "tplaiter.dev/managed-formatter-context/v1", Role: "clean-target", SourceRootLockSHA256: d, TargetRootLockSHA256: d, ReplacementDeclarationsSHA256: d, DecisionsSHA256: d, ObservedProjectSHA256: d, ObservedRegistrySHA256: d, RendererAnswersSHA256: d}
	raw, err := canonicaljson.Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManagedFormatterContext(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append([]byte(" "), raw...), []byte(`{"apiVersion":"tplaiter.dev/managed-formatter-context/v1"}`), bytes.Replace(raw, []byte(`"clean-target"`), []byte(`"merged-candidate"`), 1), bytes.Replace(raw, []byte(`"role":`), []byte(`"Role":`), 1)} {
		if _, err := ParseManagedFormatterContext(bad); err == nil {
			t.Fatal("invalid context accepted")
		}
	}
}

func TestContextNewFormatterDataClosedAndLegacySeparated(t *testing.T) {
	digest := evidencecas.Digest([]byte("source-owned fixture data"))
	c := ContextNewFormatterContext{APIVersion: "tplaiter.dev/managed-formatter-context/v2", Role: "clean-target", SourceRootLockSHA256: digest, TargetRootLockSHA256: digest, ReplacementDeclarationsSHA256: evidencecas.Digest([]byte(`{"replacements":[],"version":1}`)), DecisionsSHA256: evidencecas.Digest([]byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":[]}`)), ObservedProjectSHA256: evidencecas.Digest(nil), ObservedRegistrySHA256: digest, RendererAnswersSHA256: digest, DependencyLockSHA256: digest, SourceGraphSHA256: digest, NativeContextSHA256: digest}
	raw, err := canonicaljson.Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseContextNewFormatterContext(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManagedFormatterContext(raw); err == nil {
		t.Fatal("v2 data entered legacy v1 parser")
	}
	if err := ValidateRetainedFormatterContext(raw, "new"); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"link", "update", "run", ""} {
		if err := ValidateRetainedFormatterContext(raw, scope); err == nil {
			t.Fatal("v2 data entered foreign purpose", scope)
		}
	}
	for _, change := range []string{"predecessor", "observation", "role", "graph", "dependency", "native"} {
		bad := c
		switch change {
		case "predecessor":
			bad.PredecessorCleanProofSHA256 = digest
		case "observation":
			bad.ObservedProjectSHA256 = digest
		case "role":
			bad.Role = "merged-candidate"
		case "graph":
			bad.SourceGraphSHA256 = ""
		case "dependency":
			bad.DependencyLockSHA256 = ""
		case "native":
			bad.NativeContextSHA256 = ""
		}
		data, err := canonicaljson.Canonical(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseContextNewFormatterContext(data); err == nil {
			t.Fatal("invalid v2 context accepted", change)
		}
	}
	if _, err := ResolveContextNewFormatterComposition(context.Background(), nil, nil, nil, trustverify.OperationInputs{}, trustverify.ActionMaterial{}, FormatterInput{ContextJSON: raw}); err == nil {
		t.Fatal("data constructed missing native source authority")
	}
}
