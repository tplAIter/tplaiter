package resources

import (
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"testing"
)

func TestIndependentMalformedToolchainAdmission(t *testing.T) {
	for _, index := range [][]byte{[]byte("not JSON"), []byte(`{"apiVersion":"unknown","files":[]}`)} {
		a := operationtrust.ProjectBuildAction{APIVersion: "tplaiter.dev/project-build-action/v1", Adapter: "go-project-build-v1", CommandName: "build", Argv: operationtrust.ProjectBuildArguments(), TimeoutMillis: 1000, ToolchainIndexSHA256: evidencecas.Digest(index)}
		raw, e := json.Marshal(a)
		if e != nil {
			t.Fatal(e)
		}
		snap, e := nativeSnapshotFixture(t, "commands:\n  build:\n    run: go build -mod=readonly -buildvcs=false ./...\n", map[string][]byte{"toolchain/index.json": index, operationtrust.ProjectBuildActionPath: raw}, false)
		if e != nil {
			t.Fatal(e)
		}
		_, e = nativeGeneratorFiles(snap)
		t.Logf("index=%q admitted=%v", index, e == nil)
		if e == nil {
			t.Error("invalid toolchain index admitted despite requested admission refusal")
		}
	}
}
