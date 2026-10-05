package operationtrust

import (
	"context"
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectBuildRecordContract(t *testing.T) {
	idx := trustload.ToolchainIndex{APIVersion: trustload.ToolchainIndexVersion, GoVersion: "go1.27.1", GOOS: "darwin", GOARCH: "arm64"}
	for _, name := range []string{"VERSION", "bin/go", "pkg/tool/darwin_arm64/asm", "pkg/tool/darwin_arm64/compile", "pkg/tool/darwin_arm64/link", "src/runtime/runtime.go"} {
		mode := "100644"
		if name == "bin/go" || strings.HasPrefix(name, "pkg/tool/") {
			mode = "100755"
		}
		idx.Files = append(idx.Files, trustload.ToolchainFile{Path: name, Mode: mode, Size: 1, SHA256: evidencecas.Digest([]byte("inert")), Chunks: []string{evidencecas.Digest([]byte("absent inert CAS"))}})
	}
	index, _ := json.Marshal(idx)
	a := ProjectBuildAction{APIVersion: "tplaiter.dev/project-build-action/v1", Adapter: "go-project-build-v1", CommandName: "build", Argv: ProjectBuildArguments(), TimeoutMillis: 1000, ToolchainIndexSHA256: evidencecas.Digest(index)}
	raw, _ := json.Marshal(a)
	if e := validateProjectBuildRecord(raw, index); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name   string
		change func(*ProjectBuildAction)
	}{{"unsigned adapter", func(a *ProjectBuildAction) { a.Adapter = "shell" }}, {"provider helper", func(a *ProjectBuildAction) { a.Argv = []string{"native-snapshot-tool-v1"} }}, {"extra flags", func(a *ProjectBuildAction) { a.Argv = append(a.Argv, "-toolexec=evil") }}, {"other command", func(a *ProjectBuildAction) { a.CommandName = "test" }}, {"timeout", func(a *ProjectBuildAction) { a.TimeoutMillis = 120001 }}, {"index drift", func(a *ProjectBuildAction) { a.ToolchainIndexSHA256 = evidencecas.Digest([]byte("other")) }}} {
		t.Run(tc.name, func(t *testing.T) {
			b := a
			b.Argv = append([]string(nil), a.Argv...)
			tc.change(&b)
			raw, _ := json.Marshal(b)
			if validateProjectBuildRecord(raw, index) == nil {
				t.Fatal("accepted unsupported declaration")
			}
		})
	}
	raw = append(raw[:len(raw)-1], []byte(`,"shell":true}`)...)
	if validateProjectBuildRecord(raw, index) == nil {
		t.Fatal("unknown shell field accepted")
	}
}
func TestProjectBuildCaptureCurrentInputsAndRefusals(t *testing.T) {
	root := t.TempDir()
	root, e := filepath.EvalSymlinks(root)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.invalid/synthetic\n"), 0600)
	file := filepath.Join(root, "main.go")
	os.WriteFile(file, []byte("package main\n"), 0600)
	first, _, e := captureProjectBuild(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(file, []byte("package main\nfunc main(){}\n"), 0600)
	second, _, e := captureProjectBuild(context.Background(), root)
	if e != nil || first[1].ContentSHA256 == second[1].ContentSHA256 {
		t.Fatal("current edit not captured", e)
	}
	for _, name := range []string{"go.work", "linked.go"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(root, name)
			if name == "linked.go" {
				os.Symlink(file, p)
			} else {
				os.WriteFile(p, []byte("go 1.26\n"), 0600)
			}
			defer os.Remove(p)
			if _, _, e := captureProjectBuild(context.Background(), root); e == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := captureProjectBuild(ctx, root); e == nil {
		t.Fatal("cancel ignored")
	}
}

func TestProjectBuildMaterialGuardLossRefuses(t *testing.T) {
	m := &ExecutionMaterial{projectBuild: &ProjectBuildSelection{owner: &trustload.Runtime{}}}
	if _, e := m.StagedFor(context.Background(), &trustverify.Runtime{}, trustverify.ExecutionRequest{}); e != ErrExecutionMaterialUnavailable {
		t.Fatalf("foreign runtime not typed refused: %v", e)
	}
	if _, _, e := m.ProjectBuildFor(nil, nil, trustverify.ExecutionRequest{}); e != ErrProjectBuild {
		t.Fatalf("nil guard not typed refused: %v", e)
	}
}
