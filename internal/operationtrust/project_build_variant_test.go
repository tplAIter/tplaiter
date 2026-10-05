package operationtrust

import (
	"encoding/json"
	"fmt"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"strings"
	"testing"
)

func TestProjectBuildVariantDeclarationRefusesAmbiguousAuthority(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	makeAction := func() ProjectBuildAction {
		return ProjectBuildAction{APIVersion: "tplaiter.dev/project-build-action/v3", Adapter: "go-project-build-v3", GenBuild: true, Selector: "workflow", Variants: []ProjectBuildVariant{{ID: "workflow-false", Policy: "zero-external-modules", GoModSHA256: d, GoSumSHA256: d}, {ID: "workflow-true", Workflow: true, Policy: "module-closure", ModuleIndexSHA256: d}}}
	}
	if !validProjectBuildVersion(makeAction()) {
		t.Fatal("closed declaration refused")
	}
	for name, change := range map[string]func(*ProjectBuildAction){
		"unknown selector":          func(a *ProjectBuildAction) { a.Selector = "caller" },
		"missing false":             func(a *ProjectBuildAction) { a.Variants = a.Variants[1:] },
		"extra fallback":            func(a *ProjectBuildAction) { a.Variants = append(a.Variants, a.Variants[0]) },
		"duplicate case":            func(a *ProjectBuildAction) { a.Variants[1] = a.Variants[0] },
		"false closure ambiguity":   func(a *ProjectBuildAction) { a.Variants[0].ModuleIndexSHA256 = d },
		"false wrong discriminator": func(a *ProjectBuildAction) { a.Variants[0].Workflow = true },
		"false missing mod pin":     func(a *ProjectBuildAction) { a.Variants[0].GoModSHA256 = "" },
		"true empty closure":        func(a *ProjectBuildAction) { a.Variants[1].ModuleIndexSHA256 = "" },
		"true zero policy":          func(a *ProjectBuildAction) { a.Variants[1].Policy = "zero-external-modules" },
		"mixed top-level authority": func(a *ProjectBuildAction) { a.ModuleIndexSHA256 = d },
		"invalid digest":            func(a *ProjectBuildAction) { a.Variants[0].GoSumSHA256 = "sha256:" + strings.Repeat("g", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			a := makeAction()
			change(&a)
			if validProjectBuildVersion(a) {
				t.Fatal("ambiguous variant accepted")
			}
		})
	}
	for _, a := range []ProjectBuildAction{{APIVersion: "tplaiter.dev/project-build-action/v1", Adapter: "go-project-build-v1"}, {APIVersion: "tplaiter.dev/project-build-action/v2", Adapter: "go-project-build-v2", ModuleIndexSHA256: d, GenBuild: true}} {
		if !validProjectBuildVersion(a) {
			t.Fatal("legacy version changed")
		}
		a.Selector = "workflow"
		if validProjectBuildVersion(a) {
			t.Fatal("legacy declaration smuggled selector")
		}
	}
}

func TestProjectBuildVariantRawWirePresence(t *testing.T) {
	index := trustload.ToolchainIndex{APIVersion: trustload.ToolchainIndexVersion, GoVersion: "go1.27.1", GOOS: "darwin", GOARCH: "arm64"}
	for _, name := range []string{"VERSION", "bin/go", "pkg/tool/darwin_arm64/asm", "pkg/tool/darwin_arm64/compile", "pkg/tool/darwin_arm64/link", "src/runtime/runtime.go"} {
		mode := "100644"
		if name == "bin/go" || strings.HasPrefix(name, "pkg/tool/") {
			mode = "100755"
		}
		digest := evidencecas.Digest([]byte("inert fixture"))
		index.Files = append(index.Files, trustload.ToolchainFile{Path: name, Mode: mode, Size: 1, SHA256: digest, Chunks: []string{digest}})
	}
	indexRaw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	d := "sha256:" + strings.Repeat("a", 64)
	action := ProjectBuildAction{APIVersion: "tplaiter.dev/project-build-action/v3", Adapter: "go-project-build-v3", CommandName: "build", Argv: ProjectBuildArguments(), TimeoutMillis: 1000, ToolchainIndexSHA256: evidencecas.Digest(indexRaw), GenBuild: true, Selector: "workflow", Variants: []ProjectBuildVariant{{ID: "workflow-false", Workflow: false, Policy: "zero-external-modules", GoModSHA256: d, GoSumSHA256: d}, {ID: "workflow-true", Workflow: true, Policy: "module-closure", ModuleIndexSHA256: d}}}
	raw, err := json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProjectBuildRecord(raw, indexRaw); err != nil {
		t.Fatalf("valid explicit false: %v", err)
	}
	decode := func(t *testing.T) map[string]any {
		t.Helper()
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	variants := func(object map[string]any, i int) map[string]any {
		return object["variants"].([]any)[i].(map[string]any)
	}
	check := func(t *testing.T, object map[string]any) {
		t.Helper()
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ProjectBuildAction
		if decodeProjectBuildAction(raw, &decoded) == nil {
			t.Fatal("shared preparation decoder accepted malformed wire")
		}
		if validateProjectBuildRecord(raw, indexRaw) == nil {
			t.Fatal("declaration validator accepted malformed wire")
		}
	}
	for i, fields := range [][]string{{"id", "workflow", "policy", "goModSHA256", "goSumSHA256"}, {"id", "workflow", "policy", "moduleIndexSHA256"}} {
		for _, field := range fields {
			for _, mode := range []string{"missing", "null"} {
				t.Run(string(rune('0'+i))+"/"+field+"/"+mode, func(t *testing.T) {
					object := decode(t)
					v := variants(object, i)
					if mode == "missing" {
						delete(v, field)
					} else {
						v[field] = nil
					}
					check(t, object)
				})
			}
		}
	}
	for _, field := range []string{"apiVersion", "adapter", "commandName", "argv", "timeoutMillis", "toolchainIndexSHA256", "genBuild", "selector", "variants"} {
		for _, mode := range []string{"missing", "null"} {
			t.Run("top/"+field+"/"+mode, func(t *testing.T) {
				object := decode(t)
				if mode == "missing" {
					delete(object, field)
				} else {
					object[field] = nil
				}
				check(t, object)
			})
		}
	}
	for _, forbidden := range []struct {
		at    int
		field string
	}{{-1, "moduleIndexSHA256"}, {0, "moduleIndexSHA256"}, {1, "goModSHA256"}, {1, "goSumSHA256"}} {
		for _, value := range []any{"", nil, d} {
			t.Run("forbidden/"+string(rune('1'+forbidden.at))+"/"+forbidden.field+"/"+fmt.Sprint(value), func(t *testing.T) {
				object := decode(t)
				target := object
				if forbidden.at >= 0 {
					target = variants(object, forbidden.at)
				}
				target[forbidden.field] = value
				check(t, object)
			})
		}
	}
	for _, version := range []string{"v1", "v2"} {
		legacy := action
		legacy.APIVersion = "tplaiter.dev/project-build-action/" + version
		legacy.Adapter = "go-project-build-" + version
		legacy.Selector = ""
		legacy.Variants = nil
		legacy.GenBuild = false
		if version == "v2" {
			legacy.ModuleIndexSHA256 = d
			legacy.GenBuild = true
		}
		raw, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ProjectBuildAction
		if err := decodeProjectBuildAction(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := validateProjectBuildRecord(raw, indexRaw); err != nil {
			t.Fatalf("legacy %s: %v", version, err)
		}
	}
}
