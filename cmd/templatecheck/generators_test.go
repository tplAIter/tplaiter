package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

func TestGeneratorPreflightUsesManifestAndNeverExecutes(t *testing.T) {
	root := writeGeneratorTemplate(t)
	before, err := fixtureSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "rendered")
	var stdout, stderr bytes.Buffer
	if err := runWithPreflight(root, out, "", true, true, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	// Lint writes progress before JSON; decode the final report line.
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	var got report
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Renders) == 0 {
		t.Fatal("no rendered fixtures")
	}
	for _, render := range got.Renders {
		if len(render.Generators) != 1 || render.Generators[0].Kind != "scaffold" ||
			len(render.Generators[0].Names) != 2 || !strings.Contains(render.Generators[0].Status, "duplicate rejected") {
			t.Fatalf("generator report = %+v", render.Generators)
		}
		project := filepath.Join(out, safeComboName(render.Combo))
		main, err := os.ReadFile(filepath.Join(project, "main.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(main) != "// CODEGEN:WIRING\n// CODEGEN:IMPORTS\n" {
			t.Fatalf("preflight changed anchors: %q", main)
		}
		if _, err := os.Stat(filepath.Join(project, "generated")); !os.IsNotExist(err) {
			t.Fatal("preflight created generator targets")
		}
	}
	after, err := fixtureSnapshot(root)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("source modified: %v", err)
	}
}

func TestGeneratorPreflightRejectsActualPreparationErrors(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, root string)
		want   string
	}{
		{"two anchors share marker in one file", func(t *testing.T, root string) {
			appendFixture(t, root, "template.manifest.yaml", "      - file: main.txt\n        anchor: '// CODEGEN:IMPORTS'\n        insert: generators/wiring.tmpl\n")
		}, "already present"},
		{"missing anchor", func(t *testing.T, root string) {
			writeFixture(t, root, "files/main.txt", "no anchor\n")
		}, "anchor"},
		{"duplicate owned anchor", func(t *testing.T, root string) {
			appendFixture(t, root, "files/main.txt", "// CODEGEN:WIRING\n")
		}, "must occur exactly once"},
		{"missing insertion marker", func(t *testing.T, root string) {
			replaceFixture(t, root, "generators/wiring.tmpl", "{{ .Marker }}", "")
		}, "exactly one unchanged Marker"},
		{"duplicate insertion marker", func(t *testing.T, root string) {
			replaceFixture(t, root, "generators/wiring.tmpl", "{{ .Marker }}", "{{ .Marker }}\n{{ .Marker }}")
		}, "exactly one unchanged Marker"},
		{"transformed insertion marker", func(t *testing.T, root string) {
			replaceFixture(t, root, "generators/wiring.tmpl", "{{ .Marker }}", "{{ printf \"%.8s\" .Marker }}")
		}, "exactly one unchanged Marker"},
		{"insertion repeats owned anchor", func(t *testing.T, root string) {
			appendFixture(t, root, "generators/wiring.tmpl", "// CODEGEN:WIRING\n")
		}, "duplicates owned anchor"},
		{"target exists", func(t *testing.T, root string) {
			writeFixture(t, root, "files/generated/check_first.txt", "keep this\n")
		}, "already exists"},
		{"wiring marker already exists", func(t *testing.T, root string) {
			appendFixture(t, root, "files/main.txt", "// gen:scaffold:check_first\n")
		}, "already present"},
		{"required parameter has no default", func(t *testing.T, root string) {
			appendFixture(t, root, "template.manifest.yaml", "    params:\n      - name: label\n        type: string\n        required: true\n")
		}, "default parameters"},
		{"snippet requires absent parameter", func(t *testing.T, root string) {
			writeFixture(t, root, "generators/item.tmpl", "{{ .Missing.Field }}")
		}, "preparation"},
		{"unsafe target", func(t *testing.T, root string) {
			replaceFixture(t, root, "template.manifest.yaml", "generated/{{ .Name.Snake }}.txt", "../{{ .Name.Snake }}.txt")
		}, "path must stay within"},
		{"two names collide", func(t *testing.T, root string) {
			replaceFixture(t, root, "template.manifest.yaml", "generated/{{ .Name.Snake }}.txt", "generated/fixed.txt")
		}, "already planned"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := writeGeneratorTemplate(t)
			tc.change(t, root)
			before, err := fixtureSnapshot(root)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			err = runWithPreflight(root, filepath.Join(t.TempDir(), "out"), "", false, true, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			after, err := fixtureSnapshot(root)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("source modified: %v", err)
			}
		})
	}
}

func TestGeneratorPreflightSkipsUnavailableKindsAndUsesDefaultParams(t *testing.T) {
	root := writeGeneratorTemplate(t)
	replaceFixture(t, root, "template.manifest.yaml", "generators:\n", "settings:\n  - group: enabled\n    type: toggle\n    default: false\ngenerators:\n")
	appendFixture(t, root, "template.manifest.yaml", "    params:\n      - name: label\n        type: string\n        default: neutral\n    when: ['enabled=true']\n")
	writeFixture(t, root, "generators/item.tmpl", "{{ index .Params \"label\" }} {{ .Name.Pascal }}\n")
	var stdout, stderr bytes.Buffer
	if err := runWithPreflight(root, filepath.Join(t.TempDir(), "out"), "", true, true, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "skipped:") || !strings.Contains(stdout.String(), "prepared; execution unavailable") {
		t.Fatalf("did not cover gated and default-parameter variants: %s", stdout.String())
	}
}

func writeGeneratorTemplate(t *testing.T) string {
	t.Helper()
	root := writeTemplate(t, false)
	writeFixture(t, root, "files/main.txt", "// CODEGEN:WIRING\n// CODEGEN:IMPORTS\n")
	// This fixture defines its own manifest, targets and anchor; the checker
	// consumes them through gen.Generate rather than reconstructing wiring.
	appendFixture(t, root, "template.manifest.yaml", `
commands:
  build:
    run: "touch MUST_NOT_RUN"
hooks:
  postCreate:
    - run: "touch MUST_NOT_RUN"
generators:
  - kind: scaffold
    targets:
      - snippet: generators/item.tmpl
        target: generated/{{ .Name.Snake }}.txt
      - snippet: generators/item.tmpl
        target: generated/{{ .Name.Snake }}/nested.txt
    anchors:
      - file: main.txt
        anchor: '// CODEGEN:WIRING'
        insert: generators/wiring.tmpl
`)
	// Remove the original render target rather than rendering two main.txt files.
	if err := os.Remove(filepath.Join(root, "files/main.txt.tmpl")); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "generators/item.tmpl", "{{ .Name.Pascal }}\n")
	writeFixture(t, root, "generators/wiring.tmpl", "{{ .Marker }}\nwire {{ .Name.Pascal }}\n")
	return root
}

func writeFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	original, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, rel, string(original)+content)
}

func replaceFixture(t *testing.T, root, rel, from, to string) {
	t.Helper()
	original, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, rel, strings.ReplaceAll(string(original), from, to))
}

// Distinct raw target paths remove the usual target collision. The actual
// GenerateBatch API must reject repeated normalized wiring through its marker.
func TestRepeatedWiringRejectedWithoutTargetCollision(t *testing.T) {
	root := writeGeneratorTemplate(t)
	replaceFixture(t, root, "template.manifest.yaml", ".Name.Snake", ".Name.Raw")
	tpl, err := manifest.LoadTemplate(filepath.Join(root, "template.manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	writeFixture(t, fixture, "main.txt", "// CODEGEN:WIRING\n// CODEGEN:IMPORTS\n")
	before, err := fixtureSnapshot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	opts := gen.Options{ProjectRoot: fixture, GeneratorsDir: root, NoBuild: true, Runner: noExecution{}}
	_, err = gen.GenerateBatch(context.Background(), tpl, []gen.Operation{
		{Kind: "scaffold", Name: "CheckFirst"}, {Kind: "scaffold", Name: "check_first"},
	}, opts)
	if err == nil || errors.Is(err, gen.ErrExecutionUnavailable) || !strings.Contains(err.Error(), "marker") || !strings.Contains(err.Error(), "already present") {
		t.Fatalf("expected wiring-marker rejection with distinct targets, got %v", err)
	}
	after, err := fixtureSnapshot(fixture)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("preflight wrote fixture: %v", err)
	}
}

func TestAnchorContractCheckedBeforeTargetCollisionWithoutWrites(t *testing.T) {
	for _, mutation := range []struct{ name, file, body, want string }{
		{"missing marker", "generators/wiring.tmpl", "wire {{ .Name.Pascal }}\n", "unchanged Marker"},
		{"duplicate marker", "generators/wiring.tmpl", "{{ .Marker }}\n{{ .Marker }}\n", "unchanged Marker"},
		{"duplicate owned anchor", "files/main.txt", "// CODEGEN:WIRING\n// CODEGEN:WIRING\n", "exactly once"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			root := writeGeneratorTemplate(t)
			writeFixture(t, root, mutation.file, mutation.body)
			// Render through the actual checker, then snapshot the fixture before
			// preflight so every error path also proves there are no preflight writes.
			out := filepath.Join(t.TempDir(), "renders")
			var stdout, stderr bytes.Buffer
			if err := run(root, out, "defaults", false, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			fixture := filepath.Join(out, "defaults")
			writeFixture(t, fixture, "generated/check_first.txt", "existing target\n")
			before, err := fixtureSnapshot(fixture)
			if err != nil {
				t.Fatal(err)
			}
			tpl, err := manifest.LoadTemplate(filepath.Join(root, "template.manifest.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = preflightGenerators(root, fixture, tpl, settings.Values{})
			if err == nil || !strings.Contains(err.Error(), mutation.want) {
				t.Fatalf("got %v, want own anchor/marker error %q before target collision", err, mutation.want)
			}
			after, err := fixtureSnapshot(fixture)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("preflight changed fixture: %v", err)
			}
		})
	}
}
