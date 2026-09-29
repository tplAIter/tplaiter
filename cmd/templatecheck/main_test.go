package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsUnsafeRootsAndOutputs(t *testing.T) {
	source := writeTemplate(t, false)
	outside := t.TempDir()
	tests := []struct {
		name   string
		root   func(t *testing.T) string
		output func(t *testing.T) string
	}{
		{"symlink template root", func(t *testing.T) string { return symlink(t, source) }, func(t *testing.T) string { return filepath.Join(t.TempDir(), "out") }},
		{"template contains symlink", func(t *testing.T) string {
			root := writeTemplate(t, false)
			symlinkAt(t, filepath.Join(root, "files", "escape"), outside)
			return root
		}, func(t *testing.T) string { return filepath.Join(t.TempDir(), "out") }},
		{"symlink output root", func(t *testing.T) string { return source }, func(t *testing.T) string { return symlink(t, outside) }},
		{"output inside source", func(t *testing.T) string { return source }, func(t *testing.T) string { return filepath.Join(source, "rendered") }},
		{"nonempty output", func(t *testing.T) string { return source }, func(t *testing.T) string {
			out := filepath.Join(t.TempDir(), "out")
			if err := os.Mkdir(out, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "kept"), []byte("kept"), 0o644); err != nil {
				t.Fatal(err)
			}
			return out
		}},
		{"output parent symlink escaping source", func(t *testing.T) string { return source }, func(t *testing.T) string { parent := symlink(t, source); return filepath.Join(parent, "out") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(tc.root(t), tc.output(t), "", false, &stdout, &stderr); err == nil {
				t.Fatal("run succeeded for unsafe fixture")
			}
		})
	}
}

func TestRunRendersIntoOwnedOutputAndFailsClosedOnLint(t *testing.T) {
	root := writeTemplate(t, false)
	out := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	if err := run(root, out, "", true, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	found := false
	if err := filepath.WalkDir(out, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "main.txt" {
			found = true
		}
		return nil
	}); err != nil || !found {
		t.Fatalf("rendered fixture missing main.txt: %v", err)
	}
	bad := writeTemplate(t, true)
	if err := run(bad, filepath.Join(t.TempDir(), "bad-out"), "", false, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "lint failed") {
		t.Fatalf("run error = %v, want failed lint", err)
	}
}

func TestComboDestinationCannotTraverseOutput(t *testing.T) {
	name := safeComboName("../../outside")
	if name != "..-..-outside" {
		t.Fatalf("safeComboName = %q", name)
	}
	output := t.TempDir()
	destination := filepath.Join(output, name)
	if !isWithin(destination, output) {
		t.Fatalf("destination %q escapes output %q", destination, output)
	}
}

func writeTemplate(t *testing.T, brokenNotes bool) string {
	t.Helper()
	root := t.TempDir()
	manifest := "apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: ci-test\n  version: 1.0.0\nengine:\n  type: gotemplate\n  root: files\n"
	if brokenNotes {
		manifest = strings.Replace(manifest, "engine:\n", "  notes: NOTES.tmpl\nengine:\n", 1)
	}
	for path, content := range map[string]string{"template.manifest.yaml": manifest, "files/main.txt.tmpl": "hello {{ .Project.Slug }}\n"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func symlink(t *testing.T, target string) string {
	t.Helper()
	link := filepath.Join(t.TempDir(), "link")
	symlinkAt(t, link, target)
	return link
}

func symlinkAt(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
