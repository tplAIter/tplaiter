package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWritesLinkerPins(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "trust")
	var out bytes.Buffer
	if err := run([]string{"--root", root}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || lines[0] != "REGISTRATION_PATH="+filepath.Join(root, "registration.json") || !strings.HasPrefix(lines[1], "REGISTRATION_SHA256=sha256:") {
		t.Fatalf("unexpected pins:\n%s", out.String())
	}
	pinsFile := filepath.Join(dir, "pins")
	if err := run([]string{"--root", root, "--output", pinsFile}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run --output: %v", err)
	}
	raw, err := os.ReadFile(pinsFile)
	if err != nil || string(raw) != out.String() {
		t.Fatalf("reinstall pins differ: %q vs %q (%v)", raw, out.String(), err)
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publishers := filepath.Join(dir, "publishers.json")
	if err := os.WriteFile(publishers, []byte(`[{"issuer":"x","unknown":1}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"missing_root":       {},
		"extra_argument":     {"--root", filepath.Join(dir, "a"), "extra"},
		"spaces_in_root":     {"--root", filepath.Join(dir, "with space")},
		"unknown_field":      {"--root", filepath.Join(dir, "b"), "--publishers", publishers},
		"missing_publishers": {"--root", filepath.Join(dir, "c"), "--publishers", filepath.Join(dir, "absent.json")},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted %v", name, args)
		}
	}
}

func TestRunFiniteProjectInputAndClosedPublicPackage(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	contexts := filepath.Join(dir, "contexts.json")
	raw := `[{"key":"a","projectID":"project-a","submitterPrincipalID":"principal:operator","minimumProfile":"oss","rootPath":"` + filepath.Join(dir, "project-a") + `"},{"key":"b","projectID":"project-b","submitterPrincipalID":"principal:operator","minimumProfile":"oss","rootPath":"` + filepath.Join(dir, "project-b") + `"}]`
	if err := os.WriteFile(contexts, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"--root", filepath.Join(dir, "trust"), "--project-contexts", contexts}, &out); err != nil {
		t.Fatal(err)
	}
	packages := filepath.Join(dir, "sources.json")
	if err := os.WriteFile(packages, []byte(`[{"apiVersion":"tplaiter.dev/initial-source-package/v1","publicKey":"self-selected"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--root", filepath.Join(dir, "bad"), "--source-packages", packages}, &out); err == nil {
		t.Fatal("package supplied key accepted")
	}
}
