package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/ossinstall"
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

func TestLocalSourceRouteConflictsProduceNoPins(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{{"--publishers", "unused"}, {"--source-packages", "unused"}, {"--rotate"}, {}} {
		root := filepath.Join(dir, "absent")
		args := append([]string{"--root", root, "--local-sources", "unused"}, extra...)
		var out bytes.Buffer
		if err := run(args, &out); err == nil || out.Len() != 0 {
			t.Fatal("conflicting local route emitted pins")
		}
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatal("conflicting local route created destination")
		}
	}
}

type failingPinWriter struct{}

func (failingPinWriter) Write([]byte) (int, error) { return 0, errors.New("test pin output failure") }

func TestPinOutputFailurePreservesCommittedInstallation(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	contexts := filepath.Join(dir, "contexts.json")
	raw := `[{"key":"a","projectID":"project-a","submitterPrincipalID":"principal:operator","minimumProfile":"oss","rootPath":"` + filepath.Join(dir, "target") + `"}]`
	if err := os.WriteFile(contexts, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "trust")
	err = run([]string{"--root", root, "--project-contexts", contexts}, failingPinWriter{})
	if !errors.Is(err, ossinstall.ErrPublicationCommitted) {
		t.Fatal("pin output failure not reported as committed")
	}
	if _, err := os.Stat(filepath.Join(root, ossinstall.RegistrationFile)); err != nil {
		t.Fatal("committed installation removed after pin output error")
	}
	var output bytes.Buffer
	if err := run([]string{"--root", root, "--project-contexts", contexts}, &output); err != nil || output.Len() == 0 {
		t.Fatal("external exact enrollment cannot reauthenticate after output failure")
	}
}

func TestLocalProviderInputRequiresExplicitContext(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(base, "local.json")
	if err = os.WriteFile(input, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"--root", filepath.Join(base, "install"), "--local-providers", input}, &bytes.Buffer{}); err == nil {
		t.Fatal("implicit project registration")
	}
	if _, err = os.Stat(filepath.Join(base, "install")); !os.IsNotExist(err) {
		t.Fatal("invalid operator input mutated root")
	}
}
