package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMakeInstallPinnedRouteRejectsEnrollmentBeforeRecipes(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	// A copied Makefile isolates the test from build products and recursively
	// executing recipes. Conflicts must fail even under -n before emitting any
	// build/install recipe, and real invocations must leave all outputs absent.
	dir := t.TempDir()
	path := filepath.Join(dir, "Makefile")
	if err := os.WriteFile(path, makefile, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, variable := range []string{"TRUST_LOCAL_SOURCES", "TRUST_PROJECT_CONTEXTS", "TRUST_SOURCE_PACKAGES", "TRUST_PUBLISHERS", "TRUST_ROTATE"} {
		for _, dry := range []bool{true, false} {
			t.Run(variable+"-dry="+strconv.FormatBool(dry), func(t *testing.T) {
				args := []string{"-f", path}
				if dry {
					args = append(args, "-n")
				}
				args = append(args, "build", "install", "REGISTRATION_PATH=/public/registration.json", "REGISTRATION_SHA256=sha256:"+strings.Repeat("a", 64), variable+"=explicit")
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "make", args...)
				cmd.Dir = dir
				raw, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(string(raw), "conflict with trust enrollment inputs") {
					t.Fatalf("expected route refusal, got %s (%v)", raw, err)
				}
				for _, recipe := range []string{"go build", "go run", "install -", "mkdir -p"} {
					if strings.Contains(string(raw), recipe) {
						t.Fatal("route conflict reached recipe output")
					}
				}
				if _, err := os.Stat(filepath.Join(dir, "bin")); !os.IsNotExist(err) {
					t.Fatal("route conflict allocated build output")
				}
			})
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Existing pins alone still produce the expected linker/build/install route.
	cmd := exec.CommandContext(ctx, "make", "-n", "-f", path, "install", "REGISTRATION_PATH=/public/registration.json", "REGISTRATION_SHA256=sha256:"+strings.Repeat("a", 64))
	cmd.Dir = dir
	raw, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(raw), "installedRegistrationPath=/public/registration.json") || strings.Contains(string(raw), "go run ./cmd/tplaiter-oss-register") {
		t.Fatalf("pinned route regression: %s (%v)", raw, err)
	}
}
