package mcpsrv

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// toolsGoldenPath pins the complete MCP tool surface. A work package that adds
// or removes a tool updates this file in the same change; merge conflicts are
// resolved by a sorted union.
const toolsGoldenPath = "testdata/tools.golden.txt"

// TestToolRegistryGolden asserts that the sorted list of registered tool names
// equals the golden file. Regenerate deliberately with
//
//	TPLAITER_UPDATE_GOLDEN=1 go test -run TestToolRegistryGolden ./internal/mcpsrv/
//
// and review the diff.
func TestToolRegistryGolden(t *testing.T) {
	srv := New("/nonexistent/tplaiter", "test", nil)
	registered := srv.MCP().ListTools()
	names := make([]string, 0, len(registered))
	for name := range registered {
		names = append(names, name)
	}
	sort.Strings(names)
	got := strings.Join(names, "\n") + "\n"

	if os.Getenv("TPLAITER_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(toolsGoldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(toolsGoldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(toolsGoldenPath)
	if err != nil {
		t.Fatalf("read %s: %v", toolsGoldenPath, err)
	}
	if got != string(want) {
		t.Fatalf("registered MCP tools differ from %s\n--- got ---\n%s--- want ---\n%s", toolsGoldenPath, got, want)
	}
}

// TestToolRegistrarsAreUniqueDomains guards the registration list itself: every
// domain registers at least one tool and no tool name is registered twice
// (mcp-go would silently replace the earlier handler).
func TestToolRegistrarsAreUniqueDomains(t *testing.T) {
	srv := New("/nonexistent/tplaiter", "test", nil)
	total := len(srv.MCP().ListTools())
	seen := 0
	for i, register := range toolRegistrars {
		probe := New("/nonexistent/tplaiter", "test", nil)
		probe.mcp.DeleteTools(toolNames(probe)...)
		register(probe)
		added := len(probe.MCP().ListTools())
		if added == 0 {
			t.Fatalf("registrar %d registers no tools", i)
		}
		seen += added
	}
	if seen != total {
		t.Fatalf("registrars add %d tools in isolation but %d when combined: a tool name is registered twice", seen, total)
	}
}

func toolNames(s *Server) []string {
	tools := s.MCP().ListTools()
	names := make([]string, 0, len(tools))
	for name := range tools {
		names = append(names, name)
	}
	return names
}
