package cmd

import (
	"strings"
	"testing"
)

func TestMCPServerHelpUsesTplaiterIdentity(t *testing.T) {
	cmd := newMCPServerCmd()
	help := cmd.Short + "\n" + cmd.Long
	if !strings.Contains(help, "tplaiter") {
		t.Fatalf("MCP help does not identify tplaiter: %q", help)
	}
	if strings.Contains(help, "tplater") {
		t.Fatalf("MCP help contains legacy executable identity: %q", help)
	}
}
