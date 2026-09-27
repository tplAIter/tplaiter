package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelpUsesTplaiterIdentity(t *testing.T) {
	var out bytes.Buffer
	oldOut := rootCmd.OutOrStdout()
	rootCmd.SetOut(&out)
	t.Cleanup(func() { rootCmd.SetOut(oldOut) })
	if err := rootCmd.Help(); err != nil {
		t.Fatalf("rootCmd.Help() error = %v", err)
	}
	help := out.String()
	if !strings.Contains(help, "tplaiter") {
		t.Fatalf("root help does not identify tplaiter: %q", help)
	}
	if strings.Contains(help, "tplater") {
		t.Fatalf("root help contains legacy executable identity: %q", help)
	}
}
