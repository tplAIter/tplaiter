package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestUserFacingHelpUsesCanonicalBinaryName(t *testing.T) {
	root := newRootCommand()
	root.AddCommand(newAICmd(), newAuthCmd(), newEnvCmd(), newProjectsCmd(), newTemplateCmd(), newUpgradeCmd())
	var check func(*cobra.Command)
	check = func(command *cobra.Command) {
		t.Run(command.CommandPath(), func(t *testing.T) {
			var out bytes.Buffer
			command.SetOut(&out)
			if err := command.Help(); err != nil {
				t.Fatal(err)
			}
			help := out.String()
			if !strings.Contains(help, "tplaiter") {
				t.Fatalf("help lacks executable identity: %q", help)
			}
			// Storage/artifact names and review markers remain compatibility tokens.
			identityText := strings.NewReplacer("tplater.db", "", "tplater-upgrade-", "", "TPLATER-REVIEW", "").Replace(help)
			if strings.Contains(strings.ToLower(identityText), "tplater") {
				t.Fatalf("help suggests the legacy executable: %q", help)
			}
			if command.Name() == "auth" && !strings.Contains(help, "~/.tplaiter/tplater.db") {
				t.Fatal("auth help changed the compatible database filename")
			}
			if command.Name() == "upgrade" && (!strings.Contains(help, "TPLATER-REVIEW") || !strings.Contains(help, "./tplater-upgrade-")) {
				t.Fatal("upgrade help changed compatible review markers or artifact paths")
			}
		})
		for _, child := range command.Commands() {
			check(child)
		}
	}
	for _, command := range root.Commands() {
		check(command)
	}
}
