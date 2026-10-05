package cmd

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// wantPrerunClass pins the pre-run class of every command that is not
// stateful. Commands missing from this table must classify as stateful.
// A work package that adds a readonly, trust-owned or legacy-action command
// adds its row here together with the annotation in its own file.
var wantPrerunClass = map[string]prerunClass{
	"tplaiter diff":                prerunTrustOwned,
	"tplaiter verify":              prerunTrustOwned,
	"tplaiter check":               prerunTrustOwned,
	"tplaiter deps verify":         prerunTrustOwned,
	"tplaiter ai gen":              prerunLegacyAction, // preserved name collision, see ai.go
	"tplaiter doctor":              prerunReadonly,
	"tplaiter env list":            prerunReadonly,
	"tplaiter env setup":           prerunLegacyAction,
	"tplaiter gen":                 prerunTrustOwned,
	"tplaiter gen batch":           prerunTrustOwned,
	"tplaiter gen list":            prerunTrustOwned,
	"tplaiter migrate-state":       prerunTrustOwned,
	"tplaiter new":                 prerunTrustOwned,
	"tplaiter repo update":         prerunTrustOwned, // preserved name collision, see repo.go
	"tplaiter run":                 prerunLegacyAction,
	"tplaiter settings":            prerunTrustOwned,
	"tplaiter settings list":       prerunTrustOwned,
	"tplaiter settings set":        prerunTrustOwned,
	"tplaiter settings edit":       prerunTrustOwned,
	"tplaiter trust":               prerunTrustOwned,
	"tplaiter trust contexts":      prerunTrustOwned,
	"tplaiter trust inspect":       prerunTrustOwned,
	"tplaiter trust provision":     prerunTrustOwned,
	"tplaiter trust recover-state": prerunTrustOwned,
	"tplaiter trust refresh":       prerunTrustOwned,
	"tplaiter update":              prerunTrustOwned,
	"tplaiter update abort":        prerunTrustOwned,
	"tplaiter update continue":     prerunTrustOwned,
	"tplaiter version":             prerunReadonly,
}

// wantPrerunNoArgsClass pins classes that differ when a command runs without
// positional arguments.
var wantPrerunNoArgsClass = map[string]prerunClass{
	"tplaiter run": prerunReadonly, // bare `run` lists the available commands
}

func walkCommands(root *cobra.Command, visit func(*cobra.Command)) {
	visit(root)
	for _, c := range root.Commands() {
		walkCommands(c, visit)
	}
}

// TestPreRunClassification pins the annotation-based pre-run class of every
// command in the tree, with and without positional arguments.
func TestPreRunClassification(t *testing.T) {
	for _, tree := range []struct {
		name string
		root *cobra.Command
	}{{"rootCmd", rootCmd}, {"newTrustRootCommand", newTrustRootCommand(invocation{})}} {
		seen := map[string]bool{}
		walkCommands(tree.root, func(c *cobra.Command) {
			if !c.HasParent() || c.Name() == "help" || c.Name() == "completion" || (c.HasParent() && c.Parent().Name() == "completion") {
				return
			}
			path := c.CommandPath()
			seen[path] = true
			want, ok := wantPrerunClass[path]
			if !ok {
				want = prerunStateful
			}
			if got := classifyPrerun(c, []string{"arg"}); got != want {
				t.Errorf("%s: %q with args = %q, want %q", tree.name, path, got, want)
			}
			wantNoArgs, ok := wantPrerunNoArgsClass[path]
			if !ok {
				wantNoArgs = want
			}
			if got := classifyPrerun(c, nil); got != wantNoArgs {
				t.Errorf("%s: %q without args = %q, want %q", tree.name, path, got, wantNoArgs)
			}
		})
		for path := range wantPrerunClass {
			if !seen[path] {
				t.Errorf("%s: classified command %q is not in the tree", tree.name, path)
			}
		}
	}
}

// TestPreRunClassificationMatchesLegacySwitch proves the annotation classifier
// reproduces the removed name-based switch (legacyActionCommand,
// descriptiveCommand and the migrate-state/new/update/trust checks) for every
// command except the delivered native gen/gen batch, settings parent/list/set/edit,
// and update abort/continue
// transitions. Those commands now own authenticated composition and skip
// legacy hooks.
// Readonly and trust-owned both skip legacy hooks and compare as "skip".
func TestPreRunClassificationMatchesLegacySwitch(t *testing.T) {
	legacy := func(cmd *cobra.Command, args []string) string {
		switch cmd.Name() {
		case "run":
			if len(args) != 0 {
				return "refuse"
			}
		case "gen", "batch", "setup":
			return "refuse"
		}
		if cmd.Name() == "doctor" || cmd.Name() == "version" {
			return "skip"
		}
		if cmd.Name() == "run" && len(args) == 0 {
			return "skip"
		}
		if cmd.Name() == "list" && cmd.Parent() != nil && (cmd.Parent().Name() == "gen" || cmd.Parent().Name() == "env") {
			return "skip"
		}
		if cmd.Name() == "verify" || cmd.Name() == "check" || cmd.Name() == "migrate-state" || cmd.Name() == "new" || cmd.Name() == "update" {
			return "skip"
		}
		if cmd.Name() == "trust" || (cmd.Parent() != nil && cmd.Parent().Name() == "trust") {
			return "skip"
		}
		return "hooks"
	}
	current := func(cmd *cobra.Command, args []string) string {
		switch classifyPrerun(cmd, args) {
		case prerunLegacyAction:
			return "refuse"
		case prerunReadonly, prerunTrustOwned:
			return "skip"
		case prerunStateful:
		}
		return "hooks"
	}
	walkCommands(rootCmd, func(c *cobra.Command) {
		if !c.HasParent() {
			return
		}
		for _, args := range [][]string{nil, {"arg"}} {
			want := legacy(c, args)
			switch c.CommandPath() {
			case "tplaiter settings", "tplaiter settings list", "tplaiter settings set", "tplaiter settings edit":
				if want != "hooks" {
					t.Errorf("%q: historical settings baseline=%s, want hooks", c.CommandPath(), want)
				}
				want = "skip" // Native settings owns its authenticated boundary.
			}
			if c.CommandPath() == "tplaiter gen" || c.CommandPath() == "tplaiter gen batch" {
				if want != "refuse" {
					t.Errorf("%q: historical gen baseline=%s, want refuse", c.CommandPath(), want)
				}
				want = "skip" // Native composition owns its action/refusal boundary.
			}
			if c.CommandPath() == "tplaiter update abort" || c.CommandPath() == "tplaiter update continue" {
				if want != "hooks" {
					t.Errorf("%q: historical update recovery baseline=%s, want hooks", c.CommandPath(), want)
				}
				want = "skip" // Native recovery owns its authenticated boundary.
			}
			if got := current(c, args); got != want {
				t.Errorf("%q args=%v: classifier=%s legacy=%s", c.CommandPath(), args, got, want)
			}
		}
	})
}

// TestTrustRootCommandMatchesRootTree proves the per-invocation root built by
// newTrustRootCommand has exactly the production command tree.
func TestTrustRootCommandMatchesRootTree(t *testing.T) {
	paths := func(root *cobra.Command) string {
		var out []string
		walkCommands(root, func(c *cobra.Command) { out = append(out, c.CommandPath()) })
		sort.Strings(out)
		return strings.Join(out, "\n")
	}
	if got, want := paths(newTrustRootCommand(invocation{})), paths(rootCmd); got != want {
		t.Fatalf("newTrustRootCommand tree differs from rootCmd\n--- trust root ---\n%s\n--- rootCmd ---\n%s", got, want)
	}
}
