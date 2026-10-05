package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// genRunner is retained as a regression canary for legacy command tests.
// Native command composition uses the concrete project transaction API.
var genRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newGenCmd)
}

// newGenCmd creates `tplaiter gen <kind> <name> [--<param> ...]` (SPEC-01 §6,
// CG-1): a project scaffolder based on the authenticated native manifest.
//
// Dynamic flags are handled manually because the set depends on the selected
// generator's parameters (Generator.Params), while kind is known only at run
// time. The command therefore uses DisableFlagParsing=true: cobra does not
// parse flags; we extract positional <kind> <name>, build a pflag.FlagSet from
// the generator params (plus --no-build), and parse the remaining arguments.
// The `gen list` subcommand works normally: cobra routes to it by name before
// parsing the parent's flags.
func newGenCmd() *cobra.Command {
	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunTrustOwned),

		Use:   "gen <kind> <name> [--<param> ...]",
		Short: "Template scaffolder: create file(s) of kind <kind> with name <name>",
		Long: "Generates files and anchor insertions according to the template manifest generators (SPEC-01 §6). " +
			"The kind and its snippets come from the template, not from the tplaiter binary — " +
			"`tplaiter gen list` shows available kinds for the current project.\n\n" +
			"Generator parameters (Generator.params) become flags: `--fields \"name:type,...\"` " +
			"and arbitrary `--<param>`; required parameters without a value are an error.\n\n" +
			"Idempotency: running gen again with the same name is an error (target file already " +
			"exists or insertion marker is already present in the anchor file). " +
			"Native generation currently supports file-only transactions with --no-build. " +
			"Build, formatter and hook execution are unavailable and refuse before writes.",
		DisableFlagParsing: true,
		RunE:               runGen,
	}
	addNativeGenFlags(c, nil)
	c.AddCommand(newGenListCmd())
	c.AddCommand(newGenBatchCmd())
	// DisableFlagParsing: --json is recognized from the raw arguments by the
	// exit registry (jsonRequested); the flag is declared for help and parity.
	return withResult(c, resultdto.OperationGenRun)
}

// runGen — manual parsing of `gen` arguments (DisableFlagParsing=true).
func runGen(cmd *cobra.Command, args []string) error {
	// -h/--help as the first argument prints help and exits.
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		return cmd.Help()
	}
	if len(args) < 2 {
		return errors.New("gen requires arguments <kind> <name> (see `tplaiter gen list`)")
	}
	kind, name := args[0], args[1]
	if len(kind) > 0 && kind[0] == '-' {
		return fmt.Errorf("gen: first argument expected <kind>, got flag %q", kind)
	}
	if len(name) > 0 && name[0] == '-' {
		return fmt.Errorf("gen: second argument expected <name>, got flag %q", name)
	}
	controls, rest, err := parseNativeGenControls(cmd, args[2:])
	if err != nil {
		return &usageError{err: err}
	}
	if controls.help {
		return cmd.Help()
	}
	return runNativeGen(cmd, controls, []genBatchInput{{Kind: kind, Name: name}}, rest)
}

// paramUsage builds parameter-flag help text (type plus description).
func paramUsage(p *manifest.Param) string {
	usage := "[" + p.Type + "]"
	if p.Required {
		usage += " (required)"
	}
	if p.Description != "" {
		usage += " " + p.Description
	}
	return usage
}

// newGenListCmd creates `tplaiter gen list`.
func newGenListCmd() *cobra.Command {
	var controls nativeGenControls
	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunTrustOwned),
		Use:         "list", Short: "List generators from the authenticated native project", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return listNativeGen(cmd, controls) },
	}
	addNativeGenFlags(c, &controls)
	return withResult(c, resultdto.OperationGenList)
}

// genBatchInput — JSON representation of one CLI/MCP batch operation. Parameters
// remain strings, as for the MCP gen tool; typing occurs only after looking up
// the specific generator through gen.ResolveParams.
type genBatchInput struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Params map[string]string `json:"params"`
}

// newGenBatchCmd creates `tplaiter gen batch --operations <JSON>`. JSON gives the
// CLI a portable non-interactive format for a complex operation list; MCP adds
// a typed operations array on top (see gen_batch).
func newGenBatchCmd() *cobra.Command {
	var operationsJSON string
	var controls nativeGenControls
	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunTrustOwned),

		Use:   "batch --operations <JSON> [--no-build]",
		Short: "Generate multiple scaffolds in one native transaction",
		Long: "Plans all operations before the first write and commits them in one native transaction. " +
			"File-only generation requires --no-build; executable actions are unavailable.\n\n" +
			"Format --operations: '[{\"kind\":\"crud\",\"name\":\"Ride\",\"params\":{\"fields\":\"status:string\"}}]'.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Validate bounded input before project discovery or generator effects.
			if operationsJSON == "" {
				return &usageError{err: errors.New("gen batch: --operations with JSON array of operations is required")}
			}
			if len(operationsJSON) > 1<<20 {
				return &usageError{err: errors.New("gen batch: operations JSON exceeds 1 MiB")}
			}
			var input []genBatchInput
			if err := json.Unmarshal([]byte(operationsJSON), &input); err != nil {
				return &usageError{err: fmt.Errorf("gen batch: parsing --operations JSON: %w", err)}
			}
			if len(input) > 256 {
				return &usageError{err: errors.New("gen batch: at most 256 operations are supported")}
			}
			if len(input) == 0 {
				return &usageError{err: errors.New("gen batch: operation list is empty")}
			}
			for i, item := range input {
				if item.Kind == "" || item.Name == "" {
					return &usageError{err: fmt.Errorf("gen batch: operation %d requires kind and name", i+1)}
				}
			}
			return runNativeGen(cmd, controls, input, nil)
		},
	}
	c.Flags().StringVar(&operationsJSON, "operations", "", "JSON array of operations {kind,name,params}")
	addNativeGenFlags(c, &controls)
	return withResult(c, resultdto.OperationGenBatch)
}

func validateGenBatchParams(declared []manifest.Param, provided map[string]string) error {
	known := make(map[string]struct{}, len(declared))
	for _, p := range declared {
		known[p.Name] = struct{}{}
	}
	for name := range provided {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("unknown parameter --%s", name)
		}
	}
	return nil
}

func printGenBatchResult(cmd *cobra.Command, res *gen.BatchResult) error {
	out := cmd.OutOrStdout()
	for _, f := range res.CreatedFiles {
		fmt.Fprintf(out, "created %s\n", f)
	}
	for _, f := range res.EditedFiles {
		fmt.Fprintf(out, "edited %s\n", f)
	}
	return nil
}

// printGenList prints a KIND/DESCRIPTION/AVAILABLE table (unavailable kinds
// are dimmed with the reason, following [whenCell] in run.go).
func printGenList(cmd *cobra.Command, statuses []gen.Status) error {
	out := cmd.OutOrStdout()
	if len(statuses) == 0 {
		fmt.Fprintln(out, "template manifest does not declare generators (generators)")
		return nil
	}

	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Kind < statuses[j].Kind })

	pal := ui.Default()
	table := ui.NewTable("KIND", "DESCRIPTION", "AVAILABLE")
	for _, st := range statuses {
		table.AddRow(st.Kind, st.Description, genAvailableCell(pal, st))
	}
	fmt.Fprintln(out, table.RenderStyled(pal))
	return nil
}

// genAvailableCell builds the last `gen list` column: "yes" or a dimmed
// "no — requires <condition>" mark.
func genAvailableCell(pal ui.Palette, st gen.Status) string {
	if st.Available {
		return ui.StatusIcon(pal, ui.StatusOK) + " yes"
	}
	reason := st.Reason
	if reason == "" {
		reason = "unavailable with current settings"
	}
	return ui.StatusIcon(pal, ui.StatusWarn) + " " + pal.Muted("no — requires: "+reason)
}
