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

// genRunner — runner for formatter/build-gate post-steps of [gen.Generate].
// A package variable like runRunner (run.go), replaceable in command-level
// gen tests.
var genRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newGenCmd)
}

// newGenCmd creates `tplater gen <kind> <name> [--<param> ...]` (SPEC-01 §6,
// CG-1): a project scaffolder based on the linked template's Generators
// manifest (see [loadRunContext]).
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
		Annotations: prerunAnnotations(prerunLegacyAction),

		Use:   "gen <kind> <name> [--<param> ...]",
		Short: "Template scaffolder: create file(s) of kind <kind> with name <name>",
		Long: "Generates files and anchor insertions according to the template manifest generators (SPEC-01 §6). " +
			"The kind and its snippets come from the template, not from the tplater binary — " +
			"`tplater gen list` shows available kinds for the current project.\n\n" +
			"Generator parameters (Generator.params) become flags: `--fields \"name:type,...\"` " +
			"and arbitrary `--<param>`; required parameters without a value are an error.\n\n" +
			"Idempotency: running gen again with the same name is an error (target file already " +
			"exists or insertion marker is already present in the anchor file). " +
			"After writing, Go projects are formatted with gofumpt (best-effort), then " +
			"commands.build.run from the manifest is executed (or legacy fallback `go build ./...`); " +
			"an error rolls back changes — see --no-build.",
		DisableFlagParsing: true,
		RunE:               runGen,
	}
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
		return errors.New("gen requires arguments <kind> <name> (see `tplater gen list`)")
	}
	kind, name := args[0], args[1]
	if len(kind) > 0 && kind[0] == '-' {
		return fmt.Errorf("gen: first argument expected <kind>, got flag %q", kind)
	}
	if len(name) > 0 && name[0] == '-' {
		return fmt.Errorf("gen: second argument expected <name>, got flag %q", name)
	}
	return actionUnavailable()
	/*
		rest := args[2:]

		tpl, proj, root, err := loadRunContext()
		if err != nil {
			return err
		}
		g, err := gen.Lookup(tpl, kind)
		if err != nil {
			return err
		}

		// Build the FlagSet from generator params plus the shared --no-build.
		fs := pflag.NewFlagSet("gen "+kind, pflag.ContinueOnError)
		fs.SetOutput(cmd.OutOrStderr())
		noBuild := fs.Bool("no-build", false, "skip the build gate after generation")
		for i := range g.Params {
			p := &g.Params[i]
			fs.String(p.Name, gen.DefaultFor(p), paramUsage(p))
		}
		if err := fs.Parse(rest); err != nil {
			return fmt.Errorf("gen %s: flag parsing: %w", kind, err)
		}

		// Collect only EXPLICITLY set parameter flags (Changed) for ResolveParams.
		provided := make(map[string]string)
		fs.Visit(func(f *pflag.Flag) {
			if f.Name == "no-build" {
				return
			}
			provided[f.Name] = f.Value.String()
		})
		params, fields, err := gen.ResolveParams(g, provided)
		if err != nil {
			return fmt.Errorf("gen %s: %w", kind, err)
		}

		res, err := gen.Generate(cmd.Context(), tpl, kind, name, gen.Options{
			ProjectRoot:   root,
			GeneratorsDir: filepath.Join(root, gen.GeneratorsRelPath),
			Values:        settingsValues(proj.Settings),
			Project:       proj.Project,
			Fields:        fields,
			Params:        params,
			NoBuild:       *noBuild,
			Runner:        genRunner,
			Logf: func(format string, a ...any) {
				fmt.Fprintf(cmd.OutOrStdout(), format+"\n", a...)
			},
		})
		if err != nil {
			return err
		}
		return printGenResult(cmd, res)
	*/
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

// newGenListCmd creates `tplater gen list`.
func newGenListCmd() *cobra.Command {
	return withResult(&cobra.Command{
		Annotations: prerunAnnotations(prerunReadonly),

		Use:   "list",
		Short: "List of scaffold kinds from template manifest (kind/description/available)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tpl, proj, _, err := loadRunContext()
			if err != nil {
				return err
			}
			values := settingsValues(proj.Settings)
			statuses := gen.List(tpl, values)
			if jsonMode(cmd) {
				return emitGenList(cmd, statuses)
			}
			return printGenList(cmd, statuses)
		},
	}, resultdto.OperationGenList)
}

// emitGenList prints the generators of the project template as gen.list
// data, sorted by kind.
func emitGenList(cmd *cobra.Command, statuses []gen.Status) error {
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Kind < statuses[j].Kind })
	data := resultdto.GenListData{Generators: []resultdto.GeneratorInfo{}}
	for _, st := range statuses {
		data.Generators = append(data.Generators, resultdto.GeneratorInfo{Kind: st.Kind, Description: st.Description, Available: st.Available, Reason: st.Reason})
	}
	return emitData(cmd, resultdto.OperationGenList, currentProject(), data)
}

// genBatchInput — JSON representation of one CLI/MCP batch operation. Parameters
// remain strings, as for the MCP gen tool; typing occurs only after looking up
// the specific generator through gen.ResolveParams.
type genBatchInput struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Params map[string]string `json:"params"`
}

// newGenBatchCmd creates `tplater gen batch --operations <JSON>`. JSON gives the
// CLI a portable non-interactive format for a complex operation list; MCP adds
// a typed operations array on top (see gen_batch).
func newGenBatchCmd() *cobra.Command {
	var operationsJSON string
	var noBuild bool
	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunLegacyAction),

		Use:   "batch --operations <JSON> [--no-build]",
		Short: "Generate multiple scaffolds with single build and atomic rollback",
		Long: "Plans all operations before the first write, then creates files and executes a single final " +
			"build-gate (commands.build.run from manifest or legacy fallback `go build ./...`). " +
			"On error at any step, changes from all operations are rolled back.\n\n" +
			"Format --operations: '[{\"kind\":\"crud\",\"name\":\"Ride\",\"params\":{\"fields\":\"status:string\"}}]'.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Keep input-only validation available to direct callers.  The
			// denial follows before project discovery or any generator effect.
			if operationsJSON == "" {
				return errors.New("gen batch: --operations with JSON array of operations is required")
			}
			var input []genBatchInput
			if err := json.Unmarshal([]byte(operationsJSON), &input); err != nil {
				return fmt.Errorf("gen batch: parsing --operations JSON: %w", err)
			}
			if len(input) == 0 {
				return errors.New("gen batch: operation list is empty")
			}
			for i, item := range input {
				if item.Kind == "" || item.Name == "" {
					return fmt.Errorf("gen batch: operation %d requires kind and name", i+1)
				}
			}
			return actionUnavailable()
			/*
				if operationsJSON == "" {
					return errors.New("gen batch: --operations with a JSON array of operations is required")
				}
				var input []genBatchInput
				if err := json.Unmarshal([]byte(operationsJSON), &input); err != nil {
					return fmt.Errorf("gen batch: parsing --operations JSON: %w", err)
				}
				if len(input) == 0 {
					return errors.New("gen batch: operation list is empty")
				}
				for i, item := range input {
					if item.Kind == "" || item.Name == "" {
						return fmt.Errorf("gen batch: operation %d requires kind and name", i+1)
					}
				}

				tpl, proj, root, err := loadRunContext()
				if err != nil {
					return err
				}
				operations := make([]gen.Operation, 0, len(input))
				for i, item := range input {
					g, lookupErr := gen.Lookup(tpl, item.Kind)
					if lookupErr != nil {
						return fmt.Errorf("gen batch: operation %d: %w", i+1, lookupErr)
					}
					if err := validateGenBatchParams(g.Params, item.Params); err != nil {
						return fmt.Errorf("gen batch: operation %d (%s %s): %w", i+1, item.Kind, item.Name, err)
					}
					params, fields, resolveErr := gen.ResolveParams(g, item.Params)
					if resolveErr != nil {
						return fmt.Errorf("gen batch: operation %d (%s %s): %w", i+1, item.Kind, item.Name, resolveErr)
					}
					operations = append(operations, gen.Operation{Kind: item.Kind, Name: item.Name, Params: params, Fields: fields})
				}

				res, generateErr := gen.GenerateBatch(cmd.Context(), tpl, operations, gen.Options{
					ProjectRoot: root, GeneratorsDir: filepath.Join(root, gen.GeneratorsRelPath),
					Values: settingsValues(proj.Settings), Project: proj.Project, NoBuild: noBuild,
					Runner: genRunner,
					Logf:   func(format string, a ...any) { fmt.Fprintf(cmd.OutOrStdout(), format+"\n", a...) },
				})
				if generateErr != nil {
					return generateErr
				}
				return printGenBatchResult(cmd, res)
			*/
		},
	}
	c.Flags().StringVar(&operationsJSON, "operations", "", "JSON array of operations {kind,name,params}")
	c.Flags().BoolVar(&noBuild, "no-build", false, "skip the single final build-gate")
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

// printGenResult prints created/changed files.
func printGenResult(cmd *cobra.Command, res *gen.Result) error {
	out := cmd.OutOrStdout()
	for _, f := range res.CreatedFiles {
		fmt.Fprintf(out, "created %s\n", f)
	}
	for _, f := range res.EditedFiles {
		fmt.Fprintf(out, "edited %s\n", f)
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
