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
		Short: "Скаффолдер шаблона: создать файл(ы) вида <kind> с именем <name>",
		Long: "Генерирует файлы и вставки якорей по generators манифеста шаблона (SPEC-01 §6). " +
			"Вид (kind) и его сниппеты приходят из шаблона, не из бинарника tplater — " +
			"`tplater gen list` показывает доступные виды текущего проекта.\n\n" +
			"Параметры генератора (Generator.params) становятся флагами: `--fields \"name:type,...\"` " +
			"и произвольные `--<param>`; обязательные без значения — ошибка.\n\n" +
			"Идемпотентность: повторный gen с тем же именем — ошибка (целевой файл уже " +
			"существует либо маркер вставки уже присутствует в якорном файле). " +
			"После записи Go-проекты форматируются gofumpt (best-effort), затем выполняется " +
			"commands.build.run манифеста (либо legacy fallback `go build ./...`); ошибка откатывает изменения — см. --no-build.",
		DisableFlagParsing: true,
		RunE:               runGen,
	}
	c.AddCommand(newGenListCmd())
	c.AddCommand(newGenBatchCmd())
	return c
}

// runGen — manual parsing of `gen` arguments (DisableFlagParsing=true).
func runGen(cmd *cobra.Command, args []string) error {
	// -h/--help as the first argument prints help and exits.
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		return cmd.Help()
	}
	if len(args) < 2 {
		return errors.New("gen требует аргументы <kind> <name> (см. `tplater gen list`)")
	}
	kind, name := args[0], args[1]
	if len(kind) > 0 && kind[0] == '-' {
		return fmt.Errorf("gen: первым аргументом ожидается <kind>, получен флаг %q", kind)
	}
	if len(name) > 0 && name[0] == '-' {
		return fmt.Errorf("gen: вторым аргументом ожидается <name>, получен флаг %q", name)
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
		usage += " (обязателен)"
	}
	if p.Description != "" {
		usage += " " + p.Description
	}
	return usage
}

// newGenListCmd creates `tplater gen list`.
func newGenListCmd() *cobra.Command {
	return &cobra.Command{
		Annotations: prerunAnnotations(prerunReadonly),

		Use:   "list",
		Short: "Список видов скаффолда манифеста шаблона (kind/description/available)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tpl, proj, _, err := loadRunContext()
			if err != nil {
				return err
			}
			values := settingsValues(proj.Settings)
			return printGenList(cmd, gen.List(tpl, values))
		},
	}
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
		Short: "Сгенерировать несколько scaffolds с одной сборкой и атомарным откатом",
		Long: "Планирует все операции до первой записи, затем создаёт файлы и выполняет один финальный " +
			"build-gate (commands.build.run манифеста либо legacy fallback `go build ./...`). При ошибке любого шага изменения всех операций откатываются.\n\n" +
			"Формат --operations: '[{\"kind\":\"crud\",\"name\":\"Ride\",\"params\":{\"fields\":\"status:string\"}}]'.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Keep input-only validation available to direct callers.  The
			// denial follows before project discovery or any generator effect.
			if operationsJSON == "" {
				return errors.New("gen batch: обязателен --operations с JSON-массивом операций")
			}
			var input []genBatchInput
			if err := json.Unmarshal([]byte(operationsJSON), &input); err != nil {
				return fmt.Errorf("gen batch: разбор --operations JSON: %w", err)
			}
			if len(input) == 0 {
				return errors.New("gen batch: список операций пуст")
			}
			for i, item := range input {
				if item.Kind == "" || item.Name == "" {
					return fmt.Errorf("gen batch: операция %d требует kind и name", i+1)
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
	c.Flags().StringVar(&operationsJSON, "operations", "", "JSON-массив операций {kind,name,params}")
	c.Flags().BoolVar(&noBuild, "no-build", false, "пропустить единственный финальный build-gate")
	return c
}

func validateGenBatchParams(declared []manifest.Param, provided map[string]string) error {
	known := make(map[string]struct{}, len(declared))
	for _, p := range declared {
		known[p.Name] = struct{}{}
	}
	for name := range provided {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("неизвестный параметр --%s", name)
		}
	}
	return nil
}

// printGenResult prints created/changed files.
func printGenResult(cmd *cobra.Command, res *gen.Result) error {
	out := cmd.OutOrStdout()
	for _, f := range res.CreatedFiles {
		fmt.Fprintf(out, "создан %s\n", f)
	}
	for _, f := range res.EditedFiles {
		fmt.Fprintf(out, "изменён %s\n", f)
	}
	return nil
}

func printGenBatchResult(cmd *cobra.Command, res *gen.BatchResult) error {
	out := cmd.OutOrStdout()
	for _, f := range res.CreatedFiles {
		fmt.Fprintf(out, "создан %s\n", f)
	}
	for _, f := range res.EditedFiles {
		fmt.Fprintf(out, "изменён %s\n", f)
	}
	return nil
}

// printGenList prints a KIND/DESCRIPTION/AVAILABLE table (unavailable kinds
// are dimmed with the reason, following [whenCell] in run.go).
func printGenList(cmd *cobra.Command, statuses []gen.Status) error {
	out := cmd.OutOrStdout()
	if len(statuses) == 0 {
		fmt.Fprintln(out, "манифест шаблона не объявляет генераторов (generators)")
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
		return ui.StatusIcon(pal, ui.StatusOK) + " да"
	}
	reason := st.Reason
	if reason == "" {
		reason = "недоступно при текущих настройках"
	}
	return ui.StatusIcon(pal, ui.StatusWarn) + " " + pal.Muted("нет — требуется: "+reason)
}
