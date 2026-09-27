package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// genRunner — Runner formatter/build-gate пост-шагов [gen.Generate].
// Пакетная переменная по образцу runRunner (run.go) — подмена в тестах при
// появлении cmd-уровневых тестов gen.
var genRunner execx.Runner = execx.Exec{}

func init() {
	rootCmd.AddCommand(newGenCmd())
}

// newGenCmd создаёт команду `tplater gen <kind> <name> [--<param> ...]`
// ( проверку): скаффолдер проекта на основе Generators манифеста
// шаблона, привязанного к текущему проекту (см. [loadRunContext]).
//
// Решение по динамическим флагам: набор флагов зависит от параметров
// конкретного генератора (Generator.Params), а вид (kind) известен лишь во
// время исполнения. Поэтому команда объявлена с DisableFlagParsing=true —
// cobra НЕ парсит флаги сама; мы вручную выделяем позиционные <kind> <name>,
// затем строим pflag.FlagSet по params найденного генератора (+ общий
// --no-build) и разбираем остаток аргументов. Подкоманда `gen list` работает
// как обычно: cobra маршрутизирует к ней по имени до разбора флагов родителя.
func newGenCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "gen <kind> <name> [--<param> ...]",
		Short: "Скаффолдер шаблона: создать файл(ы) вида <kind> с именем <name>",
		Long: "Генерирует файлы и вставки якорей по generators манифеста шаблона. " +
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

// runGen — ручной разбор аргументов команды `gen` (DisableFlagParsing=true).
func runGen(cmd *cobra.Command, args []string) error {
	// -h/--help как первый аргумент — печатаем справку и выходим.
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
	rest := args[2:]

	tpl, proj, root, err := loadRunContext()
	if err != nil {
		return err
	}
	g, err := gen.Lookup(tpl, kind)
	if err != nil {
		return err
	}

	// Строим FlagSet по параметрам генератора + общий --no-build.
	fs := pflag.NewFlagSet("gen "+kind, pflag.ContinueOnError)
	fs.SetOutput(cmd.OutOrStderr())
	noBuild := fs.Bool("no-build", false, "пропустить build-gate после генерации")
	for i := range g.Params {
		p := &g.Params[i]
		fs.String(p.Name, gen.DefaultFor(p), paramUsage(p))
	}
	if err := fs.Parse(rest); err != nil {
		return fmt.Errorf("gen %s: разбор флагов: %w", kind, err)
	}

	// Собираем только ЯВНО заданные флаги-параметры (Changed) для ResolveParams.
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
}

// paramUsage формирует строку справки флага-параметра (тип + описание).
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

// newGenListCmd создаёт `tplater gen list`.
func newGenListCmd() *cobra.Command {
	return &cobra.Command{
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

// genBatchInput — JSON-представление одной batch-операции CLI/MCP. Параметры
// оставлены строками, как у MCP tool gen: их типизация выполняется только
// после Lookup конкретного generator через gen.ResolveParams.
type genBatchInput struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Params map[string]string `json:"params"`
}

// newGenBatchCmd создаёт `tplater gen batch --operations <JSON>`. JSON нужен
// CLI как переносимый неинтерактивный формат сложного списка операций; MCP
// предоставляет поверх него типизированный массив operations (см. gen_batch).
func newGenBatchCmd() *cobra.Command {
	var operationsJSON string
	var noBuild bool
	c := &cobra.Command{
		Use:   "batch --operations <JSON> [--no-build]",
		Short: "Сгенерировать несколько scaffolds с одной сборкой и атомарным откатом",
		Long: "Планирует все операции до первой записи, затем создаёт файлы и выполняет один финальный " +
			"build-gate (commands.build.run манифеста либо legacy fallback `go build ./...`). При ошибке любого шага изменения всех операций откатываются.\n\n" +
			"Формат --operations: '[{\"kind\":\"crud\",\"name\":\"Ride\",\"params\":{\"fields\":\"status:string\"}}]'.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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

			tpl, proj, root, err := loadRunContext()
			if err != nil {
				return err
			}
			operations := make([]gen.Operation, 0, len(input))
			for i, item := range input {
				g, lookupErr := gen.Lookup(tpl, item.Kind)
				if lookupErr != nil {
					return fmt.Errorf("gen batch: операция %d: %w", i+1, lookupErr)
				}
				if err := validateGenBatchParams(g.Params, item.Params); err != nil {
					return fmt.Errorf("gen batch: операция %d (%s %s): %w", i+1, item.Kind, item.Name, err)
				}
				params, fields, resolveErr := gen.ResolveParams(g, item.Params)
				if resolveErr != nil {
					return fmt.Errorf("gen batch: операция %d (%s %s): %w", i+1, item.Kind, item.Name, resolveErr)
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

// printGenResult печатает список созданных/изменённых файлов.
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

// printGenList печатает таблицу KIND/DESCRIPTION/AVAILABLE (недоступные виды
// приглушены палитрой с причиной — по образцу [whenCell] в run.go).
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

// genAvailableCell формирует последнюю колонку `gen list`: "да" либо
// приглушённая пометка "нет — требуется <условие>".
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
