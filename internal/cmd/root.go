// Package cmd содержит cobra-команды CLI tplaiter.
package cmd

import (
	"context"
	"errors"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// invocation carries only dependencies selected by the installed launcher.
// It is deliberately per-command and never populated from CLI input.
type invocation struct {
	Selection  trustload.LaunchSelection
	ProjectKey string
	Clock      bootstrap.Clock
}

type invocationKey struct{}

func withInvocation(ctx context.Context, in invocation) context.Context {
	return context.WithValue(ctx, invocationKey{}, in)
}

func composeRuntime(ctx context.Context) (*trustload.Runtime, error) {
	if ctx == nil {
		return nil, trustload.ErrAnchorMissing
	}
	in, ok := ctx.Value(invocationKey{}).(invocation)
	if !ok || in.Clock == nil || in.ProjectKey == "" {
		return nil, trustload.ErrAnchorMissing
	}
	return trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: in.Selection, ProjectKey: in.ProjectKey, Clock: in.Clock})
}

func commandInvocation(ctx context.Context) (invocation, error) {
	if ctx == nil {
		return invocation{}, trustload.ErrAnchorMissing
	}
	in, ok := ctx.Value(invocationKey{}).(invocation)
	if !ok || in.Clock == nil || in.ProjectKey == "" {
		return invocation{}, trustload.ErrAnchorMissing
	}
	return in, nil
}

// newTrustRootCommand is the explicit per-invocation composition seam. The
// installed launcher supplies this value; command flags can never replace its
// selection, project key, or clock.
func newTrustRootCommand(in invocation) *cobra.Command {
	root := &cobra.Command{
		Use:               "tplaiter",
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: rootPreRun,
		Version:           resolveVersion(),
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.SetContext(withInvocation(context.Background(), in))
	root.AddCommand(newNewCmd(), newUpdateCmd(), newTrustCmd())
	return root
}

func stableVerifierFactory(ctx context.Context) (trustload.VerifierFactory, error) {
	in, err := commandInvocation(ctx)
	if err != nil {
		return nil, err
	}
	if in.Clock == nil {
		return nil, errors.New("TRUST_ANCHOR_MISSING")
	}
	return func(reader evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(reader, in.Clock, nil, 0)
	}, nil
}

// ExitError несёт код выхода процесса, отличный от 1 (например, 2 — конфликты
// при `tplaiter update`). main обрабатывает его через errors.As.
type ExitError struct {
	Code int
	Err  error
}

// Error реализует интерфейс error.
func (e *ExitError) Error() string {
	if e.Err == nil {
		return "exit"
	}
	return e.Err.Error()
}

// Unwrap возвращает вложенную ошибку.
func (e *ExitError) Unwrap() error { return e.Err }

// verbose — persistent-флаг подробного вывода. Заготовка: пока не влияет на
// поведение команд, будет прокинут в логирование/UI последующими связанными компонентами
// (см. документацию проекта, реализацию).
var verbose bool

// upgradeFlag — root-флаг `--upgrade`, алиас команды `tplaiter self-upgrade`
//. Локальный (не persistent) флаг: имеет смысл только на самой
// root-команде, см. rootCmd.RunE и [rootPreRun].
var upgradeFlag bool

// rootCmd — корневая команда tplaiter.
var rootCmd = &cobra.Command{
	Use:   "tplaiter",
	Short: "Менеджер репозиториев шаблонов",
	Long: "tplaiter — менеджер репозиториев шаблонов: устанавливает, " +
		"обновляет и отслеживает дрейф сгенерированных из шаблонов проектов.\n\n" +
		"См. README.md и docs/ в репозитории tplaiter для деталей архитектуры.",
	SilenceUsage:  true,
	SilenceErrors: true,
	// PersistentPreRunE — компоновка first-run приветствия и
	// suggest-проверки обновлений, см. [rootPreRun].
	PersistentPreRunE: rootPreRun,
	// RunE — есть только затем, чтобы `tplaiter --upgrade` работал как алиас
	// `tplaiter self-upgrade` без объявления --upgrade persistent-флагом на
	// каждой подкоманде. Без --upgrade поведение bare `tplaiter` не меняется
	// (печатает help, как раньше — см. [rootPreRun] про сохранение этого
	// поведения при появлении RunE).
	RunE: func(cmd *cobra.Command, args []string) error {
		if !upgradeFlag {
			return cmd.Help()
		}
		return runSelfUpgrade(cmd, args)
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "подробный вывод")
	rootCmd.Flags().BoolVar(&upgradeFlag, "upgrade", false, "самообновление (алиас `tplaiter self-upgrade`)")

	rootCmd.Version = resolveVersion()
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newDoctorCmd())
	rootCmd.AddCommand(newSelfUpgradeCmd())
	rootCmd.AddCommand(newInitShellCmd())
	rootCmd.AddCommand(newMigrationCmd())
	rootCmd.AddCommand(newTrustCmd())
}

// rootPreRun — единая PersistentPreRunE корневой команды: сначала
// [firstRunPreRun], затем [suggestUpdatePreRun],
// затем [projectSyncPreRun]. Скомпоновано явно одной функцией (а
// не цепочкой cobra-хуков по дереву команд), чтобы порядок и общий обход
// bare-инвокации читались в одном месте.
//
// До этой реализации rootCmd не имел Run/RunE и поэтому не был Runnable — cobra
// печатала help ДО вызова PersistentPreRunE (см. cobra Command.execute:
// `if !c.Runnable() { return flag.ErrHelp }` предшествует c.preRun()).
// Флаг --upgrade требует RunE на root, что делает root Runnable всегда — без
// этой явной проверки bare `tplaiter` начал бы создавать ~/.tplaiter и запускать
// suggest-проверку, чего раньше не делал. Сохраняем прежнее отсутствие
// побочных эффектов для этого конкретного случая (без подкоманды и без
// --upgrade); `tplaiter --upgrade` (тоже bare-инвокация root, но с флагом)
// проходит first-run/suggest как обычная команда.
func rootPreRun(cmd *cobra.Command, args []string) error {
	// Naming migration is explicitly rooted by its sealed plan. It must not
	// create/discover a process home or synchronize a registry while planning
	// or applying an unrelated synthetic/isolated state transaction.
	if cmd.Name() == "migrate-state" {
		return nil
	}
	// T5 new/update owns its complete per-invocation composition. In
	// particular, first-run, update suggestion and project sync must not run
	// before the fixed trust runtime has been selected.
	if cmd.Name() == "new" || cmd.Name() == "update" {
		return nil
	}
	if cmd.Name() == "trust" || (cmd.Parent() != nil && cmd.Parent().Name() == "trust") {
		return nil
	}
	// !cmd.HasParent() вместо `cmd == rootCmd` — иначе замыкание создаёт
	// цикл инициализации пакета (rootCmd содержит PersistentPreRunE:
	// rootPreRun, а rootPreRun ссылался бы на rootCmd). Условие эквивалентно:
	// PersistentPreRunE вызывается с cmd == та команда, которую нашла cobra
	// (см. Find в cobra/command.go), а её нет родителя ровно у самого root.
	if !cmd.HasParent() && !upgradeFlag {
		return nil
	}

	if err := firstRunPreRun(cmd, args); err != nil {
		return err
	}
	suggestUpdatePreRun(cmd, args)
	projectSyncPreRun(cmd, args)
	return nil
}

// Execute запускает корневую команду.
func Execute() error {
	return rootCmd.Execute()
}
