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

// ErrActionUnavailable is returned for legacy CLI actions for which this
// binary has no fixed, launcher-selected execution material.  It is kept
// deliberately free of command, path, and environment data.
var ErrActionUnavailable = errors.New("TRUST_ACTION_UNAVAILABLE")

func actionUnavailable() error {
	return errors.Join(trustload.ErrProvenanceUnavailable, ErrActionUnavailable)
}

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
	root.AddCommand(newNewCmd(), newUpdateCmd(), newTrustCmd(), newVersionCmd(), newDoctorCmd(), newRunCmd(), newEnvCmd(), newGenCmd())
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
// поведение команд, будет прокинут в логирование/UI последующими задачами
// (см. PLAN.md §4, tp-U1).
var verbose bool

// upgradeFlag — root-флаг `--upgrade`, алиас команды `tplaiter self-upgrade`
// (SPEC-05 §2). Локальный (не persistent) флаг: имеет смысл только на самой
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
	// PersistentPreRunE — компоновка first-run приветствия (SPEC-05 §4) и
	// suggest-проверки обновлений (SPEC-05 §2), см. [rootPreRun].
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
// [firstRunPreRun] (SPEC-05 §4), затем [suggestUpdatePreRun] (SPEC-05 §2),
// затем [projectSyncPreRun] (SPEC-04 §1). Скомпоновано явно одной функцией (а
// не цепочкой cobra-хуков по дереву команд), чтобы порядок и общий обход
// bare-инвокации читались в одном месте.
//
// До этой задачи rootCmd не имел Run/RunE и поэтому не был Runnable — cobra
// печатала help ДО вызова PersistentPreRunE (см. cobra Command.execute:
// `if !c.Runnable() { return flag.ErrHelp }` предшествует c.preRun()).
// Флаг --upgrade требует RunE на root, что делает root Runnable всегда — без
// этой явной проверки bare `tplaiter` начал бы создавать ~/.tplaiter и запускать
// suggest-проверку, чего раньше не делал. Сохраняем прежнее отсутствие
// побочных эффектов для этого конкретного случая (без подкоманды и без
// --upgrade); `tplaiter --upgrade` (тоже bare-инвокация root, но с флагом)
// проходит first-run/suggest как обычная команда.
func rootPreRun(cmd *cobra.Command, args []string) error {
	// This classification precedes every legacy root hook.  A command that
	// could execute manifest-derived input must not initialize process state,
	// inspect HOME, or synchronize a project before it has fixed material.
	if legacyActionCommand(cmd, args) {
		return actionUnavailable()
	}
	if descriptiveCommand(cmd, args) {
		return nil
	}
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

func descriptiveCommand(cmd *cobra.Command, args []string) bool {
	if cmd == nil {
		return false
	}
	if cmd.Name() == "doctor" || cmd.Name() == "version" {
		return true
	}
	if cmd.Name() == "run" && len(args) == 0 {
		return true
	}
	return cmd.Name() == "list" && cmd.Parent() != nil && (cmd.Parent().Name() == "gen" || cmd.Parent().Name() == "env")
}

// legacyActionCommand distinguishes action ingress from the descriptive
// list/help routes.  It intentionally does not infer authority from flags,
// the manifest, cwd, or process state.
func legacyActionCommand(cmd *cobra.Command, args []string) bool {
	if cmd == nil {
		return false
	}
	switch cmd.Name() {
	case "run":
		return len(args) != 0
	case "gen", "batch", "setup":
		return true
	default:
		return false
	}
}

// Execute запускает корневую команду.
func Execute() error {
	return rootCmd.Execute()
}
