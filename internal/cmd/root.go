// Package cmd contains tplaiter CLI cobra commands.
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
	in, err := commandInvocation(ctx)
	if err != nil {
		return nil, err
	}
	return trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: in.Selection, ProjectKey: in.ProjectKey, Clock: in.Clock})
}

func commandInvocation(ctx context.Context) (invocation, error) {
	if ctx == nil {
		return invocation{}, trustload.ErrAnchorMissing
	}
	in, ok := ctx.Value(invocationKey{}).(invocation)
	if ok && in.Clock != nil && in.ProjectKey != "" {
		return in, nil
	}
	return installedInvocation(ctx)
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

// ExitError carries a process exit code other than 1 (for example, 2 for
// conflicts during `tplaiter update`). main handles it through errors.As.
type ExitError struct {
	Code int
	Err  error
}

// Error implements the error interface.
func (e *ExitError) Error() string {
	if e.Err == nil {
		return "exit"
	}
	return e.Err.Error()
}

// Unwrap returns the wrapped error.
func (e *ExitError) Unwrap() error { return e.Err }

// verbose — persistent flag for verbose output. Placeholder: it does not yet
// affect command behavior and will be passed to logging/UI by later tasks
// (see PLAN.md §4, tp-U1).
var verbose bool

// upgradeFlag — root `--upgrade` flag, an alias for `tplaiter self-upgrade`
// (SPEC-05 §2). A local (non-persistent) flag: meaningful only on the root
// command; see rootCmd.RunE and [rootPreRun].
var upgradeFlag bool

// rootCmd — root tplaiter command.
var rootCmd = &cobra.Command{
	Use:   "tplaiter",
	Short: "Менеджер репозиториев шаблонов",
	Long: "tplaiter — менеджер репозиториев шаблонов: устанавливает, " +
		"обновляет и отслеживает дрейф сгенерированных из шаблонов проектов.\n\n" +
		"См. README.md и docs/ в репозитории tplaiter для деталей архитектуры.",
	SilenceUsage:  true,
	SilenceErrors: true,
	// PersistentPreRunE — composition of the first-run greeting (SPEC-05 §4) and
	// update suggestion check (SPEC-05 §2); see [rootPreRun].
	PersistentPreRunE: rootPreRun,
	// RunE — present only so `tplaiter --upgrade` works as an alias for
	// `tplaiter self-upgrade` without declaring --upgrade as a persistent flag on
	// every subcommand. Without --upgrade, bare `tplaiter` behavior is unchanged
	// (it prints help as before; see [rootPreRun] on preserving this behavior when
	// RunE was added).
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

// rootPreRun — the root command's single PersistentPreRunE: first
// [firstRunPreRun] (SPEC-05 §4), then [suggestUpdatePreRun] (SPEC-05 §2),
// then [projectSyncPreRun] (SPEC-04 §1). They are composed explicitly in one
// function (rather than a chain of cobra hooks through the command tree) so the
// order and common bare invocation path are visible in one place.
//
// Before this task rootCmd had no Run/RunE and therefore was not Runnable —
// cobra printed help BEFORE calling PersistentPreRunE (see cobra
// Command.execute: `if !c.Runnable() { return flag.ErrHelp }` precedes
// c.preRun()). The --upgrade flag requires RunE on root, making root always
// Runnable; without this explicit check, bare `tplaiter` would start creating
// ~/.tplaiter and run the suggest check, which it did not do before. Preserve
// the former lack of side effects for this specific case (no subcommand and no
// --upgrade); `tplaiter --upgrade` (also a bare root invocation, but with the
// flag) runs first-run/suggest like a normal command.
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
	// !cmd.HasParent() instead of `cmd == rootCmd` — otherwise the closure would
	// create a package initialization cycle (rootCmd contains PersistentPreRunE:
	// rootPreRun, while rootPreRun would reference rootCmd). The condition is
	// equivalent: PersistentPreRunE receives the command cobra found (see Find
	// in cobra/command.go), and only root itself has no parent.
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

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
