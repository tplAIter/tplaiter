package cmd

import (
	"errors"
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// newRunner — runner for the deps-check/hooks/ansible steps of `tplater new`.
// A package variable like runRunner/envRunner for substitution in tests.
var newRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newNewCmd)
}

// newNewCmd creates `tplater new <ref> <project-name>`: the main project
// creation command. It resolves and renders a template, asks for settings,
// copies resources, registers the project, and prints NOTES.
func newNewCmd() *cobra.Command {
	var (
		dir         string
		module      string
		system      string
		domain      string
		sets        []string
		answers     string
		defaults    bool
		noHooks     bool
		noDepsCheck bool
		envSetup    bool
		noEnvSetup  bool
		yes         bool
		port        int
		dryRun      bool
		sourceInput string
	)

	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunTrustOwned),

		Use:   "new <ref> <project-name>",
		Short: "Create a project from a template",
		Long: "Deploys a template (reference <ref> — `repo/name@version` or short `name`) " +
			"into new project <project-name>: prompts for settings, " +
			"renders tree, copies environment/generator/ai-config resources to .tplaiter/, " +
			"writes manifest snapshot and project marker, executes hooks.postCreate, " +
			"registers project, and prints NOTES.\n\n" +
			"Prompting is interactive with TTY; in CI use --set/--answers/--defaults.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime, err := composeRuntime(cmd.Context())
			if err != nil {
				return err
			}
			defer runtime.Close()
			if !dryRun {
				return newcmd.ErrLifecycleUnavailable
			}
			if sourceInput == "" {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			raw, err := readUntrustedDocument(cmd.Context(), sourceInput)
			if err != nil {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			selection, err := operationtrust.DecodeSourceSelection(raw)
			if err != nil || selection.Subject.Commit != args[0] {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			prepared, err := newcmd.Prepare(cmd.Context(), runtime, operationtrust.PrepareNewInput{SourceInput: raw, Render: renderref.Input{}, RendererVersion: resolveVersion()})
			if err != nil {
				return err
			}
			if !prepared.ValidFor(runtime.TrustRuntime()) {
				return errors.New("TRUST_RUNTIME_INVALID")
			}
			if jsonMode(cmd) {
				// Nothing is created by a dry run, so the envelope names no project.
				return emitData(cmd, resultdto.OperationProjectNew, nil, resultdto.ProjectNewData{DryRun: true, Ref: args[0], Name: args[1]})
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "dry-run prepared")
			return nil
		},
	}

	f := c.Flags()
	f.StringVar(&dir, "dir", "", "target directory (defaults to ./<slug>)")
	f.StringVar(&module, "module", "", "project go-module (defaults to example.com/<slug> — change for your namespace)")
	f.StringVar(&system, "system", "", "project system (.Project.System in render context)")
	f.StringVar(&domain, "domain", "", "project domain (.Project.Domain in render context)")
	f.StringArrayVar(&sets, "set", nil, "setting value group=value (repeatable flag)")
	f.StringVar(&answers, "answers", "", "YAML answers file (group: value)")
	f.BoolVar(&defaults, "defaults", false, "do not prompt — use defaults (+ --set/--answers)")
	f.BoolVar(&noHooks, "no-hooks", false, "skip hooks.postCreate")
	f.BoolVar(&noDepsCheck, "no-deps-check", false, "skip environment tools check")
	f.BoolVar(&envSetup, "env-setup", false, "run env setup after creation without asking")
	f.BoolVar(&noEnvSetup, "no-env-setup", false, "do not offer env setup after creation")
	f.BoolVar(&yes, "yes", false, "auto-confirm (install tools and env setup)")
	f.IntVar(&port, "port", 0, "project port (.Runtime.Port, defaults to 8080)")
	f.BoolVar(&dryRun, "dry-run", false, "prepare result without changing files")
	f.StringVar(&sourceInput, "source-input", "", "sealed JSON immutable source selection")
	return withResult(c, resultdto.OperationProjectNew)
}

// envSetupTriState converts --env-setup/--no-env-setup into the orchestrator's
// tri-state *bool: nil (ask), &true, or &false. --no-env-setup takes precedence
// when both flags are supplied.
func envSetupTriState(cmd *cobra.Command, envSetup, noEnvSetup bool) *bool {
	switch {
	case cmd.Flags().Changed("no-env-setup") && noEnvSetup:
		v := false
		return &v
	case cmd.Flags().Changed("env-setup") && envSetup:
		v := true
		return &v
	default:
		return nil
	}
}

// confirmFunc remains the shared interactive confirmation adapter used by
// workspace commands. T5 new preparation never calls it.
func confirmFunc(cmd *cobra.Command, interactive bool) func(string) (bool, error) {
	if !interactive {
		return nil
	}
	return func(prompt string) (bool, error) {
		var ok bool
		form := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().Title(prompt).Affirmative("Yes").Negative("No").Value(&ok),
		))
		form = form.WithInput(cmd.InOrStdin()).WithOutput(cmd.OutOrStdout())
		if err := form.Run(); err != nil {
			return false, err
		}
		return ok, nil
	}
}
