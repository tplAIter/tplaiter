package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// newRunner — runner for the deps-check/hooks/ansible steps of `tplater new`.
// A package variable like runRunner/envRunner for substitution in tests.
var newRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newNewCmd)
}

// newNewCmd composes the signed native live-new foundation and its preview.
func newNewCmd() *cobra.Command {
	var (
		dir            string
		module         string
		system         string
		domain         string
		sets           []string
		answers        string
		defaults       bool
		noHooks        bool
		noDepsCheck    bool
		envSetup       bool
		noEnvSetup     bool
		yes            bool
		port           int
		dryRun         bool
		sourceInput    string
		projectContext string
	)

	c := &cobra.Command{
		Annotations: prerunAnnotations(prerunTrustOwned),

		Use:   "new <ref> <project-name>",
		Short: "Create a project from a template",
		Long: "Creates a project from a signed, pinned native template using --source-input. " +
			"The target must match the installed project context. Settings use --set/--answers/--defaults " +
			"or an interactive survey. This foundation supports action-free templates; hooks, tools, " +
			"environment, generators, AI resources and managed blocks require later lifecycle slices.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime, err := composeRuntimeForProject(cmd.Context(), projectContext)
			if err != nil {
				return err
			}
			defer runtime.Close()
			if sourceInput == "" {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			raw, err := readUntrustedDocument(cmd.Context(), sourceInput)
			if err != nil {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			home, err := state.Home()
			if err != nil {
				return err
			}
			interactive := term.IsTerminal(int(os.Stdin.Fd()))
			opts := newcmd.Options{Ref: args[0], ProjectName: args[1], Dir: dir, Module: module, System: system, Domain: domain, Sets: sets, AnswersFile: answers, Defaults: defaults, NoHooks: noHooks, NoDepsCheck: noDepsCheck, EnvSetup: envSetupTriState(cmd, envSetup, noEnvSetup), Yes: yes, Port: port, Interactive: interactive, CLIVersion: resolveVersion(), DryRun: dryRun}
			err = newcmd.Run(cmd.Context(), opts, newcmd.Deps{Runtime: runtime, SourceInput: raw, Home: home, Prompter: survey.HuhPrompter{In: cmd.InOrStdin(), Out: humanOut(cmd)}, Out: humanOut(cmd), Err: cmd.ErrOrStderr(), Palette: ui.Default()})
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				var project *resultdto.Project
				if !dryRun {
					p := runtime.ProjectContext()
					project = &resultdto.Project{ID: p.ProjectID, Root: p.RootPath}
				}
				return emitData(cmd, resultdto.OperationProjectNew, project, resultdto.ProjectNewData{DryRun: dryRun, Ref: args[0], Name: args[1]})
			}
			if dryRun {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "dry-run prepared")
			}
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
	f.StringVar(&projectContext, "project-context", "", "key of an authenticated installed project context (default: registration key)")
	f.StringVar(&sourceInput, "source-input", "", "JSON pinned source selection and publisher evidence locators")
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
