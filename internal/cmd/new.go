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
)

// newRunner — runner for the deps-check/hooks/ansible steps of `tplater new`.
// A package variable like runRunner/envRunner for substitution in tests.
var newRunner execx.Runner = execx.Exec{}

func init() {
	rootCmd.AddCommand(newNewCmd())
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
		Use:   "new <ref> <project-name>",
		Short: "Создать проект из шаблона",
		Long: "Разворачивает шаблон (ссылка <ref> — `repo/name@version` или короткая `name`, " +
			") в новый проект <project-name>: опрашивает настройки (), " +
			"рендерит дерево, копирует ресурсы окружения/генераторов/ai-config в .tplaiter/, " +
			"пишет снимок манифеста и проектный маркер, выполняет hooks.postCreate, " +
			"регистрирует проект и печатает NOTES.\n\n" +
			"Опрос интерактивен при наличии TTY; в CI используйте --set/--answers/--defaults.",
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
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "dry-run prepared")
			return nil
		},
	}

	f := c.Flags()
	f.StringVar(&dir, "dir", "", "целевой каталог (по умолчанию ./<slug>)")
	f.StringVar(&module, "module", "", "go-module проекта (по умолчанию example.com/<slug> — измените под свой namespace)")
	f.StringVar(&system, "system", "", "система проекта (.Project.System в контексте рендера)")
	f.StringVar(&domain, "domain", "", "домен проекта (.Project.Domain в контексте рендера)")
	f.StringArrayVar(&sets, "set", nil, "значение настройки group=value (повторяемый флаг)")
	f.StringVar(&answers, "answers", "", "файл ответов YAML (group: value)")
	f.BoolVar(&defaults, "defaults", false, "не опрашивать — взять дефолты (+ --set/--answers)")
	f.BoolVar(&noHooks, "no-hooks", false, "пропустить hooks.postCreate")
	f.BoolVar(&noDepsCheck, "no-deps-check", false, "пропустить проверку инструментов окружения")
	f.BoolVar(&envSetup, "env-setup", false, "запустить env setup после создания без вопроса")
	f.BoolVar(&noEnvSetup, "no-env-setup", false, "не предлагать env setup после создания")
	f.BoolVar(&yes, "yes", false, "авто-подтверждение (установка инструментов и env setup)")
	f.IntVar(&port, "port", 0, "порт проекта (.Runtime.Port, по умолчанию 8080)")
	f.BoolVar(&dryRun, "dry-run", false, "подготовить результат без изменения файлов")
	f.StringVar(&sourceInput, "source-input", "", "закрытый JSON выбора неизменяемого источника")
	return c
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
			huh.NewConfirm().Title(prompt).Affirmative("Да").Negative("Нет").Value(&ok),
		))
		form = form.WithInput(cmd.InOrStdin()).WithOutput(cmd.OutOrStdout())
		if err := form.Run(); err != nil {
			return false, err
		}
		return ok, nil
	}
}
