package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// forcedWorkflowGroup — имя settings-группы, которую `workspace add-service`
// best-effort форсирует в true, если она есть в манифесте шаблона сервиса
// (см. allSets/serviceTemplateHasGroup ниже и isUnknownForcedGroupError).
const forcedWorkflowGroup = "workflow"

func init() {
	rootCmd.AddCommand(newWorkspaceCmd())
}

// newWorkspaceCmd — команда `tplater workspace`, объединяющая функции CLI,
// завязанные на kind=workspace проекта (см. docs/workspace-temporal.md
// репозитория шаблонов go-template — спека живёт там, не в tplater;
// §2.3): не команды манифеста, а отдельная логика самого tplater.
func newWorkspaceCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "workspace",
		Short: "Операции над монорепо-проектом (kind=workspace)",
		Long:  "Функции CLI, завязанные на структуру монорепо (go.work + Temporal), а не на манифест конкретного шаблона.",
	}
	c.AddCommand(newWorkspaceAddServiceCmd())
	return c
}

// newWorkspaceAddServiceCmd создаёт `tplater workspace add-service <name>`
// (см. docs/workspace-temporal.md репозитория шаблонов go-template): разворачивает
// сервис-action шаблоном того же репозитория, что и текущий workspace (тип
// `service`), под services/<slug>, best-effort форсирует настройку
// workflow=true (сервис = Temporal activities; при отсутствии группы в
// манифесте шаблона — предупреждение вместо ошибки), включает каталог в go.work.
func newWorkspaceAddServiceCmd() *cobra.Command {
	var (
		module      string
		sets        []string
		answers     string
		defaults    bool
		noHooks     bool
		noDepsCheck bool
		envSetup    bool
		noEnvSetup  bool
		yes         bool
		port        int
	)

	c := &cobra.Command{
		Use:   "add-service <name>",
		Short: "Добавить сервис-action в текущий workspace-проект",
		Long: "Разворачивает шаблон сервиса (type=service того же репозитория, что и текущий " +
			"workspace) в services/<slug>, по возможности форсирует настройку workflow=true (сервис = " +
			"набор Temporal activities, см. docs/workspace-temporal.md репозитория шаблонов go-template) и " +
			"добавляет каталог в go.work. Выполняется из корня workspace-проекта (или любого " +
			"вложенного подкаталога, включая уже созданные services/<slug>).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, _, err := state.EnsureHome()
			if err != nil {
				return err
			}

			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			root, proj, tpl, err := findWorkspaceRoot(home, cwd)
			if err != nil {
				if errors.Is(err, project.ErrNotInProject) {
					return fmt.Errorf("workspace add-service: текущий каталог не является проектом tplater (нужен корень workspace, %s): %w", project.MarkerRelPath, err)
				}
				return fmt.Errorf("workspace add-service: чтение манифеста текущего проекта: %w", err)
			}
			if !slices.Contains(tpl.Metadata.Labels["type"], "workspace") {
				return fmt.Errorf("workspace add-service: проект %s (шаблон %s) не является workspace (labels.type=%v) — команда применима только к kind=workspace проектам; если вы внутри вложенного сервиса (services/<slug>), поднимитесь в корень workspace", proj.Project.Slug, tpl.Metadata.Name, tpl.Metadata.Labels["type"])
			}

			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			svcName, err := resolveServiceTemplateName(mgr, proj.Template.Repo)
			if err != nil {
				return err
			}

			slug, err := newcmd.Slugify(args[0])
			if err != nil {
				return fmt.Errorf("workspace add-service: %w", err)
			}
			targetDir := filepath.Join(root, "services", slug)

			mod := module
			if mod == "" {
				mod = proj.Project.Module + "/services/" + slug
			}

			svcRef := proj.Template.Repo + "/" + svcName
			pal := ui.Default()

			// workflow=true форсируется best-effort (docs/workspace-temporal.md
			// репозитория шаблонов go-template): сервис-action в workspace обязан
			// быть Temporal-воркером. Но не любой шаблон сервиса обязан объявлять
			// группу workflow — если её нет в манифесте, форсировать нечего:
			// вместо жёсткого падения предупреждаем и продолжаем без
			// forced-значения (находка ревью). Если группа есть, пользовательский
			// --set той же группы не может отключить форс — добавляем
			// forced-значение последним, оно перекрывает более ранние --set той же
			// группы при разборе (survey.AskFlow берёт последнее вхождение группы).
			allSets := slices.Clone(sets)
			hasWorkflow, err := serviceTemplateHasGroup(cmd, mgr, svcRef, forcedWorkflowGroup)
			if err != nil {
				return fmt.Errorf("workspace add-service: проверка настроек шаблона сервиса %s: %w", svcRef, err)
			}
			if hasWorkflow {
				allSets = append(allSets, forcedWorkflowGroup+"=true")
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), ui.WarnLine(pal, fmt.Sprintf(
					"шаблон сервиса %s не содержит настройки %q — сервис создаётся БЕЗ форсированного "+
						"%s=true (сервис в workspace, как правило, обязан быть Temporal-воркером, "+
						"docs/workspace-temporal.md репозитория шаблонов go-template; добавьте группу "+
						"%s типа toggle в template.manifest.yaml шаблона сервиса, если это применимо)",
					svcRef, forcedWorkflowGroup, forcedWorkflowGroup, forcedWorkflowGroup,
				)))
			}

			interactive := term.IsTerminal(int(os.Stdin.Fd()))

			opts := newcmd.Options{
				Ref:         svcRef,
				ProjectName: args[0],
				Dir:         targetDir,
				Module:      mod,
				System:      proj.Project.System,
				Domain:      proj.Project.Domain,
				Sets:        allSets,
				AnswersFile: answers,
				Defaults:    defaults,
				NoHooks:     noHooks,
				NoDepsCheck: noDepsCheck,
				EnvSetup:    envSetupTriState(cmd, envSetup, noEnvSetup),
				Yes:         yes,
				Port:        port,
				Interactive: interactive,
				CLIVersion:  resolveVersion(),
			}
			d := newcmd.Deps{
				Manager:  mgr,
				Runner:   newRunner,
				Home:     home,
				Prompter: survey.HuhPrompter{In: cmd.InOrStdin(), Out: cmd.OutOrStdout()},
				Confirm:  confirmFunc(cmd, interactive),
				Out:      cmd.OutOrStdout(),
				Err:      cmd.ErrOrStderr(),
				Palette:  pal,
			}
			if err := newcmd.Run(cmd.Context(), opts, d); err != nil {
				// Защитный фолбэк: serviceTemplateHasGroup уже проверил наличие
				// forcedWorkflowGroup выше, поэтому в норме сюда не попадаем — но
				// newcmd.Run делает собственный checkout манифеста, и если он вдруг
				// разошёлся с проверкой (гонка, ошибка резолвера), даём то же понятное
				// пояснение, а не сырую ошибку settings.ParseSet.
				if isUnknownForcedGroupError(err, forcedWorkflowGroup) {
					return fmt.Errorf(
						"workspace add-service: шаблон сервиса %s/%s не содержит настройки %q "+
							"(эта команда пытается форсировать %s=true — сервис в workspace, как правило, "+
							"обязан быть Temporal-воркером, см. docs/workspace-temporal.md репозитория "+
							"шаблонов go-template; значение подставлено самим tplater, а не пользователем — "+
							"добавьте группу %s типа toggle в template.manifest.yaml шаблона сервиса): %w",
						proj.Template.Repo, svcName, forcedWorkflowGroup, forcedWorkflowGroup, forcedWorkflowGroup, err,
					)
				}
				return err
			}

			if err := addWorkspaceUse(root, "./services/"+slug); err != nil {
				return fmt.Errorf("workspace add-service: сервис создан в %s, но регистрация в go.work не удалась (добавьте вручную use ./services/%s): %w", targetDir, slug, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "\nСервис-action %s зарегистрирован в go.work (./services/%s). Выполните `tplater run sync` в корне workspace.\n", slug, slug)
			return nil
		},
	}

	f := c.Flags()
	f.StringVar(&module, "module", "", "go-module сервиса (по умолчанию <module воркспейса>/services/<slug>)")
	f.StringArrayVar(&sets, "set", nil, "значение настройки group=value (повторяемый флаг); workflow=true форсируется отдельно")
	f.StringVar(&answers, "answers", "", "файл ответов YAML (group: value)")
	f.BoolVar(&defaults, "defaults", false, "не опрашивать — взять дефолты (+ --set/--answers)")
	f.BoolVar(&noHooks, "no-hooks", false, "пропустить hooks.postCreate")
	f.BoolVar(&noDepsCheck, "no-deps-check", false, "пропустить проверку инструментов окружения")
	f.BoolVar(&envSetup, "env-setup", false, "запустить env setup после создания без вопроса")
	f.BoolVar(&noEnvSetup, "no-env-setup", false, "не предлагать env setup после создания")
	f.BoolVar(&yes, "yes", false, "авто-подтверждение (установка инструментов и env setup)")
	f.IntVar(&port, "port", 0, "порт сервиса (.Runtime.Port)")
	return c
}

// findWorkspaceRoot ищет ближайший (вверх по дереву от startDir) проект
// tplater и, если он не kind=workspace, пробует продолжить подъём от его
// родительского каталога — на один уровень выше настоящего workspace-корня
// может найтись собственный вложенный проект (например, services/<slug>,
// зарегистрированный этой же командой через свой .tplaiter/project.yaml),
// который иначе затенил бы workspace-корень для project.FindRoot (у неё
// побеждает ближайший маркер). Если выше подлинного workspace нет —
// возвращается исходно найденный (не-workspace) проект без изменений, чтобы
// сохранить прежнее поведение и сообщение об ошибке для случая, когда
// команда запущена вне workspace вовсе.
func findWorkspaceRoot(home, startDir string) (root string, proj *manifest.Project, tpl *manifest.Template, err error) {
	root, proj, err = project.FindRoot(startDir)
	if err != nil {
		return "", nil, nil, err
	}
	tpl, _, err = project.LoadManifestForProject(root, proj, home)
	if err != nil {
		return "", nil, nil, err
	}
	if slices.Contains(tpl.Metadata.Labels["type"], "workspace") {
		return root, proj, tpl, nil
	}

	if parent := filepath.Dir(root); parent != root {
		if wsRoot, wsProj, wsErr := project.FindRoot(parent); wsErr == nil {
			if wsTpl, _, lerr := project.LoadManifestForProject(wsRoot, wsProj, home); lerr == nil &&
				slices.Contains(wsTpl.Metadata.Labels["type"], "workspace") {
				return wsRoot, wsProj, wsTpl, nil
			}
		}
	}
	return root, proj, tpl, nil
}

// isUnknownForcedGroupError сообщает, вызвана ли ошибка (settings.ParseSet
// напрямую в [serviceTemplateHasGroup] либо провалившийся newcmd.Run) именно
// отсутствием группы group в манифесте шаблона сервиса — settings.ParseSet
// возвращает такой текст для любой неизвестной группы (сентинел-ошибки у неё
// нет), поэтому сверяем по тексту. Используется, чтобы отличить провал
// форсированного --set (добавлен самим tplater) от ошибки в
// пользовательском --set/--answers той же команды.
func isUnknownForcedGroupError(err error, group string) bool {
	return strings.Contains(err.Error(), fmt.Sprintf("неизвестная группа %q", group))
}

// serviceTemplateHasGroup сообщает, объявлена ли в манифесте шаблона сервиса
// ref (repoAlias/templateName — тот же формат, что уходит в
// newcmd.Options.Ref) settings-группа group. Вызывающий код (RunE
// newWorkspaceAddServiceCmd) использует результат, чтобы решить, форсировать
// ли --set workflow=true: best-effort — шаблон сервиса не обязан объявлять
// эту группу, и её отсутствие не должно валить команду.
//
// Checkout и разбор манифеста — тем же путём, что runTemplateShow
// (template.go): ResolveRef → Checkout → чтение и разбор
// template.manifest.yaml. Наличие группы проверяем через settings.ParseSet (а
// не ручной обход tpl.Settings), чтобы учитывать вложенные группы
// (Option.Settings) той же логикой, что реальная установка настроек в
// newcmd.Run — иначе эта проверка могла бы разойтись с фактическим поведением
// (например, для группы, видимой только под выбранной опцией).
func serviceTemplateHasGroup(cmd *cobra.Command, mgr *repo.Manager, ref, group string) (bool, error) {
	resolved, err := mgr.ResolveRef(ref)
	if err != nil {
		return false, fmt.Errorf("резолюция шаблона %s: %w", ref, err)
	}
	fsys, cleanup, err := mgr.Checkout(cmd.Context(), resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		return false, fmt.Errorf("checkout шаблона %s: %w", ref, err)
	}
	defer func() { _ = cleanup() }()

	data, err := fs.ReadFile(fsys, templateManifestFileName)
	if err != nil {
		return false, fmt.Errorf("чтение %s: %w", templateManifestFileName, err)
	}
	tpl, err := manifest.ParseTemplate(data)
	if err != nil {
		return false, fmt.Errorf("разбор манифеста: %w", err)
	}

	if _, _, err := settings.ParseSet(tpl, group+"=true"); err != nil {
		if isUnknownForcedGroupError(err, group) {
			return false, nil
		}
		// Группа с именем group есть, но несовместима со значением "true"
		// (например, тип select/int вместо toggle) — это уже не «группы нет»,
		// а реальный конфликт форсируемого значения с манифестом, скрывать
		// его best-effort-логикой не стоит.
		return false, fmt.Errorf("группа %q объявлена в манифесте шаблона, но несовместима с форсируемым значением true: %w", group, err)
	}
	return true, nil
}

// resolveServiceTemplateName ищет в репозитории repoAlias ровно один шаблон с
// лейблом type=service ( индекс шаблонов) — это шаблон сервиса-action
// для `workspace add-service`. Несколько или ноль совпадений — ошибка с
// перечислением найденного (неоднозначность разрешает пользователь явным --ref
// в будущей версии команды).
func resolveServiceTemplateName(mgr interface {
	Templates() (map[string][]state.TemplateEntry, error)
}, repoAlias string,
) (string, error) {
	idx, err := mgr.Templates()
	if err != nil {
		return "", fmt.Errorf("резолюция шаблона сервиса: %w", err)
	}
	entries := idx[repoAlias]
	var matches []string
	for _, e := range entries {
		if slices.Contains(e.LabelsFlat["type"], "service") {
			matches = append(matches, e.Name)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("в репозитории %s не найден шаблон с labels.type=service (tplater template list -l type=service)", repoAlias)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("в репозитории %s несколько шаблонов с labels.type=service: %v — уточнение через флаг пока не реализовано", repoAlias, matches)
	}
}

// addWorkspaceUse дописывает use-директиву diskPath в go.work корня root, если
// её там ещё нет (идемпотентно — повторный add-service с уже
// зарегистрированным путём не дублирует строку).
func addWorkspaceUse(root, diskPath string) error {
	workPath := filepath.Join(root, "go.work")
	data, err := os.ReadFile(workPath)
	if err != nil {
		return fmt.Errorf("чтение go.work: %w", err)
	}
	wf, err := modfile.ParseWork(workPath, data, nil)
	if err != nil {
		return fmt.Errorf("разбор go.work: %w", err)
	}
	// filepath.Clean normalizes "./services/<slug>" (что передаём мы) и
	// эквивалентные ручные директивы вида "use services/<slug>" (без "./",
	// валидный синтаксис go.work) к одному виду — иначе AddUse задваивает use
	// на тот же каталог, если строку уже дописали руками без "./".
	cleanDiskPath := filepath.Clean(diskPath)
	for _, u := range wf.Use {
		if filepath.Clean(u.Path) == cleanDiskPath {
			return nil // уже зарегистрирован
		}
	}
	if err := wf.AddUse(diskPath, ""); err != nil {
		return fmt.Errorf("добавление use %s: %w", diskPath, err)
	}
	wf.Cleanup()
	out := modfile.Format(wf.Syntax)
	// go.work.sum рядом не трогаем — `go work sync`/`tplater run sync`
	// пересоберёт его штатно после регистрации нового модуля.
	if err := os.WriteFile(workPath, out, 0o644); err != nil { //nolint:gosec // G306: go.work не секрет, 0644 намеренно (как в manifest.SaveSnapshot).
		return fmt.Errorf("запись go.work: %w", err)
	}
	return nil
}
