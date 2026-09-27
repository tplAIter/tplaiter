// Package envsetup исполняет ansible-плейбуки окружения, объявленные шаблоном
// в манифесте (environment.playbooks, SPEC-01 §2, SPEC-03 §4) — решение
// ревью владельца «всё должно работать в рамках экосистемы»: tplater не
// пытается сам понимать все возможные способы настройки окружения проекта, а
// устанавливает единственный универсальный инструмент (ansible) и передаёт
// ему управление, вызывая плейбук, который везёт с собой сам шаблон.
//
// Пакет назван envsetup, а не env — последнее имя слишком тесно ассоциируется
// со стандартной библиотекой (os.Environ и т.п.) и было бы вводящим в
// заблуждение соседством с internal/cmd/env.go (CLI-командой `tplater env`,
// которая оборачивает этот пакет).
//
// # Контракт .tplaiter/environment (для C2 — `tplater new`)
//
// У созданного проекта нет checkout шаблона: рендер (engine) кладёт только
// результат применения gotemplate к дереву настроек, а playbook-файлы
// (environment.playbooks[].file, обычно "environment/setup.yml" и т.п.)
// адресуются относительно КОРНЯ ШАБЛОНА, а не относительно проекта. Чтобы
// `tplater env` мог запускать плейбуки уже после того, как checkout шаблона
// давно удалён/обновлён, задача C2 (`tplater new`) ДОЛЖНА скопировать (не
// рендерить — как есть, включая .yml/.j2/vars и что угодно ansible-специфичное)
// каталог(и), на которые ссылаются пути environment.playbooks[].file шаблона,
// в проект по адресу:
//
//	<корень проекта>/.tplaiter/environment/
//
// сохраняя относительную структуру путей — то есть если манифест объявляет
// playbook с file: "environment/setup.yml", в проекте должен оказаться файл
// ".tplaiter/environment/environment/setup.yml" (простейший вариант — скопировать
// содержимое каталога шаблона целиком под .tplaiter/environment/, повторяя её
// структуру 1:1; тогда Playbook.File можно джойнить с TemplateDir без всякой
// пере-нормализации путей). [EnvironmentRelPath] — канонический относительный
// путь этого каталога, чтобы обе стороны контракта (C2 и `tplater env`)
// ссылались на одну константу. Для тестов этого пакета файлы плейбуков кладутся
// руками (без реального прохода C2/checkout).
package envsetup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// EnvironmentRelPath — путь каталога окружения проекта относительно корня
// проекта. `tplater new` (C2) копирует туда playbook-файлы шаблона (см. doc
// пакета); TemplateDir для [Options] строится как filepath.Join(root,
// EnvironmentRelPath).
const EnvironmentRelPath = ".tplaiter/environment"

// ansibleTool — требование окружения для исполнения плейбуков (SPEC-01 §2:
// `{ name: ansible, required: false, install: { brew: ansible, apt: ansible } }`).
// required здесь true не в смысле манифеста шаблона (там ansible не обязателен
// глобально), а в смысле локального требования именно этой операции — без
// ansible-playbook `tplater env setup` попросту не может исполниться.
var ansibleTool = manifest.Tool{
	Name:     "ansible",
	Required: true,
	Install: manifest.ToolInstall{
		Brew: "ansible",
		Apt:  "ansible",
	},
}

// ansiblePlaybookBinary — фактический бинарник, который запускает Runner.
// Отдельно от имени пакета ansibleTool.Name ("ansible"): формула/пакет
// называется ansible, а нужный нам исполняемый файл — ansible-playbook
// (устанавливается тем же пакетом, но это разные имена в PATH).
const ansiblePlaybookBinary = "ansible-playbook"

// ErrAnsibleMissing сообщает, что ansible-playbook не найден в PATH и (если
// пытались) установка не решила проблему — errors.Is отличает эту причину
// провала [Runner.RunPlaybook] от прочих (несуществующий playbook-файл,
// ошибка самого ansible-playbook).
var ErrAnsibleMissing = errors.New("envsetup: ansible-playbook не найден в PATH")

// ErrPlaybookFileNotFound сообщает, что файл плейбука отсутствует по
// ожидаемому пути (TemplateDir/Playbook.File).
var ErrPlaybookFileNotFound = errors.New("envsetup: файл плейбука не найден")

// ErrAnsibleAdapterUnavailable is returned before inspecting a playbook,
// resolving a tool, creating extra-vars, or invoking an installer. Generic
// Ansible imports, plugins, inventory and variable closure are not an
// approved executable adapter.
var ErrAnsibleAdapterUnavailable = errors.New("TRUST_ANSIBLE_ADAPTER_UNAVAILABLE")

// PlaybookInfo — один плейбук окружения для отчёта `tplater env list`.
type PlaybookInfo struct {
	// Name — идентификатор плейбука (environment.playbooks[].name).
	Name string
	// Description — человекочитаемое описание из манифеста.
	Description string
	// Available сообщает, выполнено ли When (или When пуст) на текущих
	// values. Условие с ошибкой разбора/неизвестной группой тоже даёт false —
	// плейбук честно недоступен, а не "не знаю".
	Available bool
	// WhenStr — исходная строка When как есть (пусто, если условия нет) —
	// для отображения в отчёте, почему плейбук недоступен.
	WhenStr string
}

// ListPlaybooks возвращает плейбуки окружения манифеста tpl с отметкой
// доступности по when-условию на текущих values (SPEC-03 §4). Порядок — как
// в манифесте.
func ListPlaybooks(tpl *manifest.Template, values settings.Values) []PlaybookInfo {
	playbooks := tpl.Environment.Playbooks
	infos := make([]PlaybookInfo, 0, len(playbooks))
	for _, pb := range playbooks {
		info := PlaybookInfo{Name: pb.Name, Description: pb.Description, WhenStr: pb.When, Available: true}
		if pb.When != "" {
			ok, err := evalWhen(pb.When, values)
			info.Available = err == nil && ok
		}
		infos = append(infos, info)
	}
	return infos
}

// evalWhen разбирает и вычисляет строку when-условия (SPEC-01 §3.2). Ошибка
// разбора/вычисления (в том числе ссылка на неизвестную группу) трактуется
// вызывающим как "условие не выполнено", а не паника — согласовано с
// [manifest.ParseCondition]/[settings.Eval].
func evalWhen(when string, values settings.Values) (bool, error) {
	cond, err := manifest.ParseCondition(when)
	if err != nil {
		return false, err
	}
	return settings.Eval(cond, values)
}

// Runner исполняет плейбуки окружения. Zero-value непригоден — используйте
// [NewRunner]; поля экспортированы, чтобы тесты могли собрать Runner напрямую
// (например, с [execx.RecordingRunner]) без прохода через конструктор.
type Runner struct {
	// Exec — слой запуска внешних команд (ansible-playbook, brew — через
	// [deps.Install]). Всегда execx.Runner, никогда напрямую os/exec — весь
	// пакет полностью мокается через execx.RecordingRunner.
	Exec execx.Runner
	// UI — вывод собственных сообщений Runner (какой плейбук запускается,
	// куда смотреть при ошибке) и приёмник стриминга stdout/stderr самого
	// ansible-playbook.
	UI deps.UI
	// DepsUI — UI, передаваемый в deps.Install при автоустановке ansible
	// (SPEC-03 §4). Отдельное поле от UI по заданию задачи — на практике
	// [NewRunner] заполняет оба одним и тем же значением; разделены, чтобы
	// вызывающий код мог осознанно приглушить вывод именно deps-подпотока
	// (например, если решит логировать установку ansible иначе), не трогая
	// основной UI.
	DepsUI deps.UI
}

// NewRunner собирает Runner поверх exec (слой запуска команд) с выводом в out,
// раскрашенным палитрой pal. UI и DepsUI указывают на один и тот же
// deps.UI — раздельные поля существуют для точечной подмены в специфичных
// сценариях (см. поле DepsUI), а не как признак того, что они обязаны
// отличаться.
func NewRunner(exec execx.Runner, out io.Writer, pal ui.Palette) *Runner {
	u := deps.NewUI(out, pal)
	return &Runner{Exec: exec, UI: u, DepsUI: u}
}

// Options — параметры одного запуска [Runner.RunPlaybook].
type Options struct {
	// TemplateDir — каталог, где физически лежат playbook-файлы (обычно
	// <корень проекта>/.tplaiter/environment — см. [EnvironmentRelPath] и doc
	// пакета про контракт с `tplater new`). Playbook.File резолвится
	// filepath.Join(TemplateDir, Playbook.File).
	TemplateDir string
	// ProjectRoot — корень проекта: рабочий каталог запуска ansible-playbook
	// и источник tplater_project_root extra-var.
	ProjectRoot string
	// Playbook — запускаемый плейбук из environment.playbooks манифеста.
	Playbook manifest.Playbook
	// Values — текущие значения настроек проекта (.tplaiter/project.yaml) —
	// уходят в extra-vars как tplater.settings.
	Values settings.Values
	// Project — идентификация проекта (.tplaiter/project.yaml: project) —
	// уходит в extra-vars как tplater.project.
	Project manifest.ProjectInfo
	// AutoYes — подтверждает установку ansible без интерактивного вопроса
	// (`--yes`, SPEC-03 §4). При false и отсутствующем ansible-playbook
	// [Runner.RunPlaybook] возвращает [ErrAnsibleMissing] с рецептом установки,
	// ничего не устанавливая.
	AutoYes bool
}

// RunPlaybook исполняет один плейбук окружения (SPEC-03 §4):
//  1. проверяет, что файл плейбука существует (TemplateDir/Playbook.File);
//  2. убеждается, что ansible-playbook доступен в PATH — если нет, предлагает
//     установку через [deps.Install] (см. [ensureAnsiblePlaybook]);
//  3. сериализует Values+Project в JSON extra-vars, пишет во временный файл
//     0600 (безопаснее длинной командной строки — секреты настроек не
//     попадают ни в argv процесса, ни в историю шелла);
//  4. запускает `ansible-playbook <file> --extra-vars @<tmp> -e
//     tplater_project_root=<ProjectRoot>` в ProjectRoot со стримингом вывода
//     в UI.Out; временный файл удаляется после завершения независимо от
//     исхода.
//
// Ошибка ansible-playbook (ненулевой код возврата) возвращается как есть —
// *execx.ExitError внутри, errors.As позволяет вызывающему командному слою
// (internal/cmd/env.go) пробросить тот же код возврата процессом tplater
// (см. execRunCommand в run.go — тот же приём).
func (r *Runner) RunPlaybook(ctx context.Context, opts Options) error {
	return ErrAnsibleAdapterUnavailable
	/*
		playbookPath := filepath.Join(opts.TemplateDir, opts.Playbook.File)
		if _, err := os.Stat(playbookPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf(
					"%w: %s (плейбук %q манифеста environment.playbooks) — проверьте, что "+
						"`tplater new` скопировал каталог окружения шаблона в %s",
					ErrPlaybookFileNotFound, playbookPath, opts.Playbook.Name, EnvironmentRelPath,
				)
			}
			return fmt.Errorf("envsetup: проверка файла плейбука %s: %w", playbookPath, err)
		}

		if err := ensureAnsiblePlaybook(ctx, r.Exec, r.DepsUI, opts.AutoYes); err != nil {
			return err
		}

		extraVarsJSON, err := buildExtraVars(opts.Values, opts.Project)
		if err != nil {
			return err
		}

		tmpPath, err := writeExtraVarsFile(extraVarsJSON)
		if err != nil {
			return err
		}
		defer os.Remove(tmpPath)

		r.UI.Info(fmt.Sprintf("envsetup: запускаю плейбук %s (%s)", opts.Playbook.Name, playbookPath))

		args := []string{
			playbookPath,
			"--extra-vars", "@" + tmpPath,
			"-e", "tplater_project_root=" + opts.ProjectRoot,
		}
		_, err = r.Exec.Run(ctx, ansiblePlaybookBinary, args, execx.Options{
			Dir:    opts.ProjectRoot,
			Stdout: r.UI.Out,
			Stderr: r.UI.Out,
		})
		return err
	*/
}

// ensureAnsiblePlaybook проверяет, что ansible-playbook доступен в PATH, и
// если нет — прогоняет флоу автоустановки ansible (SPEC-03 §4):
// [deps.Install] с confirm=autoYes, затем повторная проверка PATH. Строгая
// проверка именно "ansible-playbook" (а не "ansible" через [deps.Check]) —
// потому что это ровно тот бинарник, который запускает [Runner.RunPlaybook];
// на практике они ставятся одним пакетом ansible, но проверять нужно то, что
// реально будет исполняться.
func ensureAnsiblePlaybook(ctx context.Context, exec execx.Runner, out deps.UI, autoYes bool) error {
	return ErrAnsibleAdapterUnavailable
	/*
		if _, err := exec.LookPath(ansiblePlaybookBinary); err == nil {
			return nil
		}

		confirm := func() bool { return autoYes }
		if _, err := deps.Install(ctx, exec, out, ansibleTool, confirm); err != nil {
			return fmt.Errorf("envsetup: установка ansible: %w", err)
		}

		if _, err := exec.LookPath(ansiblePlaybookBinary); err == nil {
			return nil
		}

		recipe := installRecipe(exec)
		return fmt.Errorf(
			"%w — установите ansible (%s) и повторите; либо передайте --yes для автоматической установки",
			ErrAnsibleMissing, recipe,
		)
	*/
}

// installRecipe формирует человекочитаемый рецепт установки ansible для
// сообщения об ошибке [ensureAnsiblePlaybook], когда автоустановка не
// удалась/не запрашивалась.
func installRecipe(exec execx.Runner) string {
	action := deps.InstallPlan(ansibleTool, deps.DetectPlatform(exec))
	if action.Kind != deps.ActionNone {
		return action.Command
	}
	return "brew install " + ansibleTool.Install.Brew + " (или " + ansibleTool.Install.Apt + " через apt на linux)"
}

// projectVars — часть extra-vars tplater.project (SPEC-03 §4: JSON
// {"tplaiter": {"project": {...}, "settings": {...}}}). Явные json-теги в
// нижнем регистре — извне (ansible) ожидается snake/lower-case, а не
// Go-конвенция экспортированных полей [manifest.ProjectInfo].
type projectVars struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Module string `json:"module"`
	System string `json:"system"`
	Domain string `json:"domain"`
}

// extraVarsTplater — тело поля "tplaiter" extra-vars.
type extraVarsTplater struct {
	Project  projectVars     `json:"project"`
	Settings settings.Values `json:"settings"`
}

// extraVarsPayload — корень JSON extra-vars, передаваемого ansible-playbook.
type extraVarsPayload struct {
	Tplater extraVarsTplater `json:"tplaiter"`
}

// buildExtraVars сериализует values и project в JSON extra-vars (SPEC-03 §4):
// {"tplaiter": {"project": {name,slug,module,system,domain}, "settings":
// {...values}}}. Вынесена отдельной функцией от [Runner.RunPlaybook] намеренно
// — юниты проверяют форму JSON без необходимости гонять реальный
// ansible-playbook или временные файлы.
func buildExtraVars(values settings.Values, proj manifest.ProjectInfo) (string, error) {
	if values == nil {
		values = settings.Values{}
	}
	payload := extraVarsPayload{
		Tplater: extraVarsTplater{
			Project: projectVars{
				Name:   proj.Name,
				Slug:   proj.Slug,
				Module: proj.Module,
				System: proj.System,
				Domain: proj.Domain,
			},
			Settings: values,
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("envsetup: сериализация extra-vars: %w", err)
	}
	return string(data), nil
}

// writeExtraVarsFile пишет content во временный файл с правами 0600 (SPEC-03
// §4: extra-vars безопаснее передавать через файл, чем длинной командной
// строкой — секреты настроек не попадают в argv/историю шелла) и возвращает
// его путь. Вызывающий отвечает за удаление (см. defer os.Remove в
// [Runner.RunPlaybook]).
func writeExtraVarsFile(content string) (string, error) {
	f, err := os.CreateTemp("", "tplater-extravars-*.json")
	if err != nil {
		return "", fmt.Errorf("envsetup: создание временного файла extra-vars: %w", err)
	}
	path := f.Name()

	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("envsetup: права временного файла extra-vars %s: %w", path, err)
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("envsetup: запись временного файла extra-vars %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("envsetup: закрытие временного файла extra-vars %s: %w", path, err)
	}
	return path, nil
}
