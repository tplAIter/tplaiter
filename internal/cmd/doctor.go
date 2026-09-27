package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// rowStatus — семантический статус одной строки отчёта doctor.
type rowStatus int

const (
	rowOK rowStatus = iota
	rowWarn
	rowFail
)

// doctorRow — одна проверенная позиция отчёта (инструмент окружения,
// инструмент шаблона, элемент состояния ~/.tplaiter).
type doctorRow struct {
	Name   string
	Status rowStatus
	Detail string
	Hint   string
}

// doctorSection — именованная группа строк ("Среда", "Инструменты шаблона",
// "Состояние", SPEC-03 §4).
type doctorSection struct {
	Title string
	Rows  []doctorRow
}

// doctorCriticalTools — инструменты, чьё отсутствие/несоответствие делает
// `tplater doctor` неуспешным (ненулевой exit code). Остальные проблемы —
// только предупреждения в отчёте (SPEC-03 §4: "exit 1 при критичных ✗
// (go, git)").
var doctorCriticalTools = map[string]bool{
	"go":  true,
	"git": true,
}

// newDoctorCmd создаёт команду `tplater doctor`.
func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Проверить окружение и инструменты активного шаблона",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sections, critical := buildDoctorReport(cmd.Context(), nil, "", "")
			renderDoctorReport(cmd.OutOrStdout(), ui.Default(), sections)

			if critical {
				return errors.New("cmd: doctor: критичные инструменты окружения недоступны — см. отчёт выше")
			}
			return nil
		},
	}
}

// buildDoctorReport собирает все секции отчёта. critical — true, если хотя
// бы одна строка из [doctorCriticalTools] провалилась (Found/Satisfies не
// оба true).
func buildDoctorReport(ctx context.Context, runner execx.Runner, cwd, home string) (sections []doctorSection, critical bool) {
	// A doctor report is useful without becoming an authority or running a
	// manifest-selected executable.  The old probe path remains unavailable
	// until a separately approved bound action exists.
	_ = ctx
	_ = runner
	_ = cwd
	_ = home
	return []doctorSection{{Title: "Среда", Rows: []doctorRow{{Name: "инструменты", Status: rowWarn, Detail: "не проверено: требуется подтверждённое действие"}}}}, false
	/*
		envSection, envCritical := environmentSection(ctx, runner)
		sections = append(sections, envSection)
		critical = critical || envCritical

		if templSection, ok := templateToolsSection(ctx, runner, cwd); ok {
			sections = append(sections, templSection)
		}

		sections = append(sections, stateSection(home))

		return sections, critical
	*/
}

// environmentSection — базовый набор инструментов, не зависящий от того,
// запущен ли doctor внутри проекта шаблона (SPEC-03 §4).
func environmentSection(ctx context.Context, runner execx.Runner) (doctorSection, bool) {
	tools := []manifest.Tool{
		{
			Name:     "go",
			Version:  ">=1.26.0",
			Required: true,
			Install:  manifest.ToolInstall{URL: "https://go.dev/dl/"},
		},
		{
			Name:     "git",
			Required: true,
			Install:  manifest.ToolInstall{Brew: "git", Apt: "git"},
		},
		{
			Name:     "docker",
			Required: false,
			Install:  manifest.ToolInstall{URL: "https://docs.docker.com/get-docker/"},
		},
		{
			Name:     "brew",
			Required: false,
			Install:  manifest.ToolInstall{URL: "https://brew.sh"},
		},
	}

	statuses := deps.Check(ctx, runner, tools)
	section := doctorSection{Title: "Среда"}
	critical := false
	for _, st := range statuses {
		row := toolRow(st)
		if row.Status == rowFail && doctorCriticalTools[st.Tool.Name] {
			critical = true
		}
		section.Rows = append(section.Rows, row)
	}
	return section, critical
}

// templateToolsSection проверяет requires.tools снимка манифеста текущего
// проекта. ok=false, если cwd не является проектом tplater (снимка нет) —
// секция целиком пропускается вызывающим.
func templateToolsSection(ctx context.Context, runner execx.Runner, cwd string) (doctorSection, bool) {
	snapshotPath := filepath.Join(cwd, manifest.SnapshotRelPath)
	if _, err := os.Stat(snapshotPath); err != nil {
		return doctorSection{}, false
	}

	section := doctorSection{Title: "Инструменты шаблона"}

	tmpl, err := manifest.LoadSnapshot(snapshotPath)
	if err != nil {
		section.Rows = append(section.Rows, doctorRow{
			Name:   manifest.SnapshotRelPath,
			Status: rowFail,
			Detail: "не удалось разобрать снимок манифеста",
			Hint:   err.Error(),
		})
		return section, true
	}

	if len(tmpl.Requires.Tools) == 0 {
		section.Rows = append(section.Rows, doctorRow{
			Name:   manifest.SnapshotRelPath,
			Status: rowOK,
			Detail: "шаблон не объявляет requires.tools",
		})
		return section, true
	}

	for _, st := range deps.Check(ctx, runner, tmpl.Requires.Tools) {
		section.Rows = append(section.Rows, toolRow(st))
	}
	return section, true
}

// stateSection проверяет домашний каталог tplater (~/.tplaiter) и
// читаемость config.yaml в нём.
func stateSection(home string) doctorSection {
	section := doctorSection{Title: "Состояние"}

	if _, err := os.Stat(home); err != nil {
		section.Rows = append(section.Rows, doctorRow{
			Name:   home,
			Status: rowWarn,
			Detail: "каталог не создан",
			Hint:   "создаётся автоматически при первом запуске любой команды",
		})
		return section
	}
	section.Rows = append(section.Rows, doctorRow{
		Name:   home,
		Status: rowOK,
		Detail: "каталог существует",
	})

	cfg, err := state.LoadConfig(home)
	if err != nil {
		section.Rows = append(section.Rows, doctorRow{
			Name:   "config.yaml",
			Status: rowFail,
			Detail: "не читается",
			Hint:   err.Error(),
		})
		return section
	}
	section.Rows = append(section.Rows, doctorRow{
		Name:   "config.yaml",
		Status: rowOK,
		Detail: fmt.Sprintf("версия %d, репозиториев: %d", cfg.Version, len(cfg.Repos)),
	})
	return section
}

// toolRow превращает [deps.ToolStatus] в строку отчёта: required-инструмент
// не в порядке -> rowFail, необязательный -> rowWarn, иначе rowOK.
func toolRow(st deps.ToolStatus) doctorRow {
	row := doctorRow{Name: st.Tool.Name}

	if st.Found && st.Satisfies {
		row.Status = rowOK
		row.Detail = st.Version
		if row.Detail == "" {
			row.Detail = st.Path
		} else {
			row.Detail = fmt.Sprintf("%s (%s)", st.Version, st.Path)
		}
		return row
	}

	if st.Tool.Required {
		row.Status = rowFail
	} else {
		row.Status = rowWarn
	}
	row.Detail = toolIssueDetail(st)
	row.Hint = installHint(st.Tool)
	return row
}

// toolIssueDetail описывает, что именно не так с инструментом.
func toolIssueDetail(st deps.ToolStatus) string {
	switch {
	case !st.Found:
		return "не найден в PATH"
	case st.Version != "" && !st.Satisfies:
		return fmt.Sprintf("версия %s не удовлетворяет %q", st.Version, st.Tool.Version)
	case st.Err != nil:
		return st.Err.Error()
	default:
		return "не удовлетворяет требованиям"
	}
}

// installHint формирует рецепт установки для отчёта: платформенный план
// через [deps.InstallPlan], фоллбек на brew/apt/url манифеста, если план не
// применим ни к одной ветке (например, doctor исполняется на платформе без
// подходящего рецепта, но манифест декларирует хоть что-то).
func installHint(tool manifest.Tool) string {
	action := deps.InstallPlan(tool, deps.DetectPlatform(execx.Exec{}))
	if action.Kind != deps.ActionNone {
		return action.Command
	}
	switch {
	case tool.Install.Brew != "":
		return "brew install " + tool.Install.Brew
	case tool.Install.Apt != "":
		return "sudo apt install " + tool.Install.Apt
	case tool.Install.URL != "":
		return tool.Install.URL
	default:
		return ""
	}
}

// renderDoctorReport печатает секции report как ui.Table в out, с символами
// ✓/✗/! и рецептами установки для строк не в порядке.
func renderDoctorReport(out io.Writer, pal ui.Palette, sections []doctorSection) {
	for _, section := range sections {
		ui.Section(out, pal, section.Title)

		table := ui.NewTable("Компонент", "Детали", "Статус")
		for _, row := range section.Rows {
			table.AddRow(row.Name, row.Detail, statusCell(pal, row))
		}
		fmt.Fprintln(out, table.RenderStyled(pal))
		fmt.Fprintln(out)
	}
}

// statusCell формирует последнюю (не выравниваемую отступами) колонку
// таблицы — символ статуса, окрашенный палитрой, плюс рецепт установки для
// строк не в порядке. Колонка выбрана последней в таблице намеренно: ANSI-
// коды палитры прибавляют "невидимые" руны, которые сломали бы выравнивание
// ЛЮБОЙ колонки, кроме последней ([ui.Table] не дополняет её пробелами).
func statusCell(pal ui.Palette, row doctorRow) string {
	var symbol string
	switch row.Status {
	case rowOK:
		symbol = ui.StatusIcon(pal, ui.StatusOK)
	case rowWarn:
		symbol = ui.StatusIcon(pal, ui.StatusWarn)
	case rowFail:
		symbol = ui.StatusIcon(pal, ui.StatusFail)
	}
	if row.Hint == "" {
		return symbol
	}
	return symbol + " — " + row.Hint
}
