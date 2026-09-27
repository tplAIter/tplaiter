package deps

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// EnsureOptions настраивает поведение [EnsureTools] для неинтерактивных
// сценариев (`tplater new`, CI).
type EnsureOptions struct {
	// AutoYes — установка подтверждается автоматически, без интерактивного
	// вопроса (соответствует `--yes` CLI-флагу). Полноценный
	// интерактивный confirm (huh) описан отдельным интерфейсом; здесь
	// AutoYes — единственный источник согласия.
	AutoYes bool
	// SkipInstall полностью отключает предложения установки — только
	// проверка (соответствует `--no-deps-check` в части инсталляции;
	// сама проверка версий всё равно выполняется, чтобы отчёт был честным).
	SkipInstall bool
}

// ErrMissingRequiredTools возвращается [EnsureTools], если после проверки
// (и попытки установки) хотя бы один required-инструмент так и не найден
// либо не satisfies constraint. errors.Is отличает эту ситуацию от прочих
// ошибок оркестрации.
var ErrMissingRequiredTools = errors.New("deps: отсутствуют обязательные инструменты окружения")

// EnsureTools — оркестрация проверки и (опциональной) установки tools для
// `tplater new`: проверка -> предложение установки для
// отсутствующих/несоответствующих -> повторная проверка -> провал, если
// после этого остались required-инструменты не в порядке.
//
// required=false инструменты, оставшиеся не в порядке, только
// предупреждаются через out.Warn и не влияют на итоговую ошибку.
func EnsureTools(ctx context.Context, runner execx.Runner, out UI, tools []manifest.Tool, opts EnsureOptions) error {
	statuses := Check(ctx, runner, tools)

	missing := make([]ToolStatus, 0, len(statuses))
	for i, st := range statuses {
		if st.Found && st.Satisfies {
			continue
		}

		if !opts.SkipInstall {
			confirm := func() bool { return opts.AutoYes }
			if _, err := Install(ctx, runner, out, st.Tool, confirm); err != nil {
				out.Warn(err.Error())
			}
			st = checkOne(ctx, runner, st.Tool)
			statuses[i] = st
		}

		if st.Found && st.Satisfies {
			continue
		}

		if !st.Tool.Required {
			out.Warn(fmt.Sprintf("%s: %s", st.Tool.Name, statusDetail(st)))
			continue
		}
		missing = append(missing, st)
	}

	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingRequiredTools, summarizeMissing(missing))
	}
	return nil
}

// statusDetail описывает человекочитаемо, почему статус не «всё хорошо»
// (для warning-строк необязательных инструментов и итоговой сводки ошибки).
func statusDetail(st ToolStatus) string {
	switch {
	case !st.Found:
		return "не найден"
	case !st.Satisfies && st.Version != "":
		return fmt.Sprintf("версия %s не удовлетворяет требованию %q", st.Version, st.Tool.Version)
	case st.Err != nil:
		return st.Err.Error()
	default:
		return "не удовлетворяет требованиям"
	}
}

func summarizeMissing(missing []ToolStatus) string {
	parts := make([]string, 0, len(missing))
	for _, st := range missing {
		parts = append(parts, fmt.Sprintf("%s (%s)", st.Tool.Name, statusDetail(st)))
	}
	return strings.Join(parts, ", ")
}
