package deps

import (
	"context"
	"errors"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// EnsureOptions настраивает поведение [EnsureTools] для неинтерактивных
// сценариев (`tplater new`, CI).
type EnsureOptions struct {
	// AutoYes — установка подтверждается автоматически, без интерактивного
	// вопроса (соответствует `--yes` CLI-флагу, SPEC-03 §4). Полноценный
	// интерактивный confirm (huh) — задача опросника (C2/tp-U1); здесь
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
// `tplater new` (SPEC-03 §4): проверка -> предложение установки для
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
				// Generic recipes are closed. Do not expose an error whose text
				// could contain manifest-controlled values or process output.
				out.Warn("dependency installation unavailable")
			}
			st = Check(ctx, runner, []manifest.Tool{st.Tool})[0]
			statuses[i] = st
		}

		if st.Found && st.Satisfies {
			continue
		}

		if !st.Tool.Required {
			// The generic gate cannot attest an optional tool. Keep this UI
			// message fixed: names, paths, and status error text are all
			// manifest- or runner-controlled.
			out.Warn("optional dependency unavailable")
			continue
		}
		missing = append(missing, st)
	}

	if len(missing) > 0 {
		return fmt.Errorf("%w: required dependencies unavailable", ErrMissingRequiredTools)
	}
	return nil
}
