package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// ImportFromTool получает токен из CLI-инструмента `bin` (`glab`/`gh`) командой
// `<bin> auth token [--hostname <host>]` через runner и сохраняет его в стор под
// инструментом `tool` для хоста `host`. Возвращает id сохранённой записи.
//
// Вынесено в переиспользуемую функцию: её вызывают и команда
// `tplater auth import-glab|import-gh`, и интерактивный auth-флоу `repo add`.
// Все внешние вызовы идут через [execx.Runner], поэтому логика мокается в юнитах
// без реальных glab/gh.
//
// Отсутствие бинарника в PATH — осмысленная ошибка с рецептом (не паника):
// вызывающий код может показать её пользователю и предложить установку.
func ImportFromTool(ctx context.Context, s *Store, runner execx.Runner, bin, tool, host string) (int64, error) {
	if _, err := runner.LookPath(bin); err != nil {
		return 0, fmt.Errorf("auth: %s не найден в PATH — установите его и повторите (%s auth login)", bin, bin)
	}

	runArgs := []string{"auth", "token"}
	if host != "" {
		runArgs = append(runArgs, "--hostname", host)
	}
	res, err := runner.Run(ctx, bin, runArgs, execx.Options{})
	if err != nil {
		return 0, fmt.Errorf("auth: %s auth token: %w", bin, err)
	}
	token := strings.TrimSpace(res.Stdout)
	if token == "" {
		return 0, fmt.Errorf("auth: %s вернул пустой токен (выполните `%s auth login`)", bin, bin)
	}

	return s.Put(Credential{
		Host:  host,
		Tool:  tool,
		Token: token,
		Note:  "импортирован из " + bin,
	})
}
