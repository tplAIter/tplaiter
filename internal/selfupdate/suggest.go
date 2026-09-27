package selfupdate

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// suggestInterval — минимальный интервал между фоновыми проверками новой
// версии: раз в 24ч, не при каждом запуске.
const suggestInterval = 24 * time.Hour

// MaybeSuggest — ненавязчивая фоновая проверка обновлений,
// вызывается из PersistentPreRunE корневой команды. Никогда не мешает и не
// прерывает работу текущей команды:
//   - не чаще раза в [suggestInterval] (таймстемп в state.RunState.LastUpdateCheck,
//     домашний каталог home, момент "сейчас" передаётся аргументом now — для
//     тестируемости, а не time.Now() внутри);
//   - `updates.check: false` в config.yaml — проверка пропускается;
//   - любая ошибка (чтение state/config, сеть) — проглатывается молча, без
//     вывода и без прерывания; таймаут на сетевой поход (ls-remote) — забота
//     вызывающего кода через ctx (см. internal/cmd/selfupgrade.go);
//   - при обнаруженном отставании печатает ровно одну приглушённую строку в out.
//
// current — текущая версия CLI (обычно internal/cmd.resolveVersion()); принят
// параметром, а не вычислен внутри, чтобы избежать цикла импортов
// selfupdate<->cmd.
func MaybeSuggest(ctx context.Context, runner execx.Runner, home, current string, now time.Time, out io.Writer) {
	cfg, err := state.LoadConfig(home)
	if err != nil || !cfg.Updates.Check {
		return
	}

	rs, err := state.LoadRunState(home)
	if err != nil {
		return
	}
	if !rs.LastUpdateCheck.IsZero() && now.Sub(rs.LastUpdateCheck) < suggestInterval {
		return
	}

	// Таймстемп обновляем ДО сетевого похода: даже сорвавшаяся по таймауту
	// или неудачная проверка не должна повторяться на каждом следующем
	// запуске — раз в 24ч означает раз в 24ч независимо от исхода.
	rs.LastUpdateCheck = now
	_ = state.SaveRunState(home, rs)

	latest, err := LatestTag(ctx, runner, RepoURL())
	if err != nil || latest == "" {
		return
	}
	if Compare(current, latest) != CompareOutdated {
		return
	}

	p := ui.Default()
	fmt.Fprintln(out, p.Muted(fmt.Sprintf("доступна %s: tplater --upgrade", latest)))
}
