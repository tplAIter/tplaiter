package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

// ExitError оборачивает ненулевой код возврата команды. errors.As позволяет
// вызывающему коду отличить «команда отработала и вернула не-0» от «команду
// не удалось запустить вовсе» (последнее возвращается как есть, без обёртки).
type ExitError struct {
	Name     string
	Args     []string
	ExitCode int
	Stderr   string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("%s: exit code %d: %s", e.Name, e.ExitCode, firstLine(e.Stderr))
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// Exec — реализация [Runner] поверх os/exec. Значение с нулевым состоянием
// готово к использованию.
type Exec struct{}

// Run исполняет команду через os/exec.CommandContext.
func (Exec) Run(ctx context.Context, name string, args []string, opts Options) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = opts.Dir
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if opts.Stdout != nil {
		cmd.Stdout = io.MultiWriter(&stdoutBuf, opts.Stdout)
	}
	if opts.Stderr != nil {
		cmd.Stderr = io.MultiWriter(&stderrBuf, opts.Stderr)
	}

	var runErr error
	if opts.Signals != nil {
		runErr = runWithSignalForwarding(cmd, opts.Signals)
	} else {
		runErr = cmd.Run()
	}
	res := Result{Stdout: stdoutBuf.String(), Stderr: stderrBuf.String()}

	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		res.ExitCode = 0
		return res, nil
	case errors.As(runErr, &exitErr):
		res.ExitCode = exitErr.ExitCode()
		return res, &ExitError{Name: name, Args: args, ExitCode: res.ExitCode, Stderr: res.Stderr}
	default:
		// Бинарник не найден, не удалось создать процесс и т.п. — не код
		// возврата, а сбой запуска. exitCode -1 сигнализирует «не выполнялось».
		res.ExitCode = -1
		return res, fmt.Errorf("execx: run %q: %w", name, runErr)
	}
}

// LookPath ищет путь к бинарнику через exec.LookPath.
func (Exec) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// runWithSignalForwarding запускает cmd в отдельной группе процессов и, пока
// он не завершится, пересылает всей группе в фоне каждый сигнал, полученный
// из signals (см. [Options.Signals]). cmd.Run() не подходит здесь: нужен
// доступ к cmd.Process между Start и Wait, чтобы слать сигналы — поэтому
// Start/Wait разнесены явно.
//
// Группа процессов (Setpgid), а не просто cmd.Process.Signal, — потому что
// исполняемая команда почти всегда `$SHELL -c "<run>"`: прямой потомок —
// сама оболочка, а не реальная программа. У некоторых оболочек (замечено на
// системном /bin/sh) обработка перехваченного через trap сигнала откладывается
// до завершения текущей foreground-команды — то есть сигнал, посланный только
// оболочке, до фактической команды может не долетать своевременно. Setpgid
// переносит оболочку и всех её потомков в новую группу с pgid == pid самой
// оболочки; посылка сигнала всей группе (kill(-pgid, sig)) достаёт реальный
// процесс напрямую, независимо от того, как его родитель-shell обрабатывает
// собственные сигналы.
func runWithSignalForwarding(cmd *exec.Cmd, signals <-chan os.Signal) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return err
	}
	pgid := cmd.Process.Pid // Setpgid без явного Pgid делает pgid == pid лидера.

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig, ok := <-signals:
				if !ok {
					return
				}
				forwardSignal(pgid, sig)
			case <-done:
				return
			}
		}
	}()

	return cmd.Wait()
}

// forwardSignal посылает sig всей группе процессов pgid (см.
// [runWithSignalForwarding]). Ошибка (например, группа уже завершилась к
// моменту доставки сигнала) осознанно игнорируется — итоговый статус команды
// в любом случае определит cmd.Wait.
func forwardSignal(pgid int, sig os.Signal) {
	if s, ok := sig.(syscall.Signal); ok {
		_ = syscall.Kill(-pgid, s)
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
}
