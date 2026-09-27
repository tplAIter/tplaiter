package execx

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// Компиляционная проверка: Exec и RecordingRunner реализуют Runner.
var (
	_ Runner = Exec{}
	_ Runner = (*RecordingRunner)(nil)
)

func TestExec_Run_Success(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "echo hello"}, Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "hello" {
		t.Errorf("Stdout = %q, want %q", got, "hello")
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
}

func TestExec_Run_NonZeroExit(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "echo oops >&2; exit 3"}, Options{})
	if err == nil {
		t.Fatal("Run() expected error for non-zero exit")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Run() error = %v, want *ExitError", err)
	}
	if exitErr.ExitCode != 3 {
		t.Errorf("ExitError.ExitCode = %d, want 3", exitErr.ExitCode)
	}
	if res.ExitCode != 3 {
		t.Errorf("Result.ExitCode = %d, want 3", res.ExitCode)
	}
	if !strings.Contains(res.Stderr, "oops") {
		t.Errorf("Stderr = %q, want to contain %q", res.Stderr, "oops")
	}
}

func TestExec_Run_BinaryNotFound(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "tplater-definitely-not-a-real-binary", nil, Options{})
	if err == nil {
		t.Fatal("Run() expected error for missing binary")
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		t.Fatalf("Run() error should not be *ExitError for a missing binary: %v", err)
	}
	if res.ExitCode != -1 {
		t.Errorf("ExitCode = %d, want -1", res.ExitCode)
	}
}

func TestExec_Run_DirAndEnv(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "pwd; echo \"$TPLAITER_TEST_VAR\""}, Options{
		Dir: t.TempDir(),
		Env: []string{"TPLAITER_TEST_VAR=marker-123"},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(res.Stdout, "marker-123") {
		t.Errorf("Stdout = %q, want to contain env var value", res.Stdout)
	}
}

func TestExec_Run_Stdin(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "cat"}, Options{
		Stdin: strings.NewReader("piped-input"),
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.Stdout != "piped-input" {
		t.Errorf("Stdout = %q, want %q", res.Stdout, "piped-input")
	}
}

func TestExec_Run_StreamsToWriters(t *testing.T) {
	var stdout, stderr bytes.Buffer
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "echo out; echo err >&2"}, Options{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "out" {
		t.Errorf("streamed stdout = %q, want %q", stdout.String(), "out")
	}
	if strings.TrimSpace(stderr.String()) != "err" {
		t.Errorf("streamed stderr = %q, want %q", stderr.String(), "err")
	}
	// Result должен независимо накапливать полный вывод, а не только то,
	// что попало в переданные писатели.
	if strings.TrimSpace(res.Stdout) != "out" {
		t.Errorf("Result.Stdout = %q, want %q", res.Stdout, "out")
	}
}

// markerWaiter — io.Writer, который накапливает всё записанное и закрывает
// канал ready, как только в потоке встретился маркер. Нужен тесту пересылки
// сигналов: ждать готовности дочернего процесса по факту вывода, а не по
// таймеру (см. [TestExec_Run_SignalForwarding]).
type markerWaiter struct {
	marker []byte

	mu    sync.Mutex
	buf   bytes.Buffer
	seen  bool
	ready chan struct{}
}

func newMarkerWaiter(marker string) *markerWaiter {
	return &markerWaiter{marker: []byte(marker), ready: make(chan struct{})}
}

func (w *markerWaiter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if !w.seen && bytes.Contains(w.buf.Bytes(), w.marker) {
		w.seen = true
		close(w.ready)
	}
	return len(p), nil
}

// TestExec_Run_SignalForwarding проверяет, что сигнал, отправленный в
// Options.Signals, долетает до дочернего процесса (см. [runWithSignalForwarding]).
// Дочерний sh-скрипт ловит SIGINT через trap и завершается с кодом 7 —
// наблюдаемый выход из ExitError{ExitCode: 7} и есть доказательство доставки.
//
// Синхронизация по готовности, а не по таймеру: скрипт печатает маркер
// "trap-ready" в stdout сразу ПОСЛЕ установки trap, тест ждёт маркер через
// [markerWaiter] и только затем шлёт сигнал. Так под нагрузкой параллельной
// сьюты сигнал гарантированно не обгонит установку trap (раньше здесь был
// sleep 200ms — и тест флакал: ExitCode -1 вместо 7). Скрипт «спит» циклом
// коротких sleep, а не одним длинным: некоторые оболочки (системный /bin/sh —
// bash 3.2, см. комментарий к [runWithSignalForwarding]) откладывают обработку
// перехваченного сигнала до завершения текущей foreground-команды, и сигнал,
// пришедший в окно, когда очередной sleep ещё не стартовал, «завис» бы до его
// конца — с коротким sleep задержка ограничена ~100ms. Таймауты (5s) щедрые,
// чтобы тест не был хрупким под нагрузкой CI, но не завис бы навечно при
// регрессии пересылки.
func TestExec_Run_SignalForwarding(t *testing.T) {
	sig := make(chan os.Signal, 1)
	waiter := newMarkerWaiter("trap-ready\n")

	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := Exec{}.Run(context.Background(), "sh", []string{
			"-c", "trap 'echo caught; exit 7' INT; echo trap-ready; while :; do sleep 0.1; done",
		}, Options{Signals: sig, Stdout: waiter})
		done <- outcome{res: res, err: err}
	}()

	select {
	case <-waiter.ready:
		// trap установлен — можно слать сигнал.
	case out := <-done:
		t.Fatalf("процесс завершился до маркера готовности: res=%+v err=%v", out.res, out.err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for trap-ready marker from child process")
	}
	sig <- os.Interrupt

	select {
	case out := <-done:
		var exitErr *ExitError
		if !errors.As(out.err, &exitErr) {
			t.Fatalf("Run() error = %v, want *ExitError", out.err)
		}
		if exitErr.ExitCode != 7 {
			t.Errorf("ExitError.ExitCode = %d, want 7", exitErr.ExitCode)
		}
		if !strings.Contains(out.res.Stdout, "caught") {
			t.Errorf("Stdout = %q, want to contain %q (trap ran)", out.res.Stdout, "caught")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for signal-forwarded process to exit")
	}
}

func TestExec_LookPath(t *testing.T) {
	e := Exec{}
	if _, err := e.LookPath("tplater-definitely-not-a-real-binary"); err == nil {
		t.Error("LookPath() expected error for missing binary")
	}

	// "sh" должен быть доступен в PATH на любой платформе, где гоняются тесты.
	path, err := e.LookPath("sh")
	if err != nil {
		t.Fatalf("LookPath(sh) error = %v", err)
	}
	if path == "" {
		t.Error("LookPath(sh) returned empty path")
	}
}

func TestExitError_Error(t *testing.T) {
	e := &ExitError{Name: "git", ExitCode: 1, Stderr: "fatal: not a git repository\nsome more detail"}
	got := e.Error()
	if !strings.Contains(got, "git") || !strings.Contains(got, "1") || !strings.Contains(got, "fatal: not a git repository") {
		t.Errorf("Error() = %q, missing expected substrings", got)
	}
	if strings.Contains(got, "some more detail") {
		t.Errorf("Error() = %q, should only include the first stderr line", got)
	}
}

// Проверка совместимости с exec.Error, чтобы вызывающий код мог опираться на
// стандартные типы стандартной библиотеки, если нужно.
func TestLookPath_ErrorType(t *testing.T) {
	_, err := exec.LookPath("tplater-definitely-not-a-real-binary")
	if err == nil {
		t.Skip("окружение неожиданно содержит такой бинарник")
	}
	var target *exec.Error
	if !errors.As(err, &target) {
		t.Fatalf("stdlib exec.LookPath error type changed, update assumptions: %v", err)
	}
}
