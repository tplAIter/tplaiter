package mcpsrv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// Per-tool timeouts. Project generation and three-way updates take substantially
// longer than other commands (checkout, rendering, hooks), so they get a longer limit.
const (
	defaultTimeout = 120 * time.Second
	longTimeout    = 300 * time.Second
)

// runCLI executes a tplater subcommand in a separate process (the goca subprocess
// pattern): the same binary (s.exe), separate argv elements (without shell
// interpolation), cwd as working directory, and inherited environment
// (TPLAITER_HOME and other values propagate automatically because Env is unset).
// stdin is NOT connected, excluding interaction at the transport layer. The
// timeout is applied through the context; expiration kills the process.
func (s *Server) runCLI(ctx context.Context, cwd string, argv []string, timeout time.Duration) (execx.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return s.runner.Run(ctx, s.exe, argv, execx.Options{Dir: cwd})
}

// toolResult translates a child-process result into an MCP tool result. Failure
// (a nonzero exit code OR launch failure) yields isError with complete stdout+stderr:
// the agent must see all diagnostics. Success returns stdout as text (stderr is
// appended in a separate section when nonempty, because tplater commands write
// warnings as well as errors to stderr).
func toolResult(res execx.Result, runErr error) *mcp.CallToolResult {
	if failed(res, runErr) {
		return mcp.NewToolResultError(formatFailure(res, runErr))
	}

	out := res.Stdout
	if strings.TrimSpace(res.Stderr) != "" {
		out += "\n[stderr]\n" + res.Stderr
	}
	if strings.TrimSpace(out) == "" {
		out = "(команда завершилась успешно, вывод пуст)"
	}
	return mcp.NewToolResultText(out)
}

// failed identifies a failed call: a nonzero child exit code OR launch failure
// (binary not found, and so on; execx returns it without an ExitError wrapper,
// with ExitCode -1).
func failed(res execx.Result, runErr error) bool {
	if res.ExitCode != 0 {
		return true
	}
	var exitErr *execx.ExitError
	// runErr != nil with ExitCode==0 is unlikely, but be defensive: every nonnil
	// error except a clean ExitError with code 0 counts as failure.
	return runErr != nil && !errors.As(runErr, &exitErr)
}

// formatFailure collects failure diagnostics: exit code, stdout, stderr, and
// (for launch failure) the error text itself.
func formatFailure(res execx.Result, runErr error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "команда завершилась с ошибкой (код возврата %d)\n", res.ExitCode)

	var exitErr *execx.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		fmt.Fprintf(&b, "ошибка запуска: %v\n", runErr)
	}
	if strings.TrimSpace(res.Stdout) != "" {
		b.WriteString("\n[stdout]\n")
		b.WriteString(res.Stdout)
	}
	if strings.TrimSpace(res.Stderr) != "" {
		b.WriteString("\n[stderr]\n")
		b.WriteString(res.Stderr)
	}
	return b.String()
}

// resolveWorkDir makes a tool working directory absolute and validates it: the
// path must exist and be a directory. An empty dir yields an empty string (the
// child inherits server cwd). Absolutization prevents ambiguity of relative paths
// against the server cwd.
func resolveWorkDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("некорректный путь %q: %w", dir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("каталог %q недоступен: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q не является каталогом", abs)
	}
	return abs, nil
}

// resolveTargetDir makes a creator command's target directory (init-template)
// absolute: the command creates that directory, so it need not exist, but its
// parent must exist or there is nowhere to write. An empty dir yields an empty
// string (the command uses its ./<name> default).
func resolveTargetDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("некорректный путь %q: %w", dir, err)
	}
	parent := filepath.Dir(abs)
	info, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("родительский каталог %q недоступен: %w", parent, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q не является каталогом", parent)
	}
	return abs, nil
}
