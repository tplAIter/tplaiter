package gen

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// runner возвращает Options.Runner либо реальный [execx.Exec]{} (depguard
// запрещает прямой os/exec вне internal/execx — см. .golangci.yml).
func runner(opts Options) execx.Runner {
	if opts.Runner != nil {
		return opts.Runner
	}
	return execx.Exec{}
}

// runPostFormat запускает gofumpt -w либо стандартный gofmt -w best-effort по
// изменённым .go файлам. gofmt — обязательный fallback: на чистом CI/сервере
// gofumpt часто не установлен, но генератор всё равно должен оставлять
// gofmt-clean исходники. Неудача форматирования не проваливает gen; итоговый
// build-gate по-прежнему отвечает за валидность кода.
func runPostFormat(ctx context.Context, opts Options, changed []string, log func(format string, args ...any)) {
	goFiles := make([]string, 0, len(changed))
	for _, f := range changed {
		if strings.HasSuffix(f, ".go") {
			goFiles = append(goFiles, f)
		}
	}
	if len(goFiles) == 0 {
		return
	}
	path, formatter, ok := findFormatter(runner(opts))
	if !ok {
		return
	}
	args := append([]string{"-w"}, goFiles...)
	if _, err := runner(opts).Run(ctx, path, args, execx.Options{Dir: opts.ProjectRoot}); err != nil {
		log("%s: %v (пропущено, best-effort)", formatter, err)
	}
}

// isGoProject ограничивает gofumpt/gofmt проектами с Go-модулем или
// workspace. Генераторы Rust и других языков не должны получать Go formatter
// лишь потому, что post-generation gate существует у всех шаблонов.
func isGoProject(root string) bool {
	for _, name := range []string{"go.mod", "go.work"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			return true
		}
	}
	return false
}

// runBuildGate запускает объявленный в manifest commands.build.run build-gate
// один раз в корне проекта. Команда — уже доверенный текст манифеста, поэтому
// исполняется так же, как `tplater run`, через POSIX shell. Старые Go manifest
// без build-команды сохраняют workspace-aware fallback `go build ./...`.
func runBuildGate(ctx context.Context, tpl *manifest.Template, opts Options) (string, string, error) {
	if tpl != nil {
		if command, ok := tpl.Commands["build"]; ok && strings.TrimSpace(command.Run) != "" {
			res, err := runner(opts).Run(ctx, "/bin/sh", []string{"-c", command.Run}, execx.Options{Dir: opts.ProjectRoot})
			return command.Run, strings.TrimSpace(res.Stdout + res.Stderr), err
		}
	}
	out, err := goBuild(ctx, opts)
	return "go build ./...", out, err
}

// findFormatter предпочитает gofumpt из PATH/~/go/bin, затем использует
// стандартный gofmt из Go toolchain.
func findFormatter(r execx.Runner) (path, name string, ok bool) {
	if p, err := r.LookPath("gofumpt"); err == nil {
		return p, "gofumpt", true
	}
	home, err := os.UserHomeDir()
	if err == nil {
		candidate := filepath.Join(home, "go", "bin", "gofumpt")
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, "gofumpt", true
		}
	}
	if p, lookErr := r.LookPath("gofmt"); lookErr == nil {
		return p, "gofmt", true
	}
	return "", "", false
}

// goBuild запускает `go build ./...` в ProjectRoot, возвращая объединённый
// вывод при ошибке. В go.work-монорепо (корень — не модуль) сборка идёт
// помодульно по use-директориям воркспейса (находка : иначе build-гейт
// всегда падал и откатывал генерацию в workspace-проектах).
func goBuild(ctx context.Context, opts Options) (string, error) {
	dirs, err := workspaceUseDirs(opts.ProjectRoot)
	if err != nil {
		return "", err
	}
	if dirs == nil {
		dirs = []string{"."}
	}
	var combined []string
	for _, d := range dirs {
		res, rerr := runner(opts).Run(ctx, "go", []string{"build", "./..."},
			execx.Options{Dir: filepath.Join(opts.ProjectRoot, d)})
		if out := strings.TrimSpace(res.Stdout + res.Stderr); out != "" {
			combined = append(combined, out)
		}
		if rerr != nil {
			return strings.Join(combined, "\n"), rerr
		}
	}
	return strings.Join(combined, "\n"), nil
}

// workspaceUseDirs возвращает use-директории go.work в корне проекта
// (nil — go.work нет, обычный модуль).
func workspaceUseDirs(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.work"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	wf, err := modfile.ParseWork("go.work", data, nil)
	if err != nil {
		return nil, fmt.Errorf("gen: разбор go.work: %w", err)
	}
	dirs := make([]string, 0, len(wf.Use))
	for _, u := range wf.Use {
		dirs = append(dirs, u.Path)
	}
	return dirs, nil
}
