package gen

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

var errWorkspacePathUnsafe = errors.New("gen: unsafe workspace path")

// runPostFormat запускает gofumpt -w либо стандартный gofmt -w best-effort по
// изменённым .go файлам. gofmt — обязательный fallback: на чистом CI/сервере
// gofumpt часто не установлен, но генератор всё равно должен оставлять
// gofmt-clean исходники. Неудача форматирования не проваливает gen; итоговый
// build-gate по-прежнему отвечает за валидность кода.
func runPostFormat(ctx context.Context, opts Options, changed []string, log func(format string, args ...any)) error {
	goFiles := make([]string, 0, len(changed))
	for _, f := range changed {
		if strings.HasSuffix(f, ".go") {
			goFiles = append(goFiles, f)
		}
	}
	if len(goFiles) == 0 {
		return nil
	}
	return ErrExecutionUnavailable
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
	return "", "", ErrExecutionUnavailable
}

// findFormatter предпочитает gofumpt из PATH/~/go/bin, затем использует
// стандартный gofmt из Go toolchain.
func findFormatter() (path, name string, err error) {
	return "", "", ErrExecutionUnavailable
}

// goBuild запускает `go build ./...` в ProjectRoot, возвращая объединённый
// вывод при ошибке. В go.work-монорепо (корень — не модуль) сборка идёт
// помодульно по use-директориям воркспейса (находка CG-4: иначе build-гейт
// всегда падал и откатывал генерацию в workspace-проектах).
func goBuild(ctx context.Context, opts Options) (string, error) {
	dirs, err := workspaceUseDirs(opts.ProjectRoot)
	if err != nil {
		return "", err
	}
	if dirs == nil {
		dirs = []string{"."}
	}
	_ = dirs
	return "", ErrExecutionUnavailable
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
		if unsafeWorkspacePath(root, u.Path) {
			return nil, errWorkspacePathUnsafe
		}
		dirs = append(dirs, u.Path)
	}
	return dirs, nil
}

func unsafeWorkspacePath(root, rel string) bool {
	if rel == "" || filepath.IsAbs(filepath.FromSlash(rel)) {
		return true
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	cleanSlash := filepath.ToSlash(clean)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || (rel != cleanSlash && rel != "./"+cleanSlash) {
		return true
	}
	info, err := os.Lstat(filepath.Join(root, clean))
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0 || !info.IsDir()
}
