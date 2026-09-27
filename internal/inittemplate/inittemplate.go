// Package inittemplate реализует мета-уровень tplaiter ( требование
// владельца №2): генерацию ПУСТОГО репозитория шаблонов «со всем
// инструментарием» (`tplaiter init-template`) и generic-селфтест такого
// репозитория (`tplaiter lint-template`, см. [Lint]).
//
// Скелет репозитория встроен в бинарник через go:embed (каталог skeleton/**,
// маленький — это допустимо, живёт в самом репо tplaiter). Скелет-файлы
// рендерятся text/template с НЕСТАНДАРТНЫМИ разделителями `<<`/`>>` и минимальным
// контекстом ([skelContext]): это оставляет обычные `{{ … }}` (шаблонные
// конструкции второго уровня — они предназначены сгенерированному репозиторию,
// а не init-времени) нетронутыми. Так один и тот же файл несёт и init-time
// подстановку (`<< .Name >>`), и layer-2 шаблон (`{{ .Project.Slug }}`).
package inittemplate

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/execx"
)

//go:embed all:skeleton
var skeletonFS embed.FS

const (
	skeletonRoot   = "skeleton"
	skeletonCommon = skeletonRoot + "/common"   // файлы корня репозитория
	skeletonTpl    = skeletonRoot + "/template" // содержимое одного шаблона
	skeletonRepo   = skeletonRoot + "/repo"     // repo.manifest.yaml (multi)
)

// nameRe — допустимое имя шаблона: совпадает с slug-требованием
// manifest.metadata.name (строчные буквы/цифры через дефис), т.к. `<< .Name >>`
// подставляется прямо в metadata.name скелета.
var nameRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// skelContext — контекст init-времени для рендера скелета.
type skelContext struct {
	Name string
}

// InitOptions — параметры одного запуска [Init].
type InitOptions struct {
	// Name — имя шаблона (slug), подставляется в metadata.name и, для --multi,
	// в путь подкаталога шаблона.
	Name string
	// Dir — целевой каталог репозитория; пусто → ./<Name>.
	Dir string
	// Multi — сгенерировать репозиторий как multi (repo.manifest.yaml + шаблон
	// в подкаталоге <Name>/).
	Multi bool
	// NoGit — не выполнять git init + первый коммит.
	NoGit bool
	// Runner — раннер внешних процессов (git). nil → [execx.Exec].
	Runner execx.Runner
	// Out — поток вывода подсказок «что дальше».
	Out io.Writer
}

// Init генерирует репозиторий шаблона. Возвращает путь созданного
// каталога репозитория. Целевой каталог должен не существовать либо быть пустым
// (повторный init в непустой каталог — ошибка).
func Init(ctx context.Context, opts InitOptions) (string, error) {
	if !nameRe.MatchString(opts.Name) {
		return "", fmt.Errorf("inittemplate: имя %q не в формате slug (строчные буквы/цифры через дефис)", opts.Name)
	}

	repoDir := opts.Dir
	if repoDir == "" {
		repoDir = filepath.Join(".", opts.Name)
	}
	if err := ensureVacant(repoDir); err != nil {
		return "", err
	}

	ctxData := skelContext{Name: opts.Name}

	// Файлы корня репозитория (README мейнтейнера, GitHub Actions workflow).
	if err := renderSubtree(skeletonCommon, repoDir, ctxData); err != nil {
		return "", err
	}

	if opts.Multi {
		if err := renderSubtree(skeletonRepo, repoDir, ctxData); err != nil {
			return "", err
		}
		if err := renderSubtree(skeletonTpl, filepath.Join(repoDir, opts.Name), ctxData); err != nil {
			return "", err
		}
	} else if err := renderSubtree(skeletonTpl, repoDir, ctxData); err != nil {
		return "", err
	}

	if !opts.NoGit {
		initGit(ctx, opts, repoDir)
	}

	printNextSteps(opts, repoDir)
	return repoDir, nil
}

// renderSubtree рендерит встроенное поддерево embedRoot в каталог dst,
// сохраняя относительную структуру и подставляя `<< … >>` контекстом data.
func renderSubtree(embedRoot, dst string, data skelContext) error {
	return fs.WalkDir(skeletonFS, embedRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(p, embedRoot+"/")
		raw, rerr := skeletonFS.ReadFile(p)
		if rerr != nil {
			return fmt.Errorf("inittemplate: чтение скелета %s: %w", p, rerr)
		}
		out, rerr := renderSkeletonBytes(rel, raw, data)
		if rerr != nil {
			return rerr
		}
		outPath := filepath.Join(dst, filepath.FromSlash(rel))
		if mkErr := os.MkdirAll(filepath.Dir(outPath), 0o755); mkErr != nil {
			return fmt.Errorf("inittemplate: mkdir %s: %w", filepath.Dir(outPath), mkErr)
		}
		if wErr := os.WriteFile(outPath, out, 0o644); wErr != nil { //nolint:gosec // G306: генерируемые исходники шаблона — обычные файлы 0644.
			return fmt.Errorf("inittemplate: запись %s: %w", outPath, wErr)
		}
		return nil
	})
}

// renderSkeletonBytes рендерит один скелет-файл через text/template с
// разделителями `<<`/`>>`. Файлы без `<<` проходят фактически без изменений.
func renderSkeletonBytes(name string, raw []byte, data skelContext) ([]byte, error) {
	t, err := template.New(name).Delims("<<", ">>").Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("inittemplate: разбор скелета %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("inittemplate: рендер скелета %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// ensureVacant проверяет, что path не существует либо является пустым каталогом.
func ensureVacant(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inittemplate: проверка %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("inittemplate: %q существует и не является каталогом", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("inittemplate: чтение %q: %w", path, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("inittemplate: каталог %q не пуст — выберите пустой каталог или другое имя", path)
	}
	return nil
}

// initGit выполняет git init + первый коммит. Отсутствие git или сбой коммита
// (например, не настроен user.name) понижаются до предупреждения: репозиторий
// уже создан и пригоден, git можно инициализировать вручную.
func initGit(ctx context.Context, opts InitOptions, repoDir string) {
	runner := opts.Runner
	if runner == nil {
		runner = execx.Exec{}
	}
	if _, err := runner.LookPath("git"); err != nil {
		warnf(opts.Out, "git не найден — пропускаю git init (инициализируйте вручную)")
		return
	}
	steps := [][]string{
		{"init", "-b", "main"},
		{"add", "-A"},
		{"commit", "-m", "chore: init template " + opts.Name + " via tplaiter init-template"},
	}
	for _, args := range steps {
		if _, err := runner.Run(ctx, "git", args, execx.Options{Dir: repoDir}); err != nil {
			warnf(opts.Out, "git %s: %v — коммит пропущен, репозиторий создан", strings.Join(args, " "), err)
			return
		}
	}
}

// printNextSteps печатает подсказку «что дальше».
func printNextSteps(opts InitOptions, repoDir string) {
	if opts.Out == nil {
		return
	}
	fmt.Fprintf(opts.Out, "\nРепозиторий шаблона %q создан в %s.\n", opts.Name, repoDir)
	fmt.Fprintln(opts.Out, "Что дальше:")
	fmt.Fprintf(opts.Out, "  1. cd %s\n", repoDir)
	fmt.Fprintln(opts.Out, "  2. tplaiter lint-template           # прогнать селфтест угловых комбинаций")
	fmt.Fprintln(opts.Out, "  3. отредактируйте template.manifest.yaml и files/ под свою вертикаль")
	fmt.Fprintln(opts.Out, "  4. git tag v0.1.0 && git push --tags # опубликуйте версию тегом")
	fmt.Fprintln(opts.Out, "  5. tplaiter repo add <alias> <url>  # подключите репозиторий")
	fmt.Fprintln(opts.Out, "  подробнее — в README.md и ai-config/rules/00-base.md сгенерированного репозитория")
}

func warnf(out io.Writer, format string, args ...any) {
	if out == nil {
		return
	}
	fmt.Fprintf(out, "предупреждение: "+format+"\n", args...)
}
