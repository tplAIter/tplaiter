// Package renderref рендерит шаблон, уже выкаченный в файловую систему
// (checkout репозитория по зафиксированному ref), в память: разбирает манифест,
// резолвит настройки и прогоняет движок во временный каталог, читая результат в
// карту относительный-путь→содержимое. Это переиспользуемое «отрендери шаблон
// по ref+values» ядро, на котором строятся `tplater update` (3-way merge двух
// версий, реализация ) и `tplater stats` (сравнение чистого рендера с рабочим
// деревом, реализация ) — обе реализации получают файлы и baseline одинакового
// состава, без дублирования оркестрации рендера.
//
// Пакет намеренно принимает уже готовую [fs.FS] (а не сам делает checkout):
// checkout — тонкая операция [repo.Manager.Checkout], которая живёт у
// вызывающего рядом с выбором ref-а; сюда попадает лишь тяжёлая часть — загрузка
// манифеста, резолюция настроек, сбор partials и рендер в память.
package renderref

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// templateManifestFileName — имя манифеста шаблона в корне checkout'а (та же
// приватная константа, что в internal/repo/scan.go и internal/newcmd).
const templateManifestFileName = "template.manifest.yaml"

// partialsDirName — каталог ассоциированных {{ define }}-шаблонов внутри
// checkout'а шаблона (см. фикстуру single-basic/partials).
const partialsDirName = "partials"

// closeScratch is private solely to prove that a cleanup failure remains
// observable alongside an earlier safe render error. Production always calls
// the real descriptor-relative cleanup.
var closeScratch = func(dir *scratchDirectory) error { return dir.Close() }

// Input — вход [Render]: значения настроек и координаты проекта, которыми
// параметризуется рендер. Совпадают со снимком в .tplaiter/project.yaml —
// это гарантирует, что повторный рендер той же версии с тем же снимком даёт
// побайтово тот же результат (нужно для no-op update и baseline-инварианта).
type Input struct {
	// Values — полный снимок настроек проекта (как в project.yaml.settings).
	Values settings.Values
	// Project — идентификация проекта (.Project в контексте рендера).
	Project manifest.ProjectInfo
	// Runtime — runtime-параметры проекта (.Runtime.Port).
	Runtime manifest.ProjectRuntime
	// Repo — алиас репозитория-источника (.Template.Repo в контексте).
	Repo string
}

// Result — итог рендера в память.
type Result struct {
	// Files — карта относительный-slash-путь→содержимое сгенерированных файлов
	// (без .tplaiter/baseline.json — движок его в Result.Files не включает).
	Files map[string][]byte
	// Baseline — чистый baseline рендера (sha256 каждого файла + версия +
	// contextHash). Именно он становится .tplaiter/baseline.json после update.
	Baseline *engine.Baseline
	// Template — разобранный и провалидированный манифест шаблона этой версии.
	Template *manifest.Template
	// Resolved — разрешённые настройки (для хуков/ansible, которым нужен полный
	// набор значений).
	Resolved settings.Resolved
}

// Render разбирает манифест из корня src (checkout шаблона, укоренённый в
// каталоге шаблона), резолвит in.Values и рендерит дерево во временный каталог,
// возвращая содержимое в памяти и чистый baseline. Временный каталог удаляется
// перед возвратом — вызывающему нужны только байты из [Result.Files].
func Render(src fs.FS, in Input) (*Result, error) {
	tmp, err := os.MkdirTemp("", "tplater-render-*")
	if err != nil {
		return nil, fmt.Errorf("renderref: временный каталог рендера: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	return render(context.Background(), src, in, tmp, func(path string) ([]byte, error) {
		return os.ReadFile(filepath.Join(tmp, "out", filepath.FromSlash(path)))
	}, nil)
}

// RenderInScratch renders exclusively below scratchRoot. The root is chosen by
// the authenticated runtime, never by template input. It leaves no result when
// cancellation, an output bound, or cleanup fails.
func RenderInScratch(ctx context.Context, src fs.FS, in Input, scratchRoot string) (_ *Result, err error) {
	if ctx == nil {
		return nil, errors.New("renderref: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := openScratch(scratchRoot)
	if err != nil {
		return nil, err
	}
	defer func() {
		if removeErr := closeScratch(dir); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("renderref: scratch cleanup: %w", removeErr))
		}
	}()
	if err := dir.Check(); err != nil {
		return nil, err
	}
	return render(ctx, src, in, dir.Path(), func(path string) ([]byte, error) {
		return dir.ReadFile("out/" + path)
	}, dir.Check)
}

func render(ctx context.Context, src fs.FS, in Input, scratch string, readOutput func(string) ([]byte, error), checkScratch func() error) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if checkScratch != nil {
		if err := checkScratch(); err != nil {
			return nil, err
		}
	}
	tpl, err := LoadTemplate(src)
	if err != nil {
		return nil, err
	}
	resolved, err := settings.Resolve(tpl, in.Values)
	if err != nil {
		return nil, fmt.Errorf("renderref: разрешение настроек: %w", err)
	}
	partials, err := templatePartials(src)
	if err != nil {
		return nil, err
	}

	target := filepath.Join(scratch, "out")
	res, err := engine.Render(engine.Options{
		Source:   src,
		Target:   target,
		Template: tpl,
		Resolved: resolved,
		Project:  in.Project,
		Runtime:  in.Runtime,
		Repo:     in.Repo,
		Partials: partials,
	})
	if err != nil {
		return nil, fmt.Errorf("renderref: рендер: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if checkScratch != nil {
		if err := checkScratch(); err != nil {
			return nil, err
		}
	}
	if len(res.Files) > 4096 {
		return nil, errors.New("renderref: preview output entry limit")
	}

	files := make(map[string][]byte, len(res.Files))
	paths := append([]string(nil), res.Files...)
	sort.Strings(paths)
	var total int64
	for _, rel := range paths {
		if !fs.ValidPath(rel) {
			return nil, errors.New("renderref: unsafe rendered path")
		}
		data, rerr := readOutput(rel)
		if rerr != nil {
			return nil, fmt.Errorf("renderref: чтение отрендеренного %s: %w", rel, rerr)
		}
		total += int64(len(data))
		if total > 64<<20 {
			return nil, errors.New("renderref: preview output byte limit")
		}
		files[rel] = append([]byte(nil), data...)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	return &Result{Files: files, Baseline: res.Baseline, Template: tpl, Resolved: resolved}, nil
}

// LoadTemplate читает, разбирает и валидирует манифест шаблона из корня src.
func LoadTemplate(src fs.FS) (*manifest.Template, error) {
	data, err := fs.ReadFile(src, templateManifestFileName)
	if err != nil {
		return nil, fmt.Errorf("renderref: чтение %s: %w", templateManifestFileName, err)
	}
	tpl, err := manifest.ParseTemplate(data)
	if err != nil {
		return nil, fmt.Errorf("renderref: %w", err)
	}
	if err := tpl.Validate(); err != nil {
		return nil, fmt.Errorf("renderref: манифест шаблона невалиден: %w", err)
	}
	return tpl, nil
}

// Values приводит карту настроек проектного маркера (как её разобрал yaml.v3 в
// map[string]any) к [settings.Values]: единственная нормализация — multiselect
// приходит как []any, а резолвер/движок ждут []string. Скалярные значения
// (string/bool/int) yaml.v3 уже кладёт в родные Go-типы. Строгая типизация со
// сверкой опций — это [settings.ParseSet]/[settings.LoadAnswersFile]; здесь
// лишь устранение артефакта разбора YAML (та же логика, что в
// internal/cmd/run.go для `tplater run`).
func Values(raw map[string]any) settings.Values {
	out := make(settings.Values, len(raw))
	for k, v := range raw {
		if list, ok := v.([]any); ok {
			strs := make([]string, 0, len(list))
			for _, item := range list {
				if s, ok := item.(string); ok {
					strs = append(strs, s)
				}
			}
			out[k] = strs
			continue
		}
		out[k] = v
	}
	return out
}

// templatePartials собирает partials-источник из checkout'а, если каталог
// partials/ существует (иначе — nil, движок обходится без него). Совпадает с
// логикой internal/newcmd.templatePartials.
func templatePartials(src fs.FS) ([]fs.FS, error) {
	info, err := fs.Stat(src, partialsDirName)
	if err != nil || !info.IsDir() {
		return nil, nil //nolint:nilerr // отсутствие partials/ — норма, не ошибка.
	}
	sub, err := fs.Sub(src, partialsDirName)
	if err != nil {
		return nil, fmt.Errorf("renderref: подкаталог partials: %w", err)
	}
	return []fs.FS{sub}, nil
}
