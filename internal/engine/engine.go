package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// defaultRoot — каталог дерева файлов внутри источника шаблона, если
// Template.Engine.Root не задан.
const defaultRoot = "files"

// Options — параметры рендера. Замена go-template'овского Options: метаданные
// движка и файловая фильтрация теперь приходят из манифеста шаблона, а не из
// template.json/Registry; фичи заменены на разрешённые настройки.
type Options struct {
	// Source — корень репозитория шаблона (fs.FS: os.DirFS в проде/тестах,
	// встроенная сборка (embed.FS) в собранных дистрибутивах). Дерево
	// генерируемых файлов лежит внутри по пути Template.Engine.Root (по
	// умолчанию "files").
	Source fs.FS
	// Target — целевой каталог. Должен не существовать либо быть пустым.
	Target string
	// Template — манифест шаблона (источник Engine{Root,CopyWithoutRender,
	// PostReplace}, Files-правил и метаданных Template.Version для baseline).
	Template *manifest.Template
	// Resolved — разрешённые настройки шаблона (реализация ). Рендер использует
	// ActiveValues — производный набор с обнулёнными неактивными вложенными
	// группами (см. [settings.Resolved]).
	Resolved settings.Resolved
	// Project — координаты создаваемого проекта (.Project в контексте).
	Project manifest.ProjectInfo
	// Runtime — runtime-параметры проекта (.Runtime.Port в контексте).
	Runtime manifest.ProjectRuntime
	// Repo — координата репозитория, из которого взят шаблон (.Template.Repo
	// в контексте и project.yaml). Манифест шаблона сам не хранит свой repo —
	// это знание источника, поэтому передаётся отдельно вызывающим.
	Repo string
	// Partials — дополнительные источники ассоциированных шаблонов: из каждого
	// fs.FS парсятся все *.tmpl (ожидаются {{ define }}-блоки). Определённые
	// имена доступны файлам шаблона через {{ template "<name>" . }}.
	Partials []fs.FS
}

// Result — итог рендера.
type Result struct {
	// Files — отсортированный список относительных путей сгенерированных
	// файлов (без baseline.json).
	Files []string
	// Baseline — снимок дерева, записанный в Target/.tplaiter/baseline.json.
	Baseline *Baseline
	// Context — контекст, использованный для рендера (переиспользуется
	// вызывающим, например для рендера NOTES.tmpl тем же набором данных).
	Context *Context
}

// renderer держит разобранный контекст и предвычисленные наборы для одного
// прогона Render.
type renderer struct {
	src      fs.FS
	root     string
	ctx      *Context
	values   settings.Values
	excluded *globSet
	copyRaw  *globSet
	postRepl []compiledPostReplace
	funcMap  template.FuncMap
	base     *template.Template
	written  []string
}

type compiledPostReplace struct {
	matcher     *globSet
	placeholder string
	value       string
}

// Render генерирует проект из шаблона Source в каталог Target.
//
// Атомарность: рендер идёт в staging-каталог рядом с целью (гарантия того же
// файлового тома для os.Rename), и лишь при полном успехе staging атомарно
// переименовывается в Target. При любой ошибке staging удаляется, Target не
// трогается. Требование: Target не существует или является пустым каталогом.
func Render(opts Options) (*Result, error) {
	if opts.Template == nil {
		return nil, errors.New("engine: Render: nil template")
	}
	if opts.Source == nil {
		return nil, errors.New("engine: Render: nil source")
	}

	root := normalizeRoot(opts.Template.Engine.Root)
	ctx := NewContext(opts)
	values := opts.Resolved.ActiveValues

	excluded, err := compileFileRules(opts.Template.Files, values)
	if err != nil {
		return nil, err
	}
	postRepl, err := compilePostReplace(opts.Template.Engine.PostReplace, ctx)
	if err != nil {
		return nil, err
	}

	funcMap := FuncMap(ctx.Settings)
	base, err := parsePartials(opts.Partials, funcMap)
	if err != nil {
		return nil, err
	}

	r := &renderer{
		src:      opts.Source,
		root:     root,
		ctx:      ctx,
		values:   values,
		excluded: excluded,
		copyRaw:  newGlobSet(opts.Template.Engine.CopyWithoutRender),
		postRepl: postRepl,
		funcMap:  funcMap,
		base:     base,
	}

	absTarget, err := filepath.Abs(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("engine: abs target: %w", err)
	}
	if err := ensureEmptyTarget(absTarget); err != nil {
		return nil, err
	}

	parent := filepath.Dir(absTarget)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("engine: mkdir parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".tplaiter-staging-*")
	if err != nil {
		return nil, fmt.Errorf("engine: create staging: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()

	if err := r.renderTree(staging); err != nil {
		return nil, err
	}

	sort.Strings(r.written)
	hashes, err := ComputeBaseline(staging, r.written)
	if err != nil {
		return nil, err
	}
	ctxHash, err := hashContext(ctx)
	if err != nil {
		return nil, err
	}
	baseline := &Baseline{
		Schema:          BaselineSchema,
		TemplateVersion: opts.Template.Metadata.Version,
		ContextHash:     ctxHash,
		Files:           hashes,
	}
	if err := baseline.Save(staging); err != nil {
		return nil, err
	}

	if err := commitStaging(staging, absTarget); err != nil {
		return nil, err
	}
	committed = true

	return &Result{Files: r.written, Baseline: baseline, Context: ctx}, nil
}

// normalizeRoot приводит Template.Engine.Root к каноническому виду без
// начальных/конечных `/`, подставляя [defaultRoot], если поле не задано.
func normalizeRoot(root string) string {
	root = strings.Trim(strings.TrimSpace(root), "/")
	if root == "" {
		return defaultRoot
	}
	return root
}

// renderTree обходит Template.Engine.Root источника и материализует дерево в
// dst.
func (r *renderer) renderTree(dst string) error {
	walkErr := fs.WalkDir(r.src, r.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(p, r.root+"/")
		return r.renderFile(dst, p, rel)
	})
	if walkErr != nil {
		return fmt.Errorf("engine: walk %s: %w", r.root, walkErr)
	}
	return nil
}

// renderFile обрабатывает один файл шаблона: условные пути, файл-фильтрацию
// (files-правила манифеста), рендер/копирование, postReplace, запись в
// staging.
func (r *renderer) renderFile(dst, srcPath, rel string) error {
	outRel, include, err := r.transformPath(rel)
	if err != nil {
		return err
	}
	if !include {
		return nil
	}

	isTmpl := strings.HasSuffix(outRel, tmplSuffix)
	logicalRel := outRel
	if isTmpl {
		logicalRel = strings.TrimSuffix(outRel, tmplSuffix)
	}

	// Файл-фильтрация по files-правилам манифеста.
	if r.excluded.matchAny(logicalRel) {
		return nil
	}

	data, err := fs.ReadFile(r.src, srcPath)
	if err != nil {
		return fmt.Errorf("engine: read %s: %w", srcPath, err)
	}

	forceCopy := r.copyRaw.matchAny(logicalRel)
	if isTmpl && !forceCopy {
		data, err = r.execTemplate(logicalRel, data)
		if err != nil {
			return err
		}
	} else {
		data = r.applyPostReplace(logicalRel, data)
	}

	// Внутрифайловые маркеры tplater:if/begin/end обрабатываются
	// ПОСЛЕ текстового рендера и после byte-copy пути одинаково — маркеры
	// живут в исходниках вообще, не только в *.tmpl. Единственное исключение —
	// copyWithoutRender: такие файлы (обычно бинарные/сторонние дашборды)
	// копируются буквально, без какой-либо интерпретации их содержимого.
	if !forceCopy {
		data, err = processMarkers(logicalRel, data, r.values)
		if err != nil {
			return err
		}
	}

	if err := writeFile(filepath.Join(dst, filepath.FromSlash(logicalRel)), data); err != nil {
		return err
	}
	r.written = append(r.written, logicalRel)
	return nil
}

// execTemplate рендерит содержимое через text/template с FuncMap движка.
// Каждый файл получает клон базового набора partial'ов ({{ define }}-блоки),
// поэтому может вызывать {{ template "<name>" . }}.
func (r *renderer) execTemplate(name string, data []byte) ([]byte, error) {
	root, err := r.base.Clone()
	if err != nil {
		return nil, fmt.Errorf("engine: clone partials for %s: %w", name, err)
	}
	tmpl, err := root.New(name).Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("engine: parse template %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r.ctx); err != nil {
		return nil, fmt.Errorf("engine: execute template %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// parsePartials собирает базовый шаблон из всех *.tmpl каждого источника.
// Файлы обходятся в отсортированном порядке (детерминизм) и должны содержать
// только {{ define }}-блоки (loose-текст вне define не исполняется).
func parsePartials(sources []fs.FS, funcMap template.FuncMap) (*template.Template, error) {
	base := template.New("__partials__").Funcs(funcMap)
	for _, src := range sources {
		var paths []string
		err := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, tmplSuffix) {
				paths = append(paths, p)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("engine: walk partials: %w", err)
		}
		sort.Strings(paths)
		for _, p := range paths {
			data, err := fs.ReadFile(src, p)
			if err != nil {
				return nil, fmt.Errorf("engine: read partial %s: %w", p, err)
			}
			if _, err := base.Parse(string(data)); err != nil {
				return nil, fmt.Errorf("engine: parse partial %s: %w", p, err)
			}
		}
	}
	return base, nil
}

// applyPostReplace выполняет строковые замены плейсхолдеров в байт-копируемых
// файлах.
func (r *renderer) applyPostReplace(logicalRel string, data []byte) []byte {
	for _, rule := range r.postRepl {
		if rule.matcher.matchAny(logicalRel) {
			data = bytes.ReplaceAll(data, []byte(rule.placeholder), []byte(rule.value))
		}
	}
	return data
}

// writeFile создаёт родительские каталоги и пишет файл.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("engine: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: генерируемые исходники — обычные файлы 0644.
		return fmt.Errorf("engine: write %s: %w", path, err)
	}
	return nil
}

// ensureEmptyTarget проверяет, что target отсутствует или является пустым
// каталогом.
func ensureEmptyTarget(target string) error {
	info, err := os.Stat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("engine: stat target: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("engine: target %s exists and is not a directory", target)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return fmt.Errorf("engine: read target: %w", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("engine: target directory %s is not empty", target)
	}
	return nil
}

// commitStaging атомарно переносит staging в target (target — пустой/отсутствует).
func commitStaging(staging, target string) error {
	if _, err := os.Stat(target); err == nil {
		// Пустой каталог существует — удаляем, чтобы Rename прошёл кроссплатформенно.
		if err := os.Remove(target); err != nil {
			return fmt.Errorf("engine: remove empty target: %w", err)
		}
	}
	if err := os.Rename(staging, target); err != nil {
		return fmt.Errorf("engine: rename staging→target: %w", err)
	}
	return nil
}
