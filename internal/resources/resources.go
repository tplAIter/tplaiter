// Package resources переносит из checkout шаблона в .tplaiter/ созданного или
// обновляемого проекта ресурсы, которые нужны офлайн уже после удаления
// checkout: каталоги окружения (ansible-плейбуки), сниппеты
// генераторов и источник ai-config. Копируются только декларированные в
// манифесте ресурсы — если шаблон не объявляет environment/generators/aiConfig,
// соответствующие каталоги в проекте не создаются.
//
// Логика выделена из internal/newcmd (реализация ) в общий пакет, чтобы её без
// дублирования переиспользовал `tplater update` (реализация ): при обновлении
// версии те же ресурсы перекопируются из нового checkout'а. newcmd сохраняет
// тонкую обёртку copyResources → [Copy].
package resources

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/aiconfig"
	"github.com/tplAIter/tplaiter/internal/envsetup"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// Copy переносит из checkout шаблона (src) в .tplaiter/ проекта (target)
// декларированные ресурсы: окружение, генераторы, ai-config.
//
// Контракты путей (симметричны между тремя потребителями):
//   - environment/generators: файлы копируются С СОХРАНЕНИЕМ их относительного
//     пути от корня шаблона под RelPath-каталог, поэтому Playbook.File/
//     Generator.Snippet джойнятся с TemplateDir/GeneratorsDir без
//     ре-нормализации (см. envsetup.EnvironmentRelPath, gen.GeneratorsRelPath);
//   - ai-config: содержимое каталога aiConfig.path кладётся НЕПОСРЕДСТВЕННО в
//     .tplaiter/ai-config (aiconfig.Load ждёт config.json в корне этого каталога).
func Copy(src fs.FS, target string, tpl *manifest.Template) error {
	if err := copyEnvironment(src, target, tpl); err != nil {
		return err
	}
	if err := copyGenerators(src, target, tpl); err != nil {
		return err
	}
	return copyAIConfig(src, target, tpl)
}

// copyEnvironment копирует каталоги, на которые ссылаются
// environment.playbooks[].file, в .tplaiter/environment (сохраняя структуру).
func copyEnvironment(src fs.FS, target string, tpl *manifest.Template) error {
	if len(tpl.Environment.Playbooks) == 0 {
		return nil
	}
	roots := make([]string, 0, len(tpl.Environment.Playbooks))
	for _, pb := range tpl.Environment.Playbooks {
		if pb.File != "" {
			roots = append(roots, pb.File)
		}
	}
	dst := filepath.Join(target, envsetup.EnvironmentRelPath)
	return copyRootsPreserving(src, roots, dst, "environment.playbooks[].file")
}

// copyGenerators копирует каталоги сниппетов (Generator.Snippet и Anchor.Insert)
// в .tplaiter/generators (сохраняя структуру).
func copyGenerators(src fs.FS, target string, tpl *manifest.Template) error {
	if len(tpl.Generators) == 0 {
		return nil
	}
	var roots []string
	for i := range tpl.Generators {
		g := &tpl.Generators[i]
		if g.Snippet != "" {
			roots = append(roots, g.Snippet)
		}
		for _, t := range g.Targets { // мультифайловая форма (проверку)
			if t.Snippet != "" {
				roots = append(roots, t.Snippet)
			}
		}
		for _, a := range g.Anchors {
			if a.Insert != "" {
				roots = append(roots, a.Insert)
			}
		}
	}
	dst := filepath.Join(target, gen.GeneratorsRelPath)
	return copyRootsPreserving(src, roots, dst, "generators[].snippet/anchors[].insert")
}

// copyAIConfig копирует содержимое каталога aiConfig.path в .tplaiter/ai-config.
func copyAIConfig(src fs.FS, target string, tpl *manifest.Template) error {
	aiPath := strings.Trim(strings.TrimSpace(tpl.AIConfig.Path), "/")
	if aiPath == "" {
		return nil
	}
	dst := filepath.Join(target, aiconfig.AIConfigRelPath)
	if err := copyFSTree(src, aiPath, dst, true); err != nil {
		return fmt.Errorf("resources: копирование aiConfig.path %q: %w", tpl.AIConfig.Path, err)
	}
	return nil
}

// copyRootsPreserving копирует под dst каталоги (или файлы) верхнего уровня,
// в которых лежат ресурсные пути refs, сохраняя относительную структуру от
// корня шаблона. Дедупликация верхних сегментов исключает повторное копирование
// одного каталога для нескольких плейбуков/генераторов.
func copyRootsPreserving(src fs.FS, refs []string, dst, what string) error {
	seen := make(map[string]bool)
	for _, ref := range refs {
		root := topSegment(ref)
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		if err := copyFSTree(src, root, dst, false); err != nil {
			return fmt.Errorf("resources: копирование ресурса %s (%q): %w", what, root, err)
		}
	}
	return nil
}

// topSegment возвращает первый сегмент слэш-разделённого пути (каталог верхнего
// уровня ресурса) либо сам путь, если сегментов нет. Пустой/«.»/«..» — "".
func topSegment(p string) string {
	p = path.Clean(strings.TrimSpace(p))
	if p == "." || p == ".." || p == "" || strings.HasPrefix(p, "..") {
		return ""
	}
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}

// copyFSTree копирует поддерево src, укоренённое в srcRel, в каталог dst.
// flatten=false сохраняет srcRel в целевом пути (dst/<srcRel>/...); flatten=true
// снимает префикс srcRel (содержимое каталога ложится прямо в dst). Служебный
// .git checkout-worktree не копируется.
func copyFSTree(src fs.FS, srcRel, dst string, flatten bool) error {
	srcRel = path.Clean(srcRel)
	return fs.WalkDir(src, srcRel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		rel := p
		if flatten {
			rel = strings.TrimPrefix(p, srcRel)
			rel = strings.TrimPrefix(rel, "/")
		}
		if rel == "" { // корень поддерева при flatten
			if d.IsDir() {
				return nil
			}
		}
		outPath := filepath.Join(dst, filepath.FromSlash(rel))

		if d.IsDir() {
			return os.MkdirAll(outPath, 0o755)
		}
		data, rerr := fs.ReadFile(src, p)
		if rerr != nil {
			return fmt.Errorf("чтение %s: %w", p, rerr)
		}
		if mkErr := os.MkdirAll(filepath.Dir(outPath), 0o755); mkErr != nil {
			return mkErr
		}
		mode := os.FileMode(0o644)
		if info, ierr := d.Info(); ierr == nil {
			mode = info.Mode().Perm()
		}
		if werr := os.WriteFile(outPath, data, mode); werr != nil {
			return fmt.Errorf("запись %s: %w", outPath, werr)
		}
		return nil
	})
}
