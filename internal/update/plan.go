package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Op — вид файловой операции плана.
type Op int

const (
	// OpKeep — файл не трогаем (информационная запись: без изменений, оставлен
	// пользовательский вариант, файл уже отсутствует и т.п.).
	OpKeep Op = iota
	// OpWrite — записать Content (обновление, создание, merge, конфликт).
	OpWrite
	// OpDelete — удалить файл рабочего дерева.
	OpDelete
)

// Action — решение по одному файлу.
type Action struct {
	// Path — относительный slash-путь файла.
	Path string
	// Op — операция.
	Op Op
	// Content — новое содержимое (для OpWrite).
	Content []byte
	// Reason — человекочитаемое обоснование (для вывода плана).
	Reason string
	// Conflict — true, если Content содержит маркеры конфликта.
	Conflict bool
}

// Plan — набор решений update-операции.
type Plan struct {
	Actions  []Action
	Warnings []string
}

// Conflicts возвращает пути файлов с конфликт-маркерами (для exit-кода и отчёта).
func (p *Plan) Conflicts() []string {
	var out []string
	for _, a := range p.Actions {
		if a.Conflict {
			out = append(out, a.Path)
		}
	}
	sort.Strings(out)
	return out
}

// HasChanges сообщает, меняет ли план дерево (есть OpWrite/OpDelete).
func (p *Plan) HasChanges() bool {
	for _, a := range p.Actions {
		if a.Op == OpWrite || a.Op == OpDelete {
			return true
		}
	}
	return false
}

// Compute строит план по 3-way-модели.
//
// Вход:
//   - baseFiles   — чистый рендер СТАРОЙ версии шаблона (общий предок);
//   - targetFiles — чистый рендер НОВОЙ версии шаблона;
//   - baseline    — sha256 файлов из .tplaiter/baseline.json (для детекта правок
//     пользователя; если записи нет — фоллбек на хэш base-рендера);
//   - workDir     — корень проекта (читаются фактические файлы).
//
// Универсум путей = объединение ключей baseFiles, targetFiles и baseline;
// произвольные пользовательские файлы вне шаблона не затрагиваются.
func Compute(baseFiles, targetFiles map[string][]byte, baseline map[string]string, workDir string) (*Plan, error) {
	paths := unionKeys(baseFiles, targetFiles, baseline)
	plan := &Plan{} //nolint:varnamelen // plan — общепонятное имя.

	for _, rel := range paths {
		bContent, inBase := baseFiles[rel]
		tContent, inTarget := targetFiles[rel]
		wContent, workExists, err := readWork(workDir, rel)
		if err != nil {
			return nil, err
		}

		baseHash := baseline[rel]
		userUnmodified := workExists && isUnmodified(wContent, baseHash, bContent, inBase)

		switch {
		case inBase && inTarget:
			if bytes.Equal(bContent, tContent) {
				// (b) шаблон не менял файл — оставляем пользовательский.
				if !workExists {
					plan.add(rel, OpWrite, tContent, "recreate (deleted by user, template unchanged)", false)
				} else {
					plan.add(rel, OpKeep, nil, "unchanged", false)
				}
				continue
			}
			// Шаблон изменил файл.
			switch {
			case !workExists:
				plan.add(rel, OpWrite, tContent, "recreate (deleted by user, updated upstream)", false)
			case userUnmodified:
				// (a) hash(work)==baseline — перезапись target-версией.
				plan.add(rel, OpWrite, tContent, "update", false)
			default:
				// (c) все три различны — 3-way merge.
				merged, conflict := merge3(bContent, wContent, tContent)
				reason := "merge"
				if conflict {
					reason = "conflict"
				}
				plan.add(rel, OpWrite, merged, reason, conflict)
			}

		case inTarget && !inBase:
			// (d) новый файл в target.
			switch {
			case !workExists:
				plan.add(rel, OpWrite, tContent, "create", false)
			case bytes.Equal(wContent, tContent):
				plan.add(rel, OpKeep, nil, "already present", false)
			default:
				// work существует и отличается → конфликт (base пуст).
				merged, _ := merge3(nil, wContent, tContent)
				plan.add(rel, OpWrite, merged, "conflict (created upstream, differs locally)", true)
			}

		default:
			// (e) файл был в base/baseline, но отсутствует в target — удалён вверху.
			switch {
			case !workExists:
				plan.add(rel, OpKeep, nil, "already absent", false)
			case userUnmodified:
				plan.add(rel, OpDelete, nil, "delete (removed upstream)", false)
			default:
				plan.add(rel, OpKeep, nil, "kept (modified locally, removed upstream)", false)
				plan.Warnings = append(plan.Warnings,
					rel+": удалён в новой версии шаблона, но изменён локально — оставлен без изменений")
			}
		}
	}

	return plan, nil
}

// add добавляет действие в план.
func (p *Plan) add(path string, op Op, content []byte, reason string, conflict bool) {
	p.Actions = append(p.Actions, Action{
		Path:     path,
		Op:       op,
		Content:  content,
		Reason:   reason,
		Conflict: conflict,
	})
}

// Apply материализует план в рабочем каталоге workDir: записывает/удаляет файлы,
// подчищает опустевшие после удаления каталоги. Возвращает пути конфликтов.
func (p *Plan) Apply(workDir string) ([]string, error) {
	// A decoded or computed legacy plan cannot be materialized until the
	// lifecycle owner supplies the later authenticated apply boundary.
	return nil, ErrLifecycleUnavailable
}

// applyLegacy retains the former materialization algorithm as restoration
// input for the authorized lifecycle owner. T5 deliberately has no caller.
func (p *Plan) applyLegacy(workDir string) ([]string, error) {
	for _, a := range p.Actions {
		full := filepath.Join(workDir, filepath.FromSlash(a.Path))
		switch a.Op {
		case OpWrite:
			if err := writeFile(full, a.Content); err != nil {
				return nil, err
			}
		case OpDelete:
			if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("update: remove %s: %w", a.Path, err)
			}
			pruneEmptyDirs(workDir, filepath.Dir(full))
		case OpKeep:
			// no-op
		}
	}
	return p.Conflicts(), nil
}

// readWork читает файл рабочего дерева. Возвращает (content, exists, err).
func readWork(workDir, rel string) ([]byte, bool, error) {
	full := filepath.Join(workDir, filepath.FromSlash(rel))
	data, err := os.ReadFile(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("update: read work %s: %w", rel, err)
	}
	return data, true, nil
}

// isUnmodified сообщает, совпадает ли рабочий файл с «эталоном» (не правлен
// пользователем). Эталон — записанный baseline-хэш; если его нет — содержимое
// base-рендера.
func isUnmodified(work []byte, baseHash string, base []byte, inBase bool) bool {
	if baseHash != "" {
		return sha256Hex(work) == baseHash
	}
	if inBase {
		return bytes.Equal(work, base)
	}
	return false
}

// sha256Hex возвращает hex(sha256(data)) — совпадает с engine.ComputeBaseline.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// unionKeys возвращает отсортированное объединение ключей base/target-рендеров и
// baseline-карты (последняя — с иным типом значения).
func unionKeys(baseFiles, targetFiles map[string][]byte, baseline map[string]string) []string {
	seen := make(map[string]struct{}, len(baseFiles)+len(targetFiles)+len(baseline))
	for k := range baseFiles {
		seen[k] = struct{}{}
	}
	for k := range targetFiles {
		seen[k] = struct{}{}
	}
	for k := range baseline {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// writeFile создаёт родительские каталоги и пишет файл (0644).
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("update: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: генерируемые исходники — обычные файлы 0644.
		return fmt.Errorf("update: write %s: %w", path, err)
	}
	return nil
}

// pruneEmptyDirs удаляет опустевшие каталоги от dir вверх, не поднимаясь выше root.
func pruneEmptyDirs(root, dir string) {
	root = filepath.Clean(root)
	for cur := filepath.Clean(dir); cur != root && len(cur) > len(root); {
		entries, err := os.ReadDir(cur)
		if err != nil || len(entries) > 0 {
			return
		}
		if err := os.Remove(cur); err != nil {
			return
		}
		cur = filepath.Dir(cur)
	}
}
