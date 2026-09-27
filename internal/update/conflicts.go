package update

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultConflictExcludes — каталоги, исключаемые из сканера конфликтов по
// умолчанию: служебный .tplaiter, .git и docs/ (может содержать примеры маркеров).
var DefaultConflictExcludes = []string{".git", ".tplaiter", "docs"}

// conflictMarkerPrefix — начало строки-маркера конфликта (fail-fast при
// `<<<<<<< `).
const conflictMarkerPrefix = "<<<<<<< "

// ScanConflicts обходит дерево root и возвращает отсортированный список файлов,
// содержащих строку-маркер конфликта `<<<<<<< `. Каталоги из
// excludeDirs (по имени сегмента) и .git пропускаются. Пустой excludeDirs →
// DefaultConflictExcludes.
func ScanConflicts(root string, excludeDirs []string) ([]string, error) {
	if excludeDirs == nil {
		excludeDirs = DefaultConflictExcludes
	}
	exclude := make(map[string]struct{}, len(excludeDirs))
	for _, d := range excludeDirs {
		exclude[d] = struct{}{}
	}

	var found []string
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, skip := exclude[d.Name()]; skip && path != root {
				return fs.SkipDir
			}
			return nil
		}
		has, herr := fileHasConflictMarker(path)
		if herr != nil {
			return herr
		}
		if has {
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				rel = path
			}
			found = append(found, filepath.ToSlash(rel))
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("update: scan conflicts: %w", walkErr)
	}
	sort.Strings(found)
	return found, nil
}

// fileHasConflictMarker сообщает, содержит ли файл строку-маркер конфликта.
// Бинарные файлы (с NUL в первом блоке) пропускаются.
func fileHasConflictMarker(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if first {
			first = false
			if bytes.IndexByte(line, 0) >= 0 {
				return false, nil // бинарный файл
			}
		}
		if strings.HasPrefix(string(line), conflictMarkerPrefix) {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		// Слишком длинная строка/бинарь — не конфликт, не ошибка операции.
		return false, nil
	}
	return false, nil
}
