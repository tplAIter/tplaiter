package state

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic записывает data в path атомарно: во временный файл в том
// же каталоге (гарантирует rename на одной файловой системе), затем rename
// поверх итогового пути. Другие процессы/горутины видят либо старую, либо
// новую версию файла целиком — никогда частично записанную.
//
// Атомарность самой записи не заменяет [WithLock]: два конкурентных
// писателя всё равно должны сериализовать read-modify-write целиком, иначе
// один из них перезапишет изменения другого «последним пишущим». writeFileAtomic
// защищает только от чтения половины файла посередине записи.
//
// Права результирующего файла всегда [filePerm] (0600) — все файлы состояния
// tplater одинаково приватны (см. пакетный комментарий state.go), поэтому
// параметр прав не вынесен наружу: один явный источник правды вместо N
// вызовов, каждый раз передающих то же самое значение.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, homeDirPerm); err != nil {
		return fmt.Errorf("state: создание каталога %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("state: создание временного файла для %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	// Успешный Rename делает Remove no-op-ом (ENOENT молча игнорируется).
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: запись временного файла %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: chmod временного файла %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state: закрытие временного файла %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("state: переименование %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// readFile читает path и сообщает, существовал ли он. Отсутствие файла —
// не ошибка (existed=false, err=nil): вызывающий код возвращает дефолт.
func readFile(path string) (data []byte, existed bool, err error) {
	data, err = os.ReadFile(path)
	switch {
	case err == nil:
		return data, true, nil
	case os.IsNotExist(err):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("state: чтение %s: %w", path, err)
	}
}
