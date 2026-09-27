//go:build unix

package state

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/tplAIter/tplaiter/internal/naming"
)

// lockFileName — межпроцессный лок-файл в домашнем каталоге tplater.
const lockFileName = ".lock"

// WithLock сериализует fn относительно других процессов tplater, держащих
// эксклюзивный flock на ~/.tplaiter/.lock (или $TPLAITER_HOME/.lock), на время
// её выполнения. Используется для read-modify-write операций над файлами
// состояния (config.yaml/index.yaml/projects.yaml/state.yaml): без лока два
// параллельных `tplater repo add` могли бы потерять правки друг друга при
// записи через writeFileAtomic (атомарна запись одного файла, но не
// read-modify-write в целом).
//
// home должен существовать (см. [EnsureHome]) — сам WithLock каталог не
// создаёт, чтобы не плодить побочные эффекты в чисто читающих сценариях.
//
// Реализация — syscall.Flock, достаточно для darwin/linux (см. build tag
// "unix"); Windows не поддерживается этим файлом ни документацию проекта, ни .
func WithLock(home string, fn func() error) error {
	if err := naming.GuardLegacyWrite(home); err != nil {
		return fmt.Errorf("state: legacy writer guard: %w", err)
	}
	path := filepath.Join(home, lockFileName)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return fmt.Errorf("state: открытие лок-файла %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("state: захват лока %s: %w", path, err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	return fn()
}
