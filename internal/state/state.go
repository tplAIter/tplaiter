// Package state отвечает за домашний каталог tplater (~/.tplaiter по
// умолчанию, TPLAITER_HOME для переопределения — тесты/CI) и файлы состояния
// в нём: config.yaml, index.yaml, projects.yaml, state.yaml. См.
// документацию, документацию,
// документацию
//
// Все файлы — YAML с полем version для гейта совместимости и заделом под
// миграции формата (см. migrate.go). Запись всегда атомарна (tmp+rename,
// см. atomic.go); межпроцессная сериализация — через [WithLock].
package state

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/naming"
)

// HomeEnv — переменная окружения, переопределяющая домашний каталог tplater.
// Используется тестами и CI, чтобы не трогать реальный ~/.tplaiter.
const HomeEnv = naming.HomeEnv

// reposDirName — подкаталог кеша клонов репозиториев шаблонов.
const reposDirName = "repos"

// homeDirPerm/filePerm — права на каталог состояния и файлы в нём. Данные не
// секретны (токены хранятся отдельно в tplater.db, см. ), но
// ограничиваем доступ по умолчанию до владельца — меньше поверхность для
// случайного расширения прав в будущем.
const (
	homeDirPerm = 0o700
	filePerm    = 0o600
)

// Home возвращает путь к домашнему каталогу tplater: значение TPLAITER_HOME,
// если оно задано (даже пустой каталог — явный выбор вызывающего), иначе
// ~/.tplaiter.
func Home() (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("state: определение домашнего каталога пользователя: %w", err)
	}
	home, err := naming.ResolveHome(os.Getenv, dir)
	if err != nil {
		return "", fmt.Errorf("state: выбор домашнего каталога: %w", err)
	}
	return home, nil
}

// EnsureHome гарантирует существование домашнего каталога tplater и его
// скелета (подкаталог repos/). Файлы (config.yaml и т.д.) НЕ создаются здесь
// — каждый Load-хелпер сам возвращает дефолт при отсутствии файла и
// создаёт его по факту первой записи. created сообщает, существовал ли
// каталог до вызова — используется для first-run приветствия.
func EnsureHome() (home string, created bool, err error) {
	home, err = Home()
	if err != nil {
		return "", false, err
	}
	if err := naming.GuardLegacyWrite(home); err != nil {
		return "", false, fmt.Errorf("state: legacy writer guard: %w", err)
	}

	_, statErr := os.Stat(home)
	switch {
	case statErr == nil:
		created = false
	case os.IsNotExist(statErr):
		created = true
	default:
		return "", false, fmt.Errorf("state: проверка каталога %s: %w", home, statErr)
	}

	if err := os.MkdirAll(filepath.Join(home, reposDirName), homeDirPerm); err != nil {
		return "", false, fmt.Errorf("state: создание каталога %s: %w", home, err)
	}

	return home, created, nil
}
