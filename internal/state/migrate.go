package state

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// fileKind идентифицирует один из файлов состояния для реестра миграций.
type fileKind string

const (
	kindConfig   fileKind = "config.yaml"
	kindIndex    fileKind = "index.yaml"
	kindProjects fileKind = "projects.yaml"
	kindState    fileKind = "state.yaml"
)

// migrationFunc переносит сырые YAML-данные файла версии from к версии
// from+1. Возвращает новые сырые данные (обычно — результат повторной
// маршализации промежуточной структуры).
type migrationFunc func(data []byte) ([]byte, error)

// migrations — реестр миграций по (kind, from-версия). Сейчас пуст: все
// файлы стартуют с version=1, переносить не с чего. Задел на будущее —
// формат меняется, здесь регистрируется migrations[kindConfig][1] = func(...)
// при добавлении version=2 и т.д.
var migrations = map[fileKind]map[int]migrationFunc{}

// versionPeek — минимальная структура, чтобы прочитать только поле version
// без разбора всего файла (нужно до того, как известно, какая версия
// структуры валидна для остального содержимого).
type versionPeek struct {
	Version int `yaml:"version"`
}

// peekVersion читает поле version из сырых YAML-данных.
func peekVersion(data []byte) (int, error) {
	var v versionPeek
	if err := yaml.Unmarshal(data, &v); err != nil {
		return 0, err
	}
	return v.Version, nil
}

// checkAndMigrate проверяет версию файла (version) против текущей
// поддерживаемой (current) и, если файл старее, последовательно применяет
// зарегистрированные миграции до current. version > current — файл создан
// более новой версией tplater, откатывать нечем — ошибка с понятной
// подсказкой. version < current без зарегистрированной миграции на шаге —
// тоже ошибка (реестр неполон, а не «само рассосётся»).
func checkAndMigrate(kind fileKind, data []byte, version, current int) ([]byte, error) {
	if version > current {
		return nil, fmt.Errorf(
			"state: %s: версия файла (%d) новее поддерживаемой этой версией tplater (%d) — обновите tplater",
			kind, version, current,
		)
	}

	for version < current {
		fn, ok := migrations[kind][version]
		if !ok {
			return nil, fmt.Errorf(
				"state: %s: не найдена миграция версии %d -> %d",
				kind, version, version+1,
			)
		}
		migrated, err := fn(data)
		if err != nil {
			return nil, fmt.Errorf("state: %s: миграция версии %d -> %d: %w", kind, version, version+1, err)
		}
		data = migrated
		version++
	}

	return data, nil
}
