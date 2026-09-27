package state

import (
	"fmt"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// RunStateVersion — текущая поддерживаемая версия формата state.yaml.
const RunStateVersion = 1

// runStateFileName — имя файла в домашнем каталоге tplater. Отдельное от
// одноимённого пакета имя типа ([RunState]) и файла — во избежание путаницы
// вида "state.State".
const runStateFileName = "state.yaml"

// RunState — содержимое ~/.tplaiter/state.yaml: мелкие оперативные данные CLI,
// не относящиеся к конфигурации или реестрам ( — suggest раз в 24ч).
type RunState struct {
	Version int `yaml:"version"`
	// LastUpdateCheck — момент последней фоновой проверки новой версии
	// tplater. Нулевое значение — проверка ещё не выполнялась.
	LastUpdateCheck time.Time `yaml:"lastUpdateCheck"`
}

// DefaultRunState возвращает состояние для случая, когда state.yaml ещё не
// существует: проверка обновлений ещё не выполнялась.
func DefaultRunState() RunState {
	return RunState{Version: RunStateVersion}
}

// runStatePath возвращает путь к state.yaml в домашнем каталоге home.
func runStatePath(home string) string {
	return filepath.Join(home, runStateFileName)
}

// LoadRunState читает state.yaml из домашнего каталога home. Отсутствие
// файла — не ошибка: возвращается [DefaultRunState].
func LoadRunState(home string) (RunState, error) {
	data, existed, err := readFile(runStatePath(home))
	if err != nil {
		return RunState{}, err
	}
	if !existed {
		return DefaultRunState(), nil
	}
	return decodeRunState(data)
}

// SaveRunState атомарно записывает s в state.yaml домашнего каталога home.
func SaveRunState(home string, s RunState) error {
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("state: маршализация state.yaml: %w", err)
	}
	return writeFileAtomic(runStatePath(home), data)
}

func decodeRunState(data []byte) (RunState, error) {
	version, err := peekVersion(data)
	if err != nil {
		return RunState{}, fmt.Errorf("state: разбор state.yaml: %w", err)
	}

	migrated, err := checkAndMigrate(kindState, data, version, RunStateVersion)
	if err != nil {
		return RunState{}, err
	}

	var s RunState
	if err := yaml.Unmarshal(migrated, &s); err != nil {
		return RunState{}, fmt.Errorf("state: разбор state.yaml: %w", err)
	}
	return s, nil
}
