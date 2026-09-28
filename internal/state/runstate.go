package state

import (
	"fmt"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// RunStateVersion is the currently supported state.yaml format version.
const RunStateVersion = 1

// runStateFileName is the file name in the tplater home directory. It is kept
// separate from the package, type ([RunState]), and file namesake to avoid
// confusion such as "state.State".
const runStateFileName = "state.yaml"

// RunState is the contents of ~/.tplaiter/state.yaml: small operational CLI data
// unrelated to configuration or registries (such as the 24h suggest check).
type RunState struct {
	Version int `yaml:"version"`
	// LastUpdateCheck is when tplater last checked for a new version in the
	// background. Zero means the check has not run yet.
	LastUpdateCheck time.Time `yaml:"lastUpdateCheck"`
}

// DefaultRunState returns the state when state.yaml does not yet exist: update
// checks have not run yet.
func DefaultRunState() RunState {
	return RunState{Version: RunStateVersion}
}

// runStatePath returns the path to state.yaml in home.
func runStatePath(home string) string {
	return filepath.Join(home, runStateFileName)
}

// LoadRunState reads state.yaml from home. A missing file is not an error and
// returns [DefaultRunState].
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

// SaveRunState atomically writes s to state.yaml in home.
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
