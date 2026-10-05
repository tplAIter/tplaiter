package state

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// fileKind identifies a state file for the migration registry.
type fileKind string

const (
	kindConfig   fileKind = "config.yaml"
	kindIndex    fileKind = "index.yaml"
	kindProjects fileKind = "projects.yaml"
	kindState    fileKind = "state.yaml"
)

// migrationFunc migrates raw YAML data from version from to from+1. It returns
// new raw data, usually the marshaled form of an intermediate structure.
type migrationFunc func(data []byte) ([]byte, error)

// migrations is the migration registry keyed by (kind, from version). It is
// currently empty: all files start at version=1. Future format changes register
// migrations[kindConfig][1] = func(...) when version=2 is introduced, and so on.
var migrations = map[fileKind]map[int]migrationFunc{}

// versionPeek is the minimal structure for reading only version without parsing
// the whole file, before the valid structure version is known.
type versionPeek struct {
	Version int `yaml:"version"`
}

// peekVersion reads version from raw YAML data.
func peekVersion(data []byte) (int, error) {
	var v versionPeek
	if err := yaml.Unmarshal(data, &v); err != nil {
		return 0, err
	}
	return v.Version, nil
}

// checkAndMigrate compares a file version with the supported current version
// and applies registered migrations in sequence when the file is older.
// version > current means a newer tplaiter created the file and there is no safe
// rollback, so it returns a clear update hint. version < current without a
// registered migration is also an error: the registry is incomplete.
func checkAndMigrate(kind fileKind, data []byte, version, current int) ([]byte, error) {
	if version > current {
		return nil, fmt.Errorf(
			"state: %s: file version (%d) is newer than supported by this tplaiter version (%d) — update tplaiter",
			kind, version, current,
		)
	}

	for version < current {
		fn, ok := migrations[kind][version]
		if !ok {
			return nil, fmt.Errorf(
				"state: %s: migration from version %d to %d not found",
				kind, version, version+1,
			)
		}
		migrated, err := fn(data)
		if err != nil {
			return nil, fmt.Errorf("state: %s: migration from version %d to %d: %w", kind, version, version+1, err)
		}
		data = migrated
		version++
	}

	return data, nil
}
