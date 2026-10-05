package state

import (
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigVersion is the currently supported config.yaml format version.
const ConfigVersion = 1

// configFileName is the file name in the tplaiter home directory.
const configFileName = "config.yaml"

// RepoKind is the template repository hosting type and determines which auth
// adapter to use.
type RepoKind string

// Supported repository kinds.
const (
	RepoKindGitLab RepoKind = "gitlab"
	RepoKindGitHub RepoKind = "github"
	RepoKindGit    RepoKind = "git"
)

// RepoRef is one template repository registry entry in config.yaml.
type RepoRef struct {
	Alias  string   `yaml:"alias"`
	URL    string   `yaml:"url"`
	Branch string   `yaml:"branch,omitempty"`
	Type   RepoKind `yaml:"type"`
}

// Defaults contains common defaults for new projects. It is currently empty,
// but reserved for future implementations; the field has been in config.yaml
// from the start so the format version need not change when it is populated.
type Defaults struct{}

// UpdatesSettings contains settings for background tplaiter update checks.
type UpdatesSettings struct {
	// Check enables a quiet check for a new version every 24h. It defaults to
	// true and is disabled explicitly with `updates.check: false`.
	Check bool `yaml:"check"`
}

// Config is the contents of ~/.tplaiter/config.yaml.
type Config struct {
	Version  int             `yaml:"version"`
	Repos    []RepoRef       `yaml:"repos"`
	Defaults Defaults        `yaml:"defaults"`
	Updates  UpdatesSettings `yaml:"updates"`
}

// DefaultConfig returns the configuration when config.yaml does not yet exist:
// an empty repository list with update checks enabled.
func DefaultConfig() Config {
	return Config{
		Version: ConfigVersion,
		Updates: UpdatesSettings{Check: true},
	}
}

// configPath returns the path to config.yaml in home.
func configPath(home string) string {
	return filepath.Join(home, configFileName)
}

// LoadConfig reads config.yaml from home. A missing file is not an error and
// returns [DefaultConfig]. A version newer than [ConfigVersion] is an
// "update tplaiter" error; older versions use registered migrations (see migrate.go).
func LoadConfig(home string) (Config, error) {
	data, existed, err := readFile(configPath(home))
	if err != nil {
		return Config{}, err
	}
	if !existed {
		return DefaultConfig(), nil
	}
	return decodeConfig(data)
}

// SaveConfig atomically writes cfg to config.yaml in home.
func SaveConfig(home string, cfg Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("state: marshaling config.yaml: %w", err)
	}
	return writeFileAtomic(configPath(home), data)
}

func decodeConfig(data []byte) (Config, error) {
	version, err := peekVersion(data)
	if err != nil {
		return Config{}, fmt.Errorf("state: parsing config.yaml: %w", err)
	}

	migrated, err := checkAndMigrate(kindConfig, data, version, ConfigVersion)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(migrated, &cfg); err != nil {
		return Config{}, fmt.Errorf("state: parsing config.yaml: %w", err)
	}
	return cfg, nil
}
