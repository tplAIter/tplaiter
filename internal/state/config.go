package state

import (
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigVersion — текущая поддерживаемая версия формата config.yaml.
const ConfigVersion = 1

// configFileName — имя файла в домашнем каталоге tplater.
const configFileName = "config.yaml"

// RepoKind — тип хостинга репозитория шаблонов, определяет, какой
// auth-адаптер использовать.
type RepoKind string

// Поддерживаемые виды репозиториев.
const (
	RepoKindGitLab RepoKind = "gitlab"
	RepoKindGitHub RepoKind = "github"
	RepoKindGit    RepoKind = "git"
)

// RepoRef — одна запись реестра репозиториев шаблонов в config.yaml.
type RepoRef struct {
	Alias  string   `yaml:"alias"`
	URL    string   `yaml:"url"`
	Branch string   `yaml:"branch,omitempty"`
	Type   RepoKind `yaml:"type"`
}

// Defaults — общие дефолты новых проектов. Пока пусто — задел под будущие
// реализации (реализацию и далее); поле присутствует в схеме config.yaml с самого
// начала, чтобы не менять версию формата при первом наполнении.
type Defaults struct{}

// UpdatesSettings — настройки фоновой проверки обновлений tplater.
type UpdatesSettings struct {
	// Check включает ненавязчивую проверку новой версии раз в 24ч. По
	// умолчанию true; отключается явным `updates.check: false`.
	Check bool `yaml:"check"`
}

// Config — содержимое ~/.tplaiter/config.yaml.
type Config struct {
	Version  int             `yaml:"version"`
	Repos    []RepoRef       `yaml:"repos"`
	Defaults Defaults        `yaml:"defaults"`
	Updates  UpdatesSettings `yaml:"updates"`
}

// DefaultConfig возвращает конфигурацию для случая, когда config.yaml ещё
// не существует: пустой список репозиториев, проверка обновлений включена.
func DefaultConfig() Config {
	return Config{
		Version: ConfigVersion,
		Updates: UpdatesSettings{Check: true},
	}
}

// configPath возвращает путь к config.yaml в домашнем каталоге home.
func configPath(home string) string {
	return filepath.Join(home, configFileName)
}

// LoadConfig читает config.yaml из домашнего каталога home. Отсутствие
// файла — не ошибка: возвращается [DefaultConfig]. Версия файла новее
// [ConfigVersion] — ошибка «обновите tplater»; старше — применяются
// зарегистрированные миграции (см. migrate.go).
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

// SaveConfig атомарно записывает cfg в config.yaml домашнего каталога home.
func SaveConfig(home string, cfg Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("state: маршализация config.yaml: %w", err)
	}
	return writeFileAtomic(configPath(home), data)
}

func decodeConfig(data []byte) (Config, error) {
	version, err := peekVersion(data)
	if err != nil {
		return Config{}, fmt.Errorf("state: разбор config.yaml: %w", err)
	}

	migrated, err := checkAndMigrate(kindConfig, data, version, ConfigVersion)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(migrated, &cfg); err != nil {
		return Config{}, fmt.Errorf("state: разбор config.yaml: %w", err)
	}
	return cfg, nil
}
