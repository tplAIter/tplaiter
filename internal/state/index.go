package state

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// IndexVersion — текущая поддерживаемая версия формата index.yaml.
const IndexVersion = 1

// indexFileName — имя файла в домашнем каталоге tplater.
const indexFileName = "index.yaml"

// ErrIndexCorrupted сообщает, что index.yaml не удалось разобрать как YAML
// или как структуру [Index]. Индекс — чистый кеш: вызывающий
// код должен перестроить его из ~/.tplaiter/repos/, а не считать это фатальной
// ошибкой процесса. Проверяйте errors.Is(err, ErrIndexCorrupted).
var ErrIndexCorrupted = errors.New("state: index.yaml повреждён")

// TemplateEntry — один шаблон в агрегированном индексе одного репозитория.
type TemplateEntry struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	// LabelsFlat — лейблы шаблона (label -> значения); имя поля отражает,
	// что вложенность манифеста уже развёрнута в плоскую map для быстрой
	// фильтрации `template list -l lang=go`.
	LabelsFlat map[string][]string `yaml:"labelsFlat"`
	Path       string              `yaml:"path"`
	// Ref — git-ссылка «HEAD-версии» шаблона: отслеживаемая ветка репозитория
	// (или "HEAD"), из которой прочитан текущий metadata.version. Используется
	// как `@latest` при резолюции ссылок.
	Ref string `yaml:"ref"`
	// Tags — стабильные релизные теги, применимые к этому шаблону, в полном
	// git-виде (`vX.Y.Z` для single-репо, `<name>/vX.Y.Z` для multi), уже
	// отсортированные по убыванию версии (index 0 — старший). Задел под выбор
	// версии `@vX.Y.Z` / умолчание «старший стабильный тег».
	// Поле добавлено к закоммиченной схеме index.yaml как чисто аддитивное:
	// старые индексы без него читаются (nil-слайс), формат-версия не меняется.
	Tags []string `yaml:"tags,omitempty"`
}

// Index — содержимое ~/.tplaiter/index.yaml: агрегированный кеш шаблонов по
// всем добавленным репозиториям.
type Index struct {
	Version int `yaml:"version"`
	// GeneratedAt — момент построения индекса. Передаётся аргументом в
	// [NewIndex] тем, кто индекс перестраивает (repo add/update,
	// §3) — сам пакет state время не читает, чтобы Load/Save оставались
	// чистыми и тестируемыми без подмены часов.
	GeneratedAt time.Time                  `yaml:"generatedAt"`
	Repos       map[string][]TemplateEntry `yaml:"repos"`
}

// NewIndex создаёт пустой индекс с заданным моментом генерации generatedAt.
func NewIndex(generatedAt time.Time) Index {
	return Index{
		Version:     IndexVersion,
		GeneratedAt: generatedAt,
		Repos:       map[string][]TemplateEntry{},
	}
}

// indexPath возвращает путь к index.yaml в домашнем каталоге home.
func indexPath(home string) string {
	return filepath.Join(home, indexFileName)
}

// LoadIndex читает index.yaml из домашнего каталога home. Отсутствие файла
// — не ошибка: возвращается пустой индекс (Version=[IndexVersion],
// GeneratedAt — нулевое время, Repos — пустая map). Файл, который не
// удалось разобрать как YAML/[Index], возвращает [ErrIndexCorrupted]
// (см. errors.Is) — вызывающий код должен перестроить индекс, не паниковать.
func LoadIndex(home string) (Index, error) {
	data, existed, err := readFile(indexPath(home))
	if err != nil {
		return Index{}, err
	}
	if !existed {
		return NewIndex(time.Time{}), nil
	}
	return decodeIndex(data)
}

// SaveIndex атомарно записывает idx в index.yaml домашнего каталога home.
func SaveIndex(home string, idx Index) error {
	data, err := yaml.Marshal(idx)
	if err != nil {
		return fmt.Errorf("state: маршализация index.yaml: %w", err)
	}
	return writeFileAtomic(indexPath(home), data)
}

func decodeIndex(data []byte) (Index, error) {
	version, err := peekVersion(data)
	if err != nil {
		return Index{}, fmt.Errorf("%w: %v", ErrIndexCorrupted, err) //nolint:errorlint // сознательная упаковка "причины" в текст: err — деталь парсинга, не отдельный проверяемый тип
	}

	// Версия новее поддерживаемой этим tplater — это не «повреждён», а
	// «обновите tplater»: файл читаем, просто из будущего. Отдельная от
	// ErrIndexCorrupted ветка ошибок.
	migrated, err := checkAndMigrate(kindIndex, data, version, IndexVersion)
	if err != nil {
		return Index{}, err
	}

	var idx Index
	if err := yaml.Unmarshal(migrated, &idx); err != nil {
		return Index{}, fmt.Errorf("%w: %v", ErrIndexCorrupted, err) //nolint:errorlint // см. выше
	}
	if idx.Repos == nil {
		idx.Repos = map[string][]TemplateEntry{}
	}
	return idx, nil
}
