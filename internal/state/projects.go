package state

import (
	"fmt"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// ProjectsVersion — текущая поддерживаемая версия формата projects.yaml.
const ProjectsVersion = 1

// projectsFileName — имя файла в домашнем каталоге tplater.
const projectsFileName = "projects.yaml"

// TemplateSelection — шаблон, из которого сгенерирован проект: зафиксированные
// репозиторий/имя/версия .
type TemplateSelection struct {
	Repo    string `yaml:"repo"`
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

// ProjectRef — одна запись реестра проектов в projects.yaml.
type ProjectRef struct {
	// ID — стабильный якорь записи, читается из .tplaiter/project.yaml
	// проекта. Не путать с Path: путь может меняться (переезд каталога,
	// клонирование коллегой), ID — не должен.
	ID          string            `yaml:"id"`
	Path        string            `yaml:"path"`
	Template    TemplateSelection `yaml:"template"`
	CreatedAt   time.Time         `yaml:"createdAt"`
	LastSeenAt  time.Time         `yaml:"lastSeenAt"`
	BaselineSHA string            `yaml:"baselineSHA"`
}

// Projects — содержимое ~/.tplaiter/projects.yaml.
type Projects struct {
	Version int          `yaml:"version"`
	Items   []ProjectRef `yaml:"items"`
}

// DefaultProjects возвращает реестр для случая, когда projects.yaml ещё не
// существует: пустой список проектов.
func DefaultProjects() Projects {
	return Projects{Version: ProjectsVersion}
}

// projectsPath возвращает путь к projects.yaml в домашнем каталоге home.
func projectsPath(home string) string {
	return filepath.Join(home, projectsFileName)
}

// LoadProjects читает projects.yaml из домашнего каталога home. Отсутствие
// файла — не ошибка: возвращается [DefaultProjects].
func LoadProjects(home string) (Projects, error) {
	data, existed, err := readFile(projectsPath(home))
	if err != nil {
		return Projects{}, err
	}
	if !existed {
		return DefaultProjects(), nil
	}
	return decodeProjects(data)
}

// SaveProjects атомарно записывает p в projects.yaml домашнего каталога home.
func SaveProjects(home string, p Projects) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("state: маршализация projects.yaml: %w", err)
	}
	return writeFileAtomic(projectsPath(home), data)
}

func decodeProjects(data []byte) (Projects, error) {
	version, err := peekVersion(data)
	if err != nil {
		return Projects{}, fmt.Errorf("state: разбор projects.yaml: %w", err)
	}

	migrated, err := checkAndMigrate(kindProjects, data, version, ProjectsVersion)
	if err != nil {
		return Projects{}, err
	}

	var p Projects
	if err := yaml.Unmarshal(migrated, &p); err != nil {
		return Projects{}, fmt.Errorf("state: разбор projects.yaml: %w", err)
	}
	return p, nil
}

// FindByID возвращает запись с заданным id и true, если она есть в реестре.
func (p *Projects) FindByID(id string) (ProjectRef, bool) {
	for i := range p.Items {
		if p.Items[i].ID == id {
			return p.Items[i], true
		}
	}
	return ProjectRef{}, false
}

// Upsert добавляет ref в реестр (если записи с таким ID ещё нет) либо
// обновляет уже существующую запись — по правилу : сверяется id,
// путь/lastSeenAt/baselineSHA обновляются по факту (переезд каталога и
// расхождение с другой машиной отслеживаются автоматически). Template и
// CreatedAt существующей записи не трогаются: они фиксируют исходный выбор
// шаблона и момент создания, а не текущее наблюдение.
func (p *Projects) Upsert(ref ProjectRef) {
	for i := range p.Items {
		if p.Items[i].ID != ref.ID {
			continue
		}
		p.Items[i].Path = ref.Path
		p.Items[i].LastSeenAt = ref.LastSeenAt
		p.Items[i].BaselineSHA = ref.BaselineSHA
		return
	}
	p.Items = append(p.Items, ref)
}

// Remove удаляет запись с заданным id. Возвращает true, если запись была
// найдена и удалена.
func (p *Projects) Remove(id string) bool {
	for i := range p.Items {
		if p.Items[i].ID != id {
			continue
		}
		p.Items = append(p.Items[:i], p.Items[i+1:]...)
		return true
	}
	return false
}

// Prune удаляет из реестра записи, для которых exists(item.Path) вернула
// false (путь проекта больше не существует — `tplater projects prune`,
// ), и возвращает удалённые записи. exists передаётся аргументом,
// а не вызывается как os.Stat напрямую, чтобы операция была тестируема без
// реальной файловой системы.
func (p *Projects) Prune(exists func(path string) bool) []ProjectRef {
	kept := make([]ProjectRef, 0, len(p.Items))
	var removed []ProjectRef
	for _, item := range p.Items {
		if exists(item.Path) {
			kept = append(kept, item)
		} else {
			removed = append(removed, item)
		}
	}
	p.Items = kept
	return removed
}
