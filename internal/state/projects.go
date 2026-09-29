package state

import (
	"fmt"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// ProjectsVersion is the currently supported projects.yaml format version.
const ProjectsVersion = 1

// projectsFileName is the file name in the tplater home directory.
const projectsFileName = "projects.yaml"

// TemplateSelection is the template used to generate a project: pinned
// repository, name, and version.
type TemplateSelection struct {
	Repo    string `yaml:"repo"`
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

// ProjectRef is one project registry entry in projects.yaml.
type ProjectRef struct {
	// ID is the stable entry anchor, read from the project's .tplaiter/project.yaml.
	// Unlike Path, it must not change when the directory moves or is cloned.
	ID          string            `yaml:"id"`
	Path        string            `yaml:"path"`
	Template    TemplateSelection `yaml:"template"`
	CreatedAt   time.Time         `yaml:"createdAt"`
	LastSeenAt  time.Time         `yaml:"lastSeenAt"`
	BaselineSHA string            `yaml:"baselineSHA"`
}

// Projects is the contents of ~/.tplaiter/projects.yaml.
type Projects struct {
	Version int          `yaml:"version"`
	Items   []ProjectRef `yaml:"items"`
}

// DefaultProjects returns the registry when projects.yaml does not exist yet:
// an empty project list.
func DefaultProjects() Projects {
	return Projects{Version: ProjectsVersion}
}

// projectsPath returns the path to projects.yaml in home.
func projectsPath(home string) string {
	return filepath.Join(home, projectsFileName)
}

// LoadProjects reads projects.yaml from home. A missing file is not an error and
// returns [DefaultProjects].
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

// SaveProjects atomically writes p to projects.yaml in home.
func SaveProjects(home string, p Projects) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("state: marshaling projects.yaml: %w", err)
	}
	return writeFileAtomic(projectsPath(home), data)
}

func decodeProjects(data []byte) (Projects, error) {
	version, err := peekVersion(data)
	if err != nil {
		return Projects{}, fmt.Errorf("state: parsing projects.yaml: %w", err)
	}

	migrated, err := checkAndMigrate(kindProjects, data, version, ProjectsVersion)
	if err != nil {
		return Projects{}, err
	}

	var p Projects
	if err := yaml.Unmarshal(migrated, &p); err != nil {
		return Projects{}, fmt.Errorf("state: parsing projects.yaml: %w", err)
	}
	return p, nil
}

// FindByID returns the entry with id and true when it exists in the registry.
func (p *Projects) FindByID(id string) (ProjectRef, bool) {
	for i := range p.Items {
		if p.Items[i].ID == id {
			return p.Items[i], true
		}
	}
	return ProjectRef{}, false
}

// Upsert adds ref to the registry when its ID is absent, or updates the existing
// entry. The ID is compared; path/lastSeenAt/baselineSHA follow observations,
// automatically tracking directory moves and another machine's divergence.
// Template and CreatedAt are preserved because they record the original
// template choice and creation time, not the current observation.
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

// Remove deletes the entry with id and returns true when it was found and removed.
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

// Prune removes entries for which exists(item.Path) returns false (the project
// path no longer exists, as in `tplater projects prune`) and returns the removed
// entries. exists is injected instead of calling os.Stat so the operation can
// be tested without a real filesystem.
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
