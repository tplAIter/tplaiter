package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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

// ProjectsPath returns the registry path for home. Callers that coordinate an
// external transaction must retain this exact target identity in their own
// durable evidence; ordinary callers use LoadProjects and SaveProjects.
func ProjectsPath(home string) string {
	return projectsPath(home)
}

// ReadProjectsRaw returns the exact on-disk registry bytes. It is a narrow
// transaction seam: callers must hold WithLock across any read-modify-write
// sequence. A symlinked or non-regular projects.yaml is refused.
func ReadProjectsRaw(home string) (data []byte, exists bool, mode fs.FileMode, err error) {
	path := projectsPath(home)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, 0, nil
	}
	if err != nil {
		return nil, false, 0, fmt.Errorf("state: checking projects.yaml: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, 0, errors.New("state: projects.yaml is not a regular file")
	}
	data, exists, err = readFile(path)
	if err != nil || !exists {
		return data, exists, 0, err
	}
	return data, true, info.Mode().Perm(), nil
}

// WriteProjectsRaw atomically and durably replaces projects.yaml with bytes
// that must already decode as a registry. It is separate from SaveProjects so
// an external journal can record and recover the exact before/after images.
// Callers must hold WithLock for a read-modify-write operation.
func WriteProjectsRaw(home string, data []byte, mode fs.FileMode) error {
	if _, err := decodeProjects(data); err != nil {
		return err
	}
	return writeFileAtomicDurable(projectsPath(home), data, mode)
}

// RemoveProjectsRaw removes projects.yaml and durably records the directory
// update. It is the inverse of a journaled registry image that was absent
// before an external transaction.
func RemoveProjectsRaw(home string) error {
	path := projectsPath(home)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("state: removing projects.yaml: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

// MarshalProjects returns the YAML encoding used by SaveProjects, so a
// transaction plan can capture its exact future registry bytes without
// publishing them before the commit boundary.
func MarshalProjects(p Projects) ([]byte, error) {
	data, err := yaml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("state: marshaling projects.yaml: %w", err)
	}
	return data, nil
}

// DecodeProjectsRaw validates registry bytes retained by an external journal
// without consulting live state.
func DecodeProjectsRaw(data []byte) (Projects, error) { return decodeProjects(data) }

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
	data, err := MarshalProjects(p)
	if err != nil {
		return err
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
