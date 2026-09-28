package state

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// IndexVersion is the currently supported index.yaml format version.
const IndexVersion = 1

// indexFileName is the file name in the tplater home directory.
const indexFileName = "index.yaml"

// ErrIndexCorrupted reports that index.yaml could not be parsed as YAML or as
// an [Index]. The index is only a cache: callers should rebuild it from
// ~/.tplaiter/repos/ rather than treat this as a fatal process error. Check with
// errors.Is(err, ErrIndexCorrupted).
var ErrIndexCorrupted = errors.New("state: index.yaml повреждён")

// TemplateEntry is one template in an aggregated repository index.
type TemplateEntry struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	// LabelsFlat contains template labels (label -> values); the name reflects
	// that manifest nesting has been flattened for fast `template list -l lang=go`
	// filtering.
	LabelsFlat map[string][]string `yaml:"labelsFlat"`
	Path       string              `yaml:"path"`
	// Ref is the template's "HEAD version" git ref: the tracked repository branch
	// (or "HEAD") from which metadata.version was read. Used as `@latest` when
	// resolving references.
	Ref string `yaml:"ref"`
	// Tags are stable release tags applicable to this template, in full git form
	// (`vX.Y.Z` for a single repo, `<name>/vX.Y.Z` for multi), sorted descending
	// by version (index 0 is highest). Reserved for `@vX.Y.Z` selection and the
	// "highest stable tag" default. The field was added additively to index.yaml:
	// old indexes without it still read as a nil slice and the format version stays.
	Tags []string `yaml:"tags,omitempty"`
}

// Index is the contents of ~/.tplaiter/index.yaml: an aggregated template cache
// for all added repositories.
type Index struct {
	Version int `yaml:"version"`
	// GeneratedAt is when the index was built. It is passed to [NewIndex] by the
	// rebuilding caller (repo add/update, §3); state itself does not read the
	// clock so Load/Save remain pure and testable.
	GeneratedAt time.Time                  `yaml:"generatedAt"`
	Repos       map[string][]TemplateEntry `yaml:"repos"`
}

// NewIndex creates an empty index with the given generatedAt time.
func NewIndex(generatedAt time.Time) Index {
	return Index{
		Version:     IndexVersion,
		GeneratedAt: generatedAt,
		Repos:       map[string][]TemplateEntry{},
	}
}

// indexPath returns the path to index.yaml in home.
func indexPath(home string) string {
	return filepath.Join(home, indexFileName)
}

// LoadIndex reads index.yaml from home. A missing file is not an error and
// returns an empty index (Version=[IndexVersion], zero GeneratedAt, empty Repos).
// A file that cannot be parsed as YAML/[Index] returns [ErrIndexCorrupted] (see
// errors.Is); callers should rebuild the index rather than panic.
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

// SaveIndex atomically writes idx to index.yaml in home.
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
		return Index{}, fmt.Errorf("%w: %v", ErrIndexCorrupted, err) //nolint:errorlint // Deliberately embeds the cause as text: parsing detail, not a separate typed error.
	}

	// A version newer than this tplater is not "corrupt" but "update tplater":
	// the file is readable, just from the future. Keep it separate from
	// ErrIndexCorrupted.
	migrated, err := checkAndMigrate(kindIndex, data, version, IndexVersion)
	if err != nil {
		return Index{}, err
	}

	var idx Index
	if err := yaml.Unmarshal(migrated, &idx); err != nil {
		return Index{}, fmt.Errorf("%w: %v", ErrIndexCorrupted, err) //nolint:errorlint // See above.
	}
	if idx.Repos == nil {
		idx.Repos = map[string][]TemplateEntry{}
	}
	return idx, nil
}
