package project

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
)

// ErrSourceUnavailable signals from [ManifestSource.Load] that this source
// has no manifest for the project (for example, the snapshot is not saved or
// the repository cache is not fetched). It is not an error, but tells the
// caller to try the next source. Other errors, such as bad YAML or filesystem
// failures, must be returned unchanged rather than hidden by fallback.
var ErrSourceUnavailable = errors.New("источник манифеста недоступен")

// ErrNoManifest is returned by [LoadManifestForProject] when no source in the
// chain can provide a manifest.
var ErrNoManifest = errors.New("нет ни кеша шаблона, ни снимка манифеста — запусти tplater update")

// ManifestSource resolves a template manifest for a project at a pinned
// version. Implementations are [repoSource] (the preferred source, checking
// out the template repository from ~/.tplaiter/repos/<repo>/... at a pinned
// ref) and [SnapshotSource] (the offline fallback from
// .tplaiter/manifest.snapshot.yaml).
type ManifestSource interface {
	// Name is the source label reported to the caller ("snapshot"|"repo").
	Name() string
	// Load resolves the manifest for proj. It returns [ErrSourceUnavailable]
	// when this source has nothing to offer (not an error, but a signal to try
	// the next source).
	Load(proj *manifest.Project) (*manifest.Template, error)
}

// SnapshotSource reads .tplaiter/manifest.snapshot.yaml from the project root.
// Root is the snapshot saved by `tplater new`/`update` so that `run`/`gen` work
// offline when the template repository is unavailable.
type SnapshotSource struct {
	Root string
}

// Name implements [ManifestSource].
func (SnapshotSource) Name() string { return "snapshot" }

// Load implements [ManifestSource]. proj is unused because the snapshot is
// already tied to the project by its location inside Root.
func (s SnapshotSource) Load(_ *manifest.Project) (*manifest.Template, error) {
	path := filepath.Join(s.Root, manifest.SnapshotRelPath)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrSourceUnavailable
		}
		return nil, fmt.Errorf("project: проверка снимка манифеста %s: %w", path, err)
	}

	tpl, err := manifest.LoadSnapshot(path)
	if err != nil {
		return nil, fmt.Errorf("project: загрузка снимка манифеста %s: %w", path, err)
	}
	return tpl, nil
}

// templateManifestFileName is the template manifest name at the checkout root
// (the same private constant as in internal/repo/scan.go and internal/renderref).
const templateManifestFileName = "template.manifest.yaml"

// repoSource is the preferred manifest source: it reads from the template
// repository cache (~/.tplaiter/repos/<repo>/...) at the version pinned in
// proj.Template.Version. Through [repo.Manager] it resolves
// `<repo>/<name>@<version>` to a git ref, checks out that ref in a separate
// worktree of the local clone (no network or tokens are needed), and parses
// template.manifest.yaml. Thus `run`/`env`/`gen` work without a snapshot while
// the repository cache is available.
//
// Any cache unavailability (repository not added, version absent from the
// index, clone missing, or manifest unparsable) is treated as
// [ErrSourceUnavailable]. This source is optional by priority; the reliable
// fallback is [SnapshotSource].
type repoSource struct {
	home string
	repo string
}

// Name implements [ManifestSource].
func (repoSource) Name() string { return "repo" }

// Load implements [ManifestSource]: it resolves and checks out the template
// manifest from the repository cache at the pinned version. It returns
// [ErrSourceUnavailable] for any cache unavailability (see [repoSource]).
func (s repoSource) Load(proj *manifest.Project) (*manifest.Template, error) {
	if s.repo == "" || proj.Template.Name == "" || proj.Template.Version == "" {
		return nil, ErrSourceUnavailable
	}
	// Local manager: a real git runner without token storage or UI; checking out
	// a worktree from an existing clone needs neither network nor authentication.
	mgr := repo.New(s.home, execx.Exec{}, nil, repo.UI{})

	ref := s.repo + "/" + proj.Template.Name + "@" + proj.Template.Version
	resolved, err := mgr.ResolveRef(ref)
	if err != nil {
		// Cache unavailability (repository not added or version absent from the
		// index) signals fallback to the snapshot, not a process error.
		return nil, ErrSourceUnavailable
	}

	ctx := context.Background()
	src, cleanup, err := mgr.Checkout(ctx, resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		return nil, ErrSourceUnavailable // Clone/ref unavailable: fall back to snapshot.
	}
	defer func() { _ = cleanup() }()

	data, err := fs.ReadFile(src, templateManifestFileName)
	if err != nil {
		return nil, ErrSourceUnavailable // Manifest unreadable: fall back.
	}
	tpl, err := manifest.ParseTemplate(data)
	if err != nil {
		return nil, ErrSourceUnavailable // Manifest unparsable: fall back.
	}
	return tpl, nil
}

// LoadManifestForProject resolves the template manifest for proj, whose root
// is root, by trying sources in priority order: repository cache ([repoSource])
// then snapshot ([SnapshotSource]). It returns the manifest, the selected
// source label ("snapshot"|"repo"), and an error. If no source can provide a
// manifest, it returns [ErrNoManifest]; any other source error (such as a
// corrupt snapshot) is returned unchanged without trying the next source.
func LoadManifestForProject(root string, proj *manifest.Project, home string) (*manifest.Template, string, error) {
	sources := []ManifestSource{
		repoSource{home: home, repo: proj.Template.Repo},
		SnapshotSource{Root: root},
	}

	for _, src := range sources {
		tpl, err := src.Load(proj)
		switch {
		case err == nil:
			return tpl, src.Name(), nil
		case errors.Is(err, ErrSourceUnavailable):
			continue
		default:
			return nil, "", err
		}
	}

	return nil, "", ErrNoManifest
}
