package updateplan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

// RegistryImage is a detached exact image proposal, not a registry write grant.
// Timestamps and unrelated entries are retained; no clock enters the plan.
type RegistryImage struct {
	Home          string `json:"home"`
	Before        Image  `json:"before"`
	BeforeContent []byte `json:"beforeContent"`
	After         Image  `json:"after"`
	AfterContent  []byte `json:"afterContent"`
}

type registryObservation struct {
	raw          []byte
	mode         uint32
	identity     os.FileInfo
	fileIdentity os.FileInfo
}

func readRegistry(ctx context.Context, home string) (*registryObservation, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(home)
	if err != nil || !filepath.IsAbs(home) || canonical != home {
		return nil, ErrUnsafe
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	held, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	// No update/new journal may be mistaken for stable registry state. Refuse
	// symlinked transaction parents before directory enumeration.
	for _, p := range []string{"transactions", "transactions/new"} {
		info, err := root.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
			return nil, ErrUnsafe
		}
		if p == "transactions/new" {
			dir, err := root.Open(p)
			if err != nil {
				return nil, err
			}
			entries, readErr := dir.ReadDir(maxFiles + 1)
			closeErr := dir.Close()
			if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) > maxFiles {
				return nil, ErrUnsafe
			}
			for _, entry := range entries {
				if !safePath(entry.Name()) || !entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
					return nil, ErrUnsafe
				}
				if _, err := root.Lstat(p + "/" + entry.Name() + "/active.json"); err == nil {
					return nil, ErrUnsafe
				} else if !errors.Is(err, fs.ErrNotExist) {
					return nil, err
				}
			}
		}
	}
	before, err := root.Lstat("projects.yaml")
	if err != nil || !before.Mode().IsRegular() || before.Mode()&^fs.ModePerm != 0 || before.Size() < 0 || before.Size() > 1<<20 {
		return nil, ErrUnsafe
	}
	file, err := root.Open("projects.yaml")
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, ErrStale
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	final, finalErr := root.Lstat("projects.yaml")
	if err := errors.Join(readErr, statErr, closeErr, finalErr); err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 || int64(len(raw)) != opened.Size() || !os.SameFile(after, final) || after.Mode() != opened.Mode() || final.Mode() != opened.Mode() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, ErrStale
	}
	current, err := os.Lstat(home)
	if err != nil || !os.SameFile(held, current) {
		return nil, ErrStale
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &registryObservation{raw: raw, mode: uint32(opened.Mode().Perm()), identity: held, fileIdentity: opened}, nil
}

func planRegistry(ctx context.Context, home string, marker stateledger.ProjectV2, p *operationtrust.PreparedUpdate, baseline []byte, projectRoot string) (RegistryImage, *registryObservation, error) {
	observed, err := readRegistry(ctx, home)
	if err != nil {
		return RegistryImage{}, nil, err
	}
	var projects state.Projects
	decoder := yaml.NewDecoder(bytes.NewReader(observed.raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&projects); err != nil {
		return RegistryImage{}, nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return RegistryImage{}, nil, ErrUnsafe
	}
	if projects.Version != state.ProjectsVersion {
		return RegistryImage{}, nil, ErrUnsafe
	}
	ids, roots := map[string]bool{}, map[string]bool{}
	index := -1
	for i, item := range projects.Items {
		if item.ID == "" || item.Path == "" || ids[item.ID] || roots[item.Path] {
			return RegistryImage{}, nil, ErrUnsafe
		}
		ids[item.ID] = true
		roots[item.Path] = true
		if item.ID == marker.ID {
			index = i
		}
	}
	if index < 0 {
		return RegistryImage{}, nil, ErrUnsafe
	}
	current := &projects.Items[index]
	// Home is only a locator. Actual project authority remains the installed
	// runtime. Require the registered anchor to name exactly that project.
	if current.Path != projectRoot || current.Path == home || strings.HasPrefix(home, current.Path+string(filepath.Separator)) || current.Template.Repo != marker.Template.Repo || current.Template.Name != marker.Template.Name || current.Template.Version != marker.Template.ResolvedCommit || current.BaselineSHA != strings.TrimPrefix(evidencecas.Digest(baseline), "sha256:") {
		return RegistryImage{}, nil, ErrUnsafe
	}
	target := p.Rendered()
	targetBaseline, err := canonicaljson.Canonical(target.Baseline)
	if err != nil {
		return RegistryImage{}, nil, err
	}
	current.Template.Name = target.Template.Metadata.Name
	current.Template.Version = p.TargetRootLock().Root.Commit
	current.BaselineSHA = strings.TrimPrefix(evidencecas.Digest(targetBaseline), "sha256:")
	after, err := state.MarshalProjects(projects)
	if err != nil {
		return RegistryImage{}, nil, err
	}
	if p.SourceRootLock() == p.TargetRootLock() {
		after = bytes.Clone(observed.raw)
	}
	beforeImage := Image{Path: "projects.yaml", Kind: "file", Mode: observed.mode, SHA256: evidencecas.Digest(observed.raw)}
	afterImage := Image{Path: "projects.yaml", Kind: "file", Mode: observed.mode, SHA256: evidencecas.Digest(after)}
	return RegistryImage{Home: home, Before: beforeImage, BeforeContent: observed.raw, After: afterImage, AfterContent: after}, observed, nil
}
