// Package renderref renders a template already checked out into a filesystem
// (a repository checkout at a pinned ref) into memory: it parses the manifest,
// resolves settings, and runs the engine in a temporary directory, reading the
// result into a relative-path-to-content map. This reusable "render a template
// from ref+values" core powers `tplaiter update` (a 3-way merge of two
// versions) and `tplaiter stats` (comparing a clean render with the working
// tree); both receive files and a baseline of the same shape without duplicated
// render orchestration.
//
// The package deliberately accepts a ready [fs.FS] rather than performing a
// checkout itself. Checkout is the thin [repo.Manager.Checkout] operation owned
// by the caller next to ref selection; this package handles the heavier work:
// loading the manifest, resolving settings, collecting partials, and rendering
// into memory.
package renderref

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// templateManifestFileName is the template manifest name at the checkout root
// (the same private constant as in internal/repo/scan.go and internal/newcmd).
const templateManifestFileName = "template.manifest.yaml"

// partialsDirName is the directory of associated {{ define }} templates inside
// the template checkout (see the single-basic/partials fixture).
const partialsDirName = "partials"

// closeScratch is private solely to prove that a cleanup failure remains
// observable alongside an earlier safe render error. Production always calls
// the real descriptor-relative cleanup.
var closeScratch = func(dir *scratchDirectory) error { return dir.Close() }

// Input is the [Render] input: settings values and project coordinates used to
// parameterize rendering. They match the snapshot in .tplaiter/project.yaml,
// guaranteeing that rendering the same version with the same snapshot produces
// byte-for-byte identical output (needed for no-op update and the baseline invariant).
type Input struct {
	// Values is the complete project settings snapshot (as in project.yaml.settings).
	Values settings.Values
	// Project is the project identity (.Project in the render context).
	Project manifest.ProjectInfo
	// Runtime contains project runtime parameters (.Runtime.Port).
	Runtime manifest.ProjectRuntime
	// Repo is the source repository alias (.Template.Repo in the context).
	Repo string
}

// Result is the in-memory render result.
type Result struct {
	// Files maps relative slash paths to generated file contents (excluding
	// .tplaiter/baseline.json, which the engine does not include in Result.Files).
	Files map[string][]byte
	// Baseline is the clean render baseline (sha256 of each file plus version and
	// contextHash). It becomes .tplaiter/baseline.json after update.
	Baseline *engine.Baseline
	// Template is the parsed and validated manifest for this template version.
	Template *manifest.Template
	// Resolved contains resolved settings (for hooks/ansible that need all values).
	Resolved settings.Resolved
}

// Render parses the manifest at src's root (the template checkout rooted at the
// template directory), resolves in.Values, and renders the tree into a
// temporary directory, returning in-memory contents and a clean baseline. The
// temporary directory is removed before returning; callers only need the bytes
// in [Result.Files].
func Render(ctx context.Context, src fs.FS, in Input) (*Result, error) {
	tmp, err := os.MkdirTemp("", "tplater-render-*")
	if err != nil {
		return nil, fmt.Errorf("renderref: render temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	return render(ctx, src, in, tmp, func(path string) ([]byte, error) {
		return os.ReadFile(filepath.Join(tmp, "out", filepath.FromSlash(path)))
	}, nil)
}

// RenderInScratch renders exclusively below scratchRoot. The root is chosen by
// the authenticated runtime, never by template input. It leaves no result when
// cancellation, an output bound, or cleanup fails.
func RenderInScratch(ctx context.Context, src fs.FS, in Input, scratchRoot string) (_ *Result, err error) {
	if ctx == nil {
		return nil, errors.New("renderref: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := openScratch(scratchRoot)
	if err != nil {
		return nil, err
	}
	defer func() {
		if removeErr := closeScratch(dir); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("renderref: scratch cleanup: %w", removeErr))
		}
	}()
	if err := dir.Check(); err != nil {
		return nil, err
	}
	return render(ctx, src, in, dir.Path(), func(path string) ([]byte, error) {
		return dir.ReadFile("out/" + path)
	}, dir.Check)
}

func render(ctx context.Context, src fs.FS, in Input, scratch string, readOutput func(string) ([]byte, error), checkScratch func() error) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if checkScratch != nil {
		if err := checkScratch(); err != nil {
			return nil, err
		}
	}
	tpl, err := LoadTemplate(src)
	if err != nil {
		return nil, err
	}
	resolved, err := settings.Resolve(tpl, in.Values)
	if err != nil {
		return nil, fmt.Errorf("renderref: settings resolution: %w", err)
	}
	partials, err := templatePartials(src)
	if err != nil {
		return nil, err
	}

	target := filepath.Join(scratch, "out")
	res, err := engine.Render(engine.Options{
		Source:   src,
		Target:   target,
		Template: tpl,
		Resolved: resolved,
		Project:  in.Project,
		Runtime:  in.Runtime,
		Repo:     in.Repo,
		Partials: partials,
	})
	if err != nil {
		return nil, fmt.Errorf("renderref: render: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if checkScratch != nil {
		if err := checkScratch(); err != nil {
			return nil, err
		}
	}
	if len(res.Files) > 4096 {
		return nil, errors.New("renderref: preview output entry limit")
	}

	files := make(map[string][]byte, len(res.Files))
	paths := append([]string(nil), res.Files...)
	sort.Strings(paths)
	var total int64
	for _, rel := range paths {
		if !fs.ValidPath(rel) {
			return nil, errors.New("renderref: unsafe rendered path")
		}
		data, rerr := readOutput(rel)
		if rerr != nil {
			return nil, fmt.Errorf("renderref: reading rendered %s: %w", rel, rerr)
		}
		total += int64(len(data))
		if total > 64<<20 {
			return nil, errors.New("renderref: preview output byte limit")
		}
		files[rel] = append([]byte(nil), data...)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	return &Result{Files: files, Baseline: res.Baseline, Template: tpl, Resolved: resolved}, nil
}

// LoadTemplate reads, parses, and validates the template manifest from src's root.
func LoadTemplate(src fs.FS) (*manifest.Template, error) {
	data, err := fs.ReadFile(src, templateManifestFileName)
	if err != nil {
		return nil, fmt.Errorf("renderref: reading %s: %w", templateManifestFileName, err)
	}
	tpl, err := manifest.ParseTemplate(data)
	if err != nil {
		return nil, fmt.Errorf("renderref: %w", err)
	}
	if err := tpl.Validate(); err != nil {
		return nil, fmt.Errorf("renderref: template manifest is invalid: %w", err)
	}
	return tpl, nil
}

// Values converts the project marker's settings map (parsed by yaml.v3 as
// map[string]any) to [settings.Values]. The only normalization is that
// multiselect values arrive as []any while the resolver and engine expect
// []string. Scalar values (string/bool/int) are already native Go types. Strict
// typing and option checks belong to [settings.ParseSet]/[settings.LoadAnswersFile];
// this only removes a YAML parsing artifact (the same logic as in
// internal/cmd/run.go for `tplaiter run`).
func Values(raw map[string]any) settings.Values {
	out := make(settings.Values, len(raw))
	for k, v := range raw {
		if list, ok := v.([]any); ok {
			strs := make([]string, 0, len(list))
			for _, item := range list {
				if s, ok := item.(string); ok {
					strs = append(strs, s)
				}
			}
			out[k] = strs
			continue
		}
		out[k] = v
	}
	return out
}

// templatePartials builds a partials source from the checkout when partials/
// exists (otherwise nil, and the engine runs without it). It matches the logic
// in internal/newcmd.templatePartials.
func templatePartials(src fs.FS) ([]fs.FS, error) {
	info, err := fs.Stat(src, partialsDirName)
	if err != nil || !info.IsDir() {
		return nil, nil //nolint:nilerr // Missing partials/ is normal, not an error.
	}
	sub, err := fs.Sub(src, partialsDirName)
	if err != nil {
		return nil, fmt.Errorf("renderref: partials subdirectory: %w", err)
	}
	return []fs.FS{sub}, nil
}
