package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// defaultRoot is the template source's file-tree directory when
// Template.Engine.Root is unset.
const defaultRoot = "files"

// Options contains render parameters. Unlike go-template's Options, engine
// metadata and file filtering come from the template manifest rather than
// template.json/Registry; features are replaced by resolved settings.
type Options struct {
	// Source is the template repository root (fs.FS: os.DirFS in production and
	// tests, embed.FS in built distributions). The generated-file tree is under
	// Template.Engine.Root ("files" by default).
	Source fs.FS
	// Target is the destination directory. It must be absent or empty.
	Target string
	// Template is the template manifest (source of Engine{Root,CopyWithoutRender,
	// PostReplace}, Files rules, and Template.Version metadata for the baseline).
	Template *manifest.Template
	// Resolved contains resolved template settings (the  implementation). Render
	// uses ActiveValues, a derived set with inactive nested groups zeroed out
	// (see [settings.Resolved]).
	Resolved settings.Resolved
	// Project contains the coordinates of the created project (.Project in the context).
	Project manifest.ProjectInfo
	// Runtime contains project runtime parameters (.Runtime.Port in the context).
	Runtime manifest.ProjectRuntime
	// Repo identifies the repository from which the template was obtained
	// (.Template.Repo in the context and project.yaml). The template manifest
	// does not store its repository, so the caller passes this source metadata separately.
	Repo string
	// Partials are additional sources of associated templates: every *.tmpl is
	// parsed from each fs.FS ({{ define }} blocks are expected). Defined names are
	// available to template files through {{ template "<name>" . }}.
	Partials []fs.FS
}

// Result is the render result.
type Result struct {
	// Files is the sorted list of relative paths for generated files (excluding
	// baseline.json).
	Files []string
	// Baseline is the tree snapshot written to Target/.tplaiter/baseline.json.
	Baseline *Baseline
	// Context is the context used for rendering (the caller can reuse it, for
	// example to render NOTES.tmpl with the same data).
	Context *Context
}

// renderer holds the parsed context and precomputed sets for one Render run.
type renderer struct {
	src      fs.FS
	root     string
	ctx      *Context
	values   settings.Values
	excluded *globSet
	copyRaw  *globSet
	postRepl []compiledPostReplace
	funcMap  template.FuncMap
	base     *template.Template
	written  []string
}

type compiledPostReplace struct {
	matcher     *globSet
	placeholder string
	value       string
}

// Render generates a project from Source into Target.
//
// Atomicity: rendering runs in a staging directory beside the target (ensuring
// the same filesystem for os.Rename), and staging is atomically renamed to
// Target only after complete success. On any error staging is removed and
// Target is untouched. Target must be absent or an empty directory.
func Render(opts Options) (*Result, error) {
	if opts.Template == nil {
		return nil, errors.New("engine: Render: nil template")
	}
	if opts.Source == nil {
		return nil, errors.New("engine: Render: nil source")
	}

	root := normalizeRoot(opts.Template.Engine.Root)
	ctx := NewContext(opts)
	values := opts.Resolved.ActiveValues

	excluded, err := compileFileRules(opts.Template.Files, values)
	if err != nil {
		return nil, err
	}
	postRepl, err := compilePostReplace(opts.Template.Engine.PostReplace, ctx)
	if err != nil {
		return nil, err
	}

	funcMap := FuncMap(ctx.Settings)
	base, err := parsePartials(opts.Partials, funcMap)
	if err != nil {
		return nil, err
	}

	r := &renderer{
		src:      opts.Source,
		root:     root,
		ctx:      ctx,
		values:   values,
		excluded: excluded,
		copyRaw:  newGlobSet(opts.Template.Engine.CopyWithoutRender),
		postRepl: postRepl,
		funcMap:  funcMap,
		base:     base,
	}

	absTarget, err := filepath.Abs(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("engine: abs target: %w", err)
	}
	if err := ensureEmptyTarget(absTarget); err != nil {
		return nil, err
	}

	parent := filepath.Dir(absTarget)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("engine: mkdir parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".tplaiter-staging-*")
	if err != nil {
		return nil, fmt.Errorf("engine: create staging: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()

	if err := r.renderTree(staging); err != nil {
		return nil, err
	}

	sort.Strings(r.written)
	hashes, err := ComputeBaseline(staging, r.written)
	if err != nil {
		return nil, err
	}
	ctxHash, err := hashContext(ctx)
	if err != nil {
		return nil, err
	}
	baseline := &Baseline{
		Schema:          BaselineSchema,
		TemplateVersion: opts.Template.Metadata.Version,
		ContextHash:     ctxHash,
		Files:           hashes,
	}
	if err := baseline.Save(staging); err != nil {
		return nil, err
	}

	if err := commitStaging(staging, absTarget); err != nil {
		return nil, err
	}
	committed = true

	return &Result{Files: r.written, Baseline: baseline, Context: ctx}, nil
}

// normalizeRoot canonicalizes Template.Engine.Root by removing leading and
// trailing `/`, using [defaultRoot] when the field is unset.
func normalizeRoot(root string) string {
	root = strings.Trim(strings.TrimSpace(root), "/")
	if root == "" {
		return defaultRoot
	}
	return root
}

// renderTree walks Template.Engine.Root in the source and materializes the tree
// in dst.
func (r *renderer) renderTree(dst string) error {
	walkErr := fs.WalkDir(r.src, r.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(p, r.root+"/")
		return r.renderFile(dst, p, rel)
	})
	if walkErr != nil {
		return fmt.Errorf("engine: walk %s: %w", r.root, walkErr)
	}
	return nil
}

// renderFile handles one template file: conditional paths, file filtering
// (manifest files rules), rendering/copying, postReplace, and writing to staging.
func (r *renderer) renderFile(dst, srcPath, rel string) error {
	outRel, include, err := r.transformPath(rel)
	if err != nil {
		return err
	}
	if !include {
		return nil
	}

	isTmpl := strings.HasSuffix(outRel, tmplSuffix)
	logicalRel := outRel
	if isTmpl {
		logicalRel = strings.TrimSuffix(outRel, tmplSuffix)
	}

	// File filtering by the manifest's files rules.
	if r.excluded.matchAny(logicalRel) {
		return nil
	}

	data, err := fs.ReadFile(r.src, srcPath)
	if err != nil {
		return fmt.Errorf("engine: read %s: %w", srcPath, err)
	}

	forceCopy := r.copyRaw.matchAny(logicalRel)
	if isTmpl && !forceCopy {
		data, err = r.execTemplate(logicalRel, data)
		if err != nil {
			return err
		}
	} else {
		data = r.applyPostReplace(logicalRel, data)
	}

	// In-file tplater:if/begin/end markers are processed AFTER text rendering;
	// the byte-copy path follows the same rule, so markers may occur in any
	// source file, not only *.tmpl. The sole exception is copyWithoutRender:
	// those files (usually binaries or external dashboards) are copied literally
	// without interpreting their contents.
	if !forceCopy {
		data, err = processMarkers(logicalRel, data, r.values)
		if err != nil {
			return err
		}
	}

	if err := writeFile(filepath.Join(dst, filepath.FromSlash(logicalRel)), data); err != nil {
		return err
	}
	r.written = append(r.written, logicalRel)
	return nil
}

// execTemplate renders content through text/template with the engine FuncMap.
// Each file receives a clone of the base partial set ({{ define }} blocks), so
// it can call {{ template "<name>" . }}.
func (r *renderer) execTemplate(name string, data []byte) ([]byte, error) {
	root, err := r.base.Clone()
	if err != nil {
		return nil, fmt.Errorf("engine: clone partials for %s: %w", name, err)
	}
	tmpl, err := root.New(name).Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("engine: parse template %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r.ctx); err != nil {
		return nil, fmt.Errorf("engine: execute template %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// parsePartials builds the base template from all *.tmpl files in each source.
// Files are traversed in sorted order (determinism) and must contain only
// {{ define }} blocks (loose text outside define is not executed).
func parsePartials(sources []fs.FS, funcMap template.FuncMap) (*template.Template, error) {
	base := template.New("__partials__").Funcs(funcMap)
	for _, src := range sources {
		var paths []string
		err := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, tmplSuffix) {
				paths = append(paths, p)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("engine: walk partials: %w", err)
		}
		sort.Strings(paths)
		for _, p := range paths {
			data, err := fs.ReadFile(src, p)
			if err != nil {
				return nil, fmt.Errorf("engine: read partial %s: %w", p, err)
			}
			if _, err := base.Parse(string(data)); err != nil {
				return nil, fmt.Errorf("engine: parse partial %s: %w", p, err)
			}
		}
	}
	return base, nil
}

// applyPostReplace performs placeholder string replacements in byte-copied files.
func (r *renderer) applyPostReplace(logicalRel string, data []byte) []byte {
	for _, rule := range r.postRepl {
		if rule.matcher.matchAny(logicalRel) {
			data = bytes.ReplaceAll(data, []byte(rule.placeholder), []byte(rule.value))
		}
	}
	return data
}

// writeFile creates parent directories and writes the file.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("engine: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: generated source files are regular 0644 files.
		return fmt.Errorf("engine: write %s: %w", path, err)
	}
	return nil
}

// ensureEmptyTarget checks that target is absent or an empty directory.
func ensureEmptyTarget(target string) error {
	info, err := os.Stat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("engine: stat target: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("engine: target %s exists and is not a directory", target)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return fmt.Errorf("engine: read target: %w", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("engine: target directory %s is not empty", target)
	}
	return nil
}

// commitStaging atomically moves staging to target (target is empty or absent).
func commitStaging(staging, target string) error {
	if _, err := os.Stat(target); err == nil {
		// An empty directory exists; remove it so Rename works cross-platform.
		if err := os.Remove(target); err != nil {
			return fmt.Errorf("engine: remove empty target: %w", err)
		}
	}
	if err := os.Rename(staging, target); err != nil {
		return fmt.Errorf("engine: rename staging→target: %w", err)
	}
	return nil
}
