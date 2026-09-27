// Command templatecheck validates and renders a template repository for CI.
// It is deliberately author-facing: it never installs tools, runs hooks, or
// executes commands supplied by a template.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/inittemplate"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

type renderRecord struct {
	Combo string   `json:"combo"`
	Files []string `json:"files"`
}

type report struct {
	Template string                   `json:"template"`
	Lint     *inittemplate.LintResult `json:"lint"`
	Renders  []renderRecord           `json:"renders"`
}

func main() {
	templateRoot := flag.String("template", ".", "template repository root")
	output := flag.String("output", "", "empty directory owned by the runner for rendered fixtures")
	combo := flag.String("combo", "", "run one exact settings combination")
	jsonOutput := flag.Bool("json", false, "write a machine-readable report")
	flag.Parse()
	if err := run(*templateRoot, *output, *combo, *jsonOutput, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "templatecheck:", err)
		os.Exit(1)
	}
}

func run(root, output, combo string, asJSON bool, stdout, stderr io.Writer) error {
	root, err := canonicalSourceRoot(root)
	if err != nil {
		return fmt.Errorf("template path: %w", err)
	}
	if err := rejectSymlinks(root); err != nil {
		return err
	}
	manifestPath := filepath.Join(root, "template.manifest.yaml")
	tpl, err := manifest.LoadTemplate(manifestPath)
	if err != nil {
		return err
	}
	if err := tpl.Validate(); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	if output == "" {
		return errors.New("--output is required and must be runner-owned")
	}
	output, err = canonicalOutputPath(output)
	if err != nil {
		return fmt.Errorf("output path: %w", err)
	}
	if isWithin(output, root) {
		return errors.New("output must not be inside the template source")
	}
	if err := prepareEmpty(output); err != nil {
		return err
	}

	result, err := inittemplate.Lint(inittemplate.LintOptions{Path: root, ComboName: combo, Out: stdout})
	if err != nil {
		return err
	}
	if result.Failed {
		return errors.New("lint failed")
	}
	combos, known := inittemplate.FilterCombos(inittemplate.Combos(tpl), combo)
	if combo != "" && len(combos) == 0 {
		return fmt.Errorf("unknown combo %q (known: %s)", combo, strings.Join(known, ", "))
	}

	entries := make([]renderRecord, 0, len(combos))
	for _, c := range combos {
		resolved, err := settings.Resolve(tpl, c.Explicit)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", c.Name, err)
		}
		destination := filepath.Join(output, safeComboName(c.Name))
		if !isWithin(destination, output) {
			return fmt.Errorf("unsafe combo destination %q", c.Name)
		}
		rendered, err := engine.Render(engine.Options{
			Source: os.DirFS(root), Target: destination, Template: tpl, Resolved: resolved,
			Project: manifest.ProjectInfo{Name: "CI Fixture", Slug: "ci_fixture", Module: "example.com/ci_fixture", System: "ci", Domain: "ci"},
			Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: "ci", Partials: partials(root),
		})
		if err != nil {
			return fmt.Errorf("render %s: %w", c.Name, err)
		}
		entries = append(entries, renderRecord{Combo: c.Name, Files: rendered.Files})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Combo < entries[j].Combo })
	if asJSON {
		return json.NewEncoder(stdout).Encode(report{Template: tpl.Metadata.Name, Lint: result, Renders: entries})
	}
	fmt.Fprintf(stdout, "rendered %d combination(s) into %s\n", len(entries), output)
	_ = stderr
	return nil
}

func partials(root string) []fs.FS {
	dir := filepath.Join(root, "partials")
	info, err := os.Stat(dir)
	if err == nil && info.IsDir() {
		return []fs.FS{os.DirFS(dir)}
	}
	return nil
}

func safeComboName(name string) string {
	name = strings.ReplaceAll(name, "=", "-")
	name = strings.ReplaceAll(name, "/", "-")
	return name
}

func prepareEmpty(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output %s must not be a symlink", path)
		}
		if !info.IsDir() {
			return fmt.Errorf("output %s is not a directory", path)
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("output %s must be empty", path)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(path, 0o755)
}

func canonicalSourceRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("template root must not be a symlink")
	}
	if !info.IsDir() {
		return "", errors.New("template root is not a directory")
	}
	return filepath.EvalSymlinks(abs)
}

// canonicalOutputPath resolves all existing ancestors without creating a path.
func canonicalOutputPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("output root must not be a symlink")
		}
		return filepath.EvalSymlinks(abs)
	} else if !os.IsNotExist(err) {
		return "", err
	}

	missing := []string{filepath.Base(abs)}
	parent := filepath.Dir(abs)
	for {
		if _, err := os.Lstat(parent); err == nil {
			resolved, err := filepath.EvalSymlinks(parent)
			if err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		if parent == filepath.Dir(parent) {
			return "", fmt.Errorf("no existing parent for output %s", abs)
		}
		missing = append(missing, filepath.Base(parent))
		parent = filepath.Dir(parent)
	}
}

func rejectSymlinks(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("template root must not be a symlink")
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("template contains symlink %s", path)
		}
		return nil
	})
}

func isWithin(path, parent string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
