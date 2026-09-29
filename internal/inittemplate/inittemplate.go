// Package inittemplate implements tplaiter's meta-level (owner requirement 2):
// generating an EMPTY template repository "with all tooling"
// (`tplaiter init-template`) and a generic self-test for it
// (`tplaiter lint-template`, see [Lint]).
//
// The repository skeleton is embedded through go:embed (skeleton/**; it is
// small enough to live in the tplaiter repository). Skeleton files render with
// text/template's NONSTANDARD `<<`/`>>` delimiters and a minimal [skelContext],
// leaving ordinary `{{ … }}` untouched as second-level templates intended for
// the generated repository rather than init time. One file therefore carries
// both init-time substitution (`<< .Name >>`) and a layer-2 template
// (`{{ .Project.Slug }}`).
package inittemplate

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/execx"
)

//go:embed all:skeleton
var skeletonFS embed.FS

const (
	skeletonRoot   = "skeleton"
	skeletonCommon = skeletonRoot + "/common"   // repository-root files
	skeletonTpl    = skeletonRoot + "/template" // one template's contents
	skeletonRepo   = skeletonRoot + "/repo"     // repo.manifest.yaml (multi)
)

// nameRe — allowed template name, matching the manifest.metadata.name slug
// requirement (lowercase letters/digits separated by hyphens), because
// `<< .Name >>` is substituted directly into the skeleton metadata.name.
var nameRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// skelContext — init-time context for rendering the skeleton.
type skelContext struct {
	Name string
}

// InitOptions — parameters for one [Init] invocation.
type InitOptions struct {
	// Name — template name (slug), substituted into metadata.name and, for --multi,
	// the template subdirectory path.
	Name string
	// Dir — target repository directory; empty → ./<Name>.
	Dir string
	// Multi — generate a multi repository (repo.manifest.yaml plus a template in
	// the <Name>/ subdirectory).
	Multi bool
	// NoGit — do not run git init and the first commit.
	NoGit bool
	// Runner — external-process runner (git). nil → [execx.Exec].
	Runner execx.Runner
	// Out — output stream for "what next" hints.
	Out io.Writer
}

// Init generates a template repository and returns its created directory path.
// The target directory must be absent or empty (reinitializing a non-empty
// directory is an error).
func Init(ctx context.Context, opts InitOptions) (string, error) {
	if !nameRe.MatchString(opts.Name) {
		return "", fmt.Errorf("inittemplate: name %q is not in slug format (lowercase letters/digits with hyphens)", opts.Name)
	}

	repoDir := opts.Dir
	if repoDir == "" {
		repoDir = filepath.Join(".", opts.Name)
	}
	if err := ensureVacant(repoDir); err != nil {
		return "", err
	}
	if err := checkEnclosingProvider(opts, repoDir); err != nil {
		return "", err
	}

	ctxData := skelContext{Name: opts.Name}

	// Repository-root files (maintainer README, GitHub Actions workflow).
	if err := renderSubtree(skeletonCommon, repoDir, ctxData); err != nil {
		return "", err
	}

	if opts.Multi {
		if err := renderSubtree(skeletonRepo, repoDir, ctxData); err != nil {
			return "", err
		}
		if err := renderSubtree(skeletonTpl, filepath.Join(repoDir, opts.Name), ctxData); err != nil {
			return "", err
		}
	} else if err := renderSubtree(skeletonTpl, repoDir, ctxData); err != nil {
		return "", err
	}

	if err := verifyGenerated(opts, repoDir); err != nil {
		return "", err
	}

	if !opts.NoGit {
		initGit(ctx, opts, repoDir)
	}

	printNextSteps(opts, repoDir)
	return repoDir, nil
}

// renderSubtree renders embedded subtree embedRoot into dst, preserving relative
// structure and substituting `<< … >>` with data.
func renderSubtree(embedRoot, dst string, data skelContext) error {
	return fs.WalkDir(skeletonFS, embedRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(p, embedRoot+"/")
		raw, rerr := skeletonFS.ReadFile(p)
		if rerr != nil {
			return fmt.Errorf("inittemplate: read skeleton %s: %w", p, rerr)
		}
		out, rerr := renderSkeletonBytes(rel, raw, data)
		if rerr != nil {
			return rerr
		}
		outPath := filepath.Join(dst, filepath.FromSlash(rel))
		if mkErr := os.MkdirAll(filepath.Dir(outPath), 0o755); mkErr != nil {
			return fmt.Errorf("inittemplate: mkdir %s: %w", filepath.Dir(outPath), mkErr)
		}
		if wErr := os.WriteFile(outPath, out, 0o644); wErr != nil { //nolint:gosec // G306: generated template sources are ordinary 0644 files.
			return fmt.Errorf("inittemplate: write %s: %w", outPath, wErr)
		}
		return nil
	})
}

// renderSkeletonBytes renders one skeleton file through text/template with
// `<<`/`>>` delimiters. Files without `<<` pass through essentially unchanged.
func renderSkeletonBytes(name string, raw []byte, data skelContext) ([]byte, error) {
	t, err := template.New(name).Delims("<<", ">>").Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("inittemplate: parse skeleton %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("inittemplate: render skeleton %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// ensureVacant checks that path is absent or an empty directory.
func ensureVacant(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inittemplate: check %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("inittemplate: %q exists and is not a directory", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("inittemplate: read %q: %w", path, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("inittemplate: directory %q is not empty — choose an empty directory or different name", path)
	}
	return nil
}

// initGit runs git init and the first commit. Missing git or a commit failure
// (for example, missing user.name) becomes a warning: the repository is already
// created and usable, and git can be initialized manually.
func initGit(ctx context.Context, opts InitOptions, repoDir string) {
	runner := opts.Runner
	if runner == nil {
		runner = execx.Exec{}
	}
	if _, err := runner.LookPath("git"); err != nil {
		warnf(opts.Out, "git not found — skipping git init (initialize manually)")
		return
	}
	steps := [][]string{
		{"init", "-b", "main"},
		{"add", "-A"},
		{"commit", "-m", "chore: init template " + opts.Name + " via tplaiter init-template"},
	}
	for _, args := range steps {
		if _, err := runner.Run(ctx, "git", args, execx.Options{Dir: repoDir}); err != nil {
			warnf(opts.Out, "git %s: %v — commit skipped, repository created", strings.Join(args, " "), err)
			return
		}
	}
}

// printNextSteps prints a "what next" hint.
func printNextSteps(opts InitOptions, repoDir string) {
	if opts.Out == nil {
		return
	}
	fmt.Fprintf(opts.Out, "\nTemplate repository %q created in %s.\n", opts.Name, repoDir)
	fmt.Fprintln(opts.Out, "What's next:")
	fmt.Fprintf(opts.Out, "  1. cd %s\n", repoDir)
	fmt.Fprintln(opts.Out, "  2. tplaiter lint-template           # run self-test of corner combinations")
	fmt.Fprintln(opts.Out, "  3. edit template.manifest.yaml and files/ for your vertical")
	fmt.Fprintln(opts.Out, "  4. git tag v0.1.0 && git push --tags # publish version as tag")
	fmt.Fprintln(opts.Out, "  5. tplaiter repo add <alias> <url>  # add repository")
	fmt.Fprintln(opts.Out, "  for details see README.md and ai-config/rules/00-base.md in the generated repository")
}

func warnf(out io.Writer, format string, args ...any) {
	if out == nil {
		return
	}
	fmt.Fprintf(out, "warning: "+format+"\n", args...)
}
