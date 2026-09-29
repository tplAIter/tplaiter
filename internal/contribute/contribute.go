// Package contribute implements `tplater upgrade`: a developer who changed
// code in a generated project proposes those changes to the template itself by
// reverse-parameterizing (derendering) the changes and opening an MR/PR in the
// template repository (or producing a series of git patches in --patch mode).
//
// Flow: diff work↔reference render (reusing internal/stats and
// internal/renderref) → candidates (changed reference files + --files extras)
// → interactive selection (huh multiselect) → derender (slug/module/... →
// placeholders) → branch in a cached template-repository clone → commit →
// push + glab/gh MR (by repository type) OR git format-patch (--patch/plain git).
// The cached clone returns to its original ref after the operation.
package contribute

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stats"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// defaultRoot — default generated-file tree directory inside a template
// (matching engine.defaultRoot, which is not exported).
const defaultRoot = "files"

// tmplSuffix — suffix of sources rendered by the engine (engine.tmplSuffix).
const tmplSuffix = ".tmpl"

// excludedFromCandidates — files always excluded from drift candidates:
// go.mod/go.sum are noisy due to local replaces and versions and almost never
// represent a meaningful template contribution.
var excludedFromCandidates = map[string]struct{}{
	"go.mod": {},
	"go.sum": {},
}

// Options — [Upgrade] run parameters.
type Options struct {
	// StartDir — working directory for finding the project (usually os.Getwd).
	StartDir string
	// Files — glob patterns for extra files (absent from the reference) added to
	// candidates. A non-empty list also bypasses interactive selection.
	Files []string
	// Title — MR/PR title (generated from the project by default).
	Title string
	// Draft — open the MR/PR as a draft.
	Draft bool
	// Patch — force patch mode (git format-patch instead of push+MR).
	Patch bool
	// Yes — ask no interactive questions (select all candidates).
	Yes bool
}

// Deps — external [Upgrade] dependencies injected by cobra and tests.
type Deps struct {
	// Manager — template-version resolution/checkout and git operations in the cached clone.
	Manager *repo.Manager
	// Runner — glab/gh execution (execx.RecordingRunner in tests). Separate from
	// the manager's git runner so e2e can run real git while mocking the MR CLI.
	Runner execx.Runner
	// Home — tplater home directory (for reading the repository registry).
	Home string
	// Out, Err — main output and warning streams.
	Out io.Writer
	Err io.Writer
	// Palette — message palette.
	Palette ui.Palette
	// Picker — interactive file selection (huh in production, scripted in tests).
	Picker FilePicker
	// Now — time source for branch/patch-directory names (fixed in tests).
	Now func() time.Time
}

// Result — result of `tplater upgrade` (for tests and printing).
type Result struct {
	// Mode — "mr" (push+MR/PR) or "patch" (git format-patch).
	Mode string
	// Branch — created contribution branch.
	Branch string
	// Files — derendered template source paths (in application order).
	Files []string
	// PatchDir — patch directory (only for Mode=="patch").
	PatchDir string
	// MRArgs — arguments passed to the MR CLI (glab/gh; only for Mode=="mr").
	MRArgs []string
}

// modeMR/modePatch — Result.Mode values.
const (
	modeMR    = "mr"
	modePatch = "patch"
)

// fileChange — one file applied to the template tree.
type fileChange struct {
	logical    string // logical project path (churned.txt)
	sourceRel  string // template source path relative to the template directory (files/churned.txt.tmpl)
	content    []byte // derendered content
	condition  string // vertical condition, if the file belongs to one
	reviewDesc bool   // review marker could not be put in the file — added to MR description
}

// reference — result of resolving and rendering the project's template reference version.
type reference struct {
	res      repo.Resolved
	rendered *renderref.Result
	// srcMap — reference logical path → source path in the template tree
	// (relative to the template directory, with a .tmpl suffix for rendered files).
	srcMap map[string]string
}

// Upgrade runs `tplater upgrade`: finds the project, computes drift candidates,
// selects files, derenders them, and opens an MR/PR (or creates patches).
// Invariant: the cached template-repository clone returns to its original ref
// regardless of the outcome after branch creation.
func Upgrade(ctx context.Context, d Deps, opts Options) (*Result, error) {
	if d.Now == nil {
		d.Now = time.Now
	}

	root, proj, err := project.FindRoot(opts.StartDir)
	if err != nil {
		return nil, err
	}

	ref, err := renderReference(ctx, d.Manager, proj)
	if err != nil {
		return nil, err
	}

	report, err := stats.Analyze(stats.AnalyzeInput{
		RefFiles:   ref.rendered.Files,
		WorkDir:    root,
		CopyGlobs:  ref.rendered.Template.Engine.CopyWithoutRender,
		Generators: ref.rendered.Template.Generators,
	})
	if err != nil {
		return nil, err
	}

	candidates := selectCandidates(report, opts.Files)
	if len(candidates) == 0 {
		fmt.Fprintln(d.Out, "No changes to contribute: working tree matches template reference.")
		return &Result{}, nil
	}

	selected, err := chooseFiles(d, opts, candidates)
	if err != nil {
		return nil, err
	}
	if len(selected) == 0 {
		fmt.Fprintln(d.Out, "No files selected — contribution cancelled.")
		return &Result{}, nil
	}

	changes, err := buildChanges(root, proj.Project, ref, selected)
	if err != nil {
		return nil, err
	}

	// Registry: URL and repository type (to choose push+MR versus patch and push auth).
	repoEntry, err := repoRef(d.Home, ref.res.RepoAlias)
	if err != nil {
		return nil, err
	}

	out := &Result{
		Branch: branchName(proj.Project.Slug, d.Now()),
		Files:  changeSourcePaths(changes),
	}
	if opts.Patch || repoEntry.Type == state.RepoKindGit {
		out.Mode = modePatch
	} else {
		out.Mode = modeMR
	}

	if err := applyInClone(ctx, d, repoEntry, changes, out, opts, proj, ref, root); err != nil {
		return nil, err
	}
	printSummary(d, out, repoEntry)
	return out, nil
}

// renderReference resolves the project's template version, renders the reference,
// and builds srcMap (logical path → source path) by walking the checkout while
// it exists. The checkout is cleaned before returning; reference bytes and the
// source map are already in memory.
func renderReference(ctx context.Context, mgr *repo.Manager, proj *manifest.Project) (reference, error) {
	in := renderref.Input{
		Values:  renderref.Values(proj.Settings),
		Project: proj.Project,
		Runtime: proj.Runtime,
		Repo:    proj.Template.Repo,
	}
	coord := proj.Template.Repo + "/" + proj.Template.Name
	res, err := mgr.ResolveRef(coord + "@" + proj.Template.Version)
	if err != nil {
		return reference{}, fmt.Errorf("upgrade: version %s: %w", proj.Template.Version, err)
	}

	src, cleanup, err := mgr.Checkout(ctx, res.RepoAlias, res.GitRef, res.Entry.Path)
	if err != nil {
		return reference{}, err
	}
	defer func() { _ = cleanup() }()

	rendered, err := renderref.Render(ctx, src, in)
	if err != nil {
		return reference{}, fmt.Errorf("upgrade: render reference: %w", err)
	}

	srcMap := buildSourceMap(src, normalizeRoot(rendered.Template.Engine.Root))
	return reference{res: res, rendered: rendered, srcMap: srcMap}, nil
}

// buildSourceMap walks the checkout's generated-file tree (engineRoot) and
// builds a map from logical paths (without .tmpl) to actual source paths relative
// to the template directory. This precisely distinguishes .tmpl from byte-copy
// using the real tree rather than content heuristics.
func buildSourceMap(src fs.FS, engineRoot string) map[string]string {
	out := map[string]string{}
	if info, err := fs.Stat(src, engineRoot); err != nil || !info.IsDir() {
		return out
	}
	_ = fs.WalkDir(src, engineRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a failed file simply is not added to the map.
		}
		rel := strings.TrimPrefix(p, engineRoot+"/")
		logical := strings.TrimSuffix(rel, tmplSuffix)
		out[logical] = p
		return nil
	})
	return out
}

// selectCandidates builds candidate paths: modified reference files
// (StatusModified/ModifiedBinary) except go.mod/go.sum, plus extra files matching
// --files globs. The result is sorted and deduplicated.
func selectCandidates(report *stats.Report, fileGlobs []string) []string {
	out := make([]string, 0, len(report.Files))
	for _, f := range report.Files {
		if f.Status != stats.StatusModified && f.Status != stats.StatusModifiedBinary {
			continue
		}
		if _, skip := excludedFromCandidates[f.Path]; skip {
			continue
		}
		out = append(out, f.Path)
	}
	if len(fileGlobs) > 0 {
		gm := newGlobMatcher(fileGlobs)
		for _, extra := range report.Extras {
			if gm.match(extra) {
				out = append(out, extra)
			}
		}
	}
	sort.Strings(out)
	return dedupStrings(out)
}

// chooseFiles selects a subset of candidates: non-interactively (--yes/--files)
// it takes all; otherwise it shows a multiselect (all preselected).
func chooseFiles(d Deps, opts Options, candidates []string) ([]string, error) {
	if opts.Yes || len(opts.Files) > 0 || d.Picker == nil {
		return candidates, nil
	}
	return d.Picker.Pick(candidates)
}

// buildChanges turns selected logical paths into fileChange values: determines
// the template source path (from srcMap; heuristically for new extras), reads
// work-tree content, applies derendering, and marks files in conditional verticals.
func buildChanges(root string, proj manifest.ProjectInfo, ref reference, selected []string) ([]fileChange, error) {
	engineRoot := normalizeRoot(ref.rendered.Template.Engine.Root)
	subs := buildSubstitutions(proj)

	changes := make([]fileChange, 0, len(selected))
	for _, rel := range selected {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("upgrade: read %s: %w", rel, err)
		}

		derendered, changed := derender(content, subs)
		sourceRel := sourceRelFor(ref.srcMap, engineRoot, rel, changed)

		cond, isVertical := conditionForPath(ref.rendered.Template.Files, rel)
		reviewDesc := false
		if isVertical {
			var ok bool
			derendered, ok = markReview(derendered, sourceRel, cond)
			reviewDesc = !ok
		}

		changes = append(changes, fileChange{
			logical:    rel,
			sourceRel:  sourceRel,
			content:    derendered,
			condition:  cond,
			reviewDesc: reviewDesc,
		})
	}
	return changes, nil
}

// sourceRelFor computes the template source path for logical path rel. If rel
// is in srcMap (the file is in the reference tree), use the exact source path
// (.tmpl or byte-copy). Otherwise rel is a new extra file: write it as .tmpl
// only if derendering inserted placeholders (otherwise plain, avoiding needless
// engine processing for a static file).
func sourceRelFor(srcMap map[string]string, engineRoot, rel string, derenderChanged bool) string {
	if src, ok := srcMap[rel]; ok {
		return src
	}
	plain := path.Join(engineRoot, rel)
	if derenderChanged {
		return plain + tmplSuffix
	}
	return plain
}

// applyInClone performs all git work in the cached clone: branch from the
// project ref, write files, commit, then push+MR or format-patch. The cached
// clone always returns to the original branch, and the created branch is deleted locally.
func applyInClone(ctx context.Context, d Deps, repoEntry state.RepoRef, changes []fileChange, out *Result, opts Options, proj *manifest.Project, ref reference, root string) error {
	clone := d.Manager.CloneDir(repoEntry.Alias)

	orig, err := currentBranch(ctx, d.Manager, clone)
	if err != nil {
		return err
	}
	startPoint := resolveStartPoint(ctx, d.Manager, clone, ref.res.GitRef)

	if err := runGit(ctx, d.Manager, clone, "switch", "-c", out.Branch, startPoint); err != nil {
		return fmt.Errorf("upgrade: create branch %s: %w", out.Branch, err)
	}
	// Invariant: return the clone to the original ref and delete the branch on any outcome.
	defer func() {
		_ = runGit(ctx, d.Manager, clone, "switch", orig)
		_ = runGit(ctx, d.Manager, clone, "branch", "-D", out.Branch)
	}()

	templateDir := filepath.FromSlash(normalizeTemplatePath(ref.res.Entry.Path))
	for _, ch := range changes {
		dest := filepath.Join(clone, templateDir, filepath.FromSlash(ch.sourceRel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("upgrade: prepare directory for %s: %w", ch.sourceRel, err)
		}
		if err := os.WriteFile(dest, ch.content, 0o644); err != nil { //nolint:gosec // G306: template sources are ordinary 0644 files (committed to git, mode is not secret).
			return fmt.Errorf("upgrade: write %s: %w", ch.sourceRel, err)
		}
	}

	if err := runGit(ctx, d.Manager, clone, "add", "-A"); err != nil {
		return fmt.Errorf("upgrade: git add: %w", err)
	}
	if err := runGit(ctx, d.Manager, clone, "commit", "-m", commitMessage(proj, ref.res)); err != nil {
		return fmt.Errorf("upgrade: git commit: %w", err)
	}

	if out.Mode == modePatch {
		return formatPatch(ctx, d, clone, startPoint, out, root)
	}
	return pushAndOpenMR(ctx, d, repoEntry, out, opts, proj, ref, changes)
}

// formatPatch creates a patch series (startPoint..HEAD) in ./tplater-upgrade-<date>/.
func formatPatch(ctx context.Context, d Deps, clone, startPoint string, out *Result, root string) error {
	dir := filepath.Join(root, "tplater-upgrade-"+d.Now().Format("20060102-1504"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("upgrade: patch directory: %w", err)
	}
	if err := runGit(ctx, d.Manager, clone, "format-patch", startPoint, "-o", dir); err != nil {
		return fmt.Errorf("upgrade: git format-patch: %w", err)
	}
	out.PatchDir = dir
	return nil
}

// pushAndOpenMR pushes the branch to origin and opens an MR/PR through glab/gh.
func pushAndOpenMR(ctx context.Context, d Deps, repoEntry state.RepoRef, out *Result, opts Options, proj *manifest.Project, ref reference, changes []fileChange) error {
	clone := d.Manager.CloneDir(repoEntry.Alias)
	pushEnv := auth.HelperEnv(repoEntry.URL)
	if res, err := d.Manager.RunGit(ctx, clone, []string{"push", "-u", "origin", out.Branch}, pushEnv); err != nil {
		return fmt.Errorf(
			"upgrade: push branch %s: %s: %w\ncheck template repository access: `tplater auth add %s`",
			out.Branch, strings.TrimSpace(res.Stderr), err, hostOf(repoEntry.URL),
		)
	}

	title := opts.Title
	if title == "" {
		title = defaultTitle(proj)
	}
	desc := buildDescription(proj, ref.res, changes)

	args := mrArgs(repoEntry.Type, out.Branch, title, desc, opts.Draft)
	bin := mrBinary(repoEntry.Type)
	if _, err := d.Runner.Run(ctx, bin, args, execx.Options{Dir: clone, Env: pushEnv}); err != nil {
		return fmt.Errorf("upgrade: %s %s: %w", bin, strings.Join(args, " "), err)
	}
	out.MRArgs = args
	return nil
}

// runGit — wrapper around Manager.RunGit without extra environment (for clone operations).
func runGit(ctx context.Context, mgr *repo.Manager, clone string, args ...string) error {
	res, err := mgr.RunGit(ctx, clone, args, nil)
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// currentBranch returns the clone's current symbolic branch (for restoration).
func currentBranch(ctx context.Context, mgr *repo.Manager, clone string) (string, error) {
	res, err := mgr.RunGit(ctx, clone, []string{"symbolic-ref", "--short", "-q", "HEAD"}, nil)
	b := strings.TrimSpace(res.Stdout)
	if err != nil || b == "" {
		return "", errors.New("upgrade: cache clone is in detached HEAD state — cannot safely maintain branch (run `tplater repo update`)")
	}
	return b, nil
}

// resolveStartPoint selects the branch point: origin/<ref> if that ref exists
// (the current @latest after fetch lives at origin/<branch>), otherwise <ref>
// (tag/commit). Mirrors repo.Manager.Checkout logic.
func resolveStartPoint(ctx context.Context, mgr *repo.Manager, clone, gitRef string) string {
	if _, err := mgr.RunGit(ctx, clone, []string{"rev-parse", "--verify", "--quiet", "origin/" + gitRef}, nil); err == nil {
		return "origin/" + gitRef
	}
	return gitRef
}

// repoRef retrieves repository alias's registry entry from config.yaml.
func repoRef(home, alias string) (state.RepoRef, error) {
	cfg, err := state.LoadConfig(home)
	if err != nil {
		return state.RepoRef{}, err
	}
	for _, r := range cfg.Repos {
		if r.Alias == alias {
			return r, nil
		}
	}
	return state.RepoRef{}, fmt.Errorf("upgrade: repository %q not found in registry", alias)
}

// --- helpers ---

// normalizeRoot converts Engine.Root to its canonical form (copy of the
// unexported engine.normalizeRoot).
func normalizeRoot(root string) string {
	root = strings.Trim(strings.TrimSpace(root), "/")
	if root == "" {
		return defaultRoot
	}
	return root
}

// normalizeTemplatePath converts Entry.Path to a directory without leading or
// trailing slashes; "." and "" mean the repository root.
func normalizeTemplatePath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "." {
		return ""
	}
	return p
}

// branchName forms a contribution branch name: tplater/upgrade-<slug>-<YYYYMMDD-HHmm>.
func branchName(slug string, now time.Time) string {
	return fmt.Sprintf("tplater/upgrade-%s-%s", slug, now.Format("20060102-1504"))
}

// defaultTitle — default MR title.
func defaultTitle(proj *manifest.Project) string {
	return "tplater: contribution from project " + proj.Project.Slug
}

// commitMessage — commit message.
func commitMessage(proj *manifest.Project, res repo.Resolved) string {
	return fmt.Sprintf("tplater upgrade: contribution from %s (%s/%s@%s)",
		proj.Project.Slug, res.RepoAlias, res.Entry.Name, res.Version)
}

// mrBinary returns the MR/PR CLI for the repository type.
func mrBinary(kind state.RepoKind) string {
	if kind == state.RepoKindGitHub {
		return "gh"
	}
	return "glab"
}

// mrArgs builds glab/gh arguments for creating an MR/PR.
func mrArgs(kind state.RepoKind, branch, title, desc string, draft bool) []string {
	if kind == state.RepoKindGitHub {
		args := []string{"pr", "create", "--head", branch, "--title", title, "--body", desc}
		if draft {
			args = append(args, "--draft")
		}
		return args
	}
	args := []string{"mr", "create", "--source-branch", branch, "--title", title, "--description", desc}
	if draft {
		args = append(args, "--draft")
	}
	return args
}

// buildDescription builds the MR description: an automatic metadata block
// (template+version, project, settings snapshot, file list, TPLATER-REVIEW markers).
func buildDescription(proj *manifest.Project, res repo.Resolved, changes []fileChange) string {
	var b strings.Builder
	b.WriteString("## tplater upgrade\n\n")
	fmt.Fprintf(&b, "- Template: `%s/%s@%s`\n", res.RepoAlias, res.Entry.Name, res.Version)
	fmt.Fprintf(&b, "- Project: `%s` (module `%s`)\n", proj.Project.Slug, proj.Project.Module)

	if len(proj.Settings) > 0 {
		fmt.Fprintf(&b, "- Settings: %s\n", settingsSnapshot(proj.Settings))
	}

	b.WriteString("- Files:\n")
	for _, ch := range changes {
		line := "  - `" + ch.sourceRel + "`"
		if ch.condition != "" {
			line += fmt.Sprintf(" — conditional vertical `%s`", ch.condition)
		}
		b.WriteString(line + "\n")
	}

	var reviewNotes []string
	for _, ch := range changes {
		if ch.reviewDesc {
			reviewNotes = append(reviewNotes,
				fmt.Sprintf("`%s` (condition `%s`)", ch.sourceRel, ch.condition))
		}
	}
	if len(reviewNotes) > 0 {
		b.WriteString("\n> " + reviewMarker + ": for the files below, the marker could not be inserted in the body (no comment style) — check conditional blocks manually: ")
		b.WriteString(strings.Join(reviewNotes, ", ") + "\n")
	}

	b.WriteString("\n_Generated by `tplater upgrade`. Reverse parameterization does not restore conditional blocks — check TPLATER-REVIEW markers._\n")
	return b.String()
}

// settingsSnapshot formats the project settings snapshot as a stable key=value
// string (keys sorted).
func settingsSnapshot(s map[string]any) string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, s[k]))
	}
	return strings.Join(parts, ", ")
}

// printSummary prints the operation result for the user.
func printSummary(d Deps, out *Result, repoEntry state.RepoRef) {
	switch out.Mode {
	case modePatch:
		fmt.Fprintln(d.Out, d.Palette.Success("Patches created: ")+out.PatchDir)
		fmt.Fprintf(d.Out, "Send them to the template maintainer (%s) — for example, `git am %s/*.patch`.\n",
			repoEntry.Alias, out.PatchDir)
	case modeMR:
		fmt.Fprintln(d.Out, d.Palette.Success("Branch pushed and request opened: ")+out.Branch)
		fmt.Fprintf(d.Out, "MR/PR created via `%s` (repository %s).\n", mrBinary(repoEntry.Type), repoEntry.Alias)
	}
	if len(out.Files) > 0 {
		fmt.Fprintf(d.Out, "Files in contribution: %d.\n", len(out.Files))
	}
}

func changeSourcePaths(changes []fileChange) []string {
	out := make([]string, 0, len(changes))
	for _, ch := range changes {
		out = append(out, ch.sourceRel)
	}
	return out
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// hostOf extracts the host from a git URL for the auth hint.
func hostOf(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		if slash := strings.IndexAny(rest, "/:"); slash >= 0 {
			return rest[:slash]
		}
		return rest
	}
	return raw
}
