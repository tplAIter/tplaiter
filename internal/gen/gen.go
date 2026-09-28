// Package gen implements the `tplater gen <kind> <Name>` scaffolder (SPEC-01 §6):
// a manifest-model port of go-template's internal/gen anchor mechanics
// (idempotency marker, insertion before an anchor, backup/rollback after a
// post-step error, Go formatting post-steps, and the build gate).
//
// Unlike go-template, the scaffolder-kind table is not a go:embed binary but
// the template manifest's Generators field (SPEC-01 §6). Snippets
// (Generator.Snippet, Anchor.Insert) are read from disk relative to
// [Options.GeneratorsDir], a copied `<template source>/<aiConfig-like path>`
// that C2 places in generated projects as .tplaiter/generators (see
// [GeneratorsRelPath], the C2/C4 contract symmetric to aiconfig.AIConfigRelPath).
package gen

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// GeneratorsRelPath — path to the copied generator-snippet directory in a
// generated project, relative to its root (C2/C4 contract: `tplater new` copies
// here the directory referenced by the template manifest's Generator.Snippet/Anchor.Insert).
const GeneratorsRelPath = ".tplaiter/generators"

// identRe — allowed derived snake-name format (unchanged from go-template:
// gen primarily works with Go sources).
var identRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var ErrExecutionUnavailable = errors.New("TRUST_GENERATION_EXECUTION_UNAVAILABLE")

// Name — derived forms of the raw scaffolder name, available to target/snippet/
// insert templates as `.Name.Pascal`, etc. (go-template Data port without an
// embedded Marker; [Generate] computes the idempotency marker and passes it only
// to anchor-insertion templates, see [Context.Marker]).
type Name struct {
	Raw    string
	Pascal string
	Camel  string
	Snake  string
	Kebab  string
}

// Context — data available to target-path, snippet, and anchor-insertion
// templates (SPEC-01 §6: "context: Name{Pascal,Snake,...} + Settings"). Project
// is an additive convenience for snippets needing the project's module path/slug.
type Context struct {
	Name     Name
	Settings settings.View
	Project  manifest.ProjectInfo
	// Marker — insertion idempotency marker (`// gen:<kind>:<snake>`). Set only
	// when rendering Anchor.Insert; the insertion template MUST include
	// `{{ .Marker }}` in its output, otherwise a repeated gen is not detected as a
	// duplicate (go-template port: the marker lives in the template body rather than
	// being imposed by the engine over foreign output).
	Marker string
	// Fields — entity fields parsed from a `fields` parameter (CG-1). Empty when
	// the generator does not declare such a parameter.
	Fields []Field
	// Params — all generator parameter values by name (CG-1). The value type
	// follows Param.Type: string→string, bool→bool, int→int, fields→[]Field (the
	// same slice as .Fields).
	Params map[string]any
	// MigrationSeq — next goose migration number (NNNNN) for the target-file
	// directory; set only when a target has numbered: goose.
	MigrationSeq string
}

// Options — parameters for one [Generate] call.
type Options struct {
	// ProjectRoot — project root: Target is written here and paths resolve from here.
	// Anchor.File.
	ProjectRoot string
	// GeneratorsDir — snippet directory (usually
	// filepath.Join(ProjectRoot, [GeneratorsRelPath])); Snippet/Anchor.Insert
	// resolved relative to it.
	GeneratorsDir string
	// Values — resolved project settings (when gate + `.Settings` in render context).
	Values settings.Values
	// Project — project coordinates for `.Project` in render context.
	Project manifest.ProjectInfo
	// Fields — parsed entity fields (from a `fields` parameter, CG-1), passed into
	// Context.Fields. Resolved by the caller (cmd/gen.go) through
	// [ResolveParams].
	Fields []Field
	// Params — generator parameter values by name (CG-1), passed into
	// Context.Params. Resolved by the caller through [ResolveParams].
	Params map[string]any
	// NoBuild skips the post-generation build gate. By default the manifest's
	// commands.build.run executes; older manifests without a command retain
	// fallback `go build ./...`.
	NoBuild bool
	// Runner executes the formatter/build gate. nil → [execx.Exec]{} (real calls;
	// depguard forbids direct os/exec outside internal/execx).
	Runner execx.Runner
	// Logf — optional step logger (nil → no output).
	Logf func(format string, args ...any)
}

// Result — successful generation result.
type Result struct {
	// Kind — scaffolder kind.
	Kind string
	// CreatedFiles — relative paths of created files (Target).
	CreatedFiles []string
	// EditedFiles — relative paths of edited anchor files.
	EditedFiles []string
}

// Status — result row from [List].
type Status struct {
	Kind        string
	Description string
	Available   bool
	// Reason — availability reason (non-empty only when Available=false): an
	// unmet when condition or evaluation error (unknown group).
	Reason string
}

// Lookup finds generator kind in the manifest. An error lists available kinds
// (sorted).
func Lookup(tpl *manifest.Template, kind string) (*manifest.Generator, error) {
	for i := range tpl.Generators {
		if tpl.Generators[i].Kind == kind {
			return &tpl.Generators[i], nil
		}
	}
	return nil, fmt.Errorf("gen: неизвестный вид %q (доступны: %s)", kind, strings.Join(kindNames(tpl), ", "))
}

// kindNames returns the sorted manifest generator-kind list.
func kindNames(tpl *manifest.Template) []string {
	names := make([]string, 0, len(tpl.Generators))
	for i := range tpl.Generators {
		names = append(names, tpl.Generators[i].Kind)
	}
	sort.Strings(names)
	return names
}

// List returns each manifest generator's status for values (for `tplater gen
// list`): whether it is available (see [evalGate]) and, if not, what to enable.
func List(tpl *manifest.Template, values settings.Values) []Status {
	out := make([]Status, 0, len(tpl.Generators))
	for i := range tpl.Generators {
		g := &tpl.Generators[i]
		ok, err := evalGate(g.When, values)
		st := Status{Kind: g.Kind, Description: g.Description, Available: ok}
		if !ok {
			st.Reason = gateReason(g.When, err)
		}
		out = append(out, st)
	}
	return out
}

// evalGate evaluates a generator when gate: an empty list is always available;
// otherwise one TRUE condition in the list is sufficient (OR semantics, like
// files.anyOf). The manifest deliberately made this sole text field "when" a
// string list rather than one string containing "&&", because it represents
// alternative gates; pure conjunction is already expressible as "a=1 && b=2"
// elsewhere in §3.2.
func evalGate(when []string, values settings.Values) (bool, error) {
	if len(when) == 0 {
		return true, nil
	}
	conds := make([]manifest.Condition, 0, len(when))
	for _, w := range when {
		cond, err := manifest.ParseCondition(w)
		if err != nil {
			return false, err
		}
		conds = append(conds, cond)
	}
	return settings.EvalAny(conds, values)
}

// gateReason builds a human-readable generator-unavailable reason.
func gateReason(when []string, err error) string {
	if err != nil {
		return err.Error()
	}
	return strings.Join(when, " | ")
}

// suggestSet builds a `--set` example for an unavailable-generator error:
// conjunctions "&&" within one condition become commas (--set accepts multiple
// group=value values through repeated flags), while OR-list alternatives are
// joined with "or".
func suggestSet(when []string) string {
	if len(when) == 0 {
		return ""
	}
	parts := make([]string, len(when))
	for i, w := range when {
		parts[i] = strings.ReplaceAll(w, "&&", ",")
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return parts[0] + " (или: " + strings.Join(parts[1:], " | ") + ")"
}

// Generate performs one kind scaffolding with rawName (SPEC-01 §6).
//
// Order: when gate → derived names → target-path render → target-absence check
// → snippet render → for each anchors[]: idempotency check (marker) + insertion
// render + insertBeforeAnchor preparation (without writing) → write all files →
// best-effort formatter for Go projects only → (if !NoBuild) manifest build gate
// with full rollback on failure (created files removed, anchor files restored from backup).
func Generate(ctx context.Context, tpl *manifest.Template, kind, rawName string, opts Options) (*Result, error) {
	log := opts.Logf
	if log == nil {
		log = func(string, ...any) {}
	}

	g, err := Lookup(tpl, kind)
	if err != nil {
		return nil, err
	}

	available, gateErr := evalGate(g.When, opts.Values)
	if gateErr != nil {
		return nil, fmt.Errorf("gen %s: вычисление when: %w", kind, gateErr)
	}
	if !available {
		return nil, fmt.Errorf(
			"gen %s недоступен при текущих настройках (%s) — включи настройку: tplater settings set %s",
			kind, gateReason(g.When, nil), suggestSet(g.When),
		)
	}

	gctx, err := newContext(rawName, opts.Values, opts.Project)
	if err != nil {
		return nil, fmt.Errorf("gen %s %q: %w", kind, rawName, err)
	}
	gctx.Fields = opts.Fields
	gctx.Params = opts.Params

	// Resolve targets: single form → one target; multifile → targets passing their
	// settings when gate.
	specs, err := resolveTargets(g, opts.Values)
	if err != nil {
		return nil, fmt.Errorf("gen %s: %w", kind, err)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("gen %s: при текущих настройках ни один таргет не подлежит генерации", kind)
	}

	// The goose migration number (when a target has numbered: goose) is computed
	// BEFORE rendering paths because it enters the target-path template (`.MigrationSeq`).
	if err := resolveMigrationSeq(&gctx, opts.ProjectRoot, specs); err != nil {
		return nil, fmt.Errorf("gen %s: %w", kind, err)
	}

	// Render all targets and verify that ALL target files are absent BEFORE any
	// write; a partial repeated gen (some files already exist) is rejected wholly.
	planned, err := planTargets(opts, kind, rawName, gctx, specs)
	if err != nil {
		return nil, err
	}

	anchors, err := prepareAnchors(opts, kind, gctx, g.Anchors)
	if err != nil {
		return nil, err
	}

	_ = planned
	_ = anchors
	return nil, ErrExecutionUnavailable
	/*
		createdAbs := make([]string, 0, len(planned))
		rollback := func() {
			for _, abs := range createdAbs {
				_ = os.Remove(abs)
			}
			for _, a := range anchors {
				_ = os.WriteFile(a.abs, a.original, 0o600)
			}
		}

		createdRels := make([]string, 0, len(planned))
		for _, p := range planned {
			if mkErr := os.MkdirAll(filepath.Dir(p.abs), 0o755); mkErr != nil {
				rollback()
				return nil, fmt.Errorf("gen %s: mkdir: %w", kind, mkErr)
			}
			if wErr := os.WriteFile(p.abs, p.content, 0o600); wErr != nil {
				rollback()
				return nil, fmt.Errorf("gen %s: writing %s: %w", kind, p.rel, wErr)
			}
			createdAbs = append(createdAbs, p.abs)
			createdRels = append(createdRels, p.rel)
			log("created %s", p.rel)
		}

		editedRels := make([]string, 0, len(anchors))
		for _, a := range anchors {
			if wErr := os.WriteFile(a.abs, a.updated, 0o600); wErr != nil {
				rollback()
				return nil, fmt.Errorf("gen %s: writing %s: %w", kind, a.rel, wErr)
			}
			editedRels = append(editedRels, a.rel)
			log("edited  %s (anchor %s)", a.rel, a.anchor)
		}

		changed := append(append([]string{}, createdAbs...), anchorAbsPaths(anchors)...)
		if isGoProject(opts.ProjectRoot) {
			runPostFormat(ctx, opts, changed, log)
		}

		if !opts.NoBuild {
			gateName, out, buildErr := runBuildGate(ctx, tpl, opts)
			log("step: %s", gateName)
			if buildErr != nil {
				rollback()
				return nil, fmt.Errorf("gen %s: generated code does not build — changes rolled back:\n%s", kind, out)
			}
		}

		return &Result{Kind: kind, CreatedFiles: createdRels, EditedFiles: editedRels}, nil
	*/
}

// plannedFile — rendered target file not yet written.
type plannedFile struct {
	rel     string
	abs     string
	content []byte
}

// resolveTargets returns targets to generate. Single form (Snippet+Target) has
// one target; multifile form (Targets[]) keeps targets passing their settings
// when gate and skips the rest.
func resolveTargets(g *manifest.Generator, values settings.Values) ([]manifest.Target, error) {
	if len(g.Targets) == 0 {
		return []manifest.Target{{Snippet: g.Snippet, Target: g.Target}}, nil
	}
	out := make([]manifest.Target, 0, len(g.Targets))
	for i := range g.Targets {
		t := g.Targets[i]
		ok, err := evalGate(t.When, values)
		if err != nil {
			return nil, fmt.Errorf("targets[%d].when: %w", i, err)
		}
		if ok {
			out = append(out, t)
		}
	}
	return out, nil
}

// planTargets renders target paths and snippets for all targets and verifies no
// target file exists yet (pre-write idempotency). A duplicate target path within
// one call is also an error.
func planTargets(opts Options, kind, rawName string, gctx Context, specs []manifest.Target) ([]plannedFile, error) {
	return planTargetsWithReserved(opts, kind, rawName, gctx, specs, nil)
}

// planTargetsWithReserved — [planTargets] variant for batch generation. reserved
// contains paths already planned by earlier batch operations, so collisions are
// detected before the first disk write.
func planTargetsWithReserved(opts Options, kind, rawName string, gctx Context, specs []manifest.Target, reserved map[string]struct{}) ([]plannedFile, error) {
	out := make([]plannedFile, 0, len(specs))
	seen := make(map[string]bool, len(specs))
	for i := range specs {
		t := &specs[i]
		rel, err := renderTargetPath(t.Target, gctx)
		if err != nil {
			return nil, fmt.Errorf("gen %s: targets[%d].target: %w", kind, i, err)
		}
		if seen[rel] {
			return nil, fmt.Errorf("gen %s: целевой путь %s встречается дважды", kind, rel)
		}
		seen[rel] = true
		if _, ok := reserved[rel]; ok {
			return nil, fmt.Errorf("gen %s %q: файл %s уже запланирован другой операцией batch", kind, rawName, rel)
		}

		abs := filepath.Join(opts.ProjectRoot, filepath.FromSlash(rel))
		if _, statErr := os.Stat(abs); statErr == nil {
			return nil, fmt.Errorf("gen %s %q: файл %s уже существует (уже сгенерировано)", kind, rawName, rel)
		}
		content, err := renderTemplateFile(filepath.Join(opts.GeneratorsDir, filepath.FromSlash(t.Snippet)), gctx)
		if err != nil {
			return nil, fmt.Errorf("gen %s: %w", kind, err)
		}
		out = append(out, plannedFile{rel: rel, abs: abs, content: content})
	}
	return out, nil
}

// resolveMigrationSeq computes gctx.MigrationSeq when a target has numbered:
// goose. The migration directory comes from that target's path rendered with an
// empty .MigrationSeq (the number is in the file name, not directory). Next is
// max(NNNNN among existing files)+1, starting at 00001 when none exist.
func resolveMigrationSeq(gctx *Context, root string, specs []manifest.Target) error {
	return resolveMigrationSeqWithReserved(gctx, root, specs, nil)
}

// resolveMigrationSeqWithReserved selects the next goose migration number,
// including not-yet-written batch migrations. Otherwise two operations in one
// batch would see the same number on disk.
func resolveMigrationSeqWithReserved(gctx *Context, root string, specs []manifest.Target, reserved map[string]struct{}) error {
	for i := range specs {
		if specs[i].Numbered != manifest.NumberedGoose {
			continue
		}
		rendered, err := renderTargetPath(specs[i].Target, *gctx)
		if err != nil {
			return fmt.Errorf("numbered target: %w", err)
		}
		seq, err := nextMigrationSeq(root, path.Dir(rendered))
		if err != nil {
			return err
		}
		// Future batch migrations are not in the directory, so nextMigrationSeq
		// cannot see them. The number must be unique in the directory, not only the
		// full target path: 00001_ride and 00001_driver are both invalid.
		if reserved != nil {
			maxReserved := 0
			for rel := range reserved {
				if path.Dir(rel) != path.Dir(rendered) {
					continue
				}
				m := migSeqRe.FindStringSubmatch(path.Base(rel))
				if m == nil {
					continue
				}
				n, convErr := strconv.Atoi(m[1])
				if convErr == nil && n > maxReserved {
					maxReserved = n
				}
			}
			current, convErr := strconv.Atoi(seq)
			if convErr != nil {
				return fmt.Errorf("некорректный номер миграции %q: %w", seq, convErr)
			}
			if maxReserved >= current {
				seq = fmt.Sprintf("%05d", maxReserved+1)
			}
		}
		for {
			gctx.MigrationSeq = seq
			rendered, renderErr := renderTargetPath(specs[i].Target, *gctx)
			if renderErr != nil {
				return fmt.Errorf("numbered target: %w", renderErr)
			}
			if _, used := reserved[rendered]; !used {
				break
			}
			n, convErr := strconv.Atoi(seq)
			if convErr != nil {
				return fmt.Errorf("некорректный номер миграции %q: %w", seq, convErr)
			}
			seq = fmt.Sprintf("%05d", n+1)
		}
		return nil
	}
	return nil
}

// migSeqRe extracts the numeric NNNNN_ prefix of a goose migration name.
var migSeqRe = regexp.MustCompile(`^(\d+)_`)

// nextMigrationSeq scans dirRel (relative to root) for NNNNN_* files and returns
// the next five-digit number (max+1, minimum 00001).
func nextMigrationSeq(root, dirRel string) (string, error) {
	dirAbs := filepath.Join(root, filepath.FromSlash(dirRel))
	entries, err := os.ReadDir(dirAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return "00001", nil
		}
		return "", fmt.Errorf("чтение каталога миграций %s: %w", dirRel, err)
	}
	maxSeq := 0
	for _, e := range entries {
		m := migSeqRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, convErr := strconv.Atoi(m[1])
		if convErr != nil {
			continue
		}
		if n > maxSeq {
			maxSeq = n
		}
	}
	return fmt.Sprintf("%05d", maxSeq+1), nil
}

// pendingAnchor — prepared (rendered but not written) edit of one anchor file.
type pendingAnchor struct {
	abs      string
	rel      string
	anchor   string
	original []byte
	updated  []byte
}

// prepareAnchors renders insertions for all generator anchors and checks each
// for idempotency BEFORE any disk write, so an error in the third anchor cannot
// leave the first two partially applied.
func prepareAnchors(opts Options, kind string, gctx Context, specs []manifest.Anchor) ([]pendingAnchor, error) {
	return prepareAnchorsWithState(opts, kind, gctx, specs, nil)
}

// prepareAnchorsWithState prepares anchor edits over state. Batch generation uses
// state so multiple operations inserting into one file see each other's edits
// before writing to disk.
func prepareAnchorsWithState(opts Options, kind string, gctx Context, specs []manifest.Anchor, state map[string][]byte) ([]pendingAnchor, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	if state == nil {
		state = make(map[string][]byte)
	}
	out := make([]pendingAnchor, 0, len(specs))
	pendingByPath := make(map[string]int, len(specs))
	marker := fmt.Sprintf("// gen:%s:%s", kind, gctx.Name.Snake)

	for i := range specs {
		a := &specs[i]
		anchorAbs := filepath.Join(opts.ProjectRoot, filepath.FromSlash(a.File))
		orig, exists := state[anchorAbs]
		if !exists {
			var readErr error
			orig, readErr = os.ReadFile(anchorAbs)
			if readErr != nil {
				return nil, fmt.Errorf("gen %s: чтение якорного файла %s: %w", kind, a.File, readErr)
			}
		}
		if strings.Contains(string(orig), marker) {
			return nil, fmt.Errorf("gen %s %q: маркер %q уже присутствует в %s (уже сгенерировано)",
				kind, gctx.Name.Raw, marker, a.File)
		}

		insertCtx := gctx
		insertCtx.Marker = marker
		insertPath := filepath.Join(opts.GeneratorsDir, filepath.FromSlash(a.Insert))
		block, renderErr := renderTemplateFile(insertPath, insertCtx)
		if renderErr != nil {
			return nil, fmt.Errorf("gen %s: anchors[%d].insert: %w", kind, i, renderErr)
		}
		updated, insErr := insertBeforeAnchor(string(orig), a.Anchor, string(block))
		if insErr != nil {
			return nil, fmt.Errorf("gen %s: %w", kind, insErr)
		}
		updatedBytes := []byte(updated)
		state[anchorAbs] = updatedBytes
		if j, duplicate := pendingByPath[anchorAbs]; duplicate {
			out[j].updated = updatedBytes
			continue
		}
		pendingByPath[anchorAbs] = len(out)
		out = append(out, pendingAnchor{abs: anchorAbs, rel: a.File, anchor: a.Anchor, original: orig, updated: updatedBytes})
	}
	return out, nil
}

// anchorAbsPaths returns absolute paths of changed anchor files.
func anchorAbsPaths(anchors []pendingAnchor) []string {
	out := make([]string, 0, len(anchors))
	for _, a := range anchors {
		out = append(out, a.abs)
	}
	return out
}

// newContext builds [Context] from the raw name, resolved settings, and project
// coordinates, validating the derived snake as a valid Go identifier (go-template
// port: the name becomes part of Marker and usually part of snippet Go code).
func newContext(rawName string, values settings.Values, project manifest.ProjectInfo) (Context, error) {
	if strings.TrimSpace(rawName) == "" {
		return Context{}, errors.New("имя скаффолда не задано")
	}
	n := Name{
		Raw:    rawName,
		Pascal: engine.Pascal(rawName),
		Camel:  engine.Camel(rawName),
		Snake:  engine.Snake(rawName),
		Kebab:  engine.Kebab(rawName),
	}
	if n.Pascal == "" || !identRe.MatchString(n.Snake) {
		return Context{}, fmt.Errorf("недопустимое имя %q (производный snake %q должен соответствовать %s)",
			rawName, n.Snake, identRe.String())
	}
	return Context{
		Name:     n,
		Settings: settings.View(values),
		Project:  project,
	}, nil
}
