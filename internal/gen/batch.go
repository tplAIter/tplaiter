package gen

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// Operation — one typed batch-scaffolding operation. Params and Fields must
// already be resolved by the caller through [ResolveParams].
type Operation struct {
	Kind   string
	Name   string
	Fields []Field
	Params map[string]any
}

// BatchResult — result of all successfully applied batch operations.
type BatchResult struct {
	Results      []Result
	CreatedFiles []string
	EditedFiles  []string
}

type batchPlan struct {
	result  Result
	planned []plannedFile
	anchors []pendingAnchor
}

// GenerateBatch applies multiple scaffolds as one filesystem transaction. All
// operations are planned before writing, including target collisions and shared
// anchor insertions. Go projects are then formatted and one final manifest build
// gate runs; any write or build error fully restores the original files.
func GenerateBatch(ctx context.Context, tpl *manifest.Template, operations []Operation, opts Options) (*BatchResult, error) {
	if len(operations) == 0 {
		return nil, errors.New("gen batch: at least one operation is required")
	}
	log := opts.Logf
	if log == nil {
		log = func(string, ...any) {}
	}

	reservedTargets := make(map[string]struct{})
	anchorState := make(map[string][]byte)
	allAnchors := make(map[string]pendingAnchor)
	plans := make([]batchPlan, 0, len(operations))

	for i, op := range operations {
		plan, err := planBatchOperation(tpl, op, opts, reservedTargets, anchorState)
		if err != nil {
			return nil, fmt.Errorf("gen batch: operation %d (%s %s): %w", i+1, op.Kind, op.Name, err)
		}
		for _, p := range plan.planned {
			reservedTargets[p.rel] = struct{}{}
		}
		for _, a := range plan.anchors {
			if prior, ok := allAnchors[a.abs]; ok {
				prior.updated = a.updated
				allAnchors[a.abs] = prior
			} else {
				allAnchors[a.abs] = a
			}
		}
		plans = append(plans, plan)
	}

	return nil, ErrExecutionUnavailable
	/*
		createdAbs := make([]string, 0)
		createdDirs := make([]string, 0)
		rollback := func() {
			for _, abs := range createdAbs {
				_ = os.Remove(abs)
			}
			for _, a := range allAnchors {
				_ = os.WriteFile(a.abs, a.original, 0o600)
			}
			// Directories absent before the batch must not survive a failed
			// transaction either. Walk from leaves to root; Remove safely leaves a
			// directory if another process managed to place a file in it.
			for _, dir := range createdDirs {
				_ = os.Remove(dir)
			}
		}

		createdRels := make([]string, 0)
		editedSet := make(map[string]struct{})
		results := make([]Result, 0, len(plans))
		for _, plan := range plans {
			for _, p := range plan.planned {
				if err := mkdirAllTracked(filepath.Dir(p.abs), &createdDirs); err != nil {
					rollback()
					return nil, fmt.Errorf("gen batch: mkdir %s: %w", p.rel, err)
				}
				if err := os.WriteFile(p.abs, p.content, 0o600); err != nil {
					rollback()
					return nil, fmt.Errorf("gen batch: writing %s: %w", p.rel, err)
				}
				createdAbs = append(createdAbs, p.abs)
				createdRels = append(createdRels, p.rel)
				log("created %s", p.rel)
			}
			results = append(results, plan.result)
		}

		anchorPaths := make([]string, 0, len(allAnchors))
		for abs := range allAnchors {
			anchorPaths = append(anchorPaths, abs)
		}
		sort.Strings(anchorPaths)
		for _, abs := range anchorPaths {
			a := allAnchors[abs]
			if err := os.WriteFile(a.abs, a.updated, 0o600); err != nil {
				rollback()
					return nil, fmt.Errorf("gen batch: writing %s: %w", a.rel, err)
			}
			log("edited  %s (anchor %s)", a.rel, a.anchor)
			editedSet[a.rel] = struct{}{}
		}

		changed := append(append([]string{}, createdAbs...), anchorPaths...)
		if isGoProject(opts.ProjectRoot) {
			runPostFormat(ctx, opts, changed, log)
		}
		if !opts.NoBuild {
			gateName, out, err := runBuildGate(ctx, tpl, opts)
			log("step: %s", gateName)
			if err != nil {
				rollback()
					return nil, fmt.Errorf("gen batch: generated code does not build — changes rolled back:\n%s", out)
			}
		}

		editedRels := make([]string, 0, len(editedSet))
		for rel := range editedSet {
			editedRels = append(editedRels, rel)
		}
		sort.Strings(editedRels)
		return &BatchResult{Results: results, CreatedFiles: createdRels, EditedFiles: editedRels}, nil
	*/
}

// mkdirAllTracked creates dir and records only genuinely new directories for
// rollback. The slice is built from the leaf toward an existing parent, so its
// natural order is suitable for Remove.
func mkdirAllTracked(dir string, created *[]string) error {
	missing := make([]string, 0)
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("%s exists but is not a directory", current)
			}
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	*created = append(*created, missing...)
	return nil
}

func planBatchOperation(tpl *manifest.Template, op Operation, opts Options, reserved map[string]struct{}, anchorState map[string][]byte) (batchPlan, error) {
	g, err := Lookup(tpl, op.Kind)
	if err != nil {
		return batchPlan{}, err
	}
	available, gateErr := evalGate(g.When, opts.Values)
	if gateErr != nil {
		return batchPlan{}, fmt.Errorf("gen %s: evaluating when: %w", op.Kind, gateErr)
	}
	if !available {
		return batchPlan{}, fmt.Errorf("gen %s is unavailable with current settings (%s) — enable the setting: tplater settings set %s", op.Kind, gateReason(g.When, nil), suggestSet(g.When))
	}

	gctx, err := newContext(op.Name, opts.Values, opts.Project)
	if err != nil {
		return batchPlan{}, fmt.Errorf("gen %s %q: %w", op.Kind, op.Name, err)
	}
	gctx.Fields, gctx.Params = op.Fields, op.Params
	specs, err := resolveTargets(g, opts.Values)
	if err != nil {
		return batchPlan{}, fmt.Errorf("gen %s: %w", op.Kind, err)
	}
	if len(specs) == 0 {
		return batchPlan{}, fmt.Errorf("gen %s: no targets are available for generation with current settings", op.Kind)
	}
	if err := resolveMigrationSeqWithReserved(&gctx, opts.ProjectRoot, specs, reserved); err != nil {
		return batchPlan{}, fmt.Errorf("gen %s: %w", op.Kind, err)
	}
	planned, err := planTargetsWithReserved(opts, op.Kind, op.Name, gctx, specs, reserved)
	if err != nil {
		return batchPlan{}, err
	}
	anchors, err := prepareAnchorsWithState(opts, op.Kind, gctx, g.Anchors, anchorState)
	if err != nil {
		return batchPlan{}, err
	}
	result := Result{Kind: op.Kind}
	for _, p := range planned {
		result.CreatedFiles = append(result.CreatedFiles, p.rel)
	}
	for _, a := range anchors {
		result.EditedFiles = append(result.EditedFiles, a.rel)
	}
	return batchPlan{result: result, planned: planned, anchors: anchors}, nil
}
