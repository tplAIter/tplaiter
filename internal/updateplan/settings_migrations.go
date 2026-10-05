package updateplan

import (
	"context"
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

// planAnswerMigrations consumes freshly verified manifest bytes and exact ledger
// beforeimages. It is pure; nil Authorize deliberately refuses executable steps.
func planAnswerMigrations(source, target *manifest.Template, ledger []byte, answers map[string]stateledger.Answer) (*migrations.Plan, map[string]stateledger.Answer, error) {
	if err := migrations.ValidateAppliedHistory(source.Migrations, source.Metadata.Version, ledger); err != nil {
		return nil, nil, err
	}
	// Verify retention/digest/order also against the target declarations, but bind
	// already applied boundaries to the source version, never to a caller selector.
	if err := migrations.ValidateAppliedHistory(target.Migrations, source.Metadata.Version, ledger); err != nil {
		return nil, nil, err
	}
	if len(source.Migrations) == 0 && len(target.Migrations) == 0 {
		return nil, answers, nil
	}
	if _, err := semver.StrictNewVersion(source.Metadata.Version); err != nil {
		return nil, nil, fmt.Errorf("migrations: signed source version: %w", err)
	}
	if _, err := semver.StrictNewVersion(target.Metadata.Version); err != nil {
		return nil, nil, fmt.Errorf("migrations: signed target version: %w", err)
	}
	if source.Metadata.Version == target.Metadata.Version {
		return nil, answers, nil
	}
	plan, err := migrations.Build(target.Migrations, migrations.Options{CurrentVersion: source.Metadata.Version, TargetVersion: target.Metadata.Version, LedgerBytes: ledger})
	if err != nil {
		return nil, nil, err
	}
	if plan.Unversioned {
		return nil, nil, fmt.Errorf("migrations: signed versions must be releases")
	}
	migrated, err := migrateAnswerRecords(plan, answers)
	return plan, migrated, err
}

// migrateAnswerRecords follows ApplySettings's authored order across both phase
// lists. Each rename moves the complete answer and records migration origin;
// unrelated records and inactive snapshots remain detached and unchanged.
func migrateAnswerRecords(plan *migrations.Plan, answers map[string]stateledger.Answer) (map[string]stateledger.Answer, error) {
	records := make(map[string]any, len(answers))
	for key, answer := range answers {
		records[key] = answer
	}
	var err error
	// Apply each authored boundary separately so only actual moved records acquire
	// migration origin (including chains, swaps and later explicit deletions).
	selected := append([]migrations.PlannedMigration(nil), plan.Before...)
	selected = append(selected, plan.After...)
	sort.Slice(selected, func(i, j int) bool { return selected[i].Order < selected[j].Order })
	for _, step := range selected {
		present := map[string]bool{}
		for from := range step.Settings.Rename {
			_, present[from] = records[from]
		}
		records, err = migrations.ApplySettings(&migrations.Plan{Before: []migrations.PlannedMigration{step}}, records)
		if err != nil {
			return nil, err
		}
		for from, to := range step.Settings.Rename {
			if present[from] {
				if value, ok := records[to]; ok {
					answer := value.(stateledger.Answer)
					answer.Source = "migration"
					records[to] = answer
				}
			}
		}
	}
	result := make(map[string]stateledger.Answer, len(records))
	for key, value := range records {
		result[key] = value.(stateledger.Answer)
	}
	return result, nil
}

func (b *Backend) migrationRender(ctx context.Context, in Input, old renderref.Input, answers map[string]stateledger.Answer, ledger []byte) (renderref.Input, map[string]stateledger.Answer, *migrations.Plan, error) {
	sourceRaw, err := b.verifiedManifest(ctx, in.SourceInput)
	if err != nil {
		return old, nil, nil, err
	}
	targetRaw, err := b.verifiedManifest(ctx, in.TargetInput)
	if err != nil {
		return old, nil, nil, err
	}
	source, err := manifest.ParseTemplate(sourceRaw)
	if err != nil {
		return old, nil, nil, fmt.Errorf("%w: %w", operationtrust.ErrSourceAdapterUnsupported, err)
	}
	target, err := manifest.ParseTemplate(targetRaw)
	if err != nil {
		return old, nil, nil, fmt.Errorf("%w: %w", operationtrust.ErrSourceAdapterUnsupported, err)
	}
	if err := source.Validate(); err != nil {
		return old, nil, nil, fmt.Errorf("%w: %w", operationtrust.ErrSourceAdapterUnsupported, err)
	}
	if err := target.Validate(); err != nil {
		return old, nil, nil, fmt.Errorf("%w: %w", operationtrust.ErrSourceAdapterUnsupported, err)
	}
	plan, migrated, err := planAnswerMigrations(source, target, ledger, answers)
	if err != nil {
		return old, nil, nil, err
	}
	if plan == nil || len(plan.Before)+len(plan.After) == 0 {
		return old, migrated, plan, nil
	}
	resolved, err := ResolveSettingsAnswers(target, migrated, nil)
	if err != nil {
		return old, nil, nil, err
	}
	old.Values = renderref.Values(resolved.Values)
	return old, migrated, plan, nil
}
