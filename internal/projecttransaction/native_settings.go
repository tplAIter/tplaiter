package projecttransaction

import (
	"context"

	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

// SettingsPlan retains a concrete same-version native Update plan; its report
// is detached observation, not a decoder or grant for mutation.
type SettingsPlan struct{ plan *updateplan.Plan }

func PlanSettings(ctx context.Context, r *trustload.Runtime, home, renderer string, source []byte, pairs []string) (*SettingsPlan, error) {
	if len(pairs) == 0 {
		return nil, updateplan.ErrSettingsInput
	}
	backend, err := updateplan.New(r, home, renderer)
	if err != nil {
		return nil, err
	}
	p, err := backend.Prepare(ctx, updateplan.Input{SourceInput: source, TargetInput: source, SettingsPairs: pairs})
	if err != nil {
		return nil, err
	}
	return &SettingsPlan{plan: p}, nil
}

// PlanManagedSettings keeps the same authenticated source on both sides. The
// formatter transport is data; preparing and publishing revalidate its effects
// and the actual project and registry through the existing Update owner.
func PlanManagedSettings(ctx context.Context, r *trustload.Runtime, home, renderer string, source []byte, pairs []string, transport updateplan.ManagedInput) (*SettingsPlan, error) {
	if len(pairs) == 0 {
		return nil, updateplan.ErrSettingsInput
	}
	backend, err := updateplan.New(r, home, renderer)
	if err != nil {
		return nil, err
	}
	p, err := backend.Prepare(ctx, updateplan.Input{SourceInput: source, TargetInput: source, SettingsPairs: pairs, Managed: &transport})
	if err != nil {
		return nil, err
	}
	return &SettingsPlan{plan: p}, nil
}

// PrepareManagedSettingsEffects retains the actual source-owned formatter
// preparation. Its request projections alone never authorize execution.
func PrepareManagedSettingsEffects(ctx context.Context, r *trustload.Runtime, home, renderer string, source []byte, pairs []string, transport updateplan.ManagedInput) (*updateplan.ManagedEffects, error) {
	if len(pairs) == 0 {
		return nil, updateplan.ErrSettingsInput
	}
	backend, err := updateplan.New(r, home, renderer)
	if err != nil {
		return nil, err
	}
	return backend.PrepareManagedEffects(ctx, updateplan.Input{SourceInput: source, TargetInput: source, SettingsPairs: pairs}, transport)
}

func (p *SettingsPlan) Fingerprint() string {
	if p == nil || p.plan == nil {
		return ""
	}
	return p.plan.Fingerprint()
}

func (p *SettingsPlan) Marshal() ([]byte, error) {
	if p == nil || p.plan == nil {
		return nil, updateplan.ErrInvalid
	}
	return p.plan.Marshal()
}

// BeginSettings uses the existing native Update kind and leases. Cold recovery
// stays OpenUpdate/Commit/Rollback, including its preparing-phase restriction.
func BeginSettings(ctx context.Context, p *SettingsPlan, expected string) (*UpdateTransaction, error) {
	if p == nil || p.plan == nil {
		return nil, updateplan.ErrInvalid
	}
	return BeginUpdate(ctx, p.plan, expected)
}
