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
