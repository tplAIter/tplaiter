package exports

import "github.com/tplAIter/tplaiter/internal/canonicaljson"

// CompileAuthoredModifierPlan converts closed authored rows into the existing
// inert modifier-plan wire format. Every emitted row must carry its complete
// plan facts; no operation is inferred from a count or from Original.
func CompileAuthoredModifierPlan(raw []byte) ([]byte, error) {
	authored, err := ParseAuthoredModifier(raw)
	if err != nil {
		return nil, err
	}
	records := make([]ModifierPlanRecord, len(authored.Rules))
	for i, rule := range authored.Rules {
		if rule.Plan == nil {
			return nil, modifierPlanError("AUTHORED_PLAN_REQUIRED")
		}
		records[i] = *rule.Plan
	}
	plan := ModifierPlan{
		APIVersion: ModifierPlanAPIVersion,
		Kind:       "ModifierPlan",
		ID:         authored.Metadata.ID,
		Records:    records,
	}
	canonicalPlan, err := canonicaljson.Canonical(plan)
	if err != nil {
		return nil, modifierPlanError("AUTHORED_CANONICAL")
	}
	if _, err := ParseModifierPlan(canonicalPlan); err != nil {
		return nil, err
	}
	return canonicalPlan, nil
}
