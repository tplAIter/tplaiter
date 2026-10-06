package exports

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
)

// ProjectedModifier is inert data retained from actual opaque source reads.
// It is not a permit. Copies returned by Data never admit another source.
type ProjectedModifier struct {
	raw         []byte
	sources     []*deps.VerifiedSource
	rootAlias   string
	modifier    Modifier
	composition Composition
}

func stableSource(p deps.PinnedSource) AuthoredSourceConstraint {
	return AuthoredSourceConstraint{Alias: p.Alias, Origin: p.Origin, TemplatePath: p.TemplatePath, CommitAlgorithm: p.CommitAlgorithm, Commit: p.Commit, TreeDigest: p.TreeDigest, ContentDigest: p.ContentDigest, ContractDigest: p.ContractDigest, Parameters: p.Parameters, Dependencies: p.Dependencies}
}

// ProjectAuthoredModifier rederives the entire root ownership closure, never
// accepting a caller's RuleSet or catalog as lookup authority.
func ProjectAuthoredModifier(ctx context.Context, raw []byte, rootAlias string, sources []*deps.VerifiedSource) (*ProjectedModifier, error) {
	if ctx == nil || ctx.Err() != nil || len(sources) == 0 {
		return nil, fmt.Errorf("AUTHORED_SOURCE_REQUIRED")
	}
	a, e := ParseAuthoredModifier(raw)
	if e != nil {
		return nil, e
	}
	if len(a.Sources) != len(sources) {
		return nil, fmt.Errorf("AUTHORED_SOURCE_SET")
	}
	accepted := map[string]deps.PinnedSource{}
	verified := map[string]*deps.VerifiedSource{}
	for _, v := range sources {
		if v == nil {
			return nil, fmt.Errorf("AUTHORED_SOURCE_REQUIRED")
		}
		p, ok := v.AcceptedPin()
		if !ok || verified[p.Alias] != nil {
			return nil, fmt.Errorf("AUTHORED_SOURCE_AMBIGUOUS")
		}
		accepted[p.Alias] = p
		verified[p.Alias] = v
	}
	graphInputs := []deps.PinnedSource{}
	for _, v := range sources {
		p, _ := v.AcceptedPin()
		graphInputs = append(graphInputs, p)
	}
	if _, e := deps.BuildSourceGraph(graphInputs); e != nil {
		return nil, e
	}
	pins := []SourcePin{}
	for _, s := range a.Sources {
		p, ok := accepted[s.Alias]
		if !ok {
			return nil, fmt.Errorf("AUTHORED_SOURCE_SET")
		}
		x, _ := canonicaljson.Canonical(s)
		y, _ := canonicaljson.Canonical(stableSource(p))
		if !bytes.Equal(x, y) {
			return nil, fmt.Errorf("AUTHORED_SOURCE_PRECONDITION")
		}
		pins = append(pins, rootWirePin(p))
	}
	root, ok := verified[rootAlias]
	if !ok {
		return nil, fmt.Errorf("AUTHORED_ROOT")
	}
	prepared, e := PrepareRootRules(ctx, root, rootWirePin(accepted[rootAlias]))
	if e != nil {
		return nil, e
	}
	m := Modifier{APIVersion: "tplaiter.dev/modifier/v1", Kind: "Modifier", Metadata: a.Metadata, Compatibility: a.Compatibility, Sources: pins, SelfSource: a.SelfSource, Requires: a.Requires, Provides: a.Provides, Conflicts: a.Conflicts, Replaces: a.Replaces, Bindings: a.Bindings, ToolConstraints: a.ToolConstraints, Renames: a.Renames, Rules: []Operation{}}
	rules := map[string]Rule{}
	for _, r := range prepared.Rules.Rules {
		rules[r.ID] = r
	}
	used := map[string]bool{}
	for _, o := range a.Rules {
		op := Operation{ID: o.ID, Op: o.Op, Before: o.Before, After: o.After, Export: o.Export}
		if o.Op != "add" {
			if o.Source != rootAlias {
				return nil, fmt.Errorf("AUTHORED_TARGET_SOURCE")
			}
			expected, e := canonicaljson.Canonicalize(o.Original)
			if e != nil {
				return nil, e
			}
			matches := []RootOwnership{}
			for _, owned := range prepared.Ownership {
				actual, e := canonicaljson.Canonicalize(owned.Original)
				if e != nil {
					return nil, e
				}
				if owned.Kind == o.Kind && bytes.Equal(expected, actual) {
					matches = append(matches, owned)
				}
			}
			if len(matches) != 1 {
				return nil, fmt.Errorf("AUTHORED_ORIGINAL_MISSING_OR_AMBIGUOUS")
			}
			target := rules[matches[0].RuleID]
			if used[target.ID] {
				return nil, fmt.Errorf("AUTHORED_TARGET_AMBIGUOUS")
			}
			used[target.ID] = true
			op.Target = target.ID
			op.ExpectedDigest = target.Digest
			op.ExpectedVersion = target.Version
		}
		m.Rules = append(m.Rules, op)
	}
	if e = Validate(m); e != nil {
		return nil, e
	}
	composition, e := ResolveModifiers(prepared.Rules, []Modifier{m})
	if e != nil {
		return nil, e
	}
	encoded, e := json.Marshal(m)
	if e != nil {
		return nil, e
	}
	var copy Modifier
	if e = json.Unmarshal(encoded, &copy); e != nil {
		return nil, e
	}
	return &ProjectedModifier{raw: append([]byte(nil), raw...), sources: append([]*deps.VerifiedSource(nil), sources...), rootAlias: rootAlias, modifier: copy, composition: composition}, nil
}

// Data provides defensive pure values for inspection, never a writer capability.
func (p *ProjectedModifier) Data(ctx context.Context) (Modifier, Composition, error) {
	if p == nil {
		return Modifier{}, Composition{}, fmt.Errorf("AUTHORED_ZERO_PROJECTION")
	}
	fresh, e := ProjectAuthoredModifier(ctx, p.raw, p.rootAlias, p.sources)
	if e != nil {
		return Modifier{}, Composition{}, e
	}
	raw, e := json.Marshal(fresh.modifier)
	if e != nil {
		return Modifier{}, Composition{}, e
	}
	var m Modifier
	if e = json.Unmarshal(raw, &m); e != nil {
		return Modifier{}, Composition{}, e
	}
	cRaw, e := json.Marshal(fresh.composition)
	if e != nil {
		return Modifier{}, Composition{}, e
	}
	var c Composition
	if e = json.Unmarshal(cRaw, &c); e != nil {
		return Modifier{}, Composition{}, e
	}
	return m, c, nil
}
