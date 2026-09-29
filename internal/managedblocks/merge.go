package managedblocks

import (
	"bytes"
	"fmt"
	"sort"
)

type DeleteResolution string

const (
	DeleteKeep DeleteResolution = "keep"
	DeleteDrop DeleteResolution = "drop"
)

type PlanInput struct {
	Path               string
	Base, Ours, Theirs []byte
	Baseline           FileBaseline
	DeleteResolutions  map[string]DeleteResolution
	Renames            map[string]string // new ID -> old ID
}
type (
	BlockConflict struct{ Path, ID, Provider string }
	FilePlan      struct {
		Path          string
		Candidate     []byte
		Baseline      FileBaseline
		Conflicts     []BlockConflict
		RenameAliases map[string]string
	}
)

type plannedBlock struct {
	body, begin, end []byte
	provider         string
	anchor           Anchor
}

// PlanFile independently merges managed bodies and skeleton gaps. Rendering is
// driven by the selected upstream layout, preserving physical order,
// non-managed bytes, and exact target marker wrappers.
func PlanFile(in PlanInput) (FilePlan, error) {
	p := FilePlan{Path: in.Path, Baseline: cloneFileBaseline(in.Baseline), RenameAliases: map[string]string{}}
	if err := validatePath(in.Path); err != nil {
		return p, err
	}
	if p.Baseline.Blocks == nil {
		p.Baseline.Blocks = map[string]BlockBaseline{}
	}
	base, err := Parse(in.Path, in.Base)
	if err != nil {
		return p, err
	}
	ours, err := Parse(in.Path, in.Ours)
	if err != nil {
		return p, err
	}
	theirs, err := Parse(in.Path, in.Theirs)
	if err != nil {
		return p, err
	}
	if err := validateRenames(in.Renames, p.Baseline, base, ours, theirs); err != nil {
		return p, err
	}
	for _, n := range sortedKeys(in.Renames) {
		o := in.Renames[n]
		p.RenameAliases[o] = n
		p.Baseline.Blocks[n] = p.Baseline.Blocks[o]
		delete(p.Baseline.Blocks, o)
	}
	if err := validateResolutions(in.DeleteResolutions, p.Baseline, ours, theirs, in.Renames); err != nil {
		return FilePlan{Path: in.Path, Baseline: cloneFileBaseline(in.Baseline)}, err
	}
	eol := documentEOL(theirs, ours, base)
	lookup := func(d Document, id string) (Region, bool) {
		if r, ok := d.ByID[id]; ok {
			return r, true
		}
		if old, ok := in.Renames[id]; ok {
			r, found := d.ByID[old]
			return r, found
		}
		return Region{}, false
	}
	ids := map[string]bool{}
	for id := range p.Baseline.Blocks {
		ids[id] = true
	}
	for id := range theirs.ByID {
		ids[id] = true
	}
	planned := map[string]plannedBlock{}
	suppressed := map[string]bool{}
	for _, id := range sortedSet(ids) {
		prior, tracked := p.Baseline.Blocks[id]
		or, hasOurs := lookup(ours, id)
		tr, hasTheirs := theirs.ByID[id]
		if !tracked {
			if hasTheirs {
				planned[id] = fromRegion(tr, tr.Body, Anchor{Ordinal: tr.Ordinal})
			}
			continue
		}
		if !hasOurs {
			suppressed[id] = true
			prior.State = StateLocalDeleted
			prior.Tombstone = &Tombstone{Side: TombstoneLocal, Provider: prior.Provider, Source: prior.Source, BodySHA256: prior.BodySHA256}
			p.Baseline.Blocks[id] = prior
			continue
		}
		if !hasTheirs {
			if bytes.Equal(or.Body, []byte(prior.Body)) && in.DeleteResolutions[id] != DeleteKeep {
				suppressed[id] = true
				delete(p.Baseline.Blocks, id)
				continue
			}
			if in.DeleteResolutions[id] == DeleteDrop {
				suppressed[id] = true
				delete(p.Baseline.Blocks, id)
				continue
			}
			prior.State = StateUpstreamDeletedLocalRetained
			prior.Tombstone = &Tombstone{Side: TombstoneUpstream, Provider: prior.Provider, Source: prior.Source, BodySHA256: prior.BodySHA256}
			p.Baseline.Blocks[id] = prior
			planned[id] = fromRegion(or, or.Body, renamedAnchor(prior.Anchor, in.Renames))
			if in.DeleteResolutions[id] != DeleteKeep {
				p.Conflicts = append(p.Conflicts, BlockConflict{in.Path, id, or.Provider})
			}
			continue
		}
		if tr.Provider != prior.Provider {
			return FilePlan{Path: in.Path, Baseline: cloneFileBaseline(in.Baseline)}, failProvider(in.Path, id)
		}
		body, conflict := Merge3WithEOL([]byte(prior.Body), or.Body, tr.Body, eol)
		planned[id] = fromRegion(tr, body, renamedAnchor(prior.Anchor, in.Renames))
		if conflict {
			p.Conflicts = append(p.Conflicts, BlockConflict{in.Path, id, tr.Provider})
		}
		prior.Body, prior.BodySHA256 = string(tr.Body), bodyDigest(tr.Body)
		prior.Provider, prior.State, prior.Tombstone = tr.Provider, StatePresent, nil
		p.Baseline.Blocks[id] = prior
	}
	baseView, okBase := projectedLayout(base, in.Renames, suppressed)
	oursView, okOurs := projectedLayout(ours, in.Renames, suppressed)
	targetView, okTarget := projectedLayout(theirs, in.Renames, suppressed)
	if !okBase || !okOurs || !okTarget || unexplainedOurs(baseView, oursView) {
		return topologyConflict(in), nil
	}
	gaps, skeletonConflict, ambiguous := mergedGaps(baseView, oursView, targetView, eol)
	if ambiguous {
		return topologyConflict(in), nil
	}
	if skeletonConflict {
		p.Conflicts = append(p.Conflicts, BlockConflict{in.Path, "", ""})
	}
	priorConflicts := len(p.Conflicts)
	p.Candidate = renderLayout(targetView, gaps, planned, &p)
	if len(p.Conflicts) > priorConflicts {
		return topologyConflict(in), nil
	}
	if len(p.Conflicts) > 0 {
		p.Baseline = cloneFileBaseline(in.Baseline)
	}
	return p, nil
}

func topologyConflict(in PlanInput) FilePlan {
	return FilePlan{Path: in.Path, Candidate: cloneBytes(in.Ours), Baseline: cloneFileBaseline(in.Baseline), Conflicts: []BlockConflict{{Path: in.Path}}, RenameAliases: map[string]string{}}
}

func fromRegion(r Region, body []byte, anchor Anchor) plannedBlock {
	return plannedBlock{body: append([]byte(nil), body...), begin: cloneBytes(r.Begin), end: cloneBytes(r.End), provider: r.Provider, anchor: anchor}
}

func renamedAnchor(anchor Anchor, renames map[string]string) Anchor {
	anchor.Before = renamedID(anchor.Before, renames)
	anchor.After = renamedID(anchor.After, renames)
	return anchor
}

func renderLayout(layout Document, gaps [][]byte, planned map[string]plannedBlock, p *FilePlan) []byte {
	insert := map[int][]string{}
	for id, block := range planned {
		if _, present := layout.ByID[id]; present {
			continue
		}
		at, ok := anchorPosition(layout, block.anchor)
		if !ok {
			p.Conflicts = append(p.Conflicts, BlockConflict{p.Path, id, block.provider})
			continue
		}
		insert[at] = append(insert[at], id)
	}
	for pos, ids := range insert {
		if len(ids) != 1 {
			for _, id := range ids {
				p.Conflicts = append(p.Conflicts, BlockConflict{p.Path, id, planned[id].provider})
			}
			delete(insert, pos)
		}
	}
	var out []byte
	for i := 0; i <= len(layout.Regions); i++ {
		out = append(out, gaps[i]...)
		for _, id := range insert[i] {
			out = appendBlock(out, planned[id])
		}
		if i == len(layout.Regions) {
			break
		}
		if block, ok := planned[layout.Regions[i].ID]; ok {
			out = appendBlock(out, block)
		}
	}
	return out
}

// anchorPosition uses stored neighbor identities rather than an ordinal that
// can become stale after an upstream layout change. A sole-region layout has
// no neighbors, so position zero is its only unambiguous legacy placement.
func anchorPosition(layout Document, anchor Anchor) (int, bool) {
	before, hasBefore := -1, anchor.Before != ""
	if hasBefore {
		r, ok := layout.ByID[anchor.Before]
		if !ok {
			return 0, false
		}
		before = r.Ordinal
	}
	after, hasAfter := -1, anchor.After != ""
	if hasAfter {
		r, ok := layout.ByID[anchor.After]
		if !ok {
			return 0, false
		}
		after = r.Ordinal
	}
	switch {
	case hasBefore && hasAfter:
		return before, after+1 == before
	case hasBefore:
		return before, true
	case hasAfter:
		return after + 1, true
	case len(layout.Regions) == 0 && anchor.Ordinal == 0:
		return 0, true
	default:
		return 0, false
	}
}

func appendBlock(out []byte, block plannedBlock) []byte {
	out = append(out, block.begin...)
	out = append(out, block.body...)
	return append(out, block.end...)
}

func mergedGaps(base, ours, theirs Document, eol []byte) ([][]byte, bool, bool) {
	gaps := cloneGaps(theirs.Gaps)
	baseGaps, baseOrder := indexedGaps(base)
	oursGaps, oursOrder := indexedGaps(ours)
	targetGaps, _ := indexedGaps(theirs)
	order := append([]gapAnchor(nil), baseOrder...)
	for _, key := range oursOrder {
		if _, ok := baseGaps[key]; !ok {
			order = append(order, key)
		}
	}
	claimed := map[int]bool{}
	conflicted := false
	for _, key := range order {
		bi, hasBase := baseGaps[key]
		oi, hasOurs := oursGaps[key]
		if hasBase && hasOurs {
			if bytes.Equal(base.Gaps[bi], ours.Gaps[oi]) {
				continue
			}
			ti, hasTarget := targetGaps[key]
			if !hasTarget || claimed[ti] {
				return nil, false, true
			}
			var conflict bool
			gaps[ti], conflict = Merge3WithEOL(base.Gaps[bi], ours.Gaps[oi], theirs.Gaps[ti], eol)
			claimed[ti] = true
			conflicted = conflicted || conflict
			continue
		}
		if hasBase && len(base.Gaps[bi]) != 0 || hasOurs && len(ours.Gaps[oi]) != 0 {
			return nil, false, true
		}
	}
	return gaps, conflicted, false
}

type gapAnchor struct{ after, before string }

func indexedGaps(doc Document) (map[gapAnchor]int, []gapAnchor) {
	indexed := make(map[gapAnchor]int, len(doc.Gaps))
	order := make([]gapAnchor, 0, len(doc.Gaps))
	for i := range doc.Gaps {
		key := gapAnchor{}
		if i > 0 {
			key.after = doc.Regions[i-1].ID
		}
		if i < len(doc.Regions) {
			key.before = doc.Regions[i].ID
		}
		indexed[key] = i
		order = append(order, key)
	}
	return indexed, order
}

func projectedLayout(doc Document, renames map[string]string, suppressed map[string]bool) (Document, bool) {
	out := Document{ByID: map[string]Region{}, Gaps: [][]byte{cloneBytes(doc.Gaps[0])}}
	for i, region := range doc.Regions {
		id := renamedID(region.ID, renames)
		if suppressed[id] {
			out.Gaps[len(out.Gaps)-1] = append(out.Gaps[len(out.Gaps)-1], doc.Gaps[i+1]...)
			continue
		}
		if _, duplicate := out.ByID[id]; duplicate {
			return Document{}, false
		}
		region.ID, region.Ordinal = id, len(out.Regions)
		out.Regions = append(out.Regions, region)
		out.ByID[id] = region
		out.Gaps = append(out.Gaps, cloneBytes(doc.Gaps[i+1]))
	}
	out.Prefix, out.Suffix = cloneBytes(out.Gaps[0]), cloneBytes(out.Gaps[len(out.Gaps)-1])
	return out, true
}

func unexplainedOurs(base, ours Document) bool {
	for _, region := range ours.Regions {
		if _, known := base.ByID[region.ID]; !known {
			return true
		}
	}
	return false
}

func sameLayout(base, ours, theirs Document, renames map[string]string) bool {
	if len(base.Regions) != len(ours.Regions) || len(base.Regions) != len(theirs.Regions) || len(base.Gaps) != len(theirs.Gaps) || len(base.Gaps) != len(ours.Gaps) {
		return false
	}
	for i := range base.Regions {
		if theirs.Regions[i].ID != renamedID(base.Regions[i].ID, renames) || ours.Regions[i].ID != base.Regions[i].ID {
			return false
		}
	}
	return true
}

func renamedID(id string, renames map[string]string) string {
	for next, old := range renames {
		if old == id {
			return next
		}
	}
	return id
}

func cloneGaps(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = cloneBytes(in[i])
	}
	return out
}

func documentEOL(docs ...Document) []byte {
	for _, d := range docs {
		for _, g := range d.Gaps {
			if bytes.Contains(g, []byte("\r\n")) {
				return []byte("\r\n")
			}
		}
		for _, r := range d.Regions {
			if bytes.Contains(r.Bytes(), []byte("\r\n")) {
				return []byte("\r\n")
			}
		}
	}
	return []byte("\n")
}

func failProvider(path, id string) error {
	return fmt.Errorf("managed blocks: provider transition %s/%s", path, id)
}

func validateResolutions(r map[string]DeleteResolution, b FileBaseline, o, t Document, ren map[string]string) error {
	for id, v := range r {
		or, ok := o.ByID[id]
		if !ok {
			if old := ren[id]; old != "" {
				or, ok = o.ByID[old]
			}
		}
		_, target := t.ByID[id]
		block, tracked := b.Blocks[id]
		if !tracked || !ok || target || bytes.Equal(or.Body, []byte(block.Body)) || (v != DeleteKeep && v != DeleteDrop) {
			return fmt.Errorf("managed blocks: stale delete resolution %s", id)
		}
	}
	return nil
}

func validateRenames(r map[string]string, baseline FileBaseline, base, ours, theirs Document) error {
	oldIDs := map[string]bool{}
	for next, old := range r {
		if next == old || oldIDs[old] || baseline.Blocks[old].State == "" || baseline.Blocks[next].State != "" || base.ByID[old].ID == "" || base.ByID[next].ID != "" || ours.ByID[next].ID != "" || theirs.ByID[next].ID == "" || theirs.ByID[old].ID != "" {
			return fmt.Errorf("managed blocks: invalid rename %s", next)
		}
		oldIDs[old] = true
	}
	for next := range r {
		if oldIDs[next] {
			return fmt.Errorf("managed blocks: invalid rename %s", next)
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedSet(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
