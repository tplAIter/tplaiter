package managedblocks

import (
	"bytes"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

var (
	ErrDecision    = errors.New("managed blocks: stale or unsupported decision")
	decisionDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

const DecisionsAPIVersion = "tplaiter.dev/managed-decisions/v1"

type Decisions struct {
	APIVersion string     `json:"apiVersion"`
	Decisions  []Decision `json:"decisions"`
}
type Decision struct {
	Action               string `json:"action"`
	Path                 string `json:"path"`
	Provider             string `json:"provider"`
	OldID                string `json:"oldID"`
	NewID                string `json:"newID,omitempty"`
	SourceRootLockSHA256 string `json:"sourceRootLockSHA256"`
	TargetRootLockSHA256 string `json:"targetRootLockSHA256"`
	BaselineBodySHA256   string `json:"baselineBodySHA256"`
	ObservedFileSHA256   string `json:"observedFileSHA256"`
	TargetBodySHA256     string `json:"targetBodySHA256,omitempty"`
}

func ParseDecisions(raw []byte) (Decisions, error) {
	var d Decisions
	if len(raw) == 0 || len(raw) > 1<<20 || canonicaljson.DecodeStrict(raw, &d) != nil || d.APIVersion != DecisionsAPIVersion || d.Decisions == nil || len(d.Decisions) > 4096 {
		return Decisions{}, ErrDecision
	}
	ids := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)
	seen := map[string]bool{}
	for _, v := range d.Decisions {
		k := v.Path + "\x00" + v.OldID
		if validatePath(v.Path) != nil || !strings.HasSuffix(v.Path, ".go") || !baselineProviderRE.MatchString(v.Provider) || !ids.MatchString(v.OldID) || seen[k] {
			return Decisions{}, ErrDecision
		}
		seen[k] = true
		for _, x := range []string{v.SourceRootLockSHA256, v.TargetRootLockSHA256, v.BaselineBodySHA256, v.ObservedFileSHA256} {
			if !decisionDigest.MatchString(x) {
				return Decisions{}, ErrDecision
			}
		}
		switch v.Action {
		case "keep", "drop":
			if v.NewID != "" || v.TargetBodySHA256 != "" {
				return Decisions{}, ErrDecision
			}
		case "rename":
			if !ids.MatchString(v.NewID) || v.OldID == v.NewID || !decisionDigest.MatchString(v.TargetBodySHA256) {
				return Decisions{}, ErrDecision
			}
		default:
			return Decisions{}, ErrDecision
		}
	}
	sort.Slice(d.Decisions, func(i, j int) bool {
		a, b := d.Decisions[i], d.Decisions[j]
		return a.Path+"\x00"+a.Provider+"\x00"+a.OldID+"\x00"+a.NewID+"\x00"+a.Action < b.Path+"\x00"+b.Provider+"\x00"+b.OldID+"\x00"+b.NewID+"\x00"+b.Action
	})
	return d, nil
}

// FileDecisions binds choices to actual byte observations and signed same-file
// replacement declarations. It grants no source or write authority.
func FileDecisions(d Decisions, path, sourceDigest, targetDigest string, baseline FileBaseline, ours, theirs []byte, replacements *manifest.ManagedBlocks) (map[string]DeleteResolution, map[string]string, error) {
	deletes := map[string]DeleteResolution{}
	renames := map[string]string{}
	target, err := Parse(path, theirs)
	if err != nil {
		return nil, nil, err
	}
	current, err := Parse(path, ours)
	if err != nil {
		return nil, nil, err
	}
	for _, v := range d.Decisions {
		if v.Path != path {
			continue
		}
		prior, ok := baseline.Blocks[v.OldID]
		or, present := current.ByID[v.OldID]
		if !ok || !present || prior.Provider != v.Provider || or.Provider != v.Provider || prior.BodySHA256 != v.BaselineBodySHA256 || evidencecas.Digest(ours) != v.ObservedFileSHA256 || v.SourceRootLockSHA256 != sourceDigest || v.TargetRootLockSHA256 != targetDigest {
			return nil, nil, ErrDecision
		}
		switch v.Action {
		case "keep", "drop":
			if target.ByID[v.OldID].ID != "" || bytes.Equal(or.Body, []byte(prior.Body)) {
				return nil, nil, ErrDecision
			}
			deletes[v.OldID] = DeleteResolution(v.Action)
		case "rename":
			next, ok := target.ByID[v.NewID]
			if !ok || next.Provider != v.Provider || evidencecas.Digest(next.Body) != v.TargetBodySHA256 || target.ByID[v.OldID].ID != "" {
				return nil, nil, ErrDecision
			}
			declared := false
			if replacements != nil {
				for _, r := range replacements.Replacements {
					if r.Path == path && r.Provider == v.Provider && r.OldID == v.OldID && r.NewID == v.NewID {
						declared = true
					}
				}
			}
			if !declared {
				return nil, nil, ErrDecision
			}
			renames[v.NewID] = v.OldID
		}
	}
	return deletes, renames, nil
}
