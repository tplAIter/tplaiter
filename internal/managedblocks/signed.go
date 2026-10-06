package managedblocks

import (
	"bytes"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/provenance"
)

// SignedRootBaseline is a pure projection, not a source or formatter grant.
// Publication requires the lifecycle owner's verified clean formatter pair.
func SignedRootBaseline(files map[string][]byte, source provenance.RootSubject) (Baseline, error) {
	selected := map[string][]byte{}
	providers := map[string]bool{}
	count := 0
	for p, b := range files {
		if !bytes.Contains(b, []byte("tplater:managed-")) {
			continue
		}
		if validatePath(p) != nil || !strings.HasSuffix(p, ".go") || len(b) > 16<<20 {
			return Baseline{}, ErrDecision
		}
		count += bytes.Count(b, []byte("tplater:managed-"))
		if count > 8192 {
			return Baseline{}, ErrDecision
		}
		doc, err := Parse(p, b)
		if err != nil {
			return Baseline{}, err
		}
		if len(doc.Regions) == 0 {
			return Baseline{}, ErrDecision
		}
		selected[p] = append([]byte(nil), b...)
		for _, r := range doc.Regions {
			providers[r.Provider] = true
		}
	}
	refs := make([]ProviderSource, 0, len(providers))
	for p := range providers {
		refs = append(refs, ProviderSource{Provider: p, Source: source})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Provider < refs[j].Provider })
	return BuildBaseline(selected, refs, nil)
}
