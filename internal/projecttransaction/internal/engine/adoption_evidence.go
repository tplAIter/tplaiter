package engine

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"gopkg.in/yaml.v3"
)

// AdoptionOrigin has no constructor or decoder. Only a committed installed
// first-marker receipt can supply its material and durable evidence identities.
type AdoptionOrigin struct {
	material   Material
	inspection JournalInspection
	receipt    string
	runtime    *trustload.Runtime
}

func (o *AdoptionOrigin) Material() Material {
	t := &Transaction{plan: immutable{Material: o.material}}
	return t.Material()
}
func (o *AdoptionOrigin) ReceiptID() string     { return o.receipt }
func (o *AdoptionOrigin) PlanDigest() string    { return o.inspection.PlanDigest() }
func (o *AdoptionOrigin) ReceiptDigest() string { return o.inspection.ReceiptDigest() }

// ReadAdoptionOrigin never creates a key, acquires a writer lease or advances
// a journal. Project receipts are in the ledger's preserve namespace; current
// production new-transaction GC cannot select them. CAS is checked on each read.
func ReadAdoptionOrigin(ctx context.Context, r *trustload.Runtime, home string, want *adoptionpolicy.Policy) (*AdoptionOrigin, error) {
	if want == nil || want.Validate() != nil || r == nil || r.TrustRuntime() == nil || want.Origin.ProjectID != r.ProjectContext().ProjectID || !want.Origin.Binding.Equal(r.TrustRuntime().Binding()) {
		return nil, ErrAuthentication
	}
	entries, err := confinedReadDir(filepath.Join(home, "transactions", "project"))
	if err != nil || len(entries) > 4096 {
		return nil, ErrAuthentication
	}
	var found *AdoptionOrigin
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(entry.Name(), "tx-") {
			continue
		}
		id := strings.TrimPrefix(entry.Name(), "tx-")
		f, e := loadFirstMarker(ctx, r, home, id, true)
		if e != nil {
			continue
		}
		m, e := f.Material(ctx)
		phase := f.state.Phase
		f.Release()
		if e != nil || phase != "committed" {
			continue
		}
		var marker stateledger.ProjectV2
		if yaml.Unmarshal(m.After[".tplaiter/project.yaml"].Data, &marker) != nil {
			continue
		}
		p, e := adoptionpolicy.Parse(marker.Ownership)
		if e != nil || p == nil || p.DecisionSHA256 != want.DecisionSHA256 {
			continue
		}
		if found != nil {
			return nil, ErrAuthentication
		}
		inspected, e := inspectFirstMarker(ctx, r, home, id)
		if e != nil || inspected.Kind() != NativeLinkKind || inspected.Status() != InspectionCommitted {
			return nil, ErrAuthentication
		}
		found = &AdoptionOrigin{material: m, inspection: inspected, receipt: id, runtime: r}
	}
	if found == nil {
		return nil, ErrAuthentication
	}
	return found, nil
}
