package inventory

import (
	"context"
	"errors"
	"path/filepath"
	"sort"

	"github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Read authenticates receipts through the concrete installed runtime and its
// held CAS reader. It never accepts an interchangeable trust callback or creates
// authority. Foreign/uncovered home records stay unresolved; no phase is trusted
// from discovery alone. A returned observation cannot admit a later mutation.
func Read(ctx context.Context, runtime *trustload.Runtime, home string) ([]Record, error) {
	if ctx == nil || runtime == nil || runtime.TrustRuntime() == nil || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return nil, engine.ErrAuthentication
	}
	candidates, err := Discover(ctx, runtime.ProjectContext().RootPath, home)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	out := []Record{}
	for _, candidate := range candidates {
		if !candidate.CanonicalID || !candidate.Directory || candidate.Symlink {
			out = append(out, Record{id: candidate.ID, status: StatusUnsafe})
			continue
		}
		ids[candidate.ID] = true
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		observed, err := engine.InspectJournal(ctx, runtime, home, id)
		if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return nil, err
		}
		record := Record{id: id, kind: observed.Kind(), phase: observed.Phase(), status: Status(observed.Status()), planDigest: observed.PlanDigest(), receiptDigest: observed.ReceiptDigest(), sealed: observed.Sealed(), terminal: observed.Terminal()}
		for _, issue := range observed.Issues() {
			record.issues = append(record.issues, Status(issue))
		}
		if err != nil {
			record.sealed = false
			record.terminal = false
		}
		out = append(out, record)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime.TrustRuntime() == nil {
		return nil, engine.ErrAuthentication
	}
	return out, nil
}
