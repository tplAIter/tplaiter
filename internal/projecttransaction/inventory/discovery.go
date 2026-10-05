package inventory

import (
	"context"

	"github.com/tplAIter/tplaiter/internal/projecttransaction/inventory/catalog"
)

type Candidate = catalog.Candidate

var ErrUnsafeDiscovery = catalog.ErrUnsafeDiscovery

// Discover is namespace-only observation. Read authenticates actual receipts.
func Discover(ctx context.Context, projectRoot, home string) ([]Candidate, error) {
	return catalog.Discover(ctx, projectRoot, home)
}
