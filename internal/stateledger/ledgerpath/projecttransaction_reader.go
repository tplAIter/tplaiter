package ledgerpath

import "strings"

// HomeProjectTransactionSlot classifies only canonical engine registry-image
// slots. It supplies a non-secret namespace classification, not authentication
// or permission to relocate, recover, mutate or trust a receipt.
func HomeProjectTransactionSlot(rel string) (Class, bool) {
	suffix, found := strings.CutPrefix(rel, ProjectTransactionsDir+"/tx-")
	if !found {
		return Class{}, false
	}
	id, slot, found := strings.Cut(suffix, "/")
	if !found {
		return Class{}, false
	}
	class, reserved := ProjectTransactionImage(ProjectTransactionImagesDir + "/" + id + "/" + slot)
	if !reserved || class.Classification != "project-transaction-image" {
		return Class{}, false
	}
	return class, true
}
