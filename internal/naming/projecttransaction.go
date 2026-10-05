package naming

import (
	"errors"
	"fmt"
	"os"

	"github.com/tplAIter/tplaiter/internal/stateledger/ledgerpath"
)

// ErrNativeRelocation distinguishes unsupported receipt relocation from an
// authenticated active transaction. A terminal receipt is not permanently active.
var ErrNativeRelocation = errors.New("naming: native transaction relocation unsupported")

func refuseNativeRelocation(root string) error {
	rel, err := ledgerpath.ProjectTransactionRelocationEvidence(root)
	if err != nil {
		return err
	}
	if rel != "" {
		return fmt.Errorf("%w: %s", ErrNativeRelocation, rel)
	}
	return nil
}

func refuseNativeEntries(root Root) error {
	for _, entry := range root.Entries {
		var reserved bool
		if root.Kind == "home" {
			_, reserved = ledgerpath.HomeProjectTransaction(entry.Path)
		} else {
			_, reserved = ledgerpath.ProjectTransactionImage(entry.Path)
		}
		if reserved {
			return fmt.Errorf("%w: %s", ErrNativeRelocation, entry.Path)
		}
	}
	return nil
}

// Called only after sourceOrArchiveMatches authenticates the naming preimage.
// A valid tombstone/rename window uses the retained archive, never its contents
// as relocated native authority. Completed destinations may acquire new history.
func refuseNativeRecoveryRelocation(root Root) error {
	info, err := os.Lstat(root.SourceRoot)
	if err == nil && info.IsDir() {
		return refuseNativeRelocation(root.SourceRoot)
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return refuseNativeRelocation(root.ArchiveRoot)
}
