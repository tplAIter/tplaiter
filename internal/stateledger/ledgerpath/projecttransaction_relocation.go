package ledgerpath

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ProjectTransactionRelocationEvidence observes only reserved namespace names.
// A nonempty namespace (including unsafe components) cannot be relocated by the
// naming migration protocol. This is not a claim that terminal history is active.
// In-place marker migration must instead use concrete authenticated inventory.
func ProjectTransactionRelocationEvidence(root string) (string, error) {
	held, err := os.OpenRoot(root)
	if err != nil {
		return "", err
	}
	defer held.Close()
	for _, rel := range []string{"transactions", ProjectTransactionsDir, ProjectTransactionImagesDir} {
		info, err := held.Lstat(filepath.FromSlash(rel))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return rel, nil
		}
		if rel == "transactions" {
			continue
		}
		dir, err := held.Open(filepath.FromSlash(rel))
		if err != nil {
			return "", err
		}
		entries, readErr := dir.ReadDir(1)
		closeErr := dir.Close()
		if len(entries) > 0 {
			return rel, nil
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return "", readErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return "", nil
}
