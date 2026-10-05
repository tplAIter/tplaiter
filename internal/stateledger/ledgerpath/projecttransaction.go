package ledgerpath

import (
	"encoding/hex"
	"path"
	"strings"
)

// ProjectTransactionsDir is relative to the tplaiter home. It is deliberately
// separate from NewTransactionsDir and never uses the creation journal parser.
const ProjectTransactionsDir = "transactions/project"

// ProjectTransactionImagesDir is relative to the project state directory.
const ProjectTransactionImagesDir = "project-transactions"

// ProjectTransactionVersion names the existing-tree receipt wire family.
const ProjectTransactionVersion = "tplaiter.dev/project-transaction/v1"

// ProjectTransactionID reports whether id is a canonical engine-generated ID.
func ProjectTransactionID(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// HomeProjectTransaction classifies only the reserved existing-tree namespace.
// Classification does not authenticate a receipt or establish an active writer.
func HomeProjectTransaction(rel string) (Class, bool) {
	suffix, reserved := transactionSuffix(rel, ProjectTransactionsDir)
	if !reserved {
		return Class{}, false
	}
	class := transactionClass("project-transaction-opaque")
	id, leaf, found := strings.Cut(suffix, "/")
	if !found || !ProjectTransactionID(strings.TrimPrefix(id, "tx-")) || !strings.HasPrefix(id, "tx-") || !canonicalTransactionPath(rel) {
		return class, true
	}
	switch leaf {
	case "plan.json":
		class.Classification = "project-transaction-plan"
	case "state.json":
		class.Classification = "project-transaction-state"
	}
	return class, true
}

// ProjectTransactionImage classifies exact engine slots. Unknown entries under
// the namespace remain transaction evidence, not ordinary user files or CAS.
func ProjectTransactionImage(rel string) (Class, bool) {
	suffix, reserved := transactionSuffix(rel, ProjectTransactionImagesDir)
	if !reserved {
		return Class{}, false
	}
	class := transactionClass("project-transaction-opaque")
	id, slot, found := strings.Cut(suffix, "/")
	if !found || !ProjectTransactionID(id) || !canonicalTransactionPath(rel) || len(slot) < 6 || len(slot) > 19 || (len(slot) > 6 && slot[0] == '0') {
		return class, true
	}
	for _, ch := range slot {
		if ch < '0' || ch > '9' {
			return class, true
		}
	}
	class.Classification = "project-transaction-image"
	// Slots are inode-preserving before/after images, not content-addressed blobs.
	class.WireVersion = ""
	return class, true
}

func transactionClass(kind string) Class {
	return Class{Classification: kind, Owner: "project-transaction-engine", Retention: "preserve", WireVersion: ProjectTransactionVersion, Transaction: true}
}

func transactionSuffix(rel, namespace string) (string, bool) {
	if rel == namespace {
		return "", true
	}
	suffix, ok := strings.CutPrefix(rel, namespace+"/")
	return suffix, ok
}

func canonicalTransactionPath(rel string) bool {
	return rel != "" && path.Clean(rel) == rel && !strings.HasPrefix(rel, "/") && !strings.ContainsAny(rel, "\\\x00\n\r")
}
