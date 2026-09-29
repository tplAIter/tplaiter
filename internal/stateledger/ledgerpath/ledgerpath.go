// Package ledgerpath is the single classification table for tplaiter state
// files. The state-ledger inventory, the global new-transaction engine and the
// legacy naming migration (`migrate-state`) all consult it, so a path is never
// classified one way by the inventory and another way by a migration or
// recovery pre-check.
//
// The package is a dependency leaf: it imports only the standard library, so
// low-level packages such as internal/naming can use it without an import
// cycle.
package ledgerpath

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Class describes one state path.
type Class struct {
	// Classification is the stable ledger kind reported in inventories.
	Classification string
	// Owner names the lifecycle component allowed to write the path.
	Owner string
	// Retention is the retention policy: permanent, stable, until-terminal,
	// rebuildable, preserve, 30d-and-newest100 or external.
	Retention string
	// WireVersion is the expected wire version, empty for opaque data.
	WireVersion string
	// Transaction marks locks, journals, pending markers and CAS blobs owned
	// by a transaction engine. Their presence can indicate an unfinished
	// operation and blocks state migration.
	Transaction bool
}

// Opaque reports whether the path is unknown to every ledger writer.
func (c Class) Opaque() bool { return c.Classification == "opaque" }

// Project classifies rel, a slash-separated path relative to a project
// state directory (".tplaiter" or the legacy ".tplater").
func Project(rel string) Class {
	switch rel {
	case "project.yaml":
		return Class{Classification: "project-marker", Owner: "project", Retention: "permanent", WireVersion: "v1alpha1-or-v2"}
	case "root-template.lock.json":
		return Class{Classification: "root-lock", Owner: "new-update-link", Retention: "permanent", WireVersion: "v2"}
	case "template.lock.json":
		return Class{Classification: "dependency-lock", Owner: "new-update", Retention: "permanent", WireVersion: "v2"}
	case "baseline.json":
		return Class{Classification: "baseline", Owner: "new-update-rebaseline", Retention: "permanent", WireVersion: "v1"}
	case "ownership.json":
		return Class{Classification: "ownership", Owner: "new-update-link-rebaseline", Retention: "permanent", WireVersion: "v1"}
	case "resources.lock.json":
		return Class{Classification: "resources-lock", Owner: "new-update", Retention: "permanent", WireVersion: "v2"}
	case "ai-managed.json":
		return Class{Classification: "ai-managed", Owner: "new-update-ai-copy", Retention: "permanent", WireVersion: "v1"}
	case "generator-targets.lock.json":
		return Class{Classification: "generator-targets", Owner: "gen-update", Retention: "permanent", WireVersion: "v1"}
	case "managed-blocks.json":
		return Class{Classification: "managed-blocks", Owner: "new-update-rebaseline", Retention: "permanent", WireVersion: "v1"}
	case "migrations.json":
		return Class{Classification: "migrations", Owner: "update", Retention: "permanent", WireVersion: "v1"}
	case "manifest.snapshot.yaml":
		return Class{Classification: "manifest-snapshot", Owner: "new-update", Retention: "permanent", WireVersion: "v1alpha1"}
	case "update.lock":
		return Class{Classification: "update-lock", Owner: "transaction-engine", Retention: "stable", WireVersion: "v1", Transaction: true}
	case "update/active.json":
		return Class{Classification: "update-journal", Owner: "transaction-engine", Retention: "until-terminal", WireVersion: "v1", Transaction: true}
	case NewPendingMarker:
		return Class{Classification: "new-pending-marker", Owner: "new-transaction-engine", Retention: "until-terminal", WireVersion: "v1", Transaction: true}
	}
	switch {
	case strings.HasPrefix(rel, "update/tx-"):
		return Class{Classification: "update-cas", Owner: "transaction-engine", Retention: "until-terminal", WireVersion: "v1", Transaction: true}
	case strings.HasPrefix(rel, "graph-cache/"):
		return Class{Classification: "graph-cache", Owner: "cache-builder", Retention: "rebuildable"}
	case strings.HasPrefix(rel, "generators/"):
		return Class{Classification: "generator-snapshot", Owner: "new-update", Retention: "permanent"}
	}
	return Class{Classification: "opaque", Owner: "project-user", Retention: "preserve"}
}

// Home classifies rel, a slash-separated path relative to the tplaiter home
// directory.
func Home(rel string) Class {
	switch rel {
	case "projects.yaml":
		return Class{Classification: "registry", Owner: "transaction-registry", Retention: "rebuildable", WireVersion: "v1"}
	case "config.yaml":
		return Class{Classification: "config", Owner: "repo-manager", Retention: "preserve", WireVersion: "v1"}
	case "index.yaml":
		return Class{Classification: "index", Owner: "repo-manager", Retention: "rebuildable", WireVersion: "v1"}
	case "state.yaml":
		return Class{Classification: "run-state", Owner: "cli", Retention: "rebuildable", WireVersion: "v1"}
	case "trust-roots.json":
		return Class{Classification: "trust-cache", Owner: "trust-updater", Retention: "preserve", WireVersion: "v1"}
	case HomeLock:
		return Class{Classification: "home-lock", Owner: "state", Retention: "stable", Transaction: true}
	case NewLock:
		return Class{Classification: "new-lock", Owner: "new-transaction-engine", Retention: "stable", WireVersion: "v1", Transaction: true}
	}
	if id, rest, ok := newTransactionEntry(rel); ok && id != "" {
		switch {
		case rest == "active.json":
			return Class{Classification: "new-journal", Owner: "new-transaction-engine", Retention: "until-terminal", WireVersion: "v1", Transaction: true}
		case rest == "hooks.lock":
			return Class{Classification: "new-hooks-lock", Owner: "new-transaction-engine", Retention: "until-terminal", Transaction: true}
		case strings.HasPrefix(rest, "blobs/sha256/"):
			return Class{Classification: "new-cas", Owner: "new-transaction-engine", Retention: "30d-and-newest100", WireVersion: "v1", Transaction: true}
		}
		return Class{Classification: "new-transaction-opaque", Owner: "new-transaction-engine", Retention: "until-terminal", Transaction: true}
	}
	if strings.HasPrefix(rel, "repos/") {
		return Class{Classification: "repo-cache", Owner: "repo-manager", Retention: "rebuildable"}
	}
	return Class{Classification: "opaque", Owner: "home-user", Retention: "preserve"}
}

// Well-known relative paths shared by the ledger writers.
const (
	// HomeLock is the interprocess lock for home state files (state.WithLock).
	HomeLock = ".lock"
	// NewLock is the global lock held by one new transaction at a time.
	NewLock = "transactions/new.lock"
	// NewTransactionsDir holds one tx-<id> directory per global journal.
	NewTransactionsDir = "transactions/new"
	// NewPendingMarker is the project-state-relative marker a new transaction
	// places in its staged target until the commit record is durable.
	NewPendingMarker = "new-transaction.pending"
	// UpdateLock and UpdateJournal belong to the project update engine.
	UpdateLock    = "update.lock"
	UpdateJournal = "update/active.json"
)

// newTransactionEntry splits transactions/new/<dir>/<rest>.
func newTransactionEntry(rel string) (dir, rest string, ok bool) {
	prefix := NewTransactionsDir + "/"
	if !strings.HasPrefix(rel, prefix) {
		return "", "", false
	}
	dir, rest, found := strings.Cut(strings.TrimPrefix(rel, prefix), "/")
	if !found {
		return dir, "", true
	}
	return dir, rest, true
}

// transactionProbes are the fixed locations whose presence means that a
// transaction engine may own the state root. They cover both a home root and
// a project state directory because the legacy naming migration treats every
// captured root the same way.
var transactionProbes = []string{HomeLock, UpdateLock, UpdateJournal, NewLock, NewPendingMarker}

// ErrTransactionEvidence reports that a transaction lock or journal exists.
var ErrTransactionEvidence = errors.New("ledgerpath: transaction evidence present")

// TransactionEvidence returns the first relative path under root that is
// owned by a transaction engine (a lock, a journal or a pending marker), or
// "" when there is none. It only uses lstat and a directory listing; it never
// opens, locks or creates a file.
func TransactionEvidence(root string) (string, error) {
	for _, rel := range transactionProbes {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			return rel, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("ledgerpath: transaction check %s: %w", rel, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(NewTransactionsDir)))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("ledgerpath: transaction listing: %w", err)
	}
	for _, entry := range entries {
		rel := path.Join(NewTransactionsDir, entry.Name(), "active.json")
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			return rel, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("ledgerpath: transaction check %s: %w", rel, err)
		}
	}
	return "", nil
}
