package newtransaction

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// ErrOwnershipUncertain retains the journal and all ambiguous content. Neither
// recovery nor abort may turn an observed tree into publication authority.
var ErrOwnershipUncertain = errors.New("new transaction: ownership uncertain; journal retained")

// BeginSealedWithFault binds an initially empty target to caller-derived output
// bytes before any staging writes. Files have mode 0644, parent directories
// 0755, and the transaction-owned state directory 0700. The inventory is never
// derived from the mutable workspace. Production callers pass a nil fault.
func BeginSealedWithFault(home, target string, files map[string][]byte, fault FaultInjector) (*Transaction, error) {
	tree, err := outputTree(files)
	if err != nil {
		return nil, err
	}
	return begin(home, target, fault, digest(tree))
}

func outputTree(files map[string][]byte) ([]byte, error) {
	entries := map[string]string{".tplaiter": "dir\x00700\x00"}
	for name, raw := range files {
		if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\n\x00") || name == filepath.ToSlash(pendingMarkerRel) {
			return nil, ErrUnsafe
		}
		if _, exists := entries[name]; exists {
			return nil, ErrUnsafe
		}
		entries[name] = "file\x00644\x00" + digest(raw)
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if entry, exists := entries[parent]; exists && !strings.HasPrefix(entry, "dir\x00") {
				return nil, ErrUnsafe
			}
			if parent != ".tplaiter" {
				entries[parent] = "dir\x00755\x00"
			}
		}
	}
	lines := make([]string, 0, len(entries))
	for name, entry := range entries {
		lines = append(lines, name+"\x00"+entry)
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n")), nil
}

// SealOutputs acknowledges a completely written afterimage, only after checking
// it against the inventory supplied to BeginSealedWithFault. Recovery refuses
// publication until this acknowledgement is durable.
func (t *Transaction) SealOutputs() error {
	if t == nil || t.sealedTree == "" || t.j.Phase != Prepared {
		return ErrUnsafe
	}
	if err := t.verifySealedTree(t.j.Staging); err != nil {
		return err
	}
	t.sealedReady = true
	return t.save()
}

func (t *Transaction) verifySealedTree(root string) error {
	raw, err := snapshotTree(root)
	if err != nil || digest(raw) != t.sealedTree {
		return fmt.Errorf("%w: sealed afterimage differs", ErrOwnershipUncertain)
	}
	return nil
}

// Before staging, only the exact beforeimage is owned. After staging but before
// SealOutputs, only that image plus the transaction's empty state directory is
// safely abortable. Partial writes are deliberately retained, not guessed away.
func (t *Transaction) verifySealedAbort() error {
	if _, err := os.Lstat(filepath.Join(t.j.Staging, pendingMarkerRel)); err == nil {
		if err := t.verifyPendingAt(t.j.Staging); err != nil {
			return errors.Join(ErrOwnershipUncertain, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(ErrOwnershipUncertain, err)
	}
	if t.sealedReady {
		return t.verifySealedTree(t.j.Staging)
	}
	raw, err := snapshotTree(t.j.Staging)
	if err != nil {
		return err
	}
	if digest(raw) == t.j.TargetBeforeTreeSHA || (t.j.TargetBeforeTreeSHA == digest(nil) && string(raw) == ".tplaiter\x00dir\x00700\x00") {
		return nil
	}
	return ErrOwnershipUncertain
}
