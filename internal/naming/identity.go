// Package naming contains the public identity and compatibility boundary for
// tplaiter.  It is deliberately independent of Cobra, state encoders, and
// network clients so read-only commands can resolve identity without writes.
package naming

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	Product           = "tplaiter"
	LegacyProduct     = "tplater"
	ModulePath        = "github.com/tplAIter/tplaiter"
	HomeEnv           = "TPLAITER_HOME"
	LegacyHomeEnv     = "TPLATER_HOME"
	SelfRepoEnv       = "TPLAITER_SELF_REPO"
	LegacySelfRepoEnv = "TPLATER_SELF_REPO"
	HomeDir           = ".tplaiter"
	LegacyHomeDir     = ".tplater"
	ProjectDir        = ".tplaiter"
	LegacyProjectDir  = ".tplater"
	PlanSchema        = "tplaiter.dev/naming-migration-plan/v1"
	ReceiptSchema     = "tplaiter.dev/naming-migration-receipt/v1"
)

var (
	ErrAmbiguousHome = errors.New("naming: TPLAITER_HOME and TPLATER_HOME select different homes")
	ErrLegacyWrite   = errors.New("naming: legacy state is sealed by a completed migration")
)

// ResolveHome applies the explicit compatibility rule. New identity wins only
// when the two variables are absent or equal; a distinct pair is unsafe.
func ResolveHome(getenv func(string) string, userHome string) (string, error) {
	modern, legacy := getenv(HomeEnv), getenv(LegacyHomeEnv)
	if modern != "" && legacy != "" {
		m, l := filepath.Clean(modern), filepath.Clean(legacy)
		if m != l {
			return "", fmt.Errorf("%w: %q != %q", ErrAmbiguousHome, modern, legacy)
		}
		return m, nil
	}
	if modern != "" {
		return modern, nil
	}
	if legacy != "" {
		return legacy, nil
	}
	if userHome == "" {
		return "", errors.New("naming: user home is empty")
	}
	return filepath.Join(userHome, HomeDir), nil
}

// ResolveHomeFromEnv is the process-level convenience used by command setup.
func ResolveHomeFromEnv() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return ResolveHome(os.Getenv, h)
}

// DiscoverLegacyHome returns the old home only for explicit read-only
// compatibility discovery. It never creates or merges either home.
func DiscoverLegacyHome(modern string, userHome string) (string, error) {
	if modern == "" {
		return "", errors.New("naming: modern home is empty")
	}
	legacy := filepath.Join(userHome, LegacyHomeDir)
	if filepath.Clean(modern) == filepath.Clean(legacy) {
		return "", nil
	}
	if _, err := os.Stat(legacy); err == nil {
		return legacy, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return "", nil
}

// GuardLegacyWrite rejects supported writers after a migration tombstone is
// present. Arbitrary old binaries/manual edits remain outside this guarantee.
func GuardLegacyWrite(legacyRoot string) error {
	// A completed supported migration replaces the old root directory with a
	// regular-file tombstone. Checking the root itself matters: an old binary
	// never knew about an in-directory sentinel and will otherwise write below
	// the old path.
	if info, err := os.Lstat(legacyRoot); err == nil && info.Mode().IsRegular() {
		b, readErr := os.ReadFile(legacyRoot)
		if readErr != nil {
			return fmt.Errorf("naming: read legacy tombstone: %w", readErr)
		}
		if bytes.Equal(b, legacyTombstone) {
			return ErrLegacyWrite
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("naming: check legacy root: %w", err)
	}
	if _, err := os.Stat(filepath.Join(legacyRoot, ".tplaiter-migration-sealed")); err == nil {
		return ErrLegacyWrite
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("naming: check legacy seal: %w", err)
	}
	return nil
}

// MigratedProjectRoot recognizes exactly the post-commit project layout. A
// regular .tplater sibling is accepted only if it is our tombstone and the
// modern sibling has a receipt agreeing on both project marker directories.
// This keeps manually-created dual markers and incomplete commits fail-closed.
func MigratedProjectRoot(projectRoot string) (bool, error) {
	legacy := filepath.Join(projectRoot, LegacyProjectDir)
	modern := filepath.Join(projectRoot, ProjectDir)
	if err := GuardLegacyWrite(legacy); !errors.Is(err, ErrLegacyWrite) {
		return false, err
	}
	info, err := os.Stat(modern)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("naming: check modern project root: %w", err)
	}
	if !info.IsDir() {
		return false, errors.New("naming: modern project root is not a directory")
	}
	receiptPath := filepath.Join(modern, "migration.receipt.json")
	receipt, err := readReceipt(receiptPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("naming: read project migration receipt: %w", err)
	}
	if _, err := receiptPlan(receipt); err != nil {
		return false, nil
	}
	var r Root
	found := false
	for _, candidate := range receipt.Roots {
		if candidate.Kind != "project" || filepath.Clean(candidate.SourceRoot) != filepath.Clean(legacy) || filepath.Clean(candidate.DestinationRoot) != filepath.Clean(modern) {
			continue
		}
		if found {
			return false, nil
		}
		r, found = candidate, true
	}
	if !found {
		return false, nil
	}
	if r.Kind != "project" || filepath.Clean(r.SourceRoot) != filepath.Clean(legacy) ||
		filepath.Clean(r.DestinationRoot) != filepath.Clean(modern) ||
		r.ArchiveRoot != legacyArchive(legacy, receipt.PlanDigest) ||
		receipt.TransactionID != receipt.PlanDigest[:16] || !validProjectRoots(r.SourceRoot, r.DestinationRoot) {
		return false, nil
	}
	if _, err := os.Stat(r.ArchiveRoot); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("naming: check project archive: %w", err)
	}
	entries, err := capture(r.ArchiveRoot)
	if err != nil {
		return false, fmt.Errorf("naming: capture project archive: %w", err)
	}
	digest, err := digestBytes("tplaiter.dev/naming-source/v1", entries)
	if err != nil || digest != r.SourceDigest {
		return false, nil
	}
	// Bind the receipt to the deterministic transformed after-image, not to a
	// mutable working marker. New CLI writers legitimately update settings and
	// baselines after migration; those later writes must not invalidate the
	// immutable migration evidence.
	modernEntries, err := destinationEntries(r)
	if err != nil {
		return false, fmt.Errorf("naming: reconstruct project after-image: %w", err)
	}
	modernDigest, err := digestBytes("tplaiter.dev/naming-source/v1", modernEntries)
	if err != nil || modernDigest != r.DestinationDigest {
		return false, nil
	}
	return true, nil
}
