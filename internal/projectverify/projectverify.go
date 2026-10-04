// Package projectverify is the read-only project verification boundary.
//
// Verification consumes an already constructed stable trust runtime and the
// canonical state-ledger readers. It does not load authority, resolve a
// source, refresh evidence, invoke Git, or write project or user state.
package projectverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/stateledger/ledgerpath"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/readonlysnapshot"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

const (
	OfflineMissCode = "TPL-E-OFFLINE-MISS-001"
	DigestCode      = "TPL-E-DIGEST-001"
	RootMissingCode = "TPL-E-ROOT-MISSING"
	TrustCode       = "TPL-E-TRUST-001"
	StateCode       = "TPL-E-STATE-001"
	TransactionCode = "TPL-E-TX-ACTIVE-001"
	CancelledCode   = "TPL-E-CANCELLED-001"
	// fbdae445 has no cancellation exit in result/v1; use its registered operational value.
	ExitCancelled = resultdto.ExitOperational
)

// Options contains only read-only evidence providers.
type Options struct {
	HomeRoot       string
	CAS            evidencecas.Reader
	SecretProvider stateledger.SecretDigestProvider
}

// Report is the stable, public summary of a successful verification.
// Project contents and source origins are deliberately absent.
type Report struct {
	ProjectID       string
	EntryCount      int
	LedgerCount     int
	DependencyCount int
	DependencyState string
	Offline         bool
}

// Verify validates the v2 marker, complete ledger inventory, lock pair, CAS
// evidence, confinement and journal state using an already verified stable
// authority. A nil authority or CAS fails closed.
func Verify(ctx context.Context, projectRoot string, authority stateledger.BindingAuthority, opts Options) (Report, error) {
	report, _, err := VerifyObserved(ctx, projectRoot, authority, opts)
	return report, err
}

// VerifyObserved returns the canonical ledger observation for the check
// projection. It is metadata, not a grant or a caller-selected identity.
func VerifyObserved(ctx context.Context, projectRoot string, authority stateledger.BindingAuthority, opts Options) (Report, *stateledger.Snapshot, error) {
	if err := contextError(ctx); err != nil {
		return Report{}, nil, classify(err)
	}
	if authority == nil {
		return Report{}, nil, diagnostic(TrustCode, resultdto.ExitTrust, "stable verified authority required", nil)
	}
	if opts.CAS == nil {
		return Report{}, nil, diagnostic(OfflineMissCode, resultdto.ExitUnavailable, "read-only evidence is unavailable", nil)
	}
	observation, err := OpenObservation(ctx, projectRoot)
	if err != nil {
		return Report{}, nil, classify(err)
	}
	defer func() { _ = observation.Close() }()
	snapshot, err := stateledger.VerifyStable(ctx, projectRoot, authority, stateledger.StableVerifyOptions{
		HomeRoot: opts.HomeRoot, CAS: opts.CAS, SecretProvider: opts.SecretProvider,
	})
	if err != nil {
		return Report{}, nil, classify(err)
	}
	identity, dependencyCount, dependencyState, err := verifiedIdentity(ctx, observation, snapshot, authority, opts.CAS)
	if err != nil {
		return Report{}, nil, classify(err)
	}
	if err := contextError(ctx); err != nil {
		return Report{}, nil, classify(err)
	}
	ledgerCount := 0
	for _, entry := range snapshot.Entries {
		if entry.Classification != "opaque" && entry.Classification != "graph-cache" {
			ledgerCount++
		}
	}
	return Report{
		ProjectID:       identity,
		EntryCount:      len(snapshot.Entries),
		LedgerCount:     ledgerCount,
		DependencyCount: dependencyCount,
		DependencyState: dependencyState,
		Offline:         true,
	}, snapshot, nil
}

// VerifyDependencies validates only the canonical v2 lock pair and every
// referenced evidence object. An explicit empty dependency array is valid.
func VerifyDependencies(ctx context.Context, projectRoot string, authority stateledger.BindingAuthority, cas evidencecas.Reader) error {
	if err := contextError(ctx); err != nil {
		return classify(err)
	}
	if authority == nil {
		return diagnostic(TrustCode, resultdto.ExitTrust, "stable verified authority required", nil)
	}
	if cas == nil {
		return diagnostic(OfflineMissCode, resultdto.ExitUnavailable, "read-only evidence is unavailable", nil)
	}
	if err := stateledger.VerifyDependencyLocks(ctx, projectRoot, authority, cas); err != nil {
		return classify(err)
	}
	return classify(contextError(ctx))
}

func verifiedIdentity(ctx context.Context, observation *Observation, snapshot *stateledger.Snapshot, authority stateledger.BindingAuthority, cas evidencecas.Reader) (string, int, string, error) {
	markerRaw, err := observation.ReadVerified(ctx, snapshot, stateledger.StateDir+"/project.yaml")
	if err != nil {
		return "", 0, "", fmt.Errorf("marker observation: %w", err)
	}
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(markerRaw, &marker); err != nil {
		return "", 0, "", fmt.Errorf("%w: marker projection", stateledger.ErrUnsafe)
	}
	rootRaw, err := observation.ReadVerified(ctx, snapshot, stateledger.StateDir+"/"+stateledger.RootLockFile)
	if err != nil {
		return "", 0, "", err
	}
	dependencyRaw, err := observation.ReadVerified(ctx, snapshot, stateledger.StateDir+"/"+stateledger.DependencyLockFile)
	if err != nil {
		return "", 0, "", err
	}
	rootLock, err := provenance.DecodeRootTemplateLock(rootRaw)
	if err != nil {
		return "", 0, "", fmt.Errorf("%w: %w", stateledger.ErrDigest, err)
	}
	lock, err := provenance.DecodeTemplateLock(dependencyRaw)
	if err != nil {
		return "", 0, "", fmt.Errorf("%w: %w", stateledger.ErrDigest, err)
	}
	if err := provenance.ValidateLockPair(*rootLock, *lock); err != nil {
		return "", 0, "", fmt.Errorf("%w: %w", stateledger.ErrDigest, err)
	}
	if err := authority.CheckBinding(rootLock.TrustProfile); err != nil {
		return "", 0, "", fmt.Errorf("%w: %w", stateledger.ErrPolicyOrigin, err)
	}
	subjects := append([]provenance.DependencySubject{provenance.DependencySubject(rootLock.Root)}, lock.Dependencies...)
	for _, subject := range subjects {
		for _, ref := range []string{subject.StatementCAS, subject.SignatureCAS, subject.CheckpointCAS, subject.InclusionProofCAS} {
			if err := contextError(ctx); err != nil {
				return "", 0, "", err
			}
			data, err := cas.Read(ctx, ref)
			if err != nil {
				return "", 0, "", fmt.Errorf("%w: %w", stateledger.ErrEvidence, err)
			}
			if evidencecas.Digest(data) != ref {
				return "", 0, "", stateledger.ErrDigest
			}
		}
	}
	checker, ok := authority.(stateledger.ProjectIdentityAuthority)
	if !ok {
		return "", 0, "", stateledger.ErrProjectIdentity
	}
	if err := checker.CheckProjectIdentity(ctx, observation.path, marker.ID); err != nil {
		return "", 0, "", fmt.Errorf("%w: %w", stateledger.ErrProjectIdentity, err)
	}
	// Reobserve all projected bytes after callbacks. Reverts are safe only when
	// the exact ledger-hashed bytes/modes still match, never a cached summary.
	for _, rel := range []string{stateledger.StateDir + "/project.yaml", stateledger.StateDir + "/" + stateledger.RootLockFile, stateledger.StateDir + "/" + stateledger.DependencyLockFile} {
		if _, err := observation.ReadVerified(ctx, snapshot, rel); err != nil {
			return "", 0, "", err
		}
	}
	if err := contextError(ctx); err != nil {
		return "", 0, "", err
	}
	state := "verified"
	if len(lock.Dependencies) == 0 {
		state = "not-applicable"
	}
	return marker.ID, len(lock.Dependencies), state, nil
}

func diagnostic(code string, exit resultdto.ExitCode, message string, cause error) error {
	return resultdto.NewDiagnosticError(resultdto.Diagnostic{Code: code, Severity: "error", Message: message, Details: map[string]any{}}, exit, cause)
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return diagnostic(CancelledCode, ExitCancelled, "project verification cancelled", contextCause(err))
	}
	var miss *readonlysnapshot.OfflineMissError
	if errors.As(err, &miss) {
		return diagnostic(OfflineMissCode, resultdto.ExitUnavailable, "required offline evidence is unavailable", err)
	}
	if errors.Is(err, stateledger.ErrDigest) {
		return diagnostic(DigestCode, resultdto.ExitIncompatible, "sealed state or evidence digest mismatch", err)
	}
	if errors.Is(err, stateledger.ErrEvidence) && !errors.Is(err, fs.ErrNotExist) {
		return diagnostic(TrustCode, resultdto.ExitTrust, "offline evidence is invalid or unreadable", err)
	}
	if errors.Is(err, stateledger.ErrEvidence) && errors.Is(err, fs.ErrNotExist) {
		return diagnostic(OfflineMissCode, resultdto.ExitUnavailable, "required offline evidence is unavailable", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return diagnostic(RootMissingCode, resultdto.ExitUnavailable, "project root or required state is missing", err)
	}
	if errors.Is(err, stateledger.ErrPolicyOrigin) || errors.Is(err, stateledger.ErrLegacyLock) {
		return diagnostic(TrustCode, resultdto.ExitTrust, "trust evidence is invalid", err)
	}
	if errors.Is(err, stateledger.ErrProjectIdentity) {
		return diagnostic(TrustCode, resultdto.ExitTrust, "stable project identity authority required", err)
	}
	if errors.Is(err, stateledger.ErrFutureVersion) || errors.Is(err, ledgerpath.ErrTransactionEvidence) {
		return diagnostic(TransactionCode, resultdto.ExitTransaction, "active or unsupported transaction state", err)
	}
	if errors.Is(err, stateledger.ErrUnsafe) {
		return diagnostic(StateCode, resultdto.ExitOperational, "project state is unsafe", err)
	}
	return diagnostic(StateCode, resultdto.ExitOperational, fmt.Sprintf("project verification failed: %T", err), err)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return stateledger.ErrUnsafe
	}
	return ctx.Err()
}

func contextCause(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return context.DeadlineExceeded
}

// Observation holds the selected directory and never follows child symlinks.
// It exposes no expected identity or grant, and closes without writing state.
type Observation struct {
	path string
	root *os.File
}

func OpenObservation(ctx context.Context, root string) (*Observation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, stateledger.ErrUnsafe
	}
	before, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, stateledger.ErrUnsafe
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), root)
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, stateledger.ErrUnsafe
	}
	observation := &Observation{path: root, root: file}
	if err := observation.current(ctx); err != nil {
		_ = file.Close()
		return nil, err
	}
	return observation, nil
}
func (o *Observation) Close() error { return o.root.Close() }
func (o *Observation) current(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	held, err := o.root.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(o.path)
	if err != nil {
		return err
	}
	if !os.SameFile(held, current) || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 {
		return stateledger.ErrUnsafe
	}
	return nil
}

func (o *Observation) parent(ctx context.Context, rel string) (int, string, error) {
	if err := o.current(ctx); err != nil {
		return -1, "", err
	}
	if !fs.ValidPath(rel) || rel == "." || bytes.ContainsAny([]byte(rel), "\\\x00") {
		return -1, "", stateledger.ErrUnsafe
	}
	fd, err := unix.Dup(int(o.root.Fd()))
	if err != nil {
		return -1, "", err
	}
	unix.CloseOnExec(fd)
	components := strings.Split(rel, "/")
	for _, component := range components[:len(components)-1] {
		if err := contextError(ctx); err != nil {
			_ = unix.Close(fd)
			return -1, "", err
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, "", err
		}
		fd = next
	}
	return fd, components[len(components)-1], nil
}

// ReadState observes regular bytes or a safe literal symlink; it never opens
// a symlink target. O_NONBLOCK plus fstat prevents FIFO open/read blocking.
func (o *Observation) ReadState(ctx context.Context, rel string) (ownership.State, error) {
	fd, name, err := o.parent(ctx, rel)
	if errors.Is(err, fs.ErrNotExist) {
		return ownership.State{}, nil
	}
	if err != nil {
		return ownership.State{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	var before unix.Stat_t
	if err := unix.Fstatat(fd, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ownership.State{}, nil
		}
		return ownership.State{}, err
	}
	if before.Mode&unix.S_IFMT == unix.S_IFLNK {
		buffer := make([]byte, 4097)
		n, err := unix.Readlinkat(fd, name, buffer)
		if err != nil || n >= len(buffer) {
			return ownership.State{}, stateledger.ErrUnsafe
		}
		target := string(buffer[:n])
		if err := ownership.ValidateRelativeSymlink(rel, target); err != nil {
			return ownership.State{}, err
		}
		var after unix.Stat_t
		if err := unix.Fstatat(fd, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return ownership.State{}, err
		}
		if !sameStat(before, after) {
			return ownership.State{}, stateledger.ErrUnsafe
		}
		if err := o.current(ctx); err != nil {
			return ownership.State{}, err
		}
		return ownership.State{Exists: true, Kind: ownership.KindSymlink, Data: buffer[:n]}, nil
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return ownership.State{}, stateledger.ErrUnsafe
	}
	child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ownership.State{}, err
	}
	f := os.NewFile(uintptr(child), name)
	defer func() { _ = f.Close() }()
	var held unix.Stat_t
	if err := unix.Fstat(child, &held); err != nil {
		return ownership.State{}, err
	}
	if before.Dev != held.Dev || before.Ino != held.Ino || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Size > 16<<20 {
		return ownership.State{}, stateledger.ErrUnsafe
	}
	var raw bytes.Buffer
	buffer := make([]byte, 64<<10)
	for {
		if err := contextError(ctx); err != nil {
			return ownership.State{}, err
		}
		n, readErr := f.Read(buffer)
		if raw.Len()+n > 16<<20 {
			return ownership.State{}, stateledger.ErrUnsafe
		}
		raw.Write(buffer[:n])
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return ownership.State{}, readErr
		}
	}
	var after, named unix.Stat_t
	if err := unix.Fstat(child, &after); err != nil {
		return ownership.State{}, err
	}
	if err := unix.Fstatat(fd, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return ownership.State{}, err
	}
	if !sameStat(held, after) || !sameStat(held, named) || int64(raw.Len()) != held.Size {
		return ownership.State{}, fmt.Errorf("%w: regular file changed while reading", stateledger.ErrUnsafe)
	}
	if err := o.current(ctx); err != nil {
		return ownership.State{}, err
	}
	return ownership.State{Exists: true, Data: raw.Bytes(), Kind: ownership.KindFile, Mode: fs.FileMode(held.Mode & 0o777)}, nil
}

// ReadVerified binds bytes and mode to exactly one canonical snapshot entry.
func (o *Observation) ReadVerified(ctx context.Context, snapshot *stateledger.Snapshot, rel string) ([]byte, error) {
	state, err := o.ReadState(ctx, rel)
	if err != nil {
		return nil, err
	}
	if !state.Exists || state.Kind != ownership.KindFile {
		return nil, fmt.Errorf("%w: selected entry is not regular", stateledger.ErrUnsafe)
	}
	sum := sha256.Sum256(state.Data)
	matches := 0
	for _, entry := range snapshot.Entries {
		if entry.Scope != "project" || entry.Path != rel {
			continue
		}
		if !entry.Exists || entry.Kind != "file" || entry.Mode != uint32(state.Mode.Perm()) || entry.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
			return nil, fmt.Errorf("%w: selected entry hash/mode mismatch", stateledger.ErrUnsafe)
		}
		matches++
	}
	if matches != 1 {
		return nil, fmt.Errorf("%w: selected entry count %d", stateledger.ErrUnsafe, matches)
	}
	return state.Data, nil
}

// Access time is a permitted consequence of a read. All other exported stat
// metadata (including ctime and mtime) remains part of coherence checking.
func sameStat(a, b unix.Stat_t) bool {
	project := func(stat unix.Stat_t) []byte {
		raw, _ := json.Marshal(stat)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		delete(fields, "Atim")
		delete(fields, "Atimespec")
		raw, _ = json.Marshal(fields)
		return raw
	}
	return bytes.Equal(project(a), project(b))
}
