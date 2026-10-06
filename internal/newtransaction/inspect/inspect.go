// Package inspect owns noncreating, closed New journal inspection. Its records
// are diagnostics, never source admission or a publication capability.
package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/naming"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/stateledger/ledgerpath"
)

const (
	Schema           = 1
	APIVersion       = "tplaiter.dev/new-transaction/v1"
	apiVersionFamily = "tplaiter.dev/new-transaction/"
	commitDomain     = "tplaiter.dev/new-transaction/commit/v1"
	stagingInfix     = ".tplaiter-new-"
)

var pendingMarkerRel = filepath.Join(naming.ProjectDir, ledgerpath.NewPendingMarker)
var (
	ErrNoActive           = errors.New("new transaction: no active transaction")
	ErrUnsafe             = errors.New("new transaction: unsafe journal")
	ErrFutureVersion      = errors.New("new transaction: future journal version")
	ErrMissingCAS         = errors.New("new transaction: journal CAS evidence is missing")
	ErrOwnershipUncertain = errors.New("new transaction: ownership uncertain; journal retained")
)

type Phase string

const (
	Prepared Phase = "prepared"
	// Publishing is retained as the Go API name for one release.  Its durable
	// v1 spelling is the normative SPEC-07 phase "committing".
	Publishing   Phase = "committing"
	Committed    Phase = "committed"
	HooksRunning Phase = "hooks_running"
	HooksFailed  Phase = "hooks_failed"
	Complete     Phase = "complete"
	Aborted      Phase = "aborted"
)

type HookEntry struct {
	Kind     string `json:"kind"`
	Command  string `json:"command"`
	Optional bool   `json:"optional,omitempty"`
	Digest   string `json:"digest"`
}
type HookProgress struct {
	Plan     []HookEntry `json:"plan,omitempty"`
	Next     int         `json:"next"`
	Failures []string    `json:"failures,omitempty"`
}
type Journal struct {
	// The exported fields below are the one-release Go compatibility view.
	// Journal.MarshalJSON writes only newJournalWire; decoding a legacy wire is
	// deliberately refused rather than accepting two meanings for apiVersion v1.
	APIVersion          string       `json:"-"`
	Schema              int          `json:"-"`
	ID                  string       `json:"-"`
	Phase               Phase        `json:"-"`
	Target              string       `json:"-"`
	Staging             string       `json:"-"`
	TargetExisted       bool         `json:"-"`
	TargetBeforeSHA     string       `json:"-"`
	TargetBeforeTreeSHA string       `json:"-"`
	TargetAfterSHA      string       `json:"-"`
	RegistryTarget      string       `json:"-"`
	RegistryBeforeSHA   string       `json:"-"`
	RegistryAfterSHA    string       `json:"-"`
	CommitRecordSHA256  *string      `json:"-"`
	completedDigests    []string     `json:"-"`
	Hooks               HookProgress `json:"-"`
	PendingMarker       string       `json:"-"`
	CreatedAt           time.Time    `json:"-"`
	UpdatedAt           time.Time    `json:"-"`
}

type casPair struct {
	PathDigest string  `json:"pathDigest"`
	BeforeCAS  *string `json:"beforeCAS"`
	AfterCAS   *string `json:"afterCAS"`
}

type registryCAS struct {
	BeforeCAS *string `json:"beforeCAS"`
	AfterCAS  *string `json:"afterCAS"`
}

type wireHooks struct {
	Status           string   `json:"status"`
	CompletedDigests []string `json:"completedDigests"`
}

// Manifest is the immutable payload addressed by target.afterCAS. It
// contains every recovery-only value which cannot fit the portable normative
// journal wire; no mutable sidecar is a recovery authority.
type Manifest struct {
	Schema             int                   `json:"schema"`
	Target             string                `json:"target"`
	PathDigest         string                `json:"pathDigest"`
	Staging            string                `json:"staging"`
	RegistryTarget     string                `json:"registryTarget,omitempty"`
	PendingMarker      string                `json:"pendingMarker"`
	CreatedAt          time.Time             `json:"createdAt"`
	TreeSHA256         string                `json:"treeSHA256"`
	BeforeTreeSHA      string                `json:"beforeTreeSHA"`
	HookPlan           []HookEntry           `json:"hookPlan"`
	SealedTree         string                `json:"sealedTreeSHA256,omitempty"`
	SealedReady        bool                  `json:"sealedReady,omitempty"`
	ManagedPublication *PublicationReference `json:"managedPublication,omitempty"`
}

type newJournalWire struct {
	APIVersion         string      `json:"apiVersion"`
	Kind               string      `json:"kind"`
	TransactionID      string      `json:"transactionId"`
	Phase              Phase       `json:"phase"`
	Target             casPair     `json:"target"`
	Registry           registryCAS `json:"registry"`
	CommitRecordSHA256 *string     `json:"commitRecordSHA256"`
	Hooks              wireHooks   `json:"hooks"`
}

func (j Journal) MarshalJSON() ([]byte, error) {
	completed := make([]string, 0, j.Hooks.Next)
	for i := 0; i < j.Hooks.Next && i < len(j.Hooks.Plan); i++ {
		completed = append(completed, j.Hooks.Plan[i].Digest)
	}
	status := "pending"
	if len(j.Hooks.Failures) > 0 {
		status = "failed"
	} else if j.Hooks.Next == len(j.Hooks.Plan) {
		status = "complete"
	}
	return json.Marshal(newJournalWire{
		APIVersion: APIVersion, Kind: "NewTransaction", TransactionID: j.ID, Phase: j.Phase,
		Target:             casPair{PathDigest: digest([]byte(j.Target)), BeforeCAS: nullableDigest(j.TargetBeforeTreeSHA), AfterCAS: nullableDigest(j.TargetAfterSHA)},
		Registry:           registryCAS{BeforeCAS: nullableDigest(j.RegistryBeforeSHA), AfterCAS: nullableDigest(j.RegistryAfterSHA)},
		CommitRecordSHA256: j.CommitRecordSHA256,
		Hooks:              wireHooks{Status: status, CompletedDigests: completed},
	})
}

func (j *Journal) UnmarshalJSON(data []byte) error {
	var wire newJournalWire
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return ErrUnsafe
	}
	if wire.APIVersion != APIVersion || wire.Kind != "NewTransaction" || wire.TransactionID == "" || !validDigest(wire.Target.PathDigest) {
		return ErrUnsafe
	}
	*j = Journal{
		APIVersion: wire.APIVersion, Schema: Schema, ID: wire.TransactionID, Phase: wire.Phase,
		TargetBeforeSHA: wire.Target.PathDigest, TargetBeforeTreeSHA: derefDigest(wire.Target.BeforeCAS), TargetAfterSHA: derefDigest(wire.Target.AfterCAS),
		RegistryBeforeSHA: derefDigest(wire.Registry.BeforeCAS), RegistryAfterSHA: derefDigest(wire.Registry.AfterCAS),
		CommitRecordSHA256: wire.CommitRecordSHA256, completedDigests: wire.Hooks.CompletedDigests,
	}
	return nil
}

type Record struct {
	home, dir   string
	j           Journal
	sealedTree  string
	sealedReady bool
	manifest    Manifest
}

func (r *Record) Journal() Journal   { return r.j }
func (r *Record) Manifest() Manifest { return r.manifest }
func (r *Record) Home() string       { return r.home }
func (r *Record) Directory() string  { return r.dir }

const (
	StatusActive     = "active"
	StatusComplete   = string(Complete)
	StatusAborted    = string(Aborted)
	StatusFuture     = "future"
	StatusMissingCAS = "missing-cas"
	StatusUnsafe     = "unsafe"
	// StatusOrphan is a transaction directory without a journal: a process
	// stopped before its first journal write, while the target was untouched.
	StatusOrphan = "orphan"
)

type TransactionStatus struct {
	ID, Status, Reason string
	UpdatedAt          time.Time
}

func Load(home, id string) (*Record, error) {
	var err error
	home, err = absClean(home)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, ErrNoActive
	}
	if !validID(id) {
		return nil, ErrUnsafe
	}
	dir := filepath.Join(home, "transactions", "new", "tx-"+id)
	if info, statErr := os.Lstat(dir); statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		if os.IsNotExist(statErr) {
			return nil, ErrNoActive
		}
		return nil, ErrUnsafe
	}
	journalPath := filepath.Join(dir, "active.json")
	info, statErr := os.Lstat(journalPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, ErrNoActive
		}
		return nil, statErr
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrUnsafe
	}
	data, err := os.ReadFile(journalPath)
	if os.IsNotExist(err) {
		return nil, ErrNoActive
	}
	if err != nil {
		return nil, err
	}
	if version := peekAPIVersion(data); version != APIVersion {
		if strings.HasPrefix(version, apiVersionFamily) {
			return nil, ErrFutureVersion
		}
		return nil, ErrUnsafe
	}
	var j Journal
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return nil, ErrUnsafe
	}
	manifest, manifestErr := loadRecoveryManifest(dir, j.TargetAfterSHA)
	if errors.Is(manifestErr, ErrMissingCAS) {
		return nil, ErrMissingCAS
	}
	if manifestErr != nil || manifest.PathDigest != j.TargetBeforeSHA {
		return nil, ErrUnsafe
	}
	j.Target, j.Staging, j.PendingMarker, j.CreatedAt, j.UpdatedAt, j.RegistryTarget = manifest.Target, manifest.Staging, manifest.PendingMarker, manifest.CreatedAt, manifest.CreatedAt, manifest.RegistryTarget
	j.TargetBeforeTreeSHA = manifest.BeforeTreeSHA
	j.Hooks = HookProgress{Plan: manifest.HookPlan, Next: len(j.completedDigests)}
	j.TargetBeforeSHA = ""
	if len(j.completedDigests) != j.Hooks.Next {
		return nil, ErrUnsafe
	}
	for i, value := range j.completedDigests {
		if i >= len(j.Hooks.Plan) || j.Hooks.Plan[i].Digest != value {
			return nil, ErrUnsafe
		}
	}
	if err := validateJournal(home, dir, id, j); err != nil {
		return nil, ErrUnsafe
	}
	tx := &Record{home: home, dir: dir, j: j, sealedTree: manifest.SealedTree, sealedReady: manifest.SealedReady, manifest: manifest}
	for _, reference := range []string{j.TargetBeforeTreeSHA, j.TargetAfterSHA, j.RegistryBeforeSHA, j.RegistryAfterSHA} {
		if reference == "" {
			continue
		}
		data, readErr := tx.readBlob(reference)
		if errors.Is(readErr, ErrMissingCAS) {
			return nil, ErrMissingCAS
		}
		if readErr != nil || digest(data) != reference {
			return nil, ErrUnsafe
		}
	}
	if (j.Phase == Committed || j.Phase == HooksRunning || j.Phase == HooksFailed) && (j.CommitRecordSHA256 == nil || *j.CommitRecordSHA256 != commitRecordDigest(j.TargetAfterSHA, j.RegistryAfterSHA)) {
		return nil, ErrUnsafe
	}
	return tx, nil
}

func nullableDigest(value string) *string {
	if value == "" {
		return nil
	}
	cp := value
	return &cp
}

func derefDigest(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func loadRecoveryManifest(dir, ref string) (Manifest, error) {
	if !validDigest(ref) {
		return Manifest{}, ErrUnsafe
	}
	data, err := readCASFile(filepath.Join(dir, "blobs", "sha256", casLeaf(ref)))
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, ErrMissingCAS
	}
	if err != nil || digest(data) != ref {
		return Manifest{}, ErrUnsafe
	}
	var manifest Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil || dec.Decode(&struct{}{}) != io.EOF || (manifest.Schema != Schema && manifest.Schema != 2 && manifest.Schema != 3) || !validDigest(manifest.PathDigest) || manifest.Target == "" || manifest.Staging == "" || manifest.PendingMarker != pendingMarkerRel || manifest.CreatedAt.IsZero() {
		return Manifest{}, ErrUnsafe
	}
	if (manifest.Schema == 2 || manifest.Schema == 3) != (manifest.ManagedPublication != nil) {
		return Manifest{}, ErrUnsafe
	}
	if manifest.ManagedPublication != nil && (manifest.ManagedPublication.APIVersion != map[int]string{2: "tplaiter.dev/managed-publication-reference/v1", 3: "tplaiter.dev/managed-publication-reference/v2"}[manifest.Schema] || !validDigest(manifest.ManagedPublication.FrameSHA256) || manifest.SealedTree == "" || len(manifest.HookPlan) != 0) {
		return Manifest{}, ErrUnsafe
	}
	for _, hook := range manifest.HookPlan {
		if hook.Kind != "shell" || hook.Command == "" || hook.Digest != hookDigest(hook) {
			return Manifest{}, ErrUnsafe
		}
	}
	if manifest.SealedTree != "" && (!validDigest(manifest.SealedTree) || manifest.TreeSHA256 != manifest.SealedTree || len(manifest.HookPlan) != 0) || manifest.SealedReady && manifest.SealedTree == "" {
		return Manifest{}, ErrUnsafe
	}
	return manifest, nil
}

func (t *Record) readBlob(name string) ([]byte, error) {
	if !validDigest(name) {
		return nil, ErrUnsafe
	}
	path := filepath.Join(t.dir, "blobs", "sha256", casLeaf(name))
	data, err := readCASFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrMissingCAS
	}
	if err != nil || digest(data) != name {
		return nil, ErrUnsafe
	}
	return data, nil
}

func readCASFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return nil, ErrUnsafe
	}
	if !singleLink(before) {
		return nil, ErrUnsafe
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrUnsafe
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return nil, ErrUnsafe
	}
	return data, nil
}

func validateJournal(home, dir, id string, j Journal) error {
	if j.APIVersion != APIVersion || j.Schema != Schema || j.ID != id || !validID(j.ID) ||
		j.Target == "" || j.Staging == "" || j.PendingMarker != pendingMarkerRel ||
		j.CreatedAt.IsZero() || j.UpdatedAt.IsZero() {
		return ErrUnsafe
	}
	for _, p := range []string{j.Target, j.Staging} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return ErrUnsafe
		}
	}
	if filepath.Dir(j.Target) != filepath.Dir(j.Staging) || filepath.Base(j.Staging) != "."+filepath.Base(j.Target)+stagingInfix+id {
		return ErrUnsafe
	}
	switch j.Phase {
	case Prepared, Aborted:
	case Publishing, Committed, HooksRunning, HooksFailed, Complete:
		if !validDigest(j.RegistryBeforeSHA) || !validDigest(j.RegistryAfterSHA) || j.RegistryTarget == "" || !filepath.IsAbs(j.RegistryTarget) || filepath.Clean(j.RegistryTarget) != j.RegistryTarget || filepath.Base(j.RegistryTarget) != "projects.yaml" {
			return ErrUnsafe
		}
	default:
		return ErrUnsafe
	}
	for _, h := range j.Hooks.Plan {
		if h.Kind != "shell" || h.Command == "" || h.Digest != hookDigest(h) {
			return ErrUnsafe
		}
	}
	if j.Hooks.Next < 0 || j.Hooks.Next > len(j.Hooks.Plan) {
		return ErrUnsafe
	}
	root := filepath.Join(home, "transactions", "new")
	if filepath.Dir(dir) != root || filepath.Base(dir) != "tx-"+id {
		return ErrUnsafe
	}
	return nil
}

func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

func casLeaf(reference string) string { return strings.TrimPrefix(reference, "sha256:") }

func commitRecordDigest(target, registry string) string {
	return digest([]byte(commitDomain + "\x00" + target + "\x00" + registry))
}

func snapshotTree(root string) ([]byte, error) {
	// All reads go through an os.Root, so a symlink swapped in during the walk
	// cannot redirect a read outside the tree.
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	var entries []string
	err = fs.WalkDir(r.FS(), ".", func(rel string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if rel == "." {
			return nil
		}
		// The tree wire is newline- and NUL-separated.
		if !fs.ValidPath(rel) || strings.ContainsAny(rel, "\n\x00") {
			return ErrUnsafe
		}
		if rel == filepath.ToSlash(pendingMarkerRel) {
			return nil
		}
		info, err := r.Lstat(rel)
		if err != nil {
			return err
		}
		kind := "file"
		content := ""
		switch {
		case info.IsDir():
			kind = "dir"
		case info.Mode()&os.ModeSymlink != 0:
			kind = "symlink"
			target, readErr := r.Readlink(rel)
			if readErr != nil {
				return readErr
			}
			if ownership.ValidateRelativeSymlink(rel, target) != nil {
				return ErrUnsafe
			}
			content = digest([]byte(target))
		case info.Mode().IsRegular():
			data, readErr := r.ReadFile(rel)
			if readErr != nil {
				return readErr
			}
			content = digest(data)
		default:
			return ErrUnsafe
		}
		entries = append(entries, rel+"\x00"+kind+"\x00"+fmt.Sprintf("%o", info.Mode().Perm())+"\x00"+content)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	return []byte(strings.Join(entries, "\n")), nil
}

func hookDigest(h HookEntry) string { return digest([]byte(h.Kind + "\x00" + h.Command)) }

func validID(v string) bool {
	if len(v) != 32 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func validDigest(v string) bool {
	if !strings.HasPrefix(v, "sha256:") || len(v) != len("sha256:")+64 {
		return false
	}
	hexValue := strings.TrimPrefix(v, "sha256:")
	if strings.ToLower(hexValue) != hexValue {
		return false
	}
	_, err := hex.DecodeString(hexValue)
	return err == nil
}

func absClean(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(p), nil
}

func peekAPIVersion(data []byte) string {
	var head struct {
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return ""
	}
	return head.APIVersion
}

func (t *Record) verifyTargetUnstaged() error {
	// A missing state directory means no marker; any other shape is checked
	// by transactionDir, which refuses symlinks and non-directories.
	if _, err := os.Lstat(filepath.Join(t.j.Target, naming.ProjectDir)); err == nil {
		pendingDir, err := transactionDir(t.j.Target, false)
		if err != nil {
			return err
		}
		marker := filepath.Join(pendingDir, filepath.Base(t.j.PendingMarker))
		if _, err := os.Lstat(marker); err == nil {
			return fmt.Errorf("%w: target already holds the pending marker", ErrUnsafe)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	snapshot, err := snapshotTree(t.j.Target)
	if err != nil {
		return err
	}
	if digest(snapshot) != t.j.TargetBeforeTreeSHA {
		return fmt.Errorf("%w: target differs from the journaled before image", ErrUnsafe)
	}
	return nil
}

func (t *Record) verifyPendingAt(root string) error {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrUnsafe
	}
	pendingDir, err := transactionDir(root, false)
	if err != nil {
		return err
	}
	path := filepath.Join(pendingDir, filepath.Base(t.j.PendingMarker))
	info, err = os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return ErrUnsafe
	}
	var marker struct {
		TransactionID string `json:"transactionID"`
		Phase         string `json:"phase"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&marker); err != nil || dec.Decode(&struct{}{}) != io.EOF || marker.TransactionID != t.j.ID || marker.Phase != "pending" {
		return ErrUnsafe
	}
	return nil
}

func statusForLoadError(err error) string {
	switch {
	case errors.Is(err, ErrFutureVersion):
		return StatusFuture
	case errors.Is(err, ErrMissingCAS):
		return StatusMissingCAS
	default:
		return StatusUnsafe
	}
}

func Inventory(home string) ([]TransactionStatus, error) {
	root := filepath.Join(home, "transactions", "new")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]TransactionStatus, 0)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "tx-") {
			continue
		}
		id := strings.TrimPrefix(e.Name(), "tx-")
		tx, loadErr := Load(home, id)
		if errors.Is(loadErr, ErrNoActive) && validID(id) {
			if info, statErr := e.Info(); statErr == nil && info.IsDir() {
				out = append(out, TransactionStatus{ID: id, Status: StatusOrphan, Reason: loadErr.Error(), UpdatedAt: info.ModTime().UTC()})
				continue
			}
		}
		if loadErr != nil {
			out = append(out, TransactionStatus{ID: id, Status: statusForLoadError(loadErr), Reason: loadErr.Error()})
			continue
		}
		status := string(tx.j.Phase)
		if tx.j.Phase == Prepared || tx.j.Phase == Publishing || tx.j.Phase == Committed || tx.j.Phase == HooksRunning || tx.j.Phase == HooksFailed {
			status = StatusActive
		}
		reason := ""
		if tx.sealedTree != "" && (tx.j.Phase == Prepared || tx.j.Phase == Publishing || tx.j.Phase == Committed) {
			var checkErr error
			if _, err := os.Lstat(tx.j.Staging); err == nil {
				if tx.sealedReady {
					checkErr = tx.verifySealedTree(tx.j.Staging)
				} else {
					checkErr = tx.verifySealedAbort()
				}
			} else if tx.j.Phase == Prepared {
				checkErr = tx.verifyTargetUnstaged()
			} else {
				checkErr = tx.verifySealedTree(tx.j.Target)
			}
			if checkErr != nil {
				status, reason = "ownership_uncertain", ErrOwnershipUncertain.Error()
			}
		}
		// The journal file time is when the record last changed phase; for a
		// terminal record that is when it became terminal.
		updated := tx.j.UpdatedAt
		if info, statErr := os.Lstat(filepath.Join(tx.dir, "active.json")); statErr == nil {
			updated = info.ModTime().UTC()
		}
		out = append(out, TransactionStatus{ID: id, Status: status, Reason: reason, UpdatedAt: updated})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (t *Record) verifySealedTree(root string) error {
	raw, err := snapshotTree(root)
	if err != nil || digest(raw) != t.sealedTree {
		return fmt.Errorf("%w: sealed afterimage differs", ErrOwnershipUncertain)
	}
	return nil
}

func (t *Record) verifySealedAbort() error {
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

func transactionDir(root string, _ bool) (string, error) {
	dir := filepath.Join(root, naming.ProjectDir)
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", ErrUnsafe
	}
	return dir, nil
}

// LoadManifest and ReadCASFile use the same closed decoder as Load/Inventory.
func LoadManifest(dir, ref string) (Manifest, error)        { return loadRecoveryManifest(dir, ref) }
func ReadCASFile(path string) ([]byte, error)               { return readCASFile(path) }
func ValidateJournal(home, dir, id string, j Journal) error { return validateJournal(home, dir, id, j) }
func SnapshotTree(root string) ([]byte, error)              { return snapshotTree(root) }
func StatusForLoadError(err error) string                   { return statusForLoadError(err) }

// PublicationReference is closed locator data. It carries no admission.
type PublicationReference struct {
	APIVersion  string `json:"apiVersion"`
	FrameSHA256 string `json:"frameSHA256"`
}
