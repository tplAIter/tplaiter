package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const managedPublicationKind = "native-managed-publication/v1"

// ManagedPublication is authenticated integrity evidence, not source admission
// or a writer permit. Every consumer must reconstruct the complete signed
// source/formatter projection before obtaining its separate opaque admission.
type ManagedPublication struct {
	APIVersion           string            `json:"apiVersion"`
	Kind                 string            `json:"kind"`
	ProjectID            string            `json:"projectID"`
	Root                 string            `json:"root"`
	ProfileBindingSHA256 string            `json:"profileBindingSHA256"`
	Input                json.RawMessage   `json:"input"`
	ImagesSHA256         string            `json:"imagesSHA256"`
	RegistryBefore       Bytes             `json:"registryBefore"`
	RegistryAfter        Bytes             `json:"registryAfter"`
	FormatterFrames      map[string]string `json:"formatterFrames"`
}
type ManagedPublicationRecord struct {
	runtime *trustload.Runtime
	value   ManagedPublication
	digest  string
	locator string
}

func validManagedPublication(v ManagedPublication) bool {
	if v.APIVersion != "tplaiter.dev/managed-publication/v1" || (v.Kind != "new" && v.Kind != "link") || v.ProjectID == "" || v.Root == "" || len(v.Input) == 0 || len(v.Input) > 1<<20 || !validManagedDigest(v.ProfileBindingSHA256) || !validManagedDigest(v.ImagesSHA256) || len(v.RegistryBefore) > 4<<20 || len(v.RegistryAfter) == 0 || len(v.RegistryAfter) > 4<<20 || len(v.FormatterFrames) == 0 || len(v.FormatterFrames) > 4096 {
		return false
	}
	for path, digest := range v.FormatterFrames {
		if !fs.ValidPath(path) || path == "." || !strings.HasSuffix(path, ".go") || !validManagedDigest(digest) {
			return false
		}
	}
	return true
}

func validManagedDigest(digest string) bool {
	if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	for _, ch := range digest[7:] {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func managedPublicationOwner(ctx context.Context, r *trustload.Runtime, digest string, create bool) (*Transaction, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || !validManagedDigest(digest) {
		return nil, ErrAuthentication
	}
	pc := r.ProjectContext()
	if r.TrustRuntime().CheckProjectIdentity(ctx, pc.RootPath, pc.ProjectID) != nil {
		return nil, ErrAuthentication
	}
	var key []byte
	var err error
	if create {
		key, err = runtimeKey(ctx, r, pc.ProjectID, true)
	} else {
		key, err = privateRead(filepath.Join(r.ScratchRoot(), "project-transaction-authority", "seal.key"), 32)
	}
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, ErrAuthentication
	}
	return &Transaction{runtime: r, key: key, dir: filepath.Join(r.ScratchRoot(), "managed-publication", strings.TrimPrefix(digest, "sha256:")), plan: immutable{Kind: managedPublicationKind}}, nil
}

func (v ManagedPublication) Digest() (string, error) {
	if !validManagedPublication(v) {
		return "", ErrAuthentication
	}
	return bootstrap.DomainDigest("tplaiter.dev/managed-publication/v1", v)
}

func StoreManagedPublication(ctx context.Context, r *trustload.Runtime, v ManagedPublication) (*ManagedPublicationRecord, error) {
	if r == nil || r.TrustRuntime() == nil {
		return nil, ErrAuthentication
	}
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	if err != nil {
		return nil, err
	}
	if v.ProjectID != r.ProjectContext().ProjectID || v.Root != r.ProjectContext().RootPath || v.ProfileBindingSHA256 != binding {
		return nil, ErrAuthentication
	}
	raw, err := canonicaljson.Canonical(v)
	if err != nil {
		return nil, err
	}
	var copy ManagedPublication
	if canonicaljson.DecodeStrict(raw, &copy) != nil {
		return nil, ErrAuthentication
	}
	digest, err := copy.Digest()
	if err != nil {
		return nil, err
	}
	locator, err := copy.Locator()
	if err != nil {
		return nil, err
	}
	tx, err := managedPublicationOwner(ctx, r, locator, true)
	if err != nil {
		return nil, err
	}
	defer clear(tx.key)
	lease, err := acquireLease(r, "managed-publication/"+locator)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	if err = privateDirectory(tx.dir); err != nil {
		return nil, err
	}
	err = tx.writeSigned("publication.json", copy, true)
	if errors.Is(err, os.ErrExist) {
		var old ManagedPublication
		err = tx.readSigned("publication.json", &old)
		if err == nil {
			oldDigest, e := old.Digest()
			if e != nil || oldDigest != digest {
				err = ErrAuthentication
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return &ManagedPublicationRecord{runtime: r, value: copy, digest: digest, locator: locator}, nil
}

// ReadManagedPublication does not create directories, authority, leases or
// effects. The private stored value cannot be constructed by a caller.
func ReadManagedPublication(ctx context.Context, r *trustload.Runtime, digest string) (*ManagedPublicationRecord, error) {
	tx, err := managedPublicationOwner(ctx, r, digest, false)
	if err != nil {
		return nil, err
	}
	defer clear(tx.key)
	var value ManagedPublication
	if err = tx.readSigned("publication.json", &value); err != nil {
		return nil, err
	}
	locator, err := value.Locator()
	if err != nil || locator != digest {
		return nil, ErrAuthentication
	}
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	if err != nil || value.ProjectID != r.ProjectContext().ProjectID || value.Root != r.ProjectContext().RootPath || value.ProfileBindingSHA256 != binding {
		return nil, ErrAuthentication
	}
	return &ManagedPublicationRecord{runtime: r, value: value, digest: mustManagedPublicationDigest(value), locator: locator}, nil
}

func (r *ManagedPublicationRecord) DataFor(owner *trustload.Runtime) (ManagedPublication, error) {
	if r == nil || owner == nil || r.runtime != owner {
		return ManagedPublication{}, ErrAuthentication
	}
	raw, err := canonicaljson.Canonical(r.value)
	if err != nil {
		return ManagedPublication{}, err
	}
	var copy ManagedPublication
	if canonicaljson.DecodeStrict(raw, &copy) != nil {
		return ManagedPublication{}, ErrAuthentication
	}
	return copy, nil
}

func (r *ManagedPublicationRecord) Digest() string {
	if r == nil {
		return ""
	}
	return r.digest
}

// Locator excludes only the complete-image digest, so a lineage image may
// reference this immutable semantic frame without a hash self-reference. The
// authenticated stored record separately covers the complete image digest.
func (v ManagedPublication) Locator() (string, error) {
	if !validManagedPublication(v) {
		return "", ErrAuthentication
	}
	return bootstrap.DomainDigest("tplaiter.dev/managed-publication-frame/v1", struct {
		APIVersion           string            `json:"apiVersion"`
		Kind                 string            `json:"kind"`
		ProjectID            string            `json:"projectID"`
		Root                 string            `json:"root"`
		ProfileBindingSHA256 string            `json:"profileBindingSHA256"`
		Input                json.RawMessage   `json:"input"`
		RegistryBefore       Bytes             `json:"registryBefore"`
		RegistryAfter        Bytes             `json:"registryAfter"`
		FormatterFrames      map[string]string `json:"formatterFrames"`
	}{"tplaiter.dev/managed-publication-frame/v1", v.Kind, v.ProjectID, v.Root, v.ProfileBindingSHA256, v.Input, v.RegistryBefore, v.RegistryAfter, v.FormatterFrames})
}

func mustManagedPublicationDigest(v ManagedPublication) string {
	digest, _ := v.Digest()
	return digest
}

func (r *ManagedPublicationRecord) Locator() string {
	if r == nil {
		return ""
	}
	return r.locator
}

// CommittedUpdate is a read-only historical receipt observation. It carries no
// lease, execution permit, durability certificate or mutation admission. Its
// material is available only to the same runtime after a fresh exact inspection.
type CommittedUpdate struct {
	runtime                             *trustload.Runtime
	home, id, planDigest, receiptDigest string
}

// ReadCommittedUpdate delegates phase, MAC, retained-image, source-reference,
// root, profile and inode validation to the existing diagnostic owner. No
// journal directories, authority, locks or effects are created here.
func ReadCommittedUpdate(ctx context.Context, r *trustload.Runtime, home, id string) (*CommittedUpdate, error) {
	inspection, err := InspectJournal(ctx, r, home, id)
	if err != nil {
		return nil, err
	}
	if inspection.Kind() != NativeUpdateKind || inspection.Status() != InspectionCommitted || !inspection.Sealed() || !inspection.Terminal() || len(inspection.Issues()) != 0 {
		return nil, ErrAuthentication
	}
	return &CommittedUpdate{runtime: r, home: home, id: id, planDigest: inspection.PlanDigest(), receiptDigest: inspection.ReceiptDigest()}, nil
}

// MaterialFor returns detached reconstruction data, never a Plan or admitted
// Transaction. Callers must still reconstruct their signed semantic carrier and
// compare its complete afterimages to the current managed control projection.
func (c *CommittedUpdate) MaterialFor(ctx context.Context, r *trustload.Runtime) (Material, error) {
	if c == nil || r == nil || c.runtime != r {
		return Material{}, ErrAuthentication
	}
	fresh, err := ReadCommittedUpdate(ctx, r, c.home, c.id)
	if err != nil {
		return Material{}, err
	}
	if fresh.planDigest != c.planDigest || fresh.receiptDigest != c.receiptDigest {
		return Material{}, ErrInspectionChanged
	}
	dir := journalDir(c.home, c.id)
	planRaw, err := privateRead(filepath.Join(dir, "plan.json"), 128<<20)
	if err != nil {
		return Material{}, err
	}
	stateRaw, err := privateRead(filepath.Join(dir, "state.json"), 128<<20)
	if err != nil {
		return Material{}, err
	}
	if evidencecas.Digest(planRaw) != c.planDigest || evidencecas.Digest(stateRaw) != c.receiptDigest {
		return Material{}, ErrInspectionChanged
	}
	key, err := privateRead(filepath.Join(r.ScratchRoot(), "project-transaction-authority", "seal.key"), 32)
	if err != nil || len(key) != 32 {
		clear(key)
		return Material{}, ErrAuthentication
	}
	defer clear(key)
	tx := &Transaction{runtime: r, key: key, dir: dir, plan: immutable{Kind: NativeUpdateKind}}
	if err := tx.readSigned("plan.json", &tx.plan); err != nil {
		return Material{}, err
	}
	if err := tx.readSigned("state.json", &tx.state); err != nil {
		return Material{}, err
	}
	if tx.plan.Kind != NativeUpdateKind || tx.plan.ID != c.id || tx.plan.Material.Home != c.home || tx.plan.Material.Root != r.ProjectContext().RootPath || tx.plan.Material.ProjectID != r.ProjectContext().ProjectID || !tx.plan.Material.Binding.Equal(r.TrustRuntime().Binding()) || tx.state.Kind != NativeUpdateKind || tx.state.ID != c.id || tx.state.Phase != "committed" || tx.state.Fingerprint != tx.plan.Material.Fingerprint {
		return Material{}, ErrAuthentication
	}
	var originalPlan, originalState envelope
	if canonicaljson.DecodeStrict(planRaw, &originalPlan) != nil || canonicaljson.DecodeStrict(stateRaw, &originalState) != nil {
		return Material{}, ErrAuthentication
	}
	actualPlan, err := canonicaljson.Canonical(tx.plan)
	if err != nil || !bytes.Equal(actualPlan, originalPlan.Payload) {
		return Material{}, ErrInspectionChanged
	}
	actualState, err := canonicaljson.Canonical(tx.state)
	if err != nil || !bytes.Equal(actualState, originalState.Payload) {
		return Material{}, ErrInspectionChanged
	}
	material, err := tx.CheckedMaterial()
	if err != nil {
		return Material{}, err
	}
	// Bind decoding to the already inspected exact bytes. A replacement between
	// either observation and the internal authenticated read cannot be accepted.
	for _, record := range []struct {
		name string
		raw  []byte
	}{{"plan.json", planRaw}, {"state.json", stateRaw}} {
		actual, err := privateRead(filepath.Join(dir, record.name), 128<<20)
		if err != nil || !bytes.Equal(actual, record.raw) {
			return Material{}, ErrInspectionChanged
		}
	}
	after, err := ReadCommittedUpdate(ctx, r, c.home, c.id)
	if err != nil {
		return Material{}, err
	}
	if after.planDigest != c.planDigest || after.receiptDigest != c.receiptDigest {
		return Material{}, ErrInspectionChanged
	}
	return material, nil
}
