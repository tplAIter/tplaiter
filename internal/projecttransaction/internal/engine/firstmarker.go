package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const NativeLinkKind = "NativeLinkTransaction"

// Reuse the existing ledger reader's canonical registry-image namespace.
const firstMarkerRegistrySlot = "000000"

// FirstMarker is restricted to the concrete link adapter by Go's internal boundary.
// It publishes only managed state; no user pathname is ever a mutation target.
type FirstMarker struct {
	tx            *Transaction
	state         firstMarkerState
	fault         func(string) error // package-private process fault seam; never wire/production input
	sealedState   []byte
	sealedStateID Identity
	sealedPlan    []byte
	sealedPlanID  Identity
}
type firstMarkerState struct {
	APIVersion    string          `json:"apiVersion"`
	Kind          string          `json:"kind"`
	ID            string          `json:"id"`
	Fingerprint   string          `json:"fingerprint"`
	Phase         string          `json:"phase"`
	Parent        Identity        `json:"parent"`
	Stage         Identity        `json:"stage"`
	RegistryAfter Identity        `json:"registryAfter"`
	Receipt       Identity        `json:"receipt"`
	Plan          Identity        `json:"plan"`
	Inventory     map[string]File `json:"inventory"`
	Missing       []string        `json:"missing"`
}

func (f *FirstMarker) ID() string {
	if !f.tx.durable {
		return ""
	}
	return f.tx.plan.ID
}
func (f *FirstMarker) Release() { f.tx.Release() }
func (f *FirstMarker) Material() (Material, error) {
	if err := f.checkSealedPlan(); err != nil {
		return Material{}, err
	}
	if err := f.checkSealedState(); err != nil {
		return Material{}, err
	}
	return f.tx.CheckedMaterial()
}
func (f *FirstMarker) stage() string {
	return filepath.Join(filepath.Dir(f.tx.plan.Material.Root), "."+filepath.Base(f.tx.plan.Material.Root)+"-tplaiter-link-"+f.tx.plan.ID)
}
func (f *FirstMarker) target() string { return filepath.Join(f.tx.plan.Material.Root, ".tplaiter") }

// A live handle may advance only the exact receipt it last authenticated.
// Initial state creation is exclusive; later writes retain the existing engine's
// durable replacement semantics and recheck the sealed receipt directory.
func (f *FirstMarker) save() error {
	if err := f.checkSealedPlan(); err != nil {
		return err
	}
	if err := f.checkUsers(); err != nil {
		return err
	}
	if err := f.checkReceipt(); err != nil {
		return err
	}
	name := filepath.Join(f.tx.dir, "state.json")
	if f.sealedState != nil {
		if err := f.checkSealedState(); err != nil {
			return err
		}
	}
	if err := f.tx.writeSigned("state.json", f.state, f.sealedState == nil); err != nil {
		return err
	}
	if err := f.checkReceipt(); err != nil {
		return err
	}
	want, err := canonicaljson.Canonical(f.state)
	if err != nil {
		return err
	}
	var actual firstMarkerState
	if err = f.tx.readSigned("state.json", &actual); err != nil {
		return err
	}
	raw, err := canonicaljson.Canonical(actual)
	if err != nil || !bytes.Equal(raw, want) {
		return ErrAuthentication
	}
	i, err := confinedLstat(name)
	if err != nil {
		return err
	}
	f.sealedState, f.sealedStateID = want, fileID(i)
	return nil
}
func (f *FirstMarker) checkSealedState() error {
	if err := f.checkReceipt(); err != nil {
		return err
	}
	i, err := confinedLstat(filepath.Join(f.tx.dir, "state.json"))
	if err != nil || fileID(i) != f.sealedStateID {
		return ErrConflict
	}
	var actual firstMarkerState
	if err := f.tx.readSigned("state.json", &actual); err != nil {
		return err
	}
	raw, err := canonicaljson.Canonical(actual)
	if err != nil || !bytes.Equal(raw, f.sealedState) {
		return ErrAuthentication
	}
	return nil
}

// The signed immutable record is recovery authority, even for a live handle.
// Its owned inode is sealed into state.json so a cold opener also rejects an
// equal-byte replacement. Retention reads the freshly persisted record, never
// infers persistence from the in-memory material.
func (f *FirstMarker) retainPlan() error {
	want, err := f.tx.signedBytes("plan.json", f.tx.plan)
	if err != nil {
		return err
	}
	raw, err := f.planBytes(f.state.Plan)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, want) {
		return ErrAuthentication
	}
	f.sealedPlan, f.sealedPlanID = raw, f.state.Plan
	return f.checkSealedPlan()
}
func (f *FirstMarker) checkSealedPlan() error {
	if len(f.sealedPlan) == 0 || f.sealedPlanID.Inode == 0 {
		return ErrAuthentication
	}
	raw, err := f.planBytes(f.sealedPlanID)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, f.sealedPlan) {
		return ErrAuthentication
	}
	return nil
}
func (f *FirstMarker) planBytes(id Identity) ([]byte, error) {
	if err := f.checkReceipt(); err != nil {
		return nil, err
	}
	name := filepath.Join(f.tx.dir, "plan.json")
	root, base, err := confinedParent(name)
	if err != nil {
		return nil, ErrConflict
	}
	defer root.Close()
	valid := func(info os.FileInfo) bool {
		return info != nil && id.Inode != 0 && fileID(info) == id && info.Mode() == 0o600 && singleLink(info) && info.Size() <= 128<<20
	}
	info, err := root.Lstat(base)
	if err != nil || !valid(info) {
		return nil, ErrConflict
	}
	fd, err := root.OpenFile(base, readNoFollow(), 0)
	if err != nil {
		return nil, ErrConflict
	}
	defer fd.Close()
	opened, err := fd.Stat()
	if err != nil || !valid(opened) {
		return nil, ErrConflict
	}
	raw, err := io.ReadAll(io.LimitReader(fd, (128<<20)+1))
	if err != nil || len(raw) > 128<<20 {
		return nil, ErrAuthentication
	}
	after, err := root.Lstat(base)
	if err != nil || !valid(after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return nil, ErrConflict
	}
	if err = checkStorageParent(root, name); err != nil {
		return nil, err
	}
	if err = f.checkReceipt(); err != nil {
		return nil, err
	}
	return raw, nil
}

// Observe full permission/special bits at every user guard. Directory special
// bits are retained from Prepare; regular-file special modes always refuse.
// This helper is first-marker-only: shared update file semantics are untouched.
func firstMarkerCheckUser(name string, want File) error {
	root, base, err := confinedParent(name)
	if err != nil {
		return ErrConflict
	}
	defer root.Close()
	const bits = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	valid := func(info os.FileInfo) bool {
		if info == nil || fileID(info) != (Identity{want.Device, want.Inode}) || info.Mode()&bits != os.FileMode(want.Mode) || info.IsDir() != want.Directory {
			return false
		}
		if want.Directory {
			return info.IsDir()
		}
		return info.Mode().IsRegular() && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && singleLink(info)
	}
	info, err := root.Lstat(base)
	if err != nil || !valid(info) {
		return ErrConflict
	}
	if !want.Directory {
		fd, err := root.OpenFile(base, readNoFollow(), 0)
		if err != nil {
			return ErrConflict
		}
		defer fd.Close()
		opened, err := fd.Stat()
		if err != nil || !valid(opened) {
			return ErrConflict
		}
		raw, err := io.ReadAll(io.LimitReader(fd, (16<<20)+1))
		if err != nil || !bytes.Equal(raw, want.Data) {
			return ErrConflict
		}
		closed, err := fd.Stat()
		if err != nil || !valid(closed) {
			return ErrConflict
		}
	}
	after, err := root.Lstat(base)
	if err != nil || !valid(after) {
		return ErrConflict
	}
	return checkStorageParent(root, name)
}

func (f *FirstMarker) inject(point string) error {
	if f.fault != nil {
		return f.fault(point)
	}
	return nil
}

func AcquireFirstMarker(ctx context.Context, r *trustload.Runtime, m Material, missing []string) (*FirstMarker, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || m.Root != r.ProjectContext().RootPath || m.ProjectID != r.ProjectContext().ProjectID || !m.Binding.Equal(r.TrustRuntime().Binding()) || m.Registry == nil || !filepath.IsAbs(m.Home) || filepath.Clean(m.Home) != m.Home || overlaps(m.Root, m.Home) {
		return nil, ErrAuthentication
	}
	key, err := runtimeKey(ctx, r, m.ProjectID, true)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 16)
	if _, err = rand.Read(raw); err != nil {
		clear(key)
		return nil, err
	}
	id := hex.EncodeToString(raw)
	lease, err := acquireLease(r, m.Root)
	if err != nil {
		clear(key)
		return nil, err
	}
	tx := &Transaction{runtime: r, key: key, lease: lease, dir: journalDir(m.Home, id), plan: immutable{APIVersion: APIVersion, Kind: NativeLinkKind, ID: id, Material: m}}
	f := &FirstMarker{tx: tx, state: firstMarkerState{APIVersion: APIVersion, Kind: NativeLinkKind, ID: id, Fingerprint: m.Fingerprint, Phase: "initializing", Inventory: map[string]File{}, Missing: append([]string{}, missing...)}}
	fail := func(e error) (*FirstMarker, error) { f.Release(); return nil, e }
	for _, b := range []struct {
		name string
		id   *Identity
	}{{m.Root, &tx.plan.RootIdentity}, {m.Home, &tx.plan.HomeIdentity}, {filepath.Dir(m.Root), &f.state.Parent}} {
		i, e := confinedLstat(b.name)
		if e != nil || !i.IsDir() {
			return fail(ErrConflict)
		}
		*b.id = fileID(i)
	}
	if err = f.auth(ctx); err != nil {
		return fail(err)
	}
	if err = f.acquireLocks(); err != nil {
		return fail(err)
	}
	if err = f.auth(ctx); err != nil {
		return fail(err)
	}
	if err = tx.rejectActiveJournals(); err != nil {
		return fail(err)
	}
	if err = f.checkBefore(); err != nil {
		return fail(err)
	}
	return f, nil
}

// Seal requires the concrete adapter's freshly reconstructed post-lease material.
func (f *FirstMarker) Seal(ctx context.Context, m Material, missing []string) error {
	var err error
	if err = f.auth(ctx); err != nil {
		return err
	}
	a, _ := canonicaljson.Canonical(f.tx.plan.Material)
	b, _ := canonicaljson.Canonical(m)
	if !bytes.Equal(a, b) || !reflect.DeepEqual(missing, f.state.Missing) {
		return ErrConflict
	}
	if err = f.checkBefore(); err != nil {
		return err
	}
	if err = privateDirectory(filepath.Dir(f.tx.dir)); err != nil {
		return err
	}
	if err = confinedMkdir(f.tx.dir, 0o700); err != nil {
		return err
	}
	i, err := confinedLstat(f.tx.dir)
	if err != nil {
		return err
	}
	f.state.Receipt = fileID(i)
	if err = f.tx.writeSigned("plan.json", f.tx.plan, true); err != nil {
		return err
	}
	f.tx.durable = true
	planInfo, err := confinedLstat(filepath.Join(f.tx.dir, "plan.json"))
	if err != nil {
		return err
	}
	f.state.Plan = fileID(planInfo)
	if err = f.retainPlan(); err != nil {
		return err
	}
	if err = f.save(); err != nil {
		return err
	}
	if err = f.hit(ctx, "journal"); err != nil {
		return err
	}
	return f.prepare(ctx)
}

// Preparing resumes only a sealed prefix of exact owned inode images. Any
// extra/unrecorded entry is ambiguous and preserved, even if its bytes match.
func (f *FirstMarker) prepare(ctx context.Context) error {
	var err error
	if err = f.auth(ctx); err != nil {
		return err
	}
	if err = f.checkUsers(); err != nil {
		return err
	}
	m := f.tx.plan.Material
	if f.state.Stage.Inode == 0 {
		if _, err = confinedLstat(f.stage()); !errors.Is(err, fs.ErrNotExist) {
			return ErrConflict
		}
		if err = confinedMkdir(f.stage(), 0o700); err != nil {
			return err
		}
		info, e := confinedLstat(f.stage())
		if e != nil {
			return e
		}
		f.state.Stage = fileID(info)
		f.state.Inventory = map[string]File{".": {Data: Bytes{}, Mode: 0o700, Directory: true, Device: f.state.Stage.Device, Inode: f.state.Stage.Inode}}
		f.state.Phase = "preparing"
		if err = f.save(); err != nil {
			return err
		}
		if err = f.hit(ctx, "stage-created"); err != nil {
			return err
		}
	}
	if err = f.checkManaged(ctx, f.stage()); err != nil {
		return err
	}
	names := make([]string, 0, len(m.After))
	for name := range m.After {
		if !strings.HasPrefix(name, ".tplaiter/") || !fs.ValidPath(name) || m.After[name].Directory {
			return ErrAuthentication
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err = ctx.Err(); err != nil {
			return err
		}
		rel := strings.TrimPrefix(name, ".tplaiter/")
		prefix := ""
		for _, part := range strings.Split(filepath.ToSlash(filepath.Dir(rel)), "/") {
			if part == "." {
				continue
			}
			if prefix == "" {
				prefix = part
			} else {
				prefix += "/" + part
			}
			if _, ok := f.state.Inventory[prefix]; ok {
				continue
			}
			if err = f.checkManaged(ctx, f.stage()); err != nil {
				return err
			}
			if err = f.auth(ctx); err != nil {
				return err
			}
			if err = f.checkUsers(); err != nil {
				return err
			}
			if err = confinedMkdir(filepath.Join(f.stage(), prefix), 0o700); err != nil {
				return err
			}
			info, e := confinedLstat(filepath.Join(f.stage(), prefix))
			if e != nil {
				return e
			}
			id := fileID(info)
			f.state.Inventory[prefix] = File{Data: Bytes{}, Mode: 0o700, Directory: true, Device: id.Device, Inode: id.Inode}
			if err = f.save(); err != nil {
				return err
			}
		}
		if old, ok := f.state.Inventory[rel]; ok {
			if !sameFile(old, m.After[name]) {
				return ErrConflict
			}
			continue
		}
		if err = f.checkManaged(ctx, f.stage()); err != nil {
			return err
		}
		if err = f.auth(ctx); err != nil {
			return err
		}
		if err = f.checkUsers(); err != nil {
			return err
		}
		image, e := firstMarkerWrite(filepath.Join(f.stage(), rel), m.After[name])
		if e != nil {
			return e
		}
		f.state.Inventory[rel] = image
		if err = f.save(); err != nil {
			return err
		}
	}
	if err = f.checkManaged(ctx, f.stage()); err != nil {
		return err
	}
	if f.state.RegistryAfter.Inode == 0 {
		if err = f.auth(ctx); err != nil {
			return err
		}
		if err = f.checkUsers(); err != nil {
			return err
		}
		image, e := firstMarkerWrite(filepath.Join(f.tx.dir, firstMarkerRegistrySlot), m.Registry.After)
		if e != nil {
			return e
		}
		f.state.RegistryAfter = Identity{image.Device, image.Inode}
		if err = f.save(); err != nil {
			return err
		}
	} else if err = firstRegistryCheck(filepath.Join(f.tx.dir, firstMarkerRegistrySlot), m.Registry.After, f.state.RegistryAfter); err != nil {
		return err
	}
	f.state.Phase = "prepared"
	if err = f.save(); err != nil {
		return err
	}
	return f.hit(ctx, "prepared")
}
func firstMarkerWrite(name string, image File) (File, error) {
	root, base, err := confinedParent(name)
	if err != nil {
		return File{}, err
	}
	defer root.Close()
	f, err := root.OpenFile(base, exclusiveFlags(), os.FileMode(image.Mode))
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	if _, err = f.Write(image.Data); err != nil {
		return File{}, err
	}
	if err = f.Chmod(os.FileMode(image.Mode)); err != nil {
		return File{}, err
	}
	if err = f.Sync(); err != nil {
		return File{}, err
	}
	owned, err := f.Stat()
	if err != nil {
		return File{}, err
	}
	actual, err := root.Lstat(base)
	if err != nil || !os.SameFile(owned, actual) || !singleLink(actual) {
		return File{}, ErrConflict
	}
	if err = checkStorageParent(root, name); err != nil {
		return File{}, err
	}
	if err = syncStorageRoot(root); err != nil {
		return File{}, err
	}
	id := fileID(owned)
	image.Device, image.Inode = id.Device, id.Inode
	return image, nil
}
func (f *FirstMarker) hit(ctx context.Context, point string) error {
	if err := f.inject(point); err != nil {
		return err
	}
	return ctx.Err()
}

func OpenFirstMarker(ctx context.Context, r *trustload.Runtime, home, id string) (*FirstMarker, error) {
	f, err := loadFirstMarker(ctx, r, home, id, false)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*FirstMarker, error) { f.Release(); return nil, e }
	lease, err := acquireLease(r, f.tx.plan.Material.Root)
	if err != nil {
		return fail(err)
	}
	f.tx.lease = lease
	if err = f.acquireLocks(); err != nil {
		return fail(err)
	}
	if err = f.auth(ctx); err != nil {
		return fail(err)
	}
	return f, nil
}
func loadFirstMarker(ctx context.Context, r *trustload.Runtime, home, id string, readonly bool) (*FirstMarker, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || !inspectionID(id) || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return nil, ErrAuthentication
	}
	var key []byte
	var err error
	if readonly {
		key, err = privateRead(filepath.Join(r.ScratchRoot(), "project-transaction-authority", "seal.key"), 32)
	} else {
		key, err = runtimeKey(ctx, r, r.ProjectContext().ProjectID, false)
	}
	if err != nil || len(key) != 32 {
		return nil, ErrAuthentication
	}
	tx := &Transaction{runtime: r, key: key, dir: journalDir(home, id), plan: immutable{Kind: NativeLinkKind}}
	f := &FirstMarker{tx: tx}
	fail := func(e error) (*FirstMarker, error) { f.Release(); return nil, e }
	if err = tx.readSigned("plan.json", &tx.plan); err != nil {
		return fail(err)
	}
	if err = tx.readSigned("state.json", &f.state); err != nil {
		return fail(err)
	}
	p, s := tx.plan, f.state
	if p.APIVersion != APIVersion || p.Kind != NativeLinkKind || p.ID != id || s.APIVersion != APIVersion || s.Kind != NativeLinkKind || s.ID != id || s.Fingerprint != p.Material.Fingerprint || p.Material.Home != home || p.Material.Registry == nil {
		return fail(ErrAuthentication)
	}
	if err = f.retainPlan(); err != nil {
		return fail(err)
	}
	if err = f.auth(ctx); err != nil {
		return fail(err)
	}
	if err = f.checkReceipt(); err != nil {
		return fail(err)
	}
	i, err := confinedLstat(filepath.Join(tx.dir, "state.json"))
	if err != nil {
		return fail(err)
	}
	f.sealedState, err = canonicaljson.Canonical(f.state)
	if err != nil {
		return fail(err)
	}
	f.sealedStateID = fileID(i)
	if err = f.checkSealedState(); err != nil {
		return fail(err)
	}
	tx.durable = true
	return f, nil
}
func (f *FirstMarker) auth(ctx context.Context) error {
	var err error
	if err = f.tx.authenticate(ctx); err != nil {
		return err
	}
	info, err := confinedLstat(filepath.Dir(f.tx.plan.Material.Root))
	if err != nil || fileID(info) != f.state.Parent {
		return ErrConflict
	}
	if f.sealedPlan != nil {
		if err = f.checkSealedPlan(); err != nil {
			return err
		}
	}
	if f.sealedState != nil {
		return f.checkSealedState()
	}
	return nil
}
func (f *FirstMarker) checkReceipt() error {
	i, e := confinedLstat(f.tx.dir)
	if e != nil || fileID(i) != f.state.Receipt {
		return ErrConflict
	}
	return nil
}
func (f *FirstMarker) checkBefore() error {
	m := f.tx.plan.Material
	for name, b := range m.Before {
		if !fs.ValidPath(name) || strings.HasPrefix(name, ".tplaiter/") {
			return ErrAuthentication
		}
		if err := firstMarkerCheckUser(filepath.Join(m.Root, name), b); err != nil {
			return err
		}
	}
	for _, name := range f.state.Missing {
		if !fs.ValidPath(name) || name == "." {
			return ErrAuthentication
		}
		if _, err := confinedLstat(filepath.Join(m.Root, name)); !errors.Is(err, fs.ErrNotExist) {
			return ErrConflict
		}
	}
	for _, name := range []string{".tplaiter", ".tplater"} {
		if _, err := confinedLstat(filepath.Join(m.Root, name)); !errors.Is(err, fs.ErrNotExist) {
			return ErrConflict
		}
	}
	return firstRegistryCheck(filepath.Join(m.Home, "projects.yaml"), m.Registry.Before, Identity{m.Registry.Before.Device, m.Registry.Before.Inode})
}
func (f *FirstMarker) checkUsers() error {
	if _, e := confinedLstat(filepath.Join(f.tx.plan.Material.Root, ".tplater")); !errors.Is(e, fs.ErrNotExist) {
		return ErrConflict
	}
	for name, b := range f.tx.plan.Material.Before {
		if err := firstMarkerCheckUser(filepath.Join(f.tx.plan.Material.Root, name), b); err != nil {
			return err
		}
	}
	for _, name := range f.state.Missing {
		if _, err := confinedLstat(filepath.Join(f.tx.plan.Material.Root, name)); !errors.Is(err, fs.ErrNotExist) {
			return ErrConflict
		}
	}
	return nil
}
func firstRegistryCheck(name string, want File, id Identity) error {
	if id.Inode == 0 {
		if _, e := confinedLstat(name); !errors.Is(e, fs.ErrNotExist) {
			return ErrConflict
		}
		return nil
	}
	return checkPath(name, want, id)
}
func (f *FirstMarker) managedLocation() (string, error) {
	target, tErr := confinedLstat(f.target())
	stage, sErr := confinedLstat(f.stage())
	if tErr == nil {
		if fileID(target) != f.state.Stage || !errors.Is(sErr, fs.ErrNotExist) {
			return "", ErrConflict
		}
		return f.target(), nil
	}
	if !errors.Is(tErr, fs.ErrNotExist) || sErr != nil || fileID(stage) != f.state.Stage {
		return "", ErrConflict
	}
	return f.stage(), nil
}
func (f *FirstMarker) checkManaged(ctx context.Context, where string) error {
	got, e := firstMarkerSnapshot(ctx, where)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(got, f.state.Inventory) {
		return ErrConflict
	}
	return nil
}
func (f *FirstMarker) Commit(ctx context.Context) error {
	var err error
	if err = f.auth(ctx); err != nil {
		return err
	}
	if err = f.checkReceipt(); err != nil {
		return err
	}
	if f.state.Phase == "committed" {
		info, e := confinedLstat(f.target())
		if e != nil || fileID(info) != f.state.Stage {
			return ErrConflict
		}
		marker, e := inspectionMarker(f.tx.plan.Material.Root)
		if e != nil {
			return e
		}
		if e = f.tx.runtime.TrustRuntime().CheckProjectIdentity(ctx, f.tx.plan.Material.Root, marker); e != nil {
			return e
		}
		return syncReceipt(filepath.Join(f.tx.dir, "state.json"))
	}
	if f.state.Phase == "initializing" || f.state.Phase == "preparing" {
		if err = f.checkBefore(); err != nil {
			return err
		}
		if err = f.prepare(ctx); err != nil {
			return err
		}
	}
	if f.state.Phase != "prepared" && f.state.Phase != "publishing" && f.state.Phase != "state-published" && f.state.Phase != "registry-published" {
		return ErrPreparingContinue
	}
	if err = f.checkUsers(); err != nil {
		return err
	}
	where, err := f.managedLocation()
	if err != nil {
		return err
	}
	if err = f.checkManaged(ctx, where); err != nil {
		return err
	}
	m := f.tx.plan.Material
	registry := filepath.Join(m.Home, "projects.yaml")
	slot := filepath.Join(f.tx.dir, firstMarkerRegistrySlot)
	// Reconcile both exact inodes after a killed exclusive rename/exchange.
	registryPublished := firstRegistryCheck(registry, m.Registry.After, f.state.RegistryAfter) == nil
	if registryPublished {
		if where != f.target() {
			return ErrConflict
		}
		if err = firstRegistryCheck(slot, m.Registry.Before, Identity{m.Registry.Before.Device, m.Registry.Before.Inode}); err != nil {
			return err
		}
	} else {
		if err = firstRegistryCheck(registry, m.Registry.Before, Identity{m.Registry.Before.Device, m.Registry.Before.Inode}); err != nil {
			return err
		}
		if err = firstRegistryCheck(slot, m.Registry.After, f.state.RegistryAfter); err != nil {
			return err
		}
	}
	f.state.Phase = "publishing"
	if err = f.save(); err != nil {
		return err
	}
	if where == f.stage() {
		if err = f.publishState(false); err != nil {
			return err
		}
		if err = f.hit(ctx, "state-renamed"); err != nil {
			return err
		}
	}
	f.state.Phase = "state-published"
	if err = f.save(); err != nil {
		return err
	}
	if err = f.checkManaged(ctx, f.target()); err != nil {
		return err
	}
	if err = f.auth(ctx); err != nil {
		return err
	}
	if err = f.checkUsers(); err != nil {
		return err
	}
	if !registryPublished {
		if err = f.publishRegistry(false); err != nil {
			return err
		}
		if err = f.hit(ctx, "registry-renamed"); err != nil {
			return err
		}
	}
	f.state.Phase = "registry-published"
	if err = f.save(); err != nil {
		return err
	}
	if err = f.checkManaged(ctx, f.target()); err != nil {
		return err
	}
	if err = firstRegistryCheck(registry, m.Registry.After, f.state.RegistryAfter); err != nil {
		return err
	}
	f.state.Phase = "committed"
	if err = f.save(); err != nil {
		return err
	}
	return f.hit(ctx, "committed")
}
func (f *FirstMarker) Abort(ctx context.Context) error {
	var err error
	if err = f.auth(ctx); err != nil {
		return err
	}
	if err = f.checkReceipt(); err != nil {
		return err
	}
	if f.state.Phase == "committed" {
		return ErrAuthentication
	}
	if f.state.Phase == "rolled-back" {
		return syncReceipt(filepath.Join(f.tx.dir, "state.json"))
	}
	if f.state.Phase == "initializing" || f.state.Phase == "preparing" {
		if err = f.checkBefore(); err != nil {
			return err
		}
		if f.state.Stage.Inode == 0 {
			if _, err = confinedLstat(f.stage()); !errors.Is(err, fs.ErrNotExist) {
				return ErrConflict
			}
		} else if err = f.checkManaged(ctx, f.stage()); err != nil {
			return err
		}
		slot := filepath.Join(f.tx.dir, firstMarkerRegistrySlot)
		if f.state.RegistryAfter.Inode == 0 {
			if _, e := confinedLstat(slot); !errors.Is(e, fs.ErrNotExist) {
				return ErrConflict
			}
		} else if e := firstRegistryCheck(slot, f.tx.plan.Material.Registry.After, f.state.RegistryAfter); e != nil {
			return e
		}
		f.state.Phase = "rolled-back"
		return f.save()
	}
	if err = f.checkUsers(); err != nil {
		return err
	}
	where, err := f.managedLocation()
	if err != nil {
		return err
	}
	if err = f.checkManaged(ctx, where); err != nil {
		return err
	}
	m := f.tx.plan.Material
	registry := filepath.Join(m.Home, "projects.yaml")
	slot := filepath.Join(f.tx.dir, firstMarkerRegistrySlot)
	after := firstRegistryCheck(registry, m.Registry.After, f.state.RegistryAfter) == nil
	if after {
		if where != f.target() {
			return ErrConflict
		}
		if err = firstRegistryCheck(slot, m.Registry.Before, Identity{m.Registry.Before.Device, m.Registry.Before.Inode}); err != nil {
			return err
		}
	} else {
		if err = firstRegistryCheck(registry, m.Registry.Before, Identity{m.Registry.Before.Device, m.Registry.Before.Inode}); err != nil {
			return err
		}
		if err = firstRegistryCheck(slot, m.Registry.After, f.state.RegistryAfter); err != nil {
			return err
		}
	}
	f.state.Phase = "rolling-back"
	if err = f.save(); err != nil {
		return err
	}
	if after {
		if err = f.publishRegistry(true); err != nil {
			return err
		}
	}
	if where == f.target() {
		if err = f.publishState(true); err != nil {
			return err
		}
	}
	// Retain the authenticated managed sibling as rollback evidence; never recursive-delete.
	f.state.Phase = "rolled-back"
	return f.save()
}
func firstMarkerSnapshot(ctx context.Context, name string) (map[string]File, error) {
	return WorkspaceSnapshot(ctx, name)
}

func inspectFirstMarker(ctx context.Context, r *trustload.Runtime, home, id string) (JournalInspection, error) {
	out := JournalInspection{id: id, kind: NativeLinkKind, version: APIVersion, status: InspectionUnresolved}
	f, err := loadFirstMarker(ctx, r, home, id, true)
	if err != nil {
		return out, err
	}
	defer f.Release()
	before, e := privateRead(filepath.Join(f.tx.dir, "state.json"), 128<<20)
	if e != nil {
		return out, e
	}
	phase := f.state.Phase
	terminal := phase == "committed" || phase == "rolled-back"
	if phase != "initializing" && phase != "preparing" && phase != "prepared" && phase != "publishing" && phase != "state-published" && phase != "registry-published" && phase != "rolling-back" && !terminal {
		return out, ErrAuthentication
	}
	// Historical committed state may evolve legitimately. The signed output image
	// and source evidence remain receipt proof; current ledger verification is separate.
	if (!terminal || phase == "rolled-back") && f.state.Stage.Inode != 0 {
		where, e := f.managedLocation()
		if e != nil {
			return out, e
		}
		if e = f.checkManaged(ctx, where); e != nil {
			return out, e
		}
	}
	m := f.tx.plan.Material
	slot := filepath.Join(f.tx.dir, firstMarkerRegistrySlot)
	if phase == "committed" {
		if e := firstRegistryCheck(slot, m.Registry.Before, Identity{m.Registry.Before.Device, m.Registry.Before.Inode}); e != nil {
			return out, e
		}
	}
	if phase == "rolled-back" {
		if f.state.RegistryAfter.Inode == 0 {
			if _, e := confinedLstat(slot); !errors.Is(e, fs.ErrNotExist) {
				return out, ErrConflict
			}
		} else if e := firstRegistryCheck(slot, m.Registry.After, f.state.RegistryAfter); e != nil {
			return out, e
		}
	}
	refmat := m
	refmat.Before = m.After
	refs, e := inspectionReferences(refmat)
	if e != nil {
		return out, e
	}
	for _, ref := range refs {
		if _, e = r.Read(ctx, ref); e != nil {
			return out, e
		}
	}
	plan, e := privateRead(filepath.Join(f.tx.dir, "plan.json"), 128<<20)
	if e != nil {
		return out, e
	}
	expectedPlan, e := f.tx.signedBytes("plan.json", f.tx.plan)
	if e != nil || !bytes.Equal(plan, expectedPlan) {
		return out, ErrInspectionChanged
	}
	after, e := privateRead(filepath.Join(f.tx.dir, "state.json"), 128<<20)
	if e != nil || !bytes.Equal(before, after) {
		return out, ErrInspectionChanged
	}
	if phase == "committed" {
		marker, e := inspectionMarker(m.Root)
		if e != nil {
			return out, e
		}
		if e = r.TrustRuntime().CheckProjectIdentity(ctx, m.Root, marker); e != nil {
			return out, e
		}
	}
	out.phase = phase
	out.sealed = true
	out.terminal = terminal
	out.planDigest = evidencecas.Digest(plan)
	out.receiptDigest = evidencecas.Digest(after)
	out.sourceReferences = len(refs)
	out.status = InspectionActive
	if phase == "committed" {
		out.status = InspectionCommitted
	}
	if phase == "rolled-back" {
		out.status = InspectionRolledBack
	}
	return out, nil
}
