package updateplan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"sort"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const (
	updateMaterialDomain = "tplaiter.dev/native-update-material/v1"
	updateControlPath    = ".tplaiter/update.lock"
)

// UpdateFile and UpdateMaterial are detached transport, never writer authority.
// Cold callers must authenticate the engine receipt and actual phase/inodes BEFORE
// semantic reconstruction. No public constructor turns this data into a Plan.
type UpdateFile struct {
	Data      UpdateBytes `json:"data"`
	Mode      uint32      `json:"mode"`
	Directory bool        `json:"directory"`
	Device    uint64      `json:"device"`
	Inode     uint64      `json:"inode"`
}
type UpdateMaterial struct {
	Managed             *ManagedInput              `json:"managed,omitempty"`
	Protection          *adoptionpolicy.Protection `json:"protection,omitempty"`
	SettingsPairs       []string                   `json:"settingsPairs,omitempty"`
	RegistryDevice      uint64                     `json:"registryDevice"`
	RegistryInode       uint64                     `json:"registryInode"`
	Version             int                        `json:"version"`
	Root                string                     `json:"root"`
	Home                string                     `json:"home"`
	ProjectID           string                     `json:"projectID"`
	Binding             bootstrap.ProfileBinding   `json:"binding"`
	RendererVersion     string                     `json:"rendererVersion"`
	SourceInput         UpdateBytes                `json:"sourceInput"`
	TargetInput         UpdateBytes                `json:"targetInput"`
	ExpectedFingerprint string                     `json:"expectedFingerprint"`
	ControlAdded        bool                       `json:"controlAdded"`
	Before              map[string]UpdateFile      `json:"before"`
	After               map[string]UpdateFile      `json:"after"`
	Registry            UpdateRegistry             `json:"registry"`
	Fingerprint         string                     `json:"fingerprint"`
}

// TransactionMaterial is available only on an opaque authenticated plan. The
// concrete transaction adapter must acquire real leases then call the second
// method, and prove the narrowly added control inode against its held descriptor.
func (p *Plan) TransactionMaterial(ctx context.Context, expected string) (UpdateMaterial, *trustload.Runtime, error) {
	return p.transactionMaterial(ctx, expected, false)
}

func (p *Plan) TransactionMaterialAfterLease(ctx context.Context, expected string) (UpdateMaterial, *trustload.Runtime, error) {
	return p.transactionMaterial(ctx, expected, true)
}

func (p *Plan) transactionMaterial(ctx context.Context, expected string, afterLease bool) (UpdateMaterial, *trustload.Runtime, error) {
	fail := func(err error) (UpdateMaterial, *trustload.Runtime, error) { return UpdateMaterial{}, nil, err }
	if ctx == nil || p == nil || p.owner == nil || p.prepared == nil || expected == "" || expected != p.digest {
		return fail(ErrInvalid)
	}
	b := p.owner
	digest, err := bootstrap.DomainDigest(APIVersion, p.report)
	if err != nil || digest != expected || !p.prepared.ValidFor(b.runtime.TrustRuntime()) {
		return fail(ErrInvalid)
	}
	if _, err := stateledger.VerifyStable(ctx, p.report.Root, b.runtime.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		return fail(err)
	}
	actual, err := observe(ctx, p.report.Root)
	if err != nil {
		return fail(err)
	}
	if raw, exists := actual.files[updateControlPath]; exists {
		info := actual.identities[updateControlPath]
		if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || len(raw) != 0 || !updateSingleLink(info) {
			return fail(ErrStale)
		}
	}
	normalized := actual
	added := false
	if afterLease {
		if _, existed := p.observed.files[updateControlPath]; !existed {
			info := actual.identities[updateControlPath]
			raw, exists := actual.files[updateControlPath]
			if !exists || info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || len(raw) != 0 || !updateSingleLink(info) {
				return fail(ErrStale)
			}
			normalized = withoutControl(actual)
			added = true
		}
	}
	if !equalObservation(p.observed, normalized) {
		return fail(ErrStale)
	}
	reg, err := readRegistry(ctx, b.home)
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(p.homeIdentity, reg.identity) || !os.SameFile(p.registryIdentity, reg.fileIdentity) {
		return fail(ErrStale)
	}
	fresh, err := b.reconstruct(ctx, p.input, normalized, reg)
	if err != nil {
		return fail(err)
	}
	if fresh.digest != expected {
		return fail(ErrStale)
	}
	if !fresh.report.Publishable {
		return fail(ErrConflict)
	}
	m, err := materialFromPlan(fresh, actual, added)
	if err != nil {
		return fail(err)
	}
	final, err := observe(ctx, p.report.Root)
	if err != nil {
		return fail(err)
	}
	if !equalObservation(actual, final) {
		return fail(ErrStale)
	}
	if err := b.runtime.TrustRuntime().CheckProjectIdentity(ctx, m.Root, m.ProjectID); err != nil {
		return fail(err)
	}
	return m, b.runtime, nil
}

func withoutControl(o *observation) *observation {
	n := &observation{identity: o.identity, identities: map[string]os.FileInfo{}, files: map[string][]byte{}}
	for _, i := range o.images {
		if i.Path != updateControlPath {
			n.images = append(n.images, i)
		}
	}
	for p, v := range o.files {
		if p != updateControlPath {
			n.files[p] = v
		}
	}
	for p, v := range o.identities {
		if p != updateControlPath {
			n.identities[p] = v
		}
	}
	return n
}

func materialFromPlan(p *Plan, actual *observation, added bool) (UpdateMaterial, error) {
	intent, err := buildMutation(p)
	if err != nil {
		return UpdateMaterial{}, err
	}
	m := UpdateMaterial{Managed: p.input.Managed, SettingsPairs: append([]string(nil), p.input.SettingsPairs...), Version: 1, Root: p.report.Root, Home: p.owner.home, ProjectID: p.report.ProjectID, Binding: p.owner.runtime.TrustRuntime().Binding(), RendererVersion: p.owner.rendererVersion, SourceInput: bytes.Clone(p.input.SourceInput), TargetInput: bytes.Clone(p.input.TargetInput), ExpectedFingerprint: p.digest, ControlAdded: added, Before: map[string]UpdateFile{}, After: map[string]UpdateFile{}, Registry: updateRegistry(intent.registry)}
	if p.policy != nil {
		m.Version = 2
		m.Protection = p.protection
	}
	for _, i := range actual.images {
		device, inode := updateFileID(actual.identities[i.Path])
		f := UpdateFile{Data: bytes.Clone(actual.files[i.Path]), Mode: i.Mode, Directory: i.Kind == "directory", Device: device, Inode: inode}
		m.Before[i.Path] = f
		m.After[i.Path] = f
	}
	for _, c := range intent.changes {
		if c.after == nil {
			delete(m.After, c.path)
			continue
		}
		f := m.Before[c.path]
		f.Data = bytes.Clone(c.after.data)
		f.Mode = c.after.image.Mode
		f.Directory = c.after.image.Kind == "directory"
		m.After[c.path] = f
	}
	if _, err := materialObservation(m.After); err != nil {
		return UpdateMaterial{}, err
	}
	m.RegistryDevice, m.RegistryInode = updateFileID(p.registryIdentity)
	m.Fingerprint, err = updateMaterialFingerprint(m)
	return m, err
}

func updateMaterialFingerprint(m UpdateMaterial) (string, error) {
	m.Fingerprint = ""
	domain := updateMaterialDomain
	if m.Version == 2 {
		domain = "tplaiter.dev/native-update-material/v2"
	}
	if m.Managed != nil {
		domain += "/managed/v1"
	}
	return bootstrap.DomainDigest(domain, m)
}

// AuthenticateUpdateMaterial freshly reconstructs signed source AND target and
// all expected images (including signed answer migrations and their ledger) from immutable beforeimages. It does not read an incomplete
// tree as stable and cannot authorize publication or recovery. Actual root/phase
// ownership belongs to the authenticated engine receipt and retained lease.
func AuthenticateUpdateMaterial(ctx context.Context, r *trustload.Runtime, actualRendererVersion string, m UpdateMaterial) error {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || (m.Version != 1 && m.Version != 2) || actualRendererVersion == "" || m.RendererVersion != actualRendererVersion || r.ProjectContext().RootPath != m.Root || !r.TrustRuntime().Binding().Equal(m.Binding) || len(m.SourceInput) == 0 || len(m.SourceInput) > 1<<20 || len(m.TargetInput) == 0 || len(m.TargetInput) > 1<<20 {
		return ErrInvalid
	}
	if (m.Version == 2) != (m.Protection != nil) {
		return ErrInvalid
	}
	if err := r.TrustRuntime().CheckProjectIdentity(ctx, m.Root, m.ProjectID); err != nil {
		return err
	}
	if len(m.Before) > maxFiles || len(m.After) > maxFiles || len(m.Registry.BeforeContent) > 1<<20 || len(m.Registry.AfterContent) > 1<<20 {
		return ErrUnsafe
	}
	digest, err := updateMaterialFingerprint(m)
	if err != nil || digest != m.Fingerprint {
		return ErrInvalid
	}
	if f, exists := m.Before[updateControlPath]; exists && (f.Directory || f.Mode != 0o600 || len(f.Data) != 0 || f.Inode == 0) {
		return ErrInvalid
	}
	observed, err := materialObservation(m.Before)
	if err != nil {
		return err
	}
	if m.ControlAdded {
		f, ok := m.Before[updateControlPath]
		if !ok || f.Directory || f.Mode != 0o600 || len(f.Data) != 0 || f.Inode == 0 {
			return ErrInvalid
		}
		observed = withoutControl(observed)
	}
	b, err := New(r, m.Home, m.RendererVersion)
	if err != nil {
		return err
	}
	reg := &registryObservation{raw: bytes.Clone(m.Registry.BeforeContent), mode: m.Registry.Before.Mode}
	p, err := b.reconstruct(ctx, Input{SourceInput: m.SourceInput, TargetInput: m.TargetInput, SettingsPairs: m.SettingsPairs, Managed: m.Managed}, observed, reg, m.Protection)
	if err != nil {
		return err
	}
	if p.report.ProjectID != m.ProjectID || p.digest != m.ExpectedFingerprint || !p.report.Publishable {
		return ErrInvalid
	}
	// Rebuild semantic material; receipt inode IDs are observations, not authority.
	rebuilt, err := materialFromPlan(p, observed, false)
	if err != nil {
		return err
	}
	rebuilt.RegistryDevice, rebuilt.RegistryInode = m.RegistryDevice, m.RegistryInode
	rebuilt.ControlAdded = m.ControlAdded
	rebuilt.Before = m.Before
	for name, f := range rebuilt.After {
		if prior, ok := m.Before[name]; ok {
			f.Device, f.Inode = prior.Device, prior.Inode
			rebuilt.After[name] = f
		}
	}
	if m.ControlAdded {
		rebuilt.After[updateControlPath] = m.Before[updateControlPath]
	}
	rebuilt.Fingerprint, err = updateMaterialFingerprint(rebuilt)
	if err != nil {
		return err
	}
	raw, err := canonicaljson.Canonical(rebuilt)
	if err != nil {
		return err
	}
	actual, err := canonicaljson.Canonical(m)
	if err != nil || !bytes.Equal(raw, actual) {
		return ErrInvalid
	}
	return checkUpdateMarker(ctx, r, m)
}

func materialObservation(files map[string]UpdateFile) (*observation, error) {
	if len(files) == 0 || len(files) > maxFiles {
		return nil, ErrUnsafe
	}
	o := &observation{files: map[string][]byte{}, identities: map[string]os.FileInfo{}}
	var total int64
	for p, f := range files {
		if (p != "." && !safePath(p)) || f.Mode > 0o777 || (p == "." && !f.Directory) {
			return nil, ErrUnsafe
		}
		kind := "file"
		if f.Directory {
			kind = "directory"
			if len(f.Data) != 0 {
				return nil, ErrUnsafe
			}
		} else {
			total += int64(len(f.Data))
			if total > maxBytes {
				return nil, ErrUnsafe
			}
			o.files[p] = bytes.Clone(f.Data)
		}
		o.images = append(o.images, Image{Path: p, Kind: kind, Mode: f.Mode, SHA256: evidencecas.Digest(f.Data)})
	}
	if _, ok := files["."]; !ok {
		return nil, ErrUnsafe
	}
	sort.Slice(o.images, func(i, j int) bool { return o.images[i].Path < o.images[j].Path })
	if err := validateObservedNamespace(o, map[string][]byte{}); err != nil {
		return nil, err
	}
	return o, nil
}

// Rooted final marker reobservation must itself name the installed identity.
// Exact before/after bytes permit partial publication; the engine additionally
// classifies phase and retained inode ownership, which this check cannot grant.
func checkUpdateMarker(ctx context.Context, r *trustload.Runtime, m UpdateMaterial) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := os.OpenRoot(m.Root)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	const name = ".tplaiter/project.yaml"
	parent, err := root.Lstat(".tplaiter")
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafe
	}
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > 1<<20 {
		return ErrUnsafe
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	held, err := file.Stat()
	if err != nil || !os.SameFile(before, held) {
		return ErrStale
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return err
	}
	final, err := root.Lstat(name)
	if err != nil || len(raw) > 1<<20 || !os.SameFile(held, final) || held.Mode() != final.Mode() {
		return ErrStale
	}
	a, aok := m.Before[name]
	z, zok := m.After[name]
	if (!aok || !bytes.Equal(raw, a.Data) || uint32(final.Mode().Perm()) != a.Mode) && (!zok || !bytes.Equal(raw, z.Data) || uint32(final.Mode().Perm()) != z.Mode) {
		return ErrStale
	}
	var marker stateledger.ProjectV2
	if err := decodeMarker(raw, &marker); err != nil {
		return err
	}
	if marker.ID != m.ProjectID {
		return ErrInvalid
	}
	return r.TrustRuntime().CheckProjectIdentity(ctx, m.Root, marker.ID)
}

// Explicit byte arrays preserve absence vs empty data under strict decoding.
type UpdateBytes []byte

func (b UpdateBytes) MarshalJSON() ([]byte, error) {
	v := make([]uint16, len(b))
	for i, x := range b {
		v[i] = uint16(x)
	}
	return json.Marshal(v)
}

func (b *UpdateBytes) UnmarshalJSON(raw []byte) error {
	var v []uint16
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if v == nil {
		return ErrInvalid
	}
	out := make(UpdateBytes, len(v))
	for i, x := range v {
		if x > 255 {
			return ErrInvalid
		}
		out[i] = byte(x)
	}
	*b = out
	return nil
}

type UpdateRegistry struct {
	Home          string      `json:"home"`
	Before        Image       `json:"before"`
	BeforeContent UpdateBytes `json:"beforeContent"`
	After         Image       `json:"after"`
	AfterContent  UpdateBytes `json:"afterContent"`
}

func updateRegistry(r RegistryImage) UpdateRegistry {
	return UpdateRegistry{Home: r.Home, Before: r.Before, BeforeContent: bytes.Clone(r.BeforeContent), After: r.After, AfterContent: bytes.Clone(r.AfterContent)}
}

func RevalidateManagedUpdatePublication(ctx context.Context, r *trustload.Runtime, renderer string, m UpdateMaterial) error {
	if m.Managed == nil {
		return nil
	}
	if err := AuthenticateUpdateMaterial(ctx, r, renderer, m); err != nil {
		return err
	}
	observed, err := materialObservation(m.Before)
	if err != nil {
		return err
	}
	if m.ControlAdded {
		observed = withoutControl(observed)
	}
	backend, err := New(r, m.Home, renderer)
	if err != nil {
		return err
	}
	reg := &registryObservation{raw: bytes.Clone(m.Registry.BeforeContent), mode: m.Registry.Before.Mode}
	plan, err := backend.reconstruct(ctx, Input{SourceInput: m.SourceInput, TargetInput: m.TargetInput, SettingsPairs: m.SettingsPairs, Managed: m.Managed}, observed, reg, m.Protection)
	if err != nil {
		return err
	}
	if plan.managed == nil {
		return ErrInvalid
	}
	return plan.managed.mergedProjection.RevalidatePublication(ctx, plan.managed.merged)
}
