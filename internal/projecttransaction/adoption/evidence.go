// Package adoption exposes read-only installed proof, never detached authority.
package adoption

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/linkcmd"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"gopkg.in/yaml.v3"
)

type Evidence struct {
	origin   *originReceipt
	runtime  *trustload.Runtime
	home     string
	decision string
}

func (e *Evidence) ReceiptID() string     { return e.origin.ReceiptID() }
func (e *Evidence) PlanDigest() string    { return e.origin.PlanDigest() }
func (e *Evidence) ReceiptDigest() string { return e.origin.ReceiptDigest() }
func (e *Evidence) Matches(r *trustload.Runtime, home string, p *adoptionpolicy.Policy) bool {
	return e != nil && e.origin != nil && e.runtime == r && e.home == home && p != nil && e.decision == p.DecisionSHA256
}
func Read(ctx context.Context, r *trustload.Runtime, home string, p *adoptionpolicy.Policy) (*Evidence, error) {
	o, err := readOrigin(ctx, r, home, p)
	if err != nil {
		return nil, err
	}
	m := o.material
	var in struct {
		Input    linkcmd.Input  `json:"input"`
		Renderer string         `json:"renderer"`
		Stamp    string         `json:"stamp"`
		Report   linkcmd.Report `json:"report"`
	}
	if canonicaljson.DecodeStrict(m.Intent, &in) != nil || in.Input.Action != "adopt" {
		return nil, adoptionpolicy.ErrPolicy
	}
	stamp, err := time.Parse(time.RFC3339Nano, in.Stamp)
	if err != nil {
		return nil, err
	}
	before := map[string]linkcmd.File{}
	for path, f := range m.Before {
		before[path] = linkcmd.File{Data: bytes.Clone(f.Data), Mode: f.Mode, Directory: f.Directory, Device: f.Device, Inode: f.Inode}
	}
	fresh, err := linkcmd.ReconstructProjected(ctx, r, home, in.Input, in.Renderer, stamp, before)
	if err != nil {
		return nil, err
	}
	if len(fresh) != len(m.After) {
		return nil, adoptionpolicy.ErrPolicy
	}
	for path, raw := range fresh {
		f, ok := m.After[path]
		mode := uint32(0o644)
		if path == ".tplaiter/update.lock" {
			mode = 0o600
		}
		if !ok || f.Directory || f.Mode != mode || !bytes.Equal(raw, f.Data) {
			return nil, adoptionpolicy.ErrPolicy
		}
	}
	again, err := readOrigin(ctx, r, home, p)
	if err != nil || again.id != o.id || again.planDigest != o.planDigest || again.stateDigest != o.stateDigest {
		return nil, adoptionpolicy.ErrPolicy
	}
	return &Evidence{origin: o, runtime: r, home: home, decision: p.DecisionSHA256}, nil
}

// These private wire types read only the accepted first-marker v1 contract.
// They intentionally do not import the mutable engine: updateplan and the
// engine's own signed-boundary tests can both consume this read-only facade.
const receiptVersion = "tplaiter.dev/project-transaction/v1"
const receiptKind = "NativeLinkTransaction"

type receiptID struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type receiptBytes []byte

func (b *receiptBytes) UnmarshalJSON(raw []byte) error {
	var values []uint16
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return adoptionpolicy.ErrPolicy
	}
	out := make(receiptBytes, len(values))
	for i, v := range values {
		if v > 255 {
			return adoptionpolicy.ErrPolicy
		}
		out[i] = byte(v)
	}
	*b = out
	return nil
}

type receiptFile struct {
	Data      receiptBytes `json:"data"`
	Mode      uint32       `json:"mode"`
	Directory bool         `json:"directory"`
	Device    uint64       `json:"device"`
	Inode     uint64       `json:"inode"`
}
type receiptMaterial struct {
	Registry *struct {
		Before receiptFile `json:"before"`
		After  receiptFile `json:"after"`
	} `json:"registry,omitempty"`
	Root          string                   `json:"root"`
	Home          string                   `json:"home"`
	ProjectID     string                   `json:"projectID"`
	Binding       bootstrap.ProfileBinding `json:"binding"`
	Before        map[string]receiptFile   `json:"before"`
	After         map[string]receiptFile   `json:"after"`
	Fingerprint   string                   `json:"fingerprint"`
	ReadOnlyPaths []string                 `json:"readOnlyPaths"`
	Intent        json.RawMessage          `json:"intent"`
}
type receiptPlan struct {
	APIVersion   string          `json:"apiVersion"`
	Kind         string          `json:"kind"`
	ID           string          `json:"id"`
	HomeIdentity receiptID       `json:"homeIdentity"`
	RootIdentity receiptID       `json:"rootIdentity"`
	Material     receiptMaterial `json:"material"`
}
type receiptState struct {
	APIVersion    string                 `json:"apiVersion"`
	Kind          string                 `json:"kind"`
	ID            string                 `json:"id"`
	Fingerprint   string                 `json:"fingerprint"`
	Phase         string                 `json:"phase"`
	Parent        receiptID              `json:"parent"`
	Stage         receiptID              `json:"stage"`
	RegistryAfter receiptID              `json:"registryAfter"`
	Receipt       receiptID              `json:"receipt"`
	Plan          receiptID              `json:"plan"`
	Inventory     map[string]receiptFile `json:"inventory"`
	Missing       []string               `json:"missing"`
}
type originReceipt struct {
	material                    receiptMaterial
	id, planDigest, stateDigest string
}

func (o *originReceipt) ReceiptID() string     { return o.id }
func (o *originReceipt) PlanDigest() string    { return o.planDigest }
func (o *originReceipt) ReceiptDigest() string { return o.stateDigest }

func receiptIdentity(f linkcmd.File) receiptID { return receiptID{f.Device, f.Inode} }
func receiptDirectory(name string, id receiptID) error {
	// ObservePath roots are canonical/no-follow; directory identity is immutable.
	f, e := linkcmd.ObservePath(name, ".")
	if e != nil || !f.Directory || id.Inode == 0 || receiptIdentity(f) != id {
		return adoptionpolicy.ErrPolicy
	}
	return nil
}
func receiptSigned(key []byte, dir, name string, out any) ([]byte, linkcmd.File, error) {
	file, e := receiptObserveFile(dir, name)
	if e != nil || file.Directory || file.Mode != 0o600 || len(file.Data) > 128<<20 {
		return nil, file, adoptionpolicy.ErrPolicy
	}
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
		MAC     string          `json:"mac"`
	}
	if canonicaljson.DecodeStrict(file.Data, &envelope) != nil {
		return nil, file, adoptionpolicy.ErrPolicy
	}
	canonical, e := canonicaljson.Canonicalize(file.Data)
	if e != nil || !bytes.Equal(canonical, file.Data) {
		return nil, file, adoptionpolicy.ErrPolicy
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(receiptVersion + "\x00" + receiptKind + "\x00" + dir + "\x00" + name + "\x00"))
	mac.Write(envelope.Payload)
	actual, e := hex.DecodeString(envelope.MAC)
	if e != nil || !hmac.Equal(actual, mac.Sum(nil)) || canonicaljson.DecodeStrict(envelope.Payload, out) != nil {
		return nil, file, adoptionpolicy.ErrPolicy
	}
	return bytes.Clone(file.Data), file, nil
}
func receiptName(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	_, e := hex.DecodeString(id)
	return e == nil
}
func readOrigin(ctx context.Context, r *trustload.Runtime, home string, want *adoptionpolicy.Policy) (*originReceipt, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || want == nil || want.Validate() != nil || want.Origin.ProjectID != r.ProjectContext().ProjectID || !want.Origin.Binding.Equal(r.TrustRuntime().Binding()) || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return nil, adoptionpolicy.ErrPolicy
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	// Consume the existing runtime-owned seal read-only. Never create, replace,
	// export or return it; it is not a profile credential or caller-provided key.
	key, e := linkcmd.ObservePath(r.ScratchRoot(), "project-transaction-authority/seal.key")
	if e != nil || key.Directory || key.Mode != 0o600 || len(key.Data) != 32 {
		return nil, adoptionpolicy.ErrPolicy
	}
	defer clear(key.Data)
	directory := filepath.Join(home, "transactions", "project")
	if _, e = linkcmd.ObservePath(directory, "."); e != nil {
		return nil, e
	}
	parent, e := os.OpenRoot(directory)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	file, e := parent.Open(".")
	if e != nil {
		return nil, e
	}
	entries, e := file.ReadDir(4097)
	closeErr := file.Close()
	if e != nil || closeErr != nil || len(entries) > 4096 {
		return nil, adoptionpolicy.ErrPolicy
	}
	var found *originReceipt
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		id := strings.TrimPrefix(entry.Name(), "tx-")
		if !strings.HasPrefix(entry.Name(), "tx-") || !receiptName(id) {
			continue
		}
		dir := filepath.Join(directory, entry.Name())
		var plan receiptPlan
		planRaw, planFile, e := receiptSigned(key.Data, dir, "plan.json", &plan)
		if e != nil {
			continue
		}
		var state receiptState
		stateRaw, stateFile, e := receiptSigned(key.Data, dir, "state.json", &state)
		if e != nil {
			continue
		}
		m := plan.Material
		if plan.APIVersion != receiptVersion || plan.Kind != receiptKind || plan.ID != id || state.APIVersion != receiptVersion || state.Kind != receiptKind || state.ID != id || state.Phase != "committed" || state.Fingerprint != m.Fingerprint || m.Home != home || m.Root != r.ProjectContext().RootPath || m.ProjectID != r.ProjectContext().ProjectID || m.Registry == nil || !m.Binding.Equal(r.TrustRuntime().Binding()) || state.Plan.Inode == 0 || receiptIdentity(planFile) != state.Plan {
			continue
		}
		var marker stateledger.ProjectV2
		if yaml.Unmarshal(m.After[".tplaiter/project.yaml"].Data, &marker) != nil {
			continue
		}
		p, e := adoptionpolicy.Parse(marker.Ownership)
		if e != nil || p == nil || p.DecisionSHA256 != want.DecisionSHA256 {
			continue
		}
		if found != nil {
			return nil, adoptionpolicy.ErrPolicy
		}
		for _, binding := range []struct {
			name string
			id   receiptID
		}{{home, plan.HomeIdentity}, {m.Root, plan.RootIdentity}, {filepath.Dir(m.Root), state.Parent}, {dir, state.Receipt}} {
			if e = receiptDirectory(binding.name, binding.id); e != nil {
				return nil, e
			}
		}
		if e = r.TrustRuntime().CheckProjectIdentity(ctx, m.Root, m.ProjectID); e != nil {
			return nil, e
		}
		registry := m.Registry.Before
		slot, e := linkcmd.ObservePath(dir, "000000")
		if registry.Inode == 0 {
			if !os.IsNotExist(e) {
				return nil, adoptionpolicy.ErrPolicy
			}
		} else if e != nil || slot.Directory || slot.Mode != registry.Mode || slot.Device != registry.Device || slot.Inode != registry.Inode || !bytes.Equal(slot.Data, registry.Data) {
			return nil, adoptionpolicy.ErrPolicy
		}
		// Reobserve exact bytes, full mode and inode. A MAC-valid or equal-byte
		// replacement cannot erase the original persisted plan identity.
		finalPlan, e := receiptObserveFile(dir, "plan.json")
		if e != nil || !reflect.DeepEqual(finalPlan, planFile) {
			return nil, adoptionpolicy.ErrPolicy
		}
		finalState, e := receiptObserveFile(dir, "state.json")
		if e != nil || !reflect.DeepEqual(finalState, stateFile) {
			return nil, adoptionpolicy.ErrPolicy
		}
		if e = receiptDirectory(dir, state.Receipt); e != nil {
			return nil, e
		}
		found = &originReceipt{material: m, id: id, planDigest: evidencecas.Digest(planRaw), stateDigest: evidencecas.Digest(stateRaw)}
	}
	if found == nil {
		return nil, adoptionpolicy.ErrPolicy
	}
	return found, nil
}

// Receipt files use the existing engine's 128 MiB bound, not user-file limits.
func receiptObserveFile(dir, name string) (linkcmd.File, error) {
	initial, e := linkcmd.ObservePath(dir, ".")
	if e != nil {
		return linkcmd.File{}, e
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return linkcmd.File{}, e
	}
	defer root.Close()
	info, e := root.Lstat(name)
	if e != nil || !info.Mode().IsRegular() || info.Mode() != 0o600 || info.Size() < 0 || info.Size() > 128<<20 {
		return linkcmd.File{}, adoptionpolicy.ErrPolicy
	}
	sys := reflect.ValueOf(info.Sys())
	if sys.Kind() == reflect.Pointer {
		sys = sys.Elem()
	}
	if sys.Kind() != reflect.Struct {
		return linkcmd.File{}, adoptionpolicy.ErrPolicy
	}
	numberOf := func(sys reflect.Value, name string) uint64 {
		if sys.Kind() == reflect.Pointer {
			sys = sys.Elem()
		}
		if sys.Kind() != reflect.Struct {
			return 0
		}
		f := sys.FieldByName(name)
		if f.IsValid() && f.CanUint() {
			return f.Uint()
		}
		if f.IsValid() && f.CanInt() {
			return uint64(f.Int())
		}
		return 0
	}
	number := func(name string) uint64 { return numberOf(sys, name) }
	if number("Nlink") != 1 || number("Ino") == 0 {
		return linkcmd.File{}, adoptionpolicy.ErrPolicy
	}
	file, e := root.Open(name)
	if e != nil {
		return linkcmd.File{}, e
	}
	defer file.Close()
	held, e := file.Stat()
	if e != nil || !os.SameFile(info, held) || info.Mode() != held.Mode() {
		return linkcmd.File{}, adoptionpolicy.ErrPolicy
	}
	raw, e := io.ReadAll(io.LimitReader(file, (128<<20)+1))
	if e != nil || len(raw) > 128<<20 {
		return linkcmd.File{}, adoptionpolicy.ErrPolicy
	}
	final, e := root.Lstat(name)
	if e != nil || !os.SameFile(info, final) || info.Mode() != final.Mode() || info.Size() != final.Size() || !info.ModTime().Equal(final.ModTime()) || numberOf(reflect.ValueOf(final.Sys()), "Nlink") != 1 {
		return linkcmd.File{}, adoptionpolicy.ErrPolicy
	}
	after, e := linkcmd.ObservePath(dir, ".")
	if e != nil || !reflect.DeepEqual(initial, after) {
		return linkcmd.File{}, adoptionpolicy.ErrPolicy
	}
	return linkcmd.File{Data: raw, Mode: 0o600, Device: number("Dev"), Inode: number("Ino")}, nil
}
