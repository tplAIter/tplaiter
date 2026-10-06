// Package adoption exposes read-only installed proof, never detached authority.
package adoption

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/linkcmd"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/receiptevidence"
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
func receiptName(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func readOrigin(ctx context.Context, r *trustload.Runtime, home string, want *adoptionpolicy.Policy) (*originReceipt, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || want == nil || want.Validate() != nil || want.Origin.ProjectID != r.ProjectContext().ProjectID || !want.Origin.Binding.Equal(r.TrustRuntime().Binding()) || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return nil, adoptionpolicy.ErrPolicy
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	directory := filepath.Join(home, "transactions", "project")
	if _, e := linkcmd.ObservePath(directory, "."); e != nil {
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
		candidate, err := readOriginCandidate(ctx, r, home, id, want)
		if err != nil {
			return nil, err
		}
		if candidate != nil {
			if found != nil {
				return nil, adoptionpolicy.ErrPolicy
			}
			found = candidate
		}
	}
	if found == nil {
		return nil, adoptionpolicy.ErrPolicy
	}
	return found, nil
}

func readOriginCandidate(ctx context.Context, r *trustload.Runtime, home, id string, want *adoptionpolicy.Policy) (*originReceipt, error) {
	trusted := r.TrustRuntime()
	if trusted == nil {
		return nil, adoptionpolicy.ErrPolicy
	}
	dir := filepath.Join(home, "transactions", "project", "tx-"+id)
	journal, e := receiptevidence.Read(ctx, r, home, id)
	if e != nil {
		return nil, nil
	}
	defer journal.Close()
	var plan receiptPlan
	planRecord, e := journal.Record(ctx, r, "plan.json")
	if e != nil {
		journal.Close()
		return nil, nil
	}
	if canonicaljson.DecodeStrict(planRecord.Payload(), &plan) != nil {
		journal.Close()
		return nil, nil
	}
	var state receiptState
	stateRecord, e := journal.Record(ctx, r, "state.json")
	if e != nil || canonicaljson.DecodeStrict(stateRecord.Payload(), &state) != nil {
		journal.Close()
		return nil, nil
	}
	m := plan.Material
	if plan.APIVersion != receiptVersion || plan.Kind != receiptKind || plan.ID != id || state.APIVersion != receiptVersion || state.Kind != receiptKind || state.ID != id || state.Phase != "committed" || state.Fingerprint != m.Fingerprint || m.Home != home || m.Root != r.ProjectContext().RootPath || m.ProjectID != r.ProjectContext().ProjectID || m.Registry == nil || !m.Binding.Equal(trusted.Binding()) || state.Plan.Inode == 0 || (receiptID{planRecord.Device(), planRecord.Inode()} != state.Plan) {
		journal.Close()
		return nil, nil
	}
	var marker stateledger.ProjectV2
	if yaml.Unmarshal(m.After[".tplaiter/project.yaml"].Data, &marker) != nil {
		return nil, nil
	}
	p, e := adoptionpolicy.Parse(marker.Ownership)
	if e != nil || p == nil || p.DecisionSHA256 != want.DecisionSHA256 {
		return nil, nil
	}
	for _, binding := range []struct {
		name string
		id   receiptID
	}{{home, plan.HomeIdentity}, {m.Root, plan.RootIdentity}, {filepath.Dir(m.Root), state.Parent}, {dir, state.Receipt}} {
		if e = receiptDirectory(binding.name, binding.id); e != nil {
			return nil, e
		}
	}
	if e = trusted.CheckProjectIdentity(ctx, m.Root, m.ProjectID); e != nil {
		journal.Close()
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
	finalPlan, e := journal.Record(ctx, r, "plan.json")
	finalState, stateErr := journal.Record(ctx, r, "state.json")
	if e != nil || stateErr != nil || !bytes.Equal(finalPlan.Raw(), planRecord.Raw()) || !bytes.Equal(finalState.Raw(), stateRecord.Raw()) || finalPlan.Device() != planRecord.Device() || finalPlan.Inode() != planRecord.Inode() || finalState.Device() != stateRecord.Device() || finalState.Inode() != stateRecord.Inode() {
		journal.Close()
		return nil, adoptionpolicy.ErrPolicy
	}
	if e = receiptDirectory(dir, state.Receipt); e != nil {
		journal.Close()
		return nil, e
	}
	if e = journal.RecheckFor(ctx, r); e != nil {
		return nil, e
	}
	return &originReceipt{material: m, id: id, planDigest: evidencecas.Digest(planRecord.Raw()), stateDigest: evidencecas.Digest(stateRecord.Raw())}, nil
}
