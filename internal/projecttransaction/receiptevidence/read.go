// Package receiptevidence authenticates fixed project receipt transport only.
// Detached records are inspection data, never operation or writer admission.
package receiptevidence

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"path/filepath"
	"strings"
	"sync"
)

const maxRawReceiptBytes int64 = 128 << 20
const receiptVersion = "tplaiter.dev/project-transaction/v1"

var ErrAuthentication = errors.New("receipt evidence: authentication refused")
var ErrClosed = errors.New("receipt evidence: journal closed")

type envelope struct {
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}
type identity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type wireBytes []byte

func (b *wireBytes) UnmarshalJSON(raw []byte) error {
	var values []uint16
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return ErrAuthentication
	}
	out := make(wireBytes, len(values))
	for i, v := range values {
		if v > 255 {
			return ErrAuthentication
		}
		out[i] = byte(v)
	}
	*b = out
	return nil
}

type wireFile struct {
	Data      wireBytes `json:"data"`
	Mode      uint32    `json:"mode"`
	Directory bool      `json:"directory"`
	Device    uint64    `json:"device"`
	Inode     uint64    `json:"inode"`
}
type wireMaterial struct {
	Registry *struct {
		Before wireFile `json:"before"`
		After  wireFile `json:"after"`
	} `json:"registry,omitempty"`
	Root          string                   `json:"root"`
	Home          string                   `json:"home"`
	ProjectID     string                   `json:"projectID"`
	Binding       bootstrap.ProfileBinding `json:"binding"`
	Before        map[string]wireFile      `json:"before"`
	After         map[string]wireFile      `json:"after"`
	Fingerprint   string                   `json:"fingerprint"`
	ReadOnlyPaths []string                 `json:"readOnlyPaths"`
	Intent        json.RawMessage          `json:"intent"`
}
type wirePlan struct {
	APIVersion   string       `json:"apiVersion"`
	Kind         string       `json:"kind"`
	ID           string       `json:"id"`
	HomeIdentity identity     `json:"homeIdentity"`
	RootIdentity identity     `json:"rootIdentity"`
	Material     wireMaterial `json:"material"`
}
type wireStep struct {
	Delete        bool     `json:"delete,omitempty"`
	Registry      bool     `json:"registry,omitempty"`
	Path          string   `json:"path"`
	Slot          string   `json:"slot"`
	AfterIdentity identity `json:"afterIdentity"`
	Intent        bool     `json:"intent"`
	Done          bool     `json:"done"`
	Undone        bool     `json:"undone"`
}
type wireState struct {
	ReceiptIdentity identity   `json:"receiptIdentity,omitempty"`
	APIVersion      string     `json:"apiVersion"`
	Kind            string     `json:"kind"`
	ID              string     `json:"id"`
	Fingerprint     string     `json:"fingerprint"`
	Phase           string     `json:"phase"`
	ImageIdentity   identity   `json:"imageIdentity"`
	Steps           []wireStep `json:"steps"`
}
type wireLinkState struct {
	APIVersion    string              `json:"apiVersion"`
	Kind          string              `json:"kind"`
	ID            string              `json:"id"`
	Fingerprint   string              `json:"fingerprint"`
	Phase         string              `json:"phase"`
	Parent        identity            `json:"parent"`
	Stage         identity            `json:"stage"`
	RegistryAfter identity            `json:"registryAfter"`
	Receipt       identity            `json:"receipt"`
	Plan          identity            `json:"plan"`
	Inventory     map[string]wireFile `json:"inventory"`
	Missing       []string            `json:"missing"`
}

// Journal is bound to one runtime and original observations. Ordinary reads
// retain the per-record cap; ReadLineage charges aggregate raw work/rechecks.
type Journal struct {
	mu                      sync.Mutex
	self                    *Journal
	runtime                 *trustload.Runtime
	stable                  *trustverify.Runtime
	project                 trustload.ProjectContext
	scratch, home, id, kind string
	key                     []byte
	keyFact                 physicalFact
	keyDigest               string
	directory               *directoryHandle
	keyDirectory            *directoryHandle
	closed                  bool
	aggregate               bool
	historical              bool
	remaining               int64
	records                 map[string]*AuthenticatedRecord
}
type AuthenticatedRecord struct {
	raw, payload              []byte
	digest, epoch, name, kind string
	fact                      physicalFact
}

func (r *AuthenticatedRecord) Raw() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.raw)
}
func (r *AuthenticatedRecord) Payload() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.payload)
}
func (r *AuthenticatedRecord) Digest() string {
	if r == nil {
		return ""
	}
	return r.digest
}
func (r *AuthenticatedRecord) Name() string {
	if r == nil {
		return ""
	}
	return r.name
}
func (r *AuthenticatedRecord) Device() uint64 {
	if r == nil {
		return 0
	}
	return r.fact.device
}
func (r *AuthenticatedRecord) Inode() uint64 {
	if r == nil {
		return 0
	}
	return r.fact.inode
}

// AuthorityDigest is a comparison observation, never a signing key or grant.
func (r *AuthenticatedRecord) AuthorityDigest() string {
	if r == nil {
		return ""
	}
	return r.epoch
}

// ObserveProjectReceipt reads only fixed plan/state metadata through held
// no-follow physical descriptors. Its bytes are untrusted diagnostics: no MAC,
// layout, phase, source or admission assertion is made. Future and damaged plan
// diagnostics must remain observable independently of authentic state evidence.
func ObserveProjectReceipt(ctx context.Context, r *trustload.Runtime, home, id, name string) ([]byte, error) {
	if ctx == nil || r == nil || !validID(id) || !absoluteClean(home) || (name != "plan.json" && name != "state.json") {
		return nil, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stable, project, scratch := r.TrustRuntime(), r.ProjectContext(), r.ScratchRoot()
	if stable == nil || !absoluteClean(project.RootPath) || project.ProjectID == "" || !absoluteClean(scratch) || overlaps(home, project.RootPath) {
		return nil, ErrAuthentication
	}
	directory, err := openDirectory(ctx, filepath.Join(home, "transactions", "project", "tx-"+id))
	if err != nil {
		return nil, err
	}
	defer directory.close()
	if err := directory.private(); err != nil {
		return nil, err
	}
	raw, _, err := directory.read(ctx, name, maxRawReceiptBytes, nil)
	if err != nil {
		return nil, err
	}
	if r.TrustRuntime() != stable || r.ProjectContext() != project || r.ScratchRoot() != scratch {
		return nil, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}

func openJournal(ctx context.Context, r *trustload.Runtime, home, id string, aggregate, historical bool) (*Journal, error) {
	if ctx == nil || r == nil || !validID(id) || !absoluteClean(home) {
		return nil, ErrAuthentication
	}
	stable := r.TrustRuntime()
	pc := r.ProjectContext()
	scratch := r.ScratchRoot()
	if stable == nil || !absoluteClean(pc.RootPath) || pc.ProjectID == "" || !absoluteClean(scratch) || overlaps(home, pc.RootPath) {
		return nil, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := stable.CheckProjectIdentity(ctx, pc.RootPath, pc.ProjectID); err != nil {
		return nil, err
	}
	directory, err := openDirectory(ctx, filepath.Join(home, "transactions", "project", "tx-"+id))
	if err != nil {
		return nil, err
	}
	if err = directory.private(); err != nil {
		directory.close()
		return nil, err
	}
	keyDirectory, err := openDirectory(ctx, filepath.Join(scratch, "project-transaction-authority"))
	if err != nil {
		directory.close()
		return nil, err
	}
	if err = keyDirectory.private(); err != nil {
		directory.close()
		keyDirectory.close()
		return nil, err
	}
	key, keyFact, err := keyDirectory.read(ctx, "seal.key", 32, nil)
	if err != nil || len(key) != 32 {
		directory.close()
		keyDirectory.close()
		clear(key)
		return nil, ErrAuthentication
	}
	j := &Journal{runtime: r, stable: stable, project: pc, scratch: scratch, home: home, id: id, key: key, keyFact: keyFact, keyDigest: evidencecas.Digest(key), directory: directory, keyDirectory: keyDirectory, aggregate: aggregate, historical: historical, remaining: maxRawReceiptBytes, records: map[string]*AuthenticatedRecord{}}
	j.self = j
	if err = j.check(ctx, r); err != nil {
		j.Close()
		return nil, err
	}
	return j, nil
}
func Read(ctx context.Context, r *trustload.Runtime, home, id string) (*Journal, error) {
	return readJournal(ctx, r, home, id, false)
}
func ReadLineage(ctx context.Context, r *trustload.Runtime, home, id string) (*Journal, error) {
	return readJournal(ctx, r, home, id, true)
}
func readJournal(ctx context.Context, r *trustload.Runtime, home, id string, aggregate bool) (*Journal, error) {
	j, err := openJournal(ctx, r, home, id, aggregate, false)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"plan.json", "state.json"} {
		record, e := j.Record(ctx, r, name)
		if e != nil {
			j.Close()
			return nil, e
		}
		j.records[name] = record
	}
	return j, nil
}

// ReadProjectRecord authenticates a fixed record independently, preserving the
// diagnostic state-after-plan-damage route without a caller-selected kind/key.
func ReadProjectRecord(ctx context.Context, r *trustload.Runtime, home, id, name string) (*AuthenticatedRecord, error) {
	j, err := openJournal(ctx, r, home, id, false, false)
	if err != nil {
		return nil, err
	}
	defer j.Close()
	return j.Record(ctx, r, name)
}

// ReadProjectFenceRecord returns historical same-installation fence data only.
// A prior project identity is decoded data, never current ownership or admission.
func ReadProjectFenceRecord(ctx context.Context, r *trustload.Runtime, home, id, name string) (*AuthenticatedRecord, error) {
	j, err := openJournal(ctx, r, home, id, false, true)
	if err != nil {
		return nil, err
	}
	defer j.Close()
	return j.Record(ctx, r, name)
}
func (j *Journal) check(ctx context.Context, r *trustload.Runtime) error {
	if j == nil || j.self != j || j.closed || j.runtime == nil || r != j.runtime || len(j.key) != 32 {
		return ErrClosed
	}
	if ctx == nil {
		return ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.TrustRuntime() != j.stable || r.ProjectContext() != j.project || r.ScratchRoot() != j.scratch {
		return ErrClosed
	}
	if err := j.directory.check(); err != nil {
		return err
	}
	if err := j.stable.CheckProjectIdentity(ctx, j.project.RootPath, j.project.ProjectID); err != nil {
		return err
	}
	key, fact, err := j.keyDirectory.read(ctx, "seal.key", 32, nil)
	defer clear(key)
	if err != nil || fact != j.keyFact || !hmac.Equal(key, j.key) {
		return ErrAuthentication
	}
	if r.TrustRuntime() != j.stable || r.ProjectContext() != j.project || r.ScratchRoot() != j.scratch {
		return ErrClosed
	}
	return ctx.Err()
}
func (j *Journal) Kind() string {
	if j == nil || j.self != j {
		return ""
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ""
	}
	return j.kind
}
func (j *Journal) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if j == nil || j.self != j {
		return ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.check(ctx, r); err != nil {
		return err
	}
	for _, name := range []string{"plan.json", "state.json"} {
		old := j.records[name]
		if old == nil {
			return ErrAuthentication
		}
		now, err := j.record(ctx, r, name)
		if err != nil {
			return err
		}
		if old.fact != now.fact || old.digest != now.digest {
			return ErrAuthentication
		}
	}
	return j.check(ctx, r)
}
func (j *Journal) Record(ctx context.Context, r *trustload.Runtime, name string) (*AuthenticatedRecord, error) {
	if j == nil || j.self != j {
		return nil, ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.record(ctx, r, name)
}
func (j *Journal) record(ctx context.Context, r *trustload.Runtime, name string) (*AuthenticatedRecord, error) {
	if !validRecordName(name) {
		return nil, ErrAuthentication
	}
	if err := j.check(ctx, r); err != nil {
		return nil, err
	}
	var budget *int64
	if j.aggregate {
		budget = &j.remaining
	}
	raw, fact, err := j.directory.read(ctx, name, maxRawReceiptBytes, budget)
	if err != nil {
		return nil, err
	}
	var e envelope
	if canonicaljson.DecodeStrict(raw, &e) != nil || len(e.Payload) == 0 {
		return nil, ErrAuthentication
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrAuthentication
	}
	var h struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		ID         string `json:"id"`
	}
	if json.Unmarshal(e.Payload, &h) != nil || h.APIVersion != receiptVersion || !validKind(h.Kind) || h.ID != j.id || j.kind != "" && j.kind != h.Kind {
		return nil, ErrAuthentication
	}
	mac := hmac.New(sha256.New, j.key)
	_, _ = mac.Write([]byte(receiptVersion + "\x00" + h.Kind + "\x00" + filepath.Join(j.home, "transactions", "project", "tx-"+j.id) + "\x00" + name + "\x00"))
	_, _ = mac.Write(e.Payload)
	want, err := hex.DecodeString(e.MAC)
	if err != nil || !hmac.Equal(want, mac.Sum(nil)) {
		return nil, ErrAuthentication
	}
	if err = validatePayload(e.Payload, name, h.Kind, j); err != nil {
		return nil, err
	}
	if err = j.check(ctx, r); err != nil {
		return nil, err
	}
	if current, err := j.directory.observe(name); err != nil || current != fact {
		return nil, ErrAuthentication
	}
	j.kind = h.Kind
	return &AuthenticatedRecord{raw: raw, payload: e.Payload, digest: evidencecas.Digest(raw), epoch: j.keyDigest, name: name, kind: h.Kind, fact: fact}, nil
}
func validatePayload(raw []byte, name, kind string, j *Journal) error {
	if name == "plan.json" {
		var p wirePlan
		if canonicaljson.DecodeStrict(raw, &p) != nil {
			return ErrAuthentication
		}
		m := p.Material
		if (!j.historical && (m.Root != j.project.RootPath || m.ProjectID != j.project.ProjectID)) || !absoluteClean(m.Root) || overlaps(m.Root, j.home) || m.ProjectID == "" || m.Home != j.home || !m.Binding.Equal(j.stable.Binding()) || m.Before == nil || m.After == nil || m.ReadOnlyPaths == nil || len(m.Intent) == 0 {
			return ErrAuthentication
		}
		return nil
	}
	if kind == "NativeLinkTransaction" {
		var s wireLinkState
		if canonicaljson.DecodeStrict(raw, &s) != nil || s.Inventory == nil || s.Missing == nil {
			return ErrAuthentication
		}
		return nil
	}
	var s wireState
	if canonicaljson.DecodeStrict(raw, &s) != nil || s.Steps == nil {
		return ErrAuthentication
	}
	return nil
}
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	if j.self != j {
		return ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	clear(j.key)
	j.key = nil
	j.directory.close()
	j.keyDirectory.close()
	j.keyDirectory = nil
	j.directory = nil
	j.records = nil
	j.runtime = nil
	return nil
}
func validRecordName(n string) bool { return n == "plan.json" || n == "state.json" }
func validKind(k string) bool {
	return k == "NativeGeneratorTransaction" || k == "NativeUpdateTransaction" || k == "NativeLinkTransaction" || k == "NativeWorkspaceTransaction"
}
func validID(v string) bool {
	if len(v) != 32 || strings.ToLower(v) != v {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
func absoluteClean(v string) bool { return v != "" && filepath.IsAbs(v) && filepath.Clean(v) == v }
func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}
