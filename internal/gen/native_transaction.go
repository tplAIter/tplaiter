package gen

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// NativeFile is untrusted transport when decoded. Authentication and semantic
// reconstruction are mandatory before recovery; no setter mints a NativePlan.
type NativeFile struct {
	Data      NativeBytes `json:"data"`
	Mode      uint32      `json:"mode"`
	Directory bool        `json:"directory"`
	Device    uint64      `json:"device"`
	Inode     uint64      `json:"inode"`
}
type NativeMaterial struct {
	Version     int                      `json:"version"`
	Root        string                   `json:"root"`
	Home        string                   `json:"home"`
	ProjectID   string                   `json:"projectID"`
	Binding     bootstrap.ProfileBinding `json:"binding"`
	Operations  []NativeOperation        `json:"operations"`
	Before      map[string]NativeFile    `json:"before"`
	After       map[string]NativeFile    `json:"after"`
	Fingerprint string                   `json:"fingerprint"`
}

func nativeWire(images map[string]nativeImage) map[string]NativeFile {
	out := map[string]NativeFile{}
	for name, image := range images {
		device, inode := nativeFileID(image.info)
		out[name] = NativeFile{Data: append(NativeBytes{}, image.data...), Mode: uint32(image.mode), Directory: image.dir, Device: device, Inode: inode}
	}
	return out
}

func nativeFingerprint(m NativeMaterial) (string, error) {
	m.Fingerprint = ""
	raw, err := canonicaljson.Canonical(m)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// TransactionMaterial derives a detached material from this private plan after
// a fresh authenticated replan. The writer accepts the concrete NativePlan,
// never an arbitrary NativeMaterial or caller-provided signature.
func (p *NativePlan) TransactionMaterial(ctx context.Context) (NativeMaterial, *trustload.Runtime, error) {
	return p.transactionMaterial(ctx, false)
}

// TransactionMaterialAfterLease admits only the engine's narrowly designated
// empty persistent update lock in addition to the original observation. The
// adapter must check its actual held descriptor against this fresh image.
// This remains transport from an opaque signed plan, not a write capability.
func (p *NativePlan) TransactionMaterialAfterLease(ctx context.Context) (NativeMaterial, *trustload.Runtime, error) {
	return p.transactionMaterial(ctx, true)
}

func (p *NativePlan) transactionMaterial(ctx context.Context, afterLease bool) (NativeMaterial, *trustload.Runtime, error) {
	if p == nil || p.runtime == nil {
		return NativeMaterial{}, nil, ErrNativeIdentityUnavailable
	}
	fresh, err := PlanNative(ctx, p.runtime, p.home, p.operations)
	if err != nil {
		return NativeMaterial{}, nil, err
	}
	compareBefore, compareAfter := nativeClone(fresh.before), nativeClone(fresh.after)
	if afterLease {
		const lockPath = ".tplaiter/update.lock"
		if _, existed := p.before[lockPath]; !existed {
			lock, exists := fresh.before[lockPath]
			if !exists || lock.dir || lock.mode != 0o600 || len(lock.data) != 0 || lock.info == nil || !nativeSingleLink(lock.info) {
				return NativeMaterial{}, nil, ErrNativeOwnership
			}
			delete(compareBefore, lockPath)
			delete(compareAfter, lockPath)
		}
	}
	if !nativeEqual(p.before, compareBefore) || !nativeEqual(p.after, compareAfter) {
		return NativeMaterial{}, nil, ErrNativeOwnership
	}
	m := NativeMaterial{Version: 1, Root: p.root, Home: p.home, ProjectID: p.markerID, Binding: p.runtime.TrustRuntime().Binding(), Operations: cloneNativeOperations(p.operations), Before: nativeWire(fresh.before), After: nativeWire(fresh.after)}
	m.Fingerprint, err = nativeFingerprint(m)
	return m, p.runtime, err
}

// AuthenticateNativeMaterial is a semantic check, not a signing API or write
// capability. The transaction owner first authenticates its immutable receipt.
// It then reconstructs the generator plan from fresh signed source material.
func AuthenticateNativeMaterial(ctx context.Context, runtime *trustload.Runtime, m NativeMaterial) error {
	if m.Version != 1 || runtime == nil || runtime.TrustRuntime() == nil || runtime.ProjectContext().RootPath != m.Root || !runtime.TrustRuntime().Binding().Equal(m.Binding) {
		return ErrNativeIdentityUnavailable
	}
	if err := nativeIdentity(ctx, runtime, m.Root, m.ProjectID); err != nil {
		return err
	}
	before := map[string]nativeImage{}
	for name, file := range m.Before {
		before[name] = nativeImage{data: append([]byte(nil), file.Data...), mode: fs.FileMode(file.Mode), dir: file.Directory}
	}
	p, err := buildNativeFromImages(ctx, runtime, m.Home, before, m.Operations)
	if err != nil {
		return err
	}
	rebuilt := m
	rebuilt.After = nativeWire(p.after)
	// Existing inode identities are immutable transaction observations, never
	// source authority. Preserve them only where the authenticated beforeimage
	// and reconstructed afterimage refer to the same original path.
	for name, file := range rebuilt.After {
		if original, ok := m.Before[name]; ok {
			file.Device, file.Inode = original.Device, original.Inode
			rebuilt.After[name] = file
		}
	}
	digest, err := nativeFingerprint(rebuilt)
	if err != nil || digest != m.Fingerprint {
		return errors.Join(ErrNativeOwnership, err)
	}
	return nil
}

// NativeBytes uses an explicit integer array: strict wire decoding rejects nulls
// and byte slices encoded as ambient base64 strings. Empty directories carry [].
type NativeBytes []byte

func (b NativeBytes) MarshalJSON() ([]byte, error) {
	values := make([]uint16, len(b))
	for i, v := range b {
		values[i] = uint16(v)
	}
	return json.Marshal(values)
}

func (b *NativeBytes) UnmarshalJSON(raw []byte) error {
	var values []uint16
	if err := json.Unmarshal(raw, &values); err != nil {
		return err
	}
	if values == nil {
		return ErrNativeOwnership
	}
	out := make(NativeBytes, len(values))
	for i, v := range values {
		if v > 255 {
			return ErrNativeOwnership
		}
		out[i] = byte(v)
	}
	*b = out
	return nil
}
