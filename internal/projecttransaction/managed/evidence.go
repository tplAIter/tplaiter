// Package managed reconstructs authenticated clean managed projections for
// readers and planners. It grants no publication or execution authority.
package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

const LineagePath = ".tplaiter/managed-lineage.json"

var ErrLineage = formatproof.ErrRootLineage

// CleanProjection can only be constructed by fresh source/effect and observed
// control-image verification. Its contents are detached on every read.
type (
	cleanReader interface {
		RenderedFor(*renderref.Result) (*renderref.Result, error)
		Blocks() managedblocks.Baseline
	}
	CleanProjection struct{ owner cleanReader }
)

func (p *CleanProjection) RenderedFor(signed *renderref.Result) (*renderref.Result, error) {
	if p == nil || p.owner == nil {
		return nil, ErrLineage
	}
	return p.owner.RenderedFor(signed)
}

func (p *CleanProjection) Blocks() managedblocks.Baseline {
	if p == nil || p.owner == nil {
		return managedblocks.Baseline{}
	}
	return p.owner.Blocks()
}

// ReadNew verifies the current New lineage without importing approvals,
// creating runtime evidence or reexecuting completed formatter passes. Update
// and Link lineage have separate purpose-bound owners; they cannot use this
// New branch as a receipt or authority fallback.
func ReadNew(ctx context.Context, r *trustload.Runtime, home, renderer string) (*CleanProjection, error) {
	value, err := formatproof.ReadRootNew(ctx, r, home, renderer)
	if err != nil {
		return nil, err
	}
	return &CleanProjection{owner: value}, nil
}

// Read selects only an authenticated purpose-bound publication kind. Caller
// labels cannot choose a verifier or turn New effects into a Link projection.
func Read(ctx context.Context, r *trustload.Runtime, home, renderer string) (*CleanProjection, error) {
	return readCurrent(ctx, r, home, renderer, "")
}

func readCurrent(ctx context.Context, r *trustload.Runtime, home, renderer, requiredKind string) (*CleanProjection, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || renderer == "" {
		return nil, ErrLineage
	}
	root := r.ProjectContext().RootPath
	snapshot, err := stateledger.VerifyStable(ctx, root, r.TrustRuntime(), stateledger.StableVerifyOptions{})
	if err != nil {
		return nil, err
	}
	obs, err := projectverify.OpenObservation(ctx, root)
	if err != nil {
		return nil, err
	}
	defer obs.Close()
	raw, err := obs.ReadVerified(ctx, snapshot, LineagePath)
	if err != nil {
		return nil, err
	}
	var header struct {
		APIVersion string `json:"apiVersion"`
	}
	var projection *CleanProjection
	var images map[string][]byte
	if json.Unmarshal(raw, &header) == nil && header.APIVersion == "tplaiter.dev/managed-update-lineage/v1" {
		if requiredKind != "" {
			return nil, ErrLineage
		}
		controls := map[string][]byte{LineagePath: raw}
		// The committed material supplies the exact finite control inventory; the
		// observation then reads those files under the existing stable snapshot.
		intent, err := formatproof.CommittedUpdateIntent(ctx, r, home, raw)
		if err != nil {
			return nil, err
		}
		var material updateplan.UpdateMaterial
		if canonicaljson.DecodeStrict(intent, &material) != nil {
			return nil, ErrLineage
		}
		for name, file := range material.After {
			if strings.HasPrefix(name, ".tplaiter/") && !file.Directory {
				controls[name], err = obs.ReadVerified(ctx, snapshot, name)
				if err != nil {
					return nil, err
				}
			}
		}
		value, after, e := updateplan.ReadManagedUpdateProjection(ctx, r, home, renderer, controls)
		err = e
		images = after
		if err == nil {
			projection = &CleanProjection{owner: value}
		}
	} else {
		projection, images, err = reconstructProjection(ctx, r, home, renderer, raw, requiredKind)
	}
	if err != nil {
		return nil, err
	}
	for name, want := range images {
		if !strings.HasPrefix(name, ".tplaiter/") {
			continue
		}
		got, err := obs.ReadVerified(ctx, snapshot, name)
		if err != nil || !bytes.Equal(got, want) {
			return nil, ErrLineage
		}
	}
	fresh, err := stateledger.VerifyStable(ctx, root, r.TrustRuntime(), stateledger.StableVerifyOptions{})
	if err != nil {
		return nil, err
	}
	before, err := canonicaljson.Canonical(snapshot)
	if err != nil {
		return nil, err
	}
	after, err := canonicaljson.Canonical(fresh)
	if err != nil || !bytes.Equal(before, after) {
		return nil, ErrLineage
	}
	return projection, nil
}

// RenderedFor replaces only the clean file projection of the matching signed
// render. Ours and caller-built maps cannot become the upstream baseline.
// ReconstructNew verifies source/effect evidence against immutable beforeimage
// data. It never treats supplied maps as receipts or writer authority. Cold
// transaction callers must authenticate their native receipt and phase first.
// Reconstruct verifies the MAC-bound original publication against immutable
// control beforeimages. It returns only a clean reader projection, never a
// transaction or execution capability.
func Reconstruct(ctx context.Context, r *trustload.Runtime, home, renderer string, controls map[string][]byte) (*CleanProjection, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || renderer == "" || len(controls) > 16384 {
		return nil, ErrLineage
	}
	var header struct {
		APIVersion string `json:"apiVersion"`
	}
	if json.Unmarshal(controls[LineagePath], &header) == nil && header.APIVersion == "tplaiter.dev/managed-update-lineage/v1" {
		value, _, err := updateplan.ReadManagedUpdateProjection(ctx, r, home, renderer, controls)
		if err != nil {
			return nil, err
		}
		return &CleanProjection{owner: value}, nil
	}
	projection, images, err := reconstructProjection(ctx, r, home, renderer, controls[LineagePath], "")
	if err != nil {
		return nil, err
	}
	for name, want := range images {
		if strings.HasPrefix(name, ".tplaiter/") && !bytes.Equal(controls[name], want) {
			return nil, ErrLineage
		}
	}
	return projection, nil
}

func ReconstructNew(ctx context.Context, r *trustload.Runtime, home, renderer string, controls map[string][]byte) (*CleanProjection, error) {
	value, err := formatproof.ReconstructRootNew(ctx, r, home, renderer, controls)
	if err != nil {
		return nil, err
	}
	return &CleanProjection{owner: value}, nil
}

func reconstructNew(ctx context.Context, r *trustload.Runtime, home, renderer string, raw []byte) (*CleanProjection, map[string][]byte, error) {
	return reconstructProjection(ctx, r, home, renderer, raw, "new")
}

func reconstructProjection(ctx context.Context, r *trustload.Runtime, home, renderer string, raw []byte, requiredKind string) (*CleanProjection, map[string][]byte, error) {
	value, images, err := formatproof.ReconstructRootPublication(ctx, r, home, renderer, raw, requiredKind)
	if err != nil {
		return nil, nil, err
	}
	return &CleanProjection{owner: value}, images, nil
}
