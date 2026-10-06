// Package managed reconstructs authenticated clean managed projections for
// readers and planners. It grants no publication or execution authority.
package managed

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const LineagePath = ".tplaiter/managed-lineage.json"

var ErrLineage = errors.New("managed clean projection: invalid or unavailable authenticated lineage")

// CleanProjection can only be constructed by fresh source/effect and observed
// control-image verification. Its contents are detached on every read.
type CleanProjection struct {
	files    map[string][]byte
	baseline engine.Baseline
	blocks   managedblocks.Baseline
}

// ReadNew verifies the current New lineage without importing approvals,
// creating runtime evidence or reexecuting completed formatter passes. Update
// and Link lineage have separate purpose-bound owners; they cannot use this
// New branch as a receipt or authority fallback.
func ReadNew(ctx context.Context, r *trustload.Runtime, home, renderer string) (*CleanProjection, error) {
	return readCurrent(ctx, r, home, renderer, "new")
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
	projection, images, err := reconstructProjection(ctx, r, home, renderer, raw, requiredKind)
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
func (p *CleanProjection) RenderedFor(signed *renderref.Result) (*renderref.Result, error) {
	if p == nil || signed == nil || signed.Baseline == nil || signed.Baseline.ContextHash != p.baseline.ContextHash || signed.Baseline.TemplateVersion != p.baseline.TemplateVersion || len(signed.Files) != len(p.files) {
		return nil, ErrLineage
	}
	files := map[string][]byte{}
	for name, raw := range signed.Files {
		clean, ok := p.files[name]
		if !ok {
			return nil, ErrLineage
		}
		if !bytes.Contains(raw, []byte("tplater:managed-")) && !bytes.Equal(raw, clean) {
			return nil, ErrLineage
		}
		files[name] = append([]byte(nil), clean...)
	}
	result := *signed
	result.Files = files
	baseline := p.baseline
	baseline.Files = map[string]string{}
	for name, digest := range p.baseline.Files {
		baseline.Files[name] = digest
	}
	result.Baseline = &baseline
	return &result, nil
}

func (p *CleanProjection) Blocks() managedblocks.Baseline {
	if p == nil {
		return managedblocks.Baseline{}
	}
	return p.blocks.Clone()
}

// ReconstructNew verifies source/effect evidence against immutable beforeimage
// data. It never treats supplied maps as receipts or writer authority. Cold
// transaction callers must authenticate their native receipt and phase first.
func ReconstructNew(ctx context.Context, r *trustload.Runtime, home, renderer string, controls map[string][]byte) (*CleanProjection, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || renderer == "" || len(controls) > 16384 {
		return nil, ErrLineage
	}
	projection, images, err := reconstructNew(ctx, r, home, renderer, controls[LineagePath])
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

func reconstructNew(ctx context.Context, r *trustload.Runtime, home, renderer string, raw []byte) (*CleanProjection, map[string][]byte, error) {
	return reconstructProjection(ctx, r, home, renderer, raw, "new")
}

func reconstructProjection(ctx context.Context, r *trustload.Runtime, home, renderer string, raw []byte, requiredKind string) (*CleanProjection, map[string][]byte, error) {
	var locator struct {
		APIVersion            string                           `json:"apiVersion"`
		Publication           formatproof.PublicationReference `json:"publication"`
		RootLockSHA256        string                           `json:"rootLockSHA256"`
		ManagedBaselineSHA256 string                           `json:"managedBaselineSHA256"`
		FormatterFrames       map[string]string                `json:"formatterFrames"`
	}
	if canonicaljson.DecodeStrict(raw, &locator) != nil || locator.APIVersion != "tplaiter.dev/managed-lineage/v1" || locator.FormatterFrames == nil {
		return nil, nil, ErrLineage
	}
	kind, err := formatproof.PublicationKind(ctx, r, locator.Publication)
	if err != nil {
		return nil, nil, err
	}
	if requiredKind != "" && kind != requiredKind {
		return nil, nil, ErrLineage
	}
	var pub interface {
		ImagesFor(context.Context, *trustload.Runtime) (map[string][]byte, error)
		RegistryFor(*trustload.Runtime) (string, []byte, []byte, error)
	}
	switch kind {
	case "new":
		pub, err = formatproof.OpenNewPublication(ctx, r, locator.Publication)
	case "link":
		pub, err = formatproof.OpenLinkPublication(ctx, r, locator.Publication)
	default:
		return nil, nil, ErrLineage
	}
	if err != nil {
		return nil, nil, err
	}
	actualHome, _, _, err := pub.RegistryFor(r)
	if err != nil || actualHome != home {
		return nil, nil, ErrLineage
	}
	images, err := pub.ImagesFor(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(raw, images[LineagePath]) {
		return nil, nil, ErrLineage
	}
	lock, err := provenance.DecodeRootTemplateLock(images[".tplaiter/root-template.lock.json"])
	if err != nil || lock.Renderer.Version != renderer || lock.RootLockSHA256 != locator.RootLockSHA256 {
		return nil, nil, ErrLineage
	}
	var baseline engine.Baseline
	if canonicaljson.DecodeStrict(images[engine.BaselineRelPath], &baseline) != nil || baseline.Schema != engine.BaselineSchema || baseline.Files == nil {
		return nil, nil, ErrLineage
	}
	blocks, err := managedblocks.ParseBaseline(images[".tplaiter/managed-blocks.json"])
	if err != nil {
		return nil, nil, err
	}
	files := map[string][]byte{}
	for name := range baseline.Files {
		data, ok := images[name]
		if !ok {
			return nil, nil, ErrLineage
		}
		files[name] = append([]byte(nil), data...)
	}
	return &CleanProjection{files: files, baseline: baseline, blocks: blocks}, images, nil
}
