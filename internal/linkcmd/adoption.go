package linkcmd

import (
	"bytes"
	"sort"
	"time"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"gopkg.in/yaml.v3"
)

// ProjectAdoption is deterministic transport reconstruction, not admission.
// A recovery caller must first authenticate the engine's original observations.
func ProjectAdoption(images map[string][]byte, in Input, renderer string, stamp time.Time, before map[string]File) (map[string][]byte, error) {
	paths := []string{}
	for p, c := range in.Choices {
		if c == "user-owned" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return images, nil
	}
	if in.Action != "adopt" {
		return nil, ErrInput
	}
	root, err := provenance.DecodeRootTemplateLock(images[".tplaiter/root-template.lock.json"])
	if err != nil {
		return nil, err
	}
	var marker stateledger.ProjectV2
	if err = yaml.Unmarshal(images[".tplaiter/project.yaml"], &marker); err != nil {
		return nil, err
	}
	renderHash, err := adoptionpolicy.Digest(struct {
		Name, Module string
		Sets         []string
		Port         int
	}{in.Name, in.Module, append([]string{}, in.Sets...), in.Port})
	if err != nil {
		return nil, err
	}
	origin := adoptionpolicy.Origin{ProjectID: marker.ID, Binding: root.TrustProfile, SourceRootLockSHA256: root.RootLockSHA256, SourceCommit: in.Ref, RendererVersion: renderer, RenderInputsSHA256: renderHash, DecisionAt: stamp.Format(time.RFC3339Nano), Exclusions: []adoptionpolicy.Exclusion{}}
	for _, p := range paths {
		signed, ok := images[p]
		if !ok || !adoptionpolicy.Eligible(p) || bytes.Contains(signed, []byte("tplater:managed-")) {
			return nil, ErrInput
		}
		observed := adoptionpolicy.Observation{SHA256: evidencecas.Digest(nil)}
		state := "missing"
		if f, ok := before[p]; ok {
			if f.Directory || f.Mode > 0o777 {
				return nil, ErrState
			}
			observed = adoptionpolicy.Observation{Exists: true, Mode: f.Mode, Device: f.Device, Inode: f.Inode, SHA256: evidencecas.Digest(f.Data)}
			state = "modified"
			if f.Mode == 0o644 && bytes.Equal(f.Data, signed) {
				return nil, ErrInput
			}
		}
		origin.Exclusions = append(origin.Exclusions, adoptionpolicy.Exclusion{Path: p, SourceSHA256: evidencecas.Digest(signed), SourceMode: 0o644, InitialState: state, Observed: observed})
	}
	policy, err := adoptionpolicy.New(origin)
	if err != nil {
		return nil, err
	}
	marker.Ownership, err = policy.Map()
	if err != nil {
		return nil, err
	}
	// Filter the complete signed inventory, retaining native resource hashes.
	var inventory ownership.Inventory
	if canonicaljson.DecodeStrict(images[".tplaiter/ownership.json"], &inventory) != nil || inventory.Version != 1 || len(inventory.Skipped) != 0 || len(inventory.Tombstones) != 0 {
		return nil, ErrState
	}
	artifacts := make([]ownership.Artifact, 0, len(inventory.Artifacts))
	for _, a := range inventory.Artifacts {
		if !policy.Contains(a.Path) {
			artifacts = append(artifacts, a)
		}
	}
	inventory.Artifacts = artifacts
	inventory.Tombstones = policy.Missing()
	for _, p := range policy.Paths() {
		inventory.Skipped = append(inventory.Skipped, ownership.Decision{Path: p, Reason: "user-owned"})
	}
	b, err := canonicaljson.Canonical(inventory)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for p, b := range images {
		out[p] = bytes.Clone(b)
	}
	out[".tplaiter/ownership.json"] = b
	out[".tplaiter/project.yaml"], err = yaml.Marshal(marker)
	return out, err
}
