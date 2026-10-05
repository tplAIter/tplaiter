package adoptionpolicy

import (
	"reflect"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/ownership"
)

// Inventory retains desired signed hashes only. Policy data is not authority.
func Inventory(files map[string][]byte, p *Policy) (ownership.Inventory, error) {
	out := ownership.Inventory{Version: 1, Artifacts: []ownership.Artifact{}}
	if p != nil && p.Validate() != nil {
		return out, ErrPolicy
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if p.Contains(path) {
			continue
		}
		a, e := ownership.ArtifactFor(path, files[path], 0o644, "")
		if e != nil {
			return out, e
		}
		a.Kind = ""
		out.Artifacts = append(out.Artifacts, a)
	}
	if p != nil {
		for _, x := range p.Origin.Exclusions {
			out.Skipped = append(out.Skipped, ownership.Decision{Path: x.Path, Reason: "user-owned"})
		}
		out.Tombstones = p.Missing()
		if len(out.Tombstones) == 0 {
			out.Tombstones = nil
		}
	}
	return out, nil
}
func ValidateInventory(raw []byte, files map[string][]byte, p *Policy) error {
	var got ownership.Inventory
	if canonicaljson.DecodeStrict(raw, &got) != nil {
		return ErrPolicy
	}
	want, e := Inventory(files, p)
	if e != nil {
		return e
	}
	// Normalize supported regular-file encoding and optional empty arrays only.
	for i := range got.Artifacts {
		if got.Artifacts[i].Kind == ownership.KindFile {
			got.Artifacts[i].Kind = ""
		}
	}
	if len(got.Artifacts) == 0 {
		got.Artifacts = []ownership.Artifact{}
	}
	if len(got.Skipped) == 0 {
		got.Skipped = nil
	}
	if len(got.Tombstones) == 0 {
		got.Tombstones = nil
	}
	if !reflect.DeepEqual(got, want) {
		return ErrPolicy
	}
	return nil
}
func ValidateOrigin(p *Policy, files map[string][]byte, observed map[string]Observation) error {
	if p == nil || p.Validate() != nil {
		return ErrPolicy
	}
	for _, x := range p.Origin.Exclusions {
		b, ok := files[x.Path]
		if !ok || strings.Contains(string(b), "tplater:managed-") || evidencecas.Digest(b) != x.SourceSHA256 {
			return ErrPolicy
		}
		v, ok := observed[x.Path]
		if !ok {
			v = Observation{SHA256: evidencecas.Digest(nil)}
		}
		if v != x.Observed || v.Exists && v.Mode == 0o644 && v.SHA256 == x.SourceSHA256 {
			return ErrPolicy
		}
	}
	return nil
}
