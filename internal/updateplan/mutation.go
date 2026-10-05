package updateplan

import (
	"bytes"
	"context"
	"path"
	"sort"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

// mutationIntent is a private, read-only bridge candidate. It is not a durable
// schema, a writer grant or a caller-constructible transaction capability. The
// accepted transaction owner must rebuild it under its actual retained lease.
type mutationIntent struct {
	plan     *Plan // fresh proof, complete read set and private inode observations
	changes  []mutationImage
	registry RegistryImage
}

type exactImage struct {
	image Image
	data  []byte
}

// nil explicitly represents absence; a zero-byte file is a non-nil image.
// Directories carry kind/mode separately and have no data.
type mutationImage struct {
	path          string
	before, after *exactImage
}

func (b *Backend) prepareMutation(ctx context.Context, p *Plan, expected string) (*mutationIntent, error) {
	fresh, err := b.recheckPlan(ctx, p, expected)
	if err != nil {
		return nil, err
	}
	if !fresh.report.Publishable {
		return nil, ErrConflict
	}
	target, err := b.sourceImages(ctx, fresh.input.TargetInput, fresh.report.Target)
	if err != nil {
		return nil, err
	}
	if !resourceChangesValid(fresh.report.Changes, target, fresh.report.Target) {
		return nil, ErrConflict
	}
	return buildMutation(fresh)
}

// buildMutation only receives a fresh opaque preparation from prepareMutation.
// All foreign/unchanged images remain in the private read set, not the write set.
func buildMutation(p *Plan) (*mutationIntent, error) {
	out := &mutationIntent{plan: p, registry: p.report.Registry}
	out.registry.BeforeContent = bytes.Clone(out.registry.BeforeContent)
	out.registry.AfterContent = bytes.Clone(out.registry.AfterContent)
	known := map[string]Image{}
	for _, image := range p.observed.images {
		known[image.Path] = image
	}
	parents := map[string]bool{}
	seen := map[string]bool{}
	for _, c := range p.report.Changes {
		if (c.Conflict && !settingsConflictPublication(p.input, c)) || !safePath(c.Path) || seen[c.Path] {
			return nil, ErrUnsafe
		}
		seen[c.Path] = true
		before, exists := known[c.Path]
		if (c.Before != nil) != exists || (exists && before != *c.Before) {
			return nil, ErrStale
		}
		if c.Operation == "keep" {
			if (c.Before == nil) != (c.After == nil) || (exists && *c.Before != *c.After) {
				return nil, ErrUnsafe
			}
			continue
		}
		if protectsMutation(p.policy, c.Path) {
			return nil, ErrUnsafe
		}
		item := mutationImage{path: c.Path}
		if exists {
			if before.Kind != "file" || before.SHA256 != evidencecas.Digest(p.observed.files[c.Path]) {
				return nil, ErrUnsafe
			}
			item.before = &exactImage{image: before, data: bytes.Clone(p.observed.files[c.Path])}
		}
		switch c.Operation {
		case "write":
			if c.After == nil || c.After.Path != c.Path || c.After.Kind != "file" || c.After.Mode != 0o644 || c.After.SHA256 != evidencecas.Digest(c.Content) {
				return nil, ErrUnsafe
			}
			item.after = &exactImage{image: *c.After, data: bytes.Clone(c.Content)}
			for parent := path.Dir(c.Path); parent != "."; parent = path.Dir(parent) {
				if image, ok := known[parent]; ok {
					if image.Kind != "directory" {
						return nil, ErrUnsafe
					}
					continue
				}
				parents[parent] = true
			}
		case "delete":
			if !exists || c.After != nil {
				return nil, ErrUnsafe
			}
		default:
			return nil, ErrUnsafe
		}
		out.changes = append(out.changes, item)
	}
	for parent := range parents {
		if protectsMutation(p.policy, parent) {
			return nil, ErrUnsafe
		}
		if seen[parent] {
			return nil, ErrUnsafe
		}
		out.changes = append(out.changes, mutationImage{path: parent, after: &exactImage{image: Image{Path: parent, Kind: "directory", Mode: 0o755, SHA256: evidencecas.Digest(nil)}}})
	}
	if len(out.changes) > maxFiles {
		return nil, ErrUnsafe
	}
	// Parent-before-child order is deterministic. Existing directories are never
	// chmodded or removed, and deletes contain the exact observed file preimage.
	sort.Slice(out.changes, func(i, j int) bool { return out.changes[i].path < out.changes[j].path })
	return out, nil
}
