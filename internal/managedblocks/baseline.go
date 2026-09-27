package managedblocks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/provenance"
)

var baselineDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var baselineProviderRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._/-]{0,127}$`)

func BuildBaseline(files map[string][]byte, providers []ProviderSource, prior *Baseline) (Baseline, error) {
	providerMap := make(map[string]ProviderSource, len(providers))
	for _, p := range providers {
		if !baselineProviderRE.MatchString(p.Provider) || !validSource(p.Source) {
			return Baseline{}, fmt.Errorf("managed blocks: invalid provider source %s", p.Provider)
		}
		if _, ok := providerMap[p.Provider]; ok {
			return Baseline{}, fmt.Errorf("managed blocks: duplicate provider %s", p.Provider)
		}
		providerMap[p.Provider] = p
	}
	out := Baseline{Schema: SchemaVersion, Files: make(map[string]FileBaseline, len(files))}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, filePath := range paths {
		if err := validatePath(filePath); err != nil {
			return Baseline{}, err
		}
		doc, err := Parse(filePath, files[filePath])
		if err != nil {
			return Baseline{}, err
		}
		skel := make([]byte, 0, len(files[filePath]))
		for _, gap := range doc.Gaps {
			skel = append(skel, gap...)
		}
		fb := FileBaseline{Skeleton: SkeletonBaseline{Body: string(skel), BodySHA256: bodyDigest(skel)}, Blocks: make(map[string]BlockBaseline, len(doc.Regions))}
		for _, r := range doc.Regions {
			p, ok := providerMap[r.Provider]
			if !ok {
				return Baseline{}, fmt.Errorf("managed blocks: missing provider %s", r.Provider)
			}
			anchor := Anchor{Ordinal: r.Ordinal}
			if r.Ordinal > 0 {
				anchor.After = doc.Regions[r.Ordinal-1].ID
			}
			if r.Ordinal+1 < len(doc.Regions) {
				anchor.Before = doc.Regions[r.Ordinal+1].ID
			}
			fb.Blocks[r.ID] = BlockBaseline{Provider: r.Provider, Source: cloneRootSubject(p.Source), Body: string(r.Body), BodySHA256: bodyDigest(r.Body), Anchor: anchor, State: StatePresent}
		}
		out.Files[filePath] = fb
	}
	if prior != nil {
		for filePath, old := range prior.Files {
			if _, ok := out.Files[filePath]; ok {
				continue
			}
			if err := validatePath(filePath); err != nil {
				return Baseline{}, err
			}
			out.Files[filePath] = cloneFileBaseline(old)
		}
	}
	return out, nil
}

func (b Baseline) Clone() Baseline {
	out := Baseline{Schema: b.Schema, Files: make(map[string]FileBaseline, len(b.Files))}
	for p, f := range b.Files {
		out.Files[p] = cloneFileBaseline(f)
	}
	return out
}
func cloneFileBaseline(f FileBaseline) FileBaseline {
	out := FileBaseline{Skeleton: SkeletonBaseline{Body: f.Skeleton.Body, BodySHA256: f.Skeleton.BodySHA256}, Blocks: make(map[string]BlockBaseline, len(f.Blocks))}
	for id, v := range f.Blocks {
		v.Body = string([]byte(v.Body))
		v.Source = cloneRootSubject(v.Source)
		if v.Tombstone != nil {
			x := *v.Tombstone
			x.Source = cloneRootSubject(x.Source)
			v.Tombstone = &x
		}
		out.Blocks[id] = v
	}
	return out
}

func (b Baseline) Validate() error {
	if b.Schema != SchemaVersion || b.Files == nil {
		return fmt.Errorf("managed blocks: invalid baseline schema or files")
	}
	for p, f := range b.Files {
		if err := validatePath(p); err != nil {
			return err
		}
		if f.Blocks == nil {
			return fmt.Errorf("managed blocks: blocks missing for %s", p)
		}
		if err := validateSkeleton(f.Skeleton); err != nil {
			return fmt.Errorf("managed blocks: skeleton %s: %w", p, err)
		}
		ords := map[int]bool{}
		for id, block := range f.Blocks {
			if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`).MatchString(id) || !baselineProviderRE.MatchString(block.Provider) || !validSource(block.Source) || block.BodySHA256 != bodyDigest([]byte(block.Body)) || !validBlockState(block) {
				return fmt.Errorf("managed blocks: invalid block %s/%s", p, id)
			}
			if ords[block.Anchor.Ordinal] {
				return fmt.Errorf("managed blocks: duplicate ordinal %s", p)
			}
			ords[block.Anchor.Ordinal] = true
		}
	}
	return nil
}
func validBlockState(block BlockBaseline) bool {
	if block.State == StatePresent {
		return block.Tombstone == nil
	}
	if block.State != StateLocalDeleted && block.State != StateUpstreamDeletedLocalRetained {
		return false
	}
	if block.Tombstone == nil || !baselineProviderRE.MatchString(block.Tombstone.Provider) || !validSource(block.Tombstone.Source) || block.Tombstone.BodySHA256 != block.BodySHA256 {
		return false
	}
	if block.Tombstone.Provider != block.Provider || block.Tombstone.Source != block.Source {
		return false
	}
	return (block.State == StateLocalDeleted && block.Tombstone.Side == TombstoneLocal) || (block.State == StateUpstreamDeletedLocalRetained && block.Tombstone.Side == TombstoneUpstream)
}
func validateSkeleton(s SkeletonBaseline) error {
	if !utf8.ValidString(s.Body) || strings.IndexByte(s.Body, 0) >= 0 || s.BodySHA256 != bodyDigest([]byte(s.Body)) {
		return fmt.Errorf("invalid skeleton")
	}
	return nil
}
func validSource(s provenance.RootSubject) bool {
	return s.Validate() == nil
}

func (b Baseline) Marshal() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	raw, err := canonicaljson.Canonical(b)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
func SaveBytes(b Baseline) ([]byte, error) { return b.Marshal() }
func ParseBaseline(data []byte) (Baseline, error) {
	if _, err := canonicaljson.Canonicalize(data); err != nil {
		return Baseline{}, fmt.Errorf("managed blocks: inspect baseline JSON: %w", err)
	}
	var b Baseline
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("managed blocks: decode baseline: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return Baseline{}, fmt.Errorf("managed blocks: multiple JSON values")
	}
	if err := b.Validate(); err != nil {
		return Baseline{}, err
	}
	return b, nil
}
func bodyDigest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func validatePath(p string) error {
	if p == "" || path.IsAbs(p) || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) || strings.Contains(p, ":") {
		return fmt.Errorf("managed blocks: invalid path %q", p)
	}
	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, ".git/") || strings.HasPrefix(clean, ".tplater/") {
		return fmt.Errorf("managed blocks: invalid path %q", p)
	}
	return nil
}
