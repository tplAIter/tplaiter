// Package managedblocks contains pure managed-marker parsing and baseline
// models. It deliberately performs no filesystem, journal, or merge I/O.
package managedblocks

import (
	"fmt"

	"github.com/tplAIter/tplaiter/internal/provenance"
)

const SchemaVersion = 1

type ErrorCode string

const (
	CodeInvalidEncoding   ErrorCode = "invalid-encoding"
	CodeMalformedMarker   ErrorCode = "malformed-marker"
	CodeUnknownMarker     ErrorCode = "unknown-marker"
	CodeBeginWithoutEnd   ErrorCode = "begin-without-end"
	CodeEndWithoutBegin   ErrorCode = "end-without-begin"
	CodeEndIDMismatch     ErrorCode = "end-id-mismatch"
	CodeDuplicateID       ErrorCode = "duplicate-id"
	CodeNestedRegion      ErrorCode = "nested-region"
	CodeOverlappingRegion ErrorCode = "overlapping-region"
	CodeMarkerNotComment  ErrorCode = "marker-not-comment"
)

type Error struct {
	Path string
	Line int
	Code ErrorCode
	ID   string
}

func (e *Error) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("managed blocks: %s:%d: %s (%s)", e.Path, e.Line, e.Code, e.ID)
	}
	return fmt.Sprintf("managed blocks: %s:%d: %s", e.Path, e.Line, e.Code)
}

type Region struct {
	ID                                   string
	Provider                             string
	Begin, Body, End                     []byte
	BeginLine, EndLine, Ordinal          int
	Start, BodyStart, BodyEnd, EndOffset int
}

func (r Region) Bytes() []byte {
	out := make([]byte, 0, len(r.Begin)+len(r.Body)+len(r.End))
	out = append(out, r.Begin...)
	out = append(out, r.Body...)
	out = append(out, r.End...)
	return out
}

type Document struct {
	Prefix  []byte
	Regions []Region
	Suffix  []byte
	ByID    map[string]Region
	Gaps    [][]byte
}

// ProviderSource binds marker provider labels to the existing provenance model.
type ProviderSource struct {
	Provider string
	Source   provenance.RootSubject
}

type SkeletonBaseline struct {
	Body       string `json:"body"`
	BodySHA256 string `json:"bodySHA256"`
}
type BlockState string

const (
	StatePresent                      BlockState = "present"
	StateLocalDeleted                 BlockState = "local-deleted"
	StateUpstreamDeletedLocalRetained BlockState = "upstream-deleted-local-retained"
)

type TombstoneSide string

const (
	TombstoneLocal    TombstoneSide = "local"
	TombstoneUpstream TombstoneSide = "upstream"
)

type Tombstone struct {
	Side       TombstoneSide          `json:"side"`
	Provider   string                 `json:"provider"`
	Source     provenance.RootSubject `json:"source"`
	BodySHA256 string                 `json:"bodySHA256"`
}

type Anchor struct {
	Before  string `json:"before"`
	After   string `json:"after"`
	Ordinal int    `json:"ordinal"`
}
type BlockBaseline struct {
	Provider   string                 `json:"provider"`
	Source     provenance.RootSubject `json:"source"`
	Body       string                 `json:"body"`
	BodySHA256 string                 `json:"bodySHA256"`
	Anchor     Anchor                 `json:"anchor"`
	State      BlockState             `json:"state"`
	Tombstone  *Tombstone             `json:"tombstone,omitempty"`
}
type FileBaseline struct {
	Skeleton SkeletonBaseline         `json:"skeleton"`
	Blocks   map[string]BlockBaseline `json:"blocks"`
}
type Baseline struct {
	Schema int                     `json:"schema"`
	Files  map[string]FileBaseline `json:"files"`
}

func cloneBytes(v []byte) []byte                                       { return append([]byte(nil), v...) }
func cloneRootSubject(v provenance.RootSubject) provenance.RootSubject { return v }
