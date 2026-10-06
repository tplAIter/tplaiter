package deps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// SourceReader is the narrow bridge from a stable, already-verified source
// resolution to immutable source bytes. It owns no provider, cache, resolver,
// filesystem, network, or process capability.
type SourceReader struct{ runtime *trustverify.Runtime }

func NewSourceReader(runtime *trustverify.Runtime) (*SourceReader, error) {
	if runtime == nil {
		return nil, sourceError(SourceInvalid, "nil stable runtime")
	}
	return &SourceReader{runtime: runtime}, nil
}

// VerifiedSource is a defensive copy of the snapshot material that matched a
// PinnedSource. Its values cannot be used as proof for another runtime.
type VerifiedSource struct {
	subject     trustverify.Subject
	entries     []trustverify.SourceEntry
	contract    []byte
	blobs       map[string][]byte
	acceptedPin *PinnedSource
}

// AcceptedPin returns the exact data pin accepted by Read, not a new authority.
// ProviderID and RequestedRef remain caller-selected provenance labels.
func (s *VerifiedSource) AcceptedPin() (PinnedSource, bool) {
	if s == nil || s.acceptedPin == nil {
		return PinnedSource{}, false
	}
	return copyAcceptedPin(*s.acceptedPin), true
}

func copyAcceptedPin(pin PinnedSource) PinnedSource {
	pin.Parameters = append([]Parameter{}, pin.Parameters...)
	for i := range pin.Parameters {
		pin.Parameters[i].Value = append([]byte(nil), pin.Parameters[i].Value...)
	}
	pin.Dependencies = append([]string{}, pin.Dependencies...)
	return pin
}

func (s *VerifiedSource) Subject() trustverify.Subject {
	if s == nil {
		return trustverify.Subject{}
	}
	return s.subject
}

func (s *VerifiedSource) Entries() []trustverify.SourceEntry {
	if s == nil {
		return nil
	}
	return append([]trustverify.SourceEntry(nil), s.entries...)
}

func (s *VerifiedSource) ContractBytes() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.contract...)
}

func (s *VerifiedSource) Blob(name string) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	b, ok := s.blobs[name]
	return append([]byte(nil), b...), ok
}

// Read projects the retained runtime snapshot without re-verifying or loading
// anything, then checks the pin against its subject, retained evidence marker,
// complete content closure, contract bytes, and every file blob.
func (r *SourceReader) Read(ctx context.Context, resolution *trustverify.VerifiedResolution, pin PinnedSource) (*VerifiedSource, error) {
	if r == nil || r.runtime == nil || ctx == nil {
		return nil, sourceError(SourceInvalid, "nil source reader, runtime, or context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validatePinnedSource(pin); err != nil {
		return nil, err
	}
	snapshot, err := r.runtime.VerifiedSnapshot(resolution)
	if err != nil {
		return nil, sourceError(SourceSnapshotUnavailable, "stable runtime-bound snapshot unavailable")
	}
	if snapshot == nil {
		return nil, sourceError(SourceInvalid, "missing retained snapshot")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	subject := snapshot.Subject()
	if subject.Origin != pin.Origin || subject.TemplatePath != pin.TemplatePath || subject.Commit != pin.Commit || subject.TreeSHA256 != pin.TreeDigest || subject.ContractSHA256 != pin.ContractDigest {
		return nil, sourceError(SourceInvalid, "snapshot subject does not match immutable pin")
	}
	if refs := resolution.Evidence(); refs.StatementCAS != pin.EvidenceDigest {
		return nil, sourceError(SourceEvidenceMismatch, "snapshot evidence does not match immutable pin")
	}
	entries := snapshot.Entries()
	if !sort.SliceIsSorted(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path }) {
		return nil, sourceError(SourceInvalid, "snapshot entries are not ordered")
	}
	blobs := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.Kind == "directory" {
			continue
		}
		b, ok := snapshot.Blob(entry.Path)
		if !ok || byteDigest(b) != entry.ContentSHA256 {
			return nil, sourceError(SourceContentMismatch, "snapshot blob content mismatch")
		}
		blobs[entry.Path] = append([]byte(nil), b...)
	}
	contract := snapshot.ContractBytes()
	if len(contract) == 0 {
		return nil, sourceError(SourceInvalid, "snapshot contract missing")
	}
	if b, ok := blobs["template.contract.json"]; !ok || string(b) != string(contract) {
		return nil, sourceError(SourceContentMismatch, "snapshot contract content mismatch")
	}
	content, err := snapshotContentDigest(entries)
	if err != nil {
		return nil, err
	}
	if pin.ContentDigest != content {
		return nil, sourceError(SourceContentMismatch, "snapshot content does not match immutable pin")
	}
	accepted := copyAcceptedPin(pin)
	return &VerifiedSource{acceptedPin: &accepted, subject: subject, entries: append([]trustverify.SourceEntry(nil), entries...), contract: append([]byte(nil), contract...), blobs: blobs}, nil
}

// SnapshotContentDigest returns the exact content-closure digest expected in a
// pin. It uses the ordered verified entry records, whose file digests were
// recomputed by Read before this value is accepted.
func SnapshotContentDigest(entries []trustverify.SourceEntry) (string, error) {
	return snapshotContentDigest(entries)
}

func snapshotContentDigest(entries []trustverify.SourceEntry) (string, error) {
	copyEntries := append([]trustverify.SourceEntry(nil), entries...)
	if !sort.SliceIsSorted(copyEntries, func(i, j int) bool { return copyEntries[i].Path < copyEntries[j].Path }) {
		return "", sourceError(SourceInvalid, "snapshot entries are not ordered")
	}
	b, err := canonicaljson.Canonical(struct {
		Entries []trustverify.SourceEntry `json:"entries"`
	}{Entries: copyEntries})
	if err != nil {
		return "", fmt.Errorf("deps: canonical snapshot content: %w", err)
	}
	return byteDigest(b), nil
}

func byteDigest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
