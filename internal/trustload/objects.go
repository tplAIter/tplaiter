package trustload

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	maxRawObjectData   = 16 << 20
	maxRawObjectHeader = 128
)

// ObjectReader reads immutable, raw Git objects from roots registered in the
// authenticated RuntimeInstall. It deliberately has no checkout, ref, pack,
// process, or network fallback.
type ObjectReader struct {
	mu     sync.RWMutex
	roots  map[trustverify.SourceOrigin]*objectRoot
	closed bool
}

// NewObjectReader fixes each exact origin string to its installed object root.
// It does not normalize origins: doing so would turn a different source name
// into authority for a registered root.
func NewObjectReader(origins []ObjectOrigin) (*ObjectReader, error) {
	if len(origins) == 0 || len(origins) > maxEntries {
		return nil, ErrConfigInvalid
	}
	roots := make(map[trustverify.SourceOrigin]*objectRoot, len(origins))
	for _, entry := range origins {
		if !origin(entry.Origin) || !absolutePath(entry.RootPath) {
			return nil, ErrConfigInvalid
		}
		key := trustverify.SourceOrigin(entry.Origin)
		if _, found := roots[key]; found {
			for _, root := range roots {
				_ = root.Close()
			}
			return nil, ErrConfigInvalid
		}
		root, err := openObjectRoot(entry.RootPath)
		if err != nil {
			for _, opened := range roots {
				_ = opened.Close()
			}
			return nil, ErrProvenanceUnavailable
		}
		roots[key] = root
	}
	return &ObjectReader{roots: roots}, nil
}

// ReadObject implements trustverify.GitObjectReader. The object identity is
// intentionally rehashed by trustverify; this adapter authenticates only the
// registered origin and the raw-object wire form.
func (r *ObjectReader) ReadObject(ctx context.Context, source trustverify.SourceOrigin, id trustverify.ObjectID) (trustverify.GitObject, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !canonicalObjectID(string(id)) {
		return trustverify.GitObject{}, ErrProvenanceUnavailable
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return trustverify.GitObject{}, ErrProvenanceUnavailable
	}
	root, found := r.roots[source]
	if !found {
		return trustverify.GitObject{}, ErrProvenanceUnavailable
	}
	// id has already been constrained to a single canonical filename, so this
	// cannot select a subdirectory or an alternative object representation.
	raw, err := root.read(string(id))
	if err != nil || ctx.Err() != nil {
		return trustverify.GitObject{}, ErrProvenanceUnavailable
	}
	kind, data, err := parseRawObject(raw)
	if err != nil {
		return trustverify.GitObject{}, ErrProvenanceUnavailable
	}
	return trustverify.GitObject{Kind: kind, Data: data}, nil
}

func (r *ObjectReader) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var result error
	for _, root := range r.roots {
		result = errors.Join(result, root.Close())
	}
	r.roots = nil
	return result
}

func canonicalObjectID(id string) bool {
	if len(id) != 40 && len(id) != 64 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func parseRawObject(raw []byte) (string, []byte, error) {
	nul := -1
	for i, b := range raw {
		if b == 0 {
			nul = i
			break
		}
		if i >= maxRawObjectHeader {
			return "", nil, errors.New("raw object header too large")
		}
	}
	if nul <= 0 || nul > maxRawObjectHeader {
		return "", nil, errors.New("raw object header missing")
	}
	header := string(raw[:nul])
	space := strings.IndexByte(header, ' ')
	if space <= 0 || space == len(header)-1 || strings.IndexByte(header[space+1:], ' ') >= 0 {
		return "", nil, errors.New("raw object header invalid")
	}
	kind, sizeText := header[:space], header[space+1:]
	if kind != "commit" && kind != "tree" && kind != "blob" {
		return "", nil, errors.New("raw object kind invalid")
	}
	if (len(sizeText) > 1 && sizeText[0] == '0') || strings.ContainsAny(sizeText, "+-") {
		return "", nil, errors.New("raw object size noncanonical")
	}
	size, err := strconv.ParseUint(sizeText, 10, 64)
	if err != nil || size > maxRawObjectData || int64(len(raw)-nul-1) != int64(size) {
		return "", nil, errors.New("raw object size invalid")
	}
	return kind, append([]byte(nil), raw[nul+1:]...), nil
}
