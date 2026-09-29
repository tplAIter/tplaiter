// Package trustverify contains pure verification primitives for trusted source
// snapshots. It deliberately does not open files, fetch objects, or mint trust.
package trustverify

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git object IDs are SHA-1 by format, not a security choice
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const (
	maxCommitTreeObject = 1 << 20
	maxBlobObject       = 16 << 20
	maxContractObject   = 1 << 20
	maxSourceBytes      = 64 << 20
	maxEntries          = 4096
	maxReads            = 8192
	maxComponents       = 64
	maxPathBytes        = 4096
	maxPathRunes        = 1024
)

type (
	SourceOrigin string
	ObjectID     string
)

type GitObject struct {
	Kind string
	Data []byte
}

type GitObjectReader interface {
	ReadObject(context.Context, SourceOrigin, ObjectID) (GitObject, error)
}

type Subject struct {
	Origin         string
	TemplatePath   string
	RequestedRef   string
	Commit         string
	TreeSHA256     string
	ContractSHA256 string
}

type SourceLimits struct {
	MaxReads, MaxEntries, MaxDepth int
	MaxSourceBytes                 int64
}

func DefaultSourceLimits() SourceLimits {
	return SourceLimits{maxReads, maxEntries, maxComponents, maxSourceBytes}
}

type SourceEntry struct {
	Path          string `json:"path"`
	Kind          string `json:"kind"`
	Mode          string `json:"mode"`
	ContentSHA256 string `json:"contentSHA256,omitempty"`
}

type SourceSnapshot struct {
	subject  Subject
	entries  []SourceEntry
	contract []byte
	blobs    map[string][]byte
}

func (s *SourceSnapshot) Subject() Subject { return s.subject }
func (s *SourceSnapshot) Entries() []SourceEntry {
	if s == nil {
		return nil
	}
	r := append([]SourceEntry(nil), s.entries...)
	return r
}

func (s *SourceSnapshot) ContractBytes() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.contract...)
}

func (s *SourceSnapshot) Blob(path string) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	b, ok := s.blobs[path]
	return append([]byte(nil), b...), ok
}

// VerifySource reads and verifies the immutable Git object closure for subject.
func VerifySource(ctx context.Context, reader GitObjectReader, subject Subject) (*SourceSnapshot, error) {
	return VerifySourceWithLimits(ctx, reader, subject, DefaultSourceLimits())
}

// VerifyDevelopmentSource accepts a diagnostic mutable requested reference but
// still reads only the pinned commit. It is deliberately separate from the
// stable entry point, whose locator must be an exact commit.
func VerifyDevelopmentSource(ctx context.Context, reader GitObjectReader, subject Subject) (*SourceSnapshot, error) {
	return verifySourceWithLimits(ctx, reader, subject, DefaultSourceLimits(), true)
}

func VerifySourceWithLimits(ctx context.Context, reader GitObjectReader, subject Subject, limits SourceLimits) (*SourceSnapshot, error) {
	return verifySourceWithLimits(ctx, reader, subject, limits, false)
}

func verifySourceWithLimits(ctx context.Context, reader GitObjectReader, subject Subject, limits SourceLimits, mutableRequestedRef bool) (*SourceSnapshot, error) {
	if reader == nil || ctx == nil {
		return nil, errors.New("trustverify: nil reader or context")
	}
	if limits.MaxReads <= 0 || limits.MaxEntries <= 0 || limits.MaxDepth <= 0 || limits.MaxSourceBytes <= 0 {
		return nil, errors.New("trustverify: invalid limits")
	}
	width, err := validateSubject(subject, mutableRequestedRef)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reads := 0
	read := func(id string, limit int) (GitObject, error) {
		if err := ctx.Err(); err != nil {
			return GitObject{}, err
		}
		if reads >= limits.MaxReads {
			return GitObject{}, errors.New("trustverify: object read limit exceeded")
		}
		reads++
		o, err := reader.ReadObject(ctx, SourceOrigin(subject.Origin), ObjectID(id))
		if err != nil {
			return GitObject{}, errors.New("trustverify: object unavailable")
		}
		if err := ctx.Err(); err != nil {
			return GitObject{}, err
		}
		if len(o.Data) > limit {
			return GitObject{}, errors.New("trustverify: object size limit exceeded")
		}
		if o.Kind == "" {
			return GitObject{}, errors.New("trustverify: malformed object")
		}
		if !checkOID(width, id, o.Kind, o.Data) {
			return GitObject{}, errors.New("trustverify: object identity mismatch")
		}
		return o, nil
	}
	commit, err := read(subject.Commit, maxCommitTreeObject)
	if err != nil || commit.Kind != "commit" {
		return nil, errOr("trustverify: invalid commit", err)
	}
	treeID, err := parseCommitTree(commit.Data, width)
	if err != nil {
		return nil, err
	}
	root, err := read(treeID, maxCommitTreeObject)
	if err != nil || root.Kind != "tree" {
		return nil, errOr("trustverify: invalid root tree", err)
	}
	parts := pathParts(subject.TemplatePath)
	entries := make([]SourceEntry, 0)
	blobs := make(map[string][]byte)
	materialized := int64(0)
	selected, err := walk(ctx, read, root.Data, treeID, parts, "", 0, width, limits, &entries, blobs, &materialized)
	if err != nil {
		return nil, err
	}
	_ = selected
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare([]byte(entries[i].Path), []byte(entries[j].Path)) < 0 })
	treeDigest, err := domainDigest("tplaiter.dev/source-content-tree/v1", struct {
		APIVersion string        `json:"apiVersion"`
		Entries    []SourceEntry `json:"entries"`
	}{"tplaiter.dev/source-content-tree/v1", entries})
	if err != nil {
		return nil, err
	}
	contract, ok := blobs["template.contract.json"]
	if !ok || len(contract) == 0 || len(contract) > maxContractObject {
		return nil, errors.New("trustverify: required contract missing or invalid")
	}
	contractDigest, err := domainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", byteDigest(contract)})
	if err != nil {
		return nil, err
	}
	if subject.TreeSHA256 != treeDigest || subject.ContractSHA256 != contractDigest {
		return nil, errors.New("trustverify: source digest mismatch")
	}
	return &SourceSnapshot{subject: subject, entries: entries, contract: append([]byte(nil), contract...), blobs: cloneBlobs(blobs)}, nil
}

func validateSubject(s Subject, mutableRequestedRef bool) (int, error) {
	if s.Origin == "" || s.TemplatePath == "" || s.RequestedRef == "" || s.Commit == "" || s.TreeSHA256 == "" || s.ContractSHA256 == "" {
		return 0, errors.New("trustverify: incomplete subject")
	}
	if !mutableRequestedRef && s.RequestedRef != s.Commit {
		return 0, errors.New("trustverify: mutable ref unsupported")
	}
	if len(s.TemplatePath) > maxPathBytes || utf8.RuneCountInString(s.TemplatePath) > maxPathRunes {
		return 0, errors.New("trustverify: path limit exceeded")
	}
	if !utf8.ValidString(s.TemplatePath) {
		return 0, errors.New("trustverify: invalid path")
	}
	if s.TemplatePath != "." {
		for _, part := range strings.Split(s.TemplatePath, "/") {
			if part == "" || part == "." || part == ".." || strings.Contains(part, "\\") {
				return 0, errors.New("trustverify: invalid path")
			}
			for _, r := range part {
				if r < 0x20 || r == 0x7f {
					return 0, errors.New("trustverify: invalid path")
				}
			}
		}
	}
	if len(s.Commit) == 40 {
		return 20, nil
	}
	if len(s.Commit) == 64 {
		return 32, nil
	}
	return 0, errors.New("trustverify: invalid commit width")
}

func pathParts(path string) []string {
	if path == "." {
		return nil
	}
	return strings.Split(path, "/")
}

func parseCommitTree(data []byte, width int) (string, error) {
	sep := bytes.Index(data, []byte("\n\n"))
	if sep < 0 {
		return "", errors.New("trustverify: malformed commit")
	}
	header := data[:sep]
	if bytes.IndexByte(header, 0) >= 0 {
		return "", errors.New("trustverify: malformed commit header")
	}
	lines := bytes.Split(header, []byte{'\n'})
	if len(lines) == 0 || !bytes.HasPrefix(lines[0], []byte("tree ")) {
		return "", errors.New("trustverify: commit tree header missing")
	}
	var tree string
	for _, l := range lines {
		if bytes.HasPrefix(l, []byte("tree ")) {
			if tree != "" {
				return "", errors.New("trustverify: duplicate tree header")
			}
			tree = string(l[5:])
		}
	}
	if !checkHex(tree, width) {
		return "", errors.New("trustverify: invalid tree id")
	}
	return tree, nil
}

type treeRecord struct {
	mode, name, oid string
	dir             bool
}

func parseTree(data []byte, width int) ([]treeRecord, error) {
	var out []treeRecord
	prev := ""
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		if sp <= 0 {
			return nil, errors.New("trustverify: malformed tree")
		}
		nul := bytes.IndexByte(data[sp+1:], 0)
		if nul < 0 {
			return nil, errors.New("trustverify: malformed tree")
		}
		nul += sp + 1
		mode, name := string(data[:sp]), string(data[sp+1:nul])
		data = data[nul+1:]
		if len(data) < width {
			return nil, errors.New("trustverify: truncated tree oid")
		}
		oid := hex.EncodeToString(data[:width])
		data = data[width:]
		dir := mode == "40000"
		if mode != "40000" && mode != "100644" && mode != "100755" {
			return nil, errors.New("trustverify: unsupported tree mode")
		}
		if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
			return nil, errors.New("trustverify: invalid tree name")
		}
		for _, r := range name {
			if r < 0x20 || r == 0x7f {
				return nil, errors.New("trustverify: control in tree name")
			}
		}
		key := name
		if dir {
			key += "/"
		}
		if prev != "" && bytes.Compare([]byte(key), []byte(prev)) <= 0 {
			return nil, errors.New("trustverify: noncanonical tree order")
		}
		prev = key
		out = append(out, treeRecord{mode, name, oid, dir})
	}
	return out, nil
}

func walk(ctx context.Context, read func(string, int) (GitObject, error), data []byte, _ string, parts []string, prefix string, depth, width int, lim SourceLimits, entries *[]SourceEntry, blobs map[string][]byte, total *int64) (bool, error) { //nolint:unparam // ctx is kept for cancellation parity with the other source readers
	if depth > lim.MaxDepth {
		return false, errors.New("trustverify: depth limit exceeded")
	}
	recs, err := parseTree(data, width)
	if err != nil {
		return false, err
	}
	for _, r := range recs {
		if len(*entries) >= lim.MaxEntries {
			return false, errors.New("trustverify: entry limit exceeded")
		}
		path := r.name
		if prefix != "" {
			path = prefix + "/" + r.name
		}
		match := len(parts) == 0 || (len(parts) > 0 && parts[0] == r.name)
		if len(parts) == 0 {
			if r.dir {
				if len(*entries) >= lim.MaxEntries {
					return false, errors.New("trustverify: entry limit exceeded")
				}
				*entries = append(*entries, SourceEntry{Path: path, Kind: "directory", Mode: r.mode})
				o, e := read(r.oid, maxCommitTreeObject)
				if e != nil || o.Kind != "tree" {
					return false, errOr("trustverify: invalid tree", e)
				}
				if _, e = walk(ctx, read, o.Data, r.oid, nil, path, depth+1, width, lim, entries, blobs, total); e != nil {
					return false, e
				}
			} else {
				if err := readBlob(read, r, path, width, entries, blobs, total, lim); err != nil {
					return false, err
				}
			}
		} else if match {
			if len(parts) == 1 {
				if r.dir {
					o, e := read(r.oid, maxCommitTreeObject)
					if e != nil || o.Kind != "tree" {
						return false, errOr("trustverify: invalid selected tree", e)
					}
					if _, e = walk(ctx, read, o.Data, r.oid, nil, "", depth+1, width, lim, entries, blobs, total); e != nil {
						return false, e
					}
				} else {
					return false, errors.New("trustverify: selected path is not a tree")
				}
			} else if r.dir {
				o, e := read(r.oid, maxCommitTreeObject)
				if e != nil || o.Kind != "tree" {
					return false, errOr("trustverify: invalid intermediate tree", e)
				}
				if _, e = walk(ctx, read, o.Data, r.oid, parts[1:], "", depth+1, width, lim, entries, blobs, total); e != nil {
					return false, e
				}
			} else {
				return false, errors.New("trustverify: selected path missing")
			}
		}
	}
	if len(parts) > 0 {
		found := false
		for _, r := range recs {
			if r.name == parts[0] {
				found = true
				break
			}
		}
		if !found {
			return false, errors.New("trustverify: selected path missing")
		}
	}
	return true, nil
}

func readBlob(read func(string, int) (GitObject, error), r treeRecord, path string, width int, entries *[]SourceEntry, blobs map[string][]byte, total *int64, lim SourceLimits) error { //nolint:unparam // width mirrors walk; blobs are addressed by the recorded object ID
	o, e := read(r.oid, maxBlobObject)
	if e != nil {
		return e
	}
	if o.Kind != "blob" {
		return errors.New("trustverify: tree points to non-blob")
	}
	if path == "template.contract.json" && len(o.Data) > maxContractObject {
		return errors.New("trustverify: contract size limit exceeded")
	}
	*total += int64(len(o.Data))
	if *total > lim.MaxSourceBytes {
		return errors.New("trustverify: source size limit exceeded")
	}
	b := append([]byte(nil), o.Data...)
	blobs[path] = b
	*entries = append(*entries, SourceEntry{Path: path, Kind: "file", Mode: r.mode, ContentSHA256: byteDigest(b)})
	return nil
}

func checkOID(width int, id, kind string, data []byte) bool {
	if !checkHex(id, width) {
		return false
	}
	p := []byte(kind + " " + strconv.Itoa(len(data)) + "\x00")
	var got []byte
	if width == 20 {
		h := sha1.Sum(append(p, data...)) //nolint:gosec // git SHA-1 object ID
		got = h[:]
	} else {
		h := sha256.Sum256(append(p, data...))
		got = h[:]
	}
	return hex.EncodeToString(got) == id
}

func checkHex(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}

func byteDigest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

func domainDigest(domain string, v any) (string, error) {
	b, e := canonicaljson.Canonical(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(append(append([]byte(domain), 0), b...))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

func cloneBlobs(in map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func errOr(msg string, e error) error {
	if e != nil {
		return e
	}
	return errors.New(msg)
}
