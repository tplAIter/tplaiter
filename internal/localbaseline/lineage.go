// Package localbaseline contains the closed, data-only local baseline wire
// contract. It does not authenticate a receipt or grant an operation.
package localbaseline

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const (
	APIVersion       = "tplaiter.dev/local-baseline-lineage/v1"
	Domain           = "tplaiter.dev/local-baseline-lineage/v1"
	MaxTransitions   = 32
	MaxSelected      = 4096
	MaxMetadataBytes = 1 << 20
	MaxTotalMetadata = 32 << 20
)

var ErrInvalid = errors.New("local baseline: invalid lineage")

type ReceiptRef struct {
	ID            string `json:"id"`
	PlanDigest    string `json:"planDigest"`
	ReceiptDigest string `json:"receiptDigest"`
}

type Origin struct {
	ProjectID string `json:"projectID"`
	Decision  string `json:"decisionSHA256"`
}

type SelectedIdentity struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Digest string `json:"digest"`
	Mode   uint32 `json:"mode"`
}

type Protection struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type wireLineage struct {
	APIVersion       string             `json:"apiVersion"`
	Domain           string             `json:"domain"`
	Operation        string             `json:"operation"`
	Sequence         uint64             `json:"sequence"`
	OriginalState    string             `json:"originalOriginState"`
	OriginalOrigin   *Origin            `json:"originalOrigin,omitempty"`
	PredecessorState string             `json:"predecessorState"`
	Predecessor      *ReceiptRef        `json:"predecessor,omitempty"`
	Selected         []SelectedIdentity `json:"selected"`
	Protection       []Protection       `json:"protection"`
}

// Lineage is immutable after decoding. Slices returned by accessors are deep
// detached copies, so callers cannot mutate the decoded transport.
type Lineage struct{ wire wireLineage }

func DecodeLineage(raw []byte) (*Lineage, error) {
	if len(raw) == 0 || len(raw) > MaxMetadataBytes {
		return nil, ErrInvalid
	}
	var w wireLineage
	if err := canonicaljson.DecodeStrict(raw, &w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validate(w); err != nil {
		return nil, err
	}
	canonical, err := canonicaljson.Canonical(w)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrInvalid
	}
	return &Lineage{wire: w}, nil
}

func (l *Lineage) Canonical() ([]byte, error) {
	if l == nil {
		return nil, ErrInvalid
	}
	return canonicaljson.Canonical(l.wire)
}

func (l *Lineage) Digest() (string, error) {
	raw, err := l.Canonical()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
func (l *Lineage) APIVersion() string          { return l.wire.APIVersion }
func (l *Lineage) DomainName() string          { return l.wire.Domain }
func (l *Lineage) Operation() string           { return l.wire.Operation }
func (l *Lineage) Sequence() uint64            { return l.wire.Sequence }
func (l *Lineage) OriginalOriginPresent() bool { return l.wire.OriginalState == "present" }
func (l *Lineage) OriginalOrigin() (Origin, bool) {
	if l.wire.OriginalOrigin == nil {
		return Origin{}, false
	}
	return *l.wire.OriginalOrigin, true
}
func (l *Lineage) PredecessorPresent() bool { return l.wire.PredecessorState == "present" }
func (l *Lineage) Predecessor() (ReceiptRef, bool) {
	if l.wire.Predecessor == nil {
		return ReceiptRef{}, false
	}
	return *l.wire.Predecessor, true
}
func (l *Lineage) Selected() []SelectedIdentity {
	return append([]SelectedIdentity(nil), l.wire.Selected...)
}
func (l *Lineage) Protection() []Protection { return append([]Protection(nil), l.wire.Protection...) }

func validate(w wireLineage) error {
	if w.APIVersion != APIVersion || w.Domain != Domain || w.Sequence == 0 || w.Sequence > MaxTransitions || !oneOf(w.Operation, "recopy", "rebaseline", "update") {
		return ErrInvalid
	}
	if !oneOf(w.OriginalState, "present", "absent") || (w.OriginalState == "present") != (w.OriginalOrigin != nil) || !oneOf(w.PredecessorState, "present", "absent") || (w.PredecessorState == "present") != (w.Predecessor != nil) {
		return ErrInvalid
	}
	if w.OriginalOrigin != nil && (w.OriginalOrigin.ProjectID == "" || !validDigest(w.OriginalOrigin.Decision)) {
		return ErrInvalid
	}
	if (w.Sequence == 1) != (w.Predecessor == nil) {
		return ErrInvalid
	}
	if w.Predecessor != nil && (!validID(w.Predecessor.ID) || !validDigest(w.Predecessor.PlanDigest) || !validDigest(w.Predecessor.ReceiptDigest)) {
		return ErrInvalid
	}
	if len(w.Selected) > MaxSelected || len(w.Protection) > MaxSelected {
		return ErrInvalid
	}
	last := ""
	for _, s := range w.Selected {
		if !validPath(s.Path) || s.Device == 0 || s.Inode == 0 || !validDigest(s.Digest) || s.Mode > 0o777 || s.Path == "." {
			return ErrInvalid
		}
		if s.Path <= last {
			return ErrInvalid
		}
		last = s.Path
	}
	last = ""
	for _, p := range w.Protection {
		if !validPath(p.Path) || p.Path == "." || p.Path <= last || !oneOf(p.Reason, "user-owned", "tombstone", "skipIfExists") {
			return ErrInvalid
		}
		last = p.Path
	}
	return nil
}
func oneOf(v string, allowed ...string) bool {
	for _, x := range allowed {
		if v == x {
			return true
		}
	}
	return false
}
func validID(v string) bool {
	if len(v) != 32 || strings.ToLower(v) != v {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
func validDigest(v string) bool {
	if len(v) != 71 || !strings.HasPrefix(v, "sha256:") || strings.ToLower(v) != v {
		return false
	}
	_, err := hex.DecodeString(v[7:])
	return err == nil
}
func validPath(v string) bool {
	return v != "" && filepath.IsLocal(v) && filepath.ToSlash(filepath.Clean(v)) == v && !strings.ContainsAny(v, "\\\x00\n\r")
}
