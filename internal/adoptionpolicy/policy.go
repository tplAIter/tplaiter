// Package adoptionpolicy validates deterministic projections, never writer authority.
package adoptionpolicy

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

var ErrPolicy = errors.New("native adoption: invalid or unauthenticated ownership policy")

const Domain = "tplaiter.dev/native-adoption-decision/v1"

type Observation struct {
	Exists    bool   `json:"exists"`
	Directory bool   `json:"directory"`
	Mode      uint32 `json:"mode"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	SHA256    string `json:"sha256"`
}
type Exclusion struct {
	Path         string      `json:"path"`
	SourceSHA256 string      `json:"sourceSHA256"`
	SourceMode   uint32      `json:"sourceMode"`
	InitialState string      `json:"initialState"`
	Observed     Observation `json:"observed"`
}
type Origin struct {
	ProjectID            string                   `json:"projectID"`
	Binding              bootstrap.ProfileBinding `json:"profileBinding"`
	SourceRootLockSHA256 string                   `json:"sourceRootLockSHA256"`
	SourceCommit         string                   `json:"sourceCommit"`
	RendererVersion      string                   `json:"rendererVersion"`
	RenderInputsSHA256   string                   `json:"renderInputsSHA256"`
	DecisionAt           string                   `json:"decisionAt"`
	Exclusions           []Exclusion              `json:"exclusions"`
}
type Policy struct {
	Version        int    `json:"version"`
	DecisionSHA256 string `json:"decisionSHA256"`
	Origin         Origin `json:"origin"`
}

func Digest(v any) (string, error) {
	b, e := canonicaljson.Canonical(v)
	if e != nil {
		return "", e
	}
	return evidencecas.Digest(append([]byte(Domain+"\x00"), b...)), nil
}
func New(origin Origin) (*Policy, error) {
	hash, e := Digest(origin)
	if e != nil {
		return nil, e
	}
	p := &Policy{Version: 1, DecisionSHA256: hash, Origin: origin}
	if e = p.Validate(); e != nil {
		return nil, e
	}
	return p, nil
}
func Parse(m map[string]any) (*Policy, error) {
	if len(m) == 0 {
		return nil, nil
	}
	if len(m) != 1 {
		return nil, ErrPolicy
	}
	v, ok := m["nativeAdoption"]
	if !ok {
		return nil, ErrPolicy
	}
	raw, e := canonicaljson.Canonical(v)
	if e != nil {
		return nil, ErrPolicy
	}
	var p Policy
	if canonicaljson.DecodeStrict(raw, &p) != nil || p.Validate() != nil {
		return nil, ErrPolicy
	}
	return &p, nil
}
func (p *Policy) Map() (map[string]any, error) {
	if p == nil {
		return nil, nil
	}
	raw, e := canonicaljson.Canonical(p)
	if e != nil {
		return nil, e
	}
	var v map[string]any
	if e = json.Unmarshal(raw, &v); e != nil {
		return nil, e
	}
	return map[string]any{"nativeAdoption": v}, nil
}
func (p *Policy) Validate() error {
	if p == nil || p.Version != 1 || p.Origin.ProjectID == "" || p.Origin.RendererVersion == "" || len(p.Origin.SourceCommit) != 40 || !digest(p.Origin.SourceRootLockSHA256) || !digest(p.Origin.RenderInputsSHA256) || len(p.Origin.Exclusions) == 0 || len(p.Origin.Exclusions) > 4096 {
		return ErrPolicy
	}
	if _, e := hex.DecodeString(p.Origin.SourceCommit); e != nil || strings.ToLower(p.Origin.SourceCommit) != p.Origin.SourceCommit {
		return ErrPolicy
	}
	if _, e := time.Parse(time.RFC3339Nano, p.Origin.DecisionAt); e != nil {
		return ErrPolicy
	}
	hash, e := Digest(p.Origin)
	if e != nil || hash != p.DecisionSHA256 {
		return ErrPolicy
	}
	prior := ""
	folds := map[string]bool{}
	for _, x := range p.Origin.Exclusions {
		lower := strings.ToLower(x.Path)
		if !Eligible(x.Path) || x.Path <= prior || folds[lower] || !digest(x.SourceSHA256) || x.SourceMode != 0o644 || !digest(x.Observed.SHA256) || x.Observed.Directory {
			return ErrPolicy
		}
		for k := range folds {
			if strings.HasPrefix(lower, k+"/") || strings.HasPrefix(k, lower+"/") {
				return ErrPolicy
			}
		}
		if x.InitialState == "modified" {
			if !x.Observed.Exists || x.Observed.Inode == 0 || x.Observed.Mode > 0o777 {
				return ErrPolicy
			}
		} else if x.InitialState == "missing" {
			if x.Observed.Exists || x.Observed.Mode != 0 || x.Observed.Inode != 0 || x.Observed.Device != 0 || x.Observed.SHA256 != evidencecas.Digest(nil) {
				return ErrPolicy
			}
		} else {
			return ErrPolicy
		}
		folds[lower] = true
		prior = x.Path
	}
	return nil
}
func Eligible(p string) bool {
	if !fs.ValidPath(p) || p == "." || len(p) > 1024 || strings.ContainsAny(p, "\\\x00\r\n:*?[]#") {
		return false
	}
	for _, n := range []string{".tplaiter", ".tplater", ".globals"} {
		if p == n || strings.HasPrefix(p, n+"/") {
			return false
		}
	}
	return true
}
func (p *Policy) Paths() []string {
	v := []string{}
	if p != nil {
		for _, x := range p.Origin.Exclusions {
			v = append(v, x.Path)
		}
	}
	return v
}
func (p *Policy) Contains(name string) bool {
	if p != nil {
		for _, x := range p.Origin.Exclusions {
			if x.Path == name {
				return true
			}
		}
	}
	return false
}
func (p *Policy) Missing() []string {
	v := []string{}
	if p != nil {
		for _, x := range p.Origin.Exclusions {
			if x.InitialState == "missing" {
				v = append(v, x.Path)
			}
		}
	}
	return v
}
func digest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Protection is strict v2 intent transport. Detached values grant no authority.
// The installed transaction adapter derives it from an opaque origin proof and
// fresh no-follow observations, then authenticates it in the durable receipt.
type ProtectedPath struct {
	Path        string      `json:"path"`
	Observation Observation `json:"observation"`
}
type Protection struct {
	DecisionSHA256 string          `json:"decisionSHA256"`
	ReceiptID      string          `json:"receiptID"`
	PlanSHA256     string          `json:"planSHA256"`
	ReceiptSHA256  string          `json:"receiptSHA256"`
	Paths          []ProtectedPath `json:"paths"`
}
