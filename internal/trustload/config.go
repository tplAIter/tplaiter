// Package trustload loads the fixed, operator-installed trust profile.
//
// The package intentionally has no discovery or provisioning behavior. A
// LaunchSelection is supplied by an installed launcher and all bytes are
// checked against pins before they are returned to a caller.
package trustload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const (
	RuntimeInstallAPIVersion    = "tplaiter.dev/runtime-install/v1"
	OperatorPinRecordAPIVersion = "tplaiter.dev/operator-pin-record/v1"
	maxDocument                 = 1 << 20
	maxEntries                  = 1024
	maxPathBytes                = 4096
)

var (
	ErrAnchorMissing         = errors.New("trustload: TRUST_ANCHOR_MISSING")
	ErrConfigInvalid         = errors.New("trustload: TRUST_CONFIG_INVALID")
	ErrPinMismatch           = errors.New("trustload: TRUST_PIN_MISMATCH")
	ErrProvenanceUnavailable = errors.New("trustload: TRUST_PROVENANCE_UNAVAILABLE")
	ErrProtectedUnavailable  = errors.New("trustload: TRUST_PROTECTED_UNAVAILABLE")
)

type FilePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type ProjectContext struct {
	Key                  string              `json:"key"`
	ProjectID            string              `json:"projectID"`
	SubmitterPrincipalID string              `json:"submitterPrincipalID"`
	MinimumProfile       bootstrap.ProfileID `json:"minimumProfile"`
	RootPath             string              `json:"rootPath"`
}
type ObjectOrigin struct {
	Origin   string `json:"origin"`
	RootPath string `json:"rootPath"`
}
type OSSInstall struct {
	StorePath           string `json:"storePath"`
	InitialStatePath    string `json:"initialStatePath"`
	InitialStateSHA256  string `json:"initialStateSHA256"`
	InitialBundlePath   string `json:"initialBundlePath"`
	InitialBundleSHA256 string `json:"initialBundleSHA256"`
}
type ProtectedInstall struct {
	AdapterID string `json:"adapterID"`
}
type RuntimeInstall struct {
	APIVersion      string              `json:"apiVersion"`
	InstallationID  string              `json:"installationID"`
	Profile         bootstrap.ProfileID `json:"profile"`
	MinimumProfile  bootstrap.ProfileID `json:"minimumProfile"`
	Descriptor      FilePin             `json:"descriptor"`
	Provisioning    FilePin             `json:"provisioning"`
	OperatorRecord  FilePin             `json:"operatorRecord"`
	ExecutionPolicy FilePin             `json:"executionPolicy"`
	ProjectContexts []ProjectContext    `json:"projectContexts"`
	ObjectOrigins   []ObjectOrigin      `json:"objectOrigins"`
	EvidenceRoot    string              `json:"evidenceRoot"`
	ScratchRoot     string              `json:"scratchRoot"`
	OSS             *OSSInstall         `json:"oss,omitempty"`
	Protected       *ProtectedInstall   `json:"protected,omitempty"`
}

var runtimeFields = []string{"apiVersion", "installationID", "profile", "minimumProfile", "descriptor", "provisioning", "operatorRecord", "executionPolicy", "projectContexts", "objectOrigins", "evidenceRoot", "scratchRoot"}

func DecodeRuntimeInstall(raw []byte) (*RuntimeInstall, error) {
	if len(raw) == 0 || len(raw) > maxDocument {
		return nil, ErrConfigInvalid
	}
	if err := requiredObjectFields(raw, runtimeFields); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigInvalid, err)
	}
	var v RuntimeInstall
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigInvalid, err)
	}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return &v, nil
}

func (v RuntimeInstall) Validate() error {
	if v.APIVersion != RuntimeInstallAPIVersion || !token(v.InstallationID) || !validProfile(v.Profile) || !validProfile(v.MinimumProfile) || v.Profile == bootstrap.ProfileDevelopment {
		return ErrConfigInvalid
	}
	if bootstrap.RequireProfile(v.MinimumProfile, v.Profile) != nil {
		return ErrConfigInvalid
	}
	for _, p := range []FilePin{v.Descriptor, v.Provisioning, v.OperatorRecord, v.ExecutionPolicy} {
		if !validFilePin(p) {
			return ErrConfigInvalid
		}
	}
	paths := map[string]bool{}
	for _, p := range []FilePin{v.Descriptor, v.Provisioning, v.OperatorRecord, v.ExecutionPolicy} {
		if paths[p.Path] {
			return ErrConfigInvalid
		}
		paths[p.Path] = true
	}
	if len(v.ProjectContexts) > maxEntries || len(v.ObjectOrigins) > maxEntries {
		return ErrConfigInvalid
	}
	seen := map[string]bool{}
	for _, p := range v.ProjectContexts {
		if !token(p.Key) || !token(p.ProjectID) || !token(p.SubmitterPrincipalID) || !validProfile(p.MinimumProfile) || !absolutePath(p.RootPath) || seen[p.Key] {
			return ErrConfigInvalid
		}
		if bootstrap.RequireProfile(p.MinimumProfile, v.Profile) != nil {
			return ErrConfigInvalid
		}
		seen[p.Key] = true
	}
	seen = map[string]bool{}
	for _, o := range v.ObjectOrigins {
		if !origin(o.Origin) || !absolutePath(o.RootPath) || seen[o.Origin] {
			return ErrConfigInvalid
		}
		seen[o.Origin] = true
	}
	if !absolutePath(v.EvidenceRoot) || !absolutePath(v.ScratchRoot) || v.EvidenceRoot == v.ScratchRoot {
		return ErrConfigInvalid
	}
	for _, o := range v.ObjectOrigins {
		if paths[o.RootPath] {
			return ErrConfigInvalid
		}
		paths[o.RootPath] = true
	}
	if paths[v.EvidenceRoot] || paths[v.ScratchRoot] {
		return ErrConfigInvalid
	}
	paths[v.EvidenceRoot], paths[v.ScratchRoot] = true, true
	if v.Profile == bootstrap.ProfileOSS {
		if v.OSS == nil || v.Protected != nil || !validOSS(*v.OSS) {
			return ErrConfigInvalid
		}
		for _, p := range []string{v.OSS.StorePath, v.OSS.InitialStatePath, v.OSS.InitialBundlePath} {
			if paths[p] {
				return ErrConfigInvalid
			}
			paths[p] = true
		}
	} else if v.Protected == nil || v.OSS != nil || !token(v.Protected.AdapterID) {
		return ErrConfigInvalid
	}
	protectedRoots := make([]string, 0, len(v.ProjectContexts))
	for _, p := range v.ProjectContexts {
		protectedRoots = append(protectedRoots, filepath.Clean(p.RootPath))
	}
	authorityRoots := make([]string, 0, len(paths)+len(v.ObjectOrigins)+2)
	for _, p := range []FilePin{v.Descriptor, v.Provisioning, v.OperatorRecord, v.ExecutionPolicy} {
		authorityRoots = append(authorityRoots, p.Path)
	}
	if v.OSS != nil {
		authorityRoots = append(authorityRoots, v.OSS.StorePath, v.OSS.InitialStatePath, v.OSS.InitialBundlePath)
	}
	for _, o := range v.ObjectOrigins {
		authorityRoots = append(authorityRoots, filepath.Clean(o.RootPath))
	}
	authorityRoots = append(authorityRoots, v.EvidenceRoot, v.ScratchRoot)
	for _, root := range authorityRoots {
		for _, project := range protectedRoots {
			if pathOverlaps(root, project) {
				return ErrConfigInvalid
			}
		}
	}
	return nil
}

func (v RuntimeInstall) Digest() (string, error) {
	return bootstrap.DomainDigest(RuntimeInstallAPIVersion, v)
}

func validOSS(v OSSInstall) bool {
	return absolutePath(v.StorePath) && absolutePath(v.InitialStatePath) && absolutePath(v.InitialBundlePath) && digest(v.InitialStateSHA256) && digest(v.InitialBundleSHA256)
}
func validFilePin(v FilePin) bool { return absolutePath(v.Path) && digest(v.SHA256) }
func validProfile(v bootstrap.ProfileID) bool {
	return v == bootstrap.ProfileOSS || v == bootstrap.ProfileOrganization
}

func digest(v string) bool {
	if len(v) != 71 || !strings.HasPrefix(v, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(v[7:])
	return err == nil && strings.ToLower(v[7:]) == v[7:]
}

func token(v string) bool {
	return v != "" && utf8.ValidString(v) && !strings.ContainsAny(v, "\x00\r\n\t /\\")
}

func absolutePath(v string) bool {
	return utf8.ValidString(v) && len(v) > 0 && len([]byte(v)) <= maxPathBytes && filepath.IsAbs(v) && filepath.Clean(v) == v && v != "/" && !strings.Contains(v, "\x00")
}

func origin(v string) bool {
	if !utf8.ValidString(v) || v == "" || strings.ContainsAny(v, "\x00\r\n \t\\") {
		return false
	}
	u, err := url.Parse(v)
	return err == nil && u.Scheme != "" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

func pathOverlaps(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}

func requiredObjectFields(raw []byte, fields []string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return errors.New("expected object")
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errors.New("trailing value")
	}
	for _, f := range fields {
		if _, ok := obj[f]; !ok {
			return fmt.Errorf("missing required field %q", f)
		}
	}
	return nil
}

func rawSHA256(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

// configFileBytes reads a pinned regular file without following a symlink.
func configFileBytes(p FilePin) ([]byte, error) {
	b, err := secureReadFile(p.Path, maxDocument)
	if err != nil || len(b) > maxDocument || rawSHA256(b) != p.SHA256 {
		return nil, ErrPinMismatch
	}
	return b, nil
}
