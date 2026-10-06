package trustload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const (
	LocalProviderRegistrationVersion = "tplaiter.dev/local-provider-registration/v1"
	LocalObserved                    = "local-untrusted-observed"
)

var (
	ErrLocalProvider    = errors.New("LOCAL_PROVIDER_UNAVAILABLE")
	ErrLocalUnsupported = errors.New("LOCAL_PROVIDER_PLATFORM_UNSUPPORTED")
)

type localRegistration struct {
	APIVersion     string   `json:"apiVersion"`
	Kind           string   `json:"kind"`
	RegistrationID string   `json:"registrationID"`
	InstallationID string   `json:"installationID"`
	ProjectKeys    []string `json:"projectKeys"`
	Protocol       string   `json:"protocol"`
	Qualification  string   `json:"qualification"`
	Endpoint       struct {
		Kind       string `json:"kind"`
		SocketPath string `json:"socketPath"`
		OwnerUID   uint32 `json:"ownerUID"`
	} `json:"endpoint"`
	Limits LocalReadLimits `json:"limits"`
}

func decodeLocalRegistration(raw []byte) (localRegistration, error) {
	var v localRegistration
	if len(raw) == 0 || len(raw) > 16384 || canonicaljson.DecodeStrict(raw, &v) != nil {
		return v, ErrConfigInvalid
	}
	if requiredObjectFields(raw, []string{"apiVersion", "kind", "registrationID", "installationID", "projectKeys", "protocol", "qualification", "endpoint", "limits"}) != nil {
		return v, ErrConfigInvalid
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if requiredObjectFields(fields["endpoint"], []string{"kind", "socketPath", "ownerUID"}) != nil || requiredObjectFields(fields["limits"], []string{"frameBytes", "totalBytes", "pages", "sourceBytes", "deadlineMs"}) != nil {
		return v, ErrConfigInvalid
	}
	var endpointFields map[string]json.RawMessage
	_ = json.Unmarshal(fields["endpoint"], &endpointFields)
	if bytes.Equal(bytes.TrimSpace(endpointFields["ownerUID"]), []byte("null")) {
		return v, ErrConfigInvalid
	}
	if v.APIVersion != LocalProviderRegistrationVersion || v.Kind != "LocalProviderRegistration" || !token(v.RegistrationID) || len(v.RegistrationID) > 64 || !token(v.InstallationID) || v.Protocol != "local-provider.session/v1" || v.Qualification != LocalObserved || v.Endpoint.Kind != "unix" || !absolutePath(v.Endpoint.SocketPath) || len(v.Endpoint.SocketPath) > 103 || len(v.ProjectKeys) < 1 || len(v.ProjectKeys) > 32 {
		return v, ErrConfigInvalid
	}
	seen := map[string]bool{}
	for _, key := range v.ProjectKeys {
		if !token(key) || len(key) > 64 || seen[key] {
			return v, ErrConfigInvalid
		}
		seen[key] = true
	}
	l := v.Limits
	if l.FrameBytes < 512 || l.FrameBytes > 32768 || l.TotalBytes < l.FrameBytes || l.TotalBytes > 2097152 || l.Pages < 1 || l.Pages > 128 || l.SourceBytes < 1 || l.SourceBytes > 8192 || l.DeadlineMs < 1 || l.DeadlineMs > 2000 {
		return v, ErrConfigInvalid
	}
	return v, nil
}

// LocalSelectionObservation describes installed selection and kernel account
// observations. It never authenticates source claims or the serving program.
type LocalSelectionObservation struct {
	RegistrationID     string `json:"registrationID"`
	RegistrationSHA256 string `json:"registrationSHA256"`
	InstallationID     string `json:"installationID"`
	ProjectContext     string `json:"projectContext"`
	EndpointIdentity   string `json:"endpointIdentity"`
	CodeIdentity       string `json:"codeIdentity"`
	PeerUID            uint32 `json:"peerUID"`
	PeerPID            int    `json:"peerPID"`
}

// LocalProvider has no JSON constructor or caller-selected transport. Only the
// installed Runtime factory establishes its private connection/selection.
type LocalProvider struct {
	mu           sync.Mutex
	runtime      *Runtime
	pin          FilePin
	registration localRegistration
	observation  LocalSelectionObservation
	endpoint     *localEndpoint
	closed       bool
	expires      time.Time
	timer        *time.Timer
}

func (r *Runtime) localRegistration(ctx context.Context, id string) (localRegistration, FilePin, error) {
	var empty localRegistration
	if ctx == nil || r == nil || !token(id) {
		return empty, FilePin{}, ErrLocalProvider
	}
	r.mu.Lock()
	live := !r.closed && r.runtime != nil
	selected := r.installation
	project := r.project
	r.mu.Unlock()
	if !live {
		return empty, FilePin{}, ErrLocalProvider
	}
	loaded, err := Load(ctx, selected)
	if err != nil {
		return empty, FilePin{}, err
	}
	if loaded.Install.Profile != bootstrap.ProfileOSS || loaded.Install.APIVersion != RuntimeInstallV2APIVersion {
		return empty, FilePin{}, ErrLocalProvider
	}
	current, ok := selectedProjectContext(loaded.Install, project.Key)
	if !ok || current != project {
		return empty, FilePin{}, ErrPinMismatch
	}
	seen := map[string]bool{}
	var found localRegistration
	var pin FilePin
	for _, p := range loaded.Install.LocalProviders {
		raw, e := secureReadFile(p.Path, 16384)
		if e != nil || rawSHA256(raw) != p.SHA256 {
			return empty, FilePin{}, ErrPinMismatch
		}
		v, e := decodeLocalRegistration(raw)
		if e != nil || seen[v.RegistrationID] || v.InstallationID != loaded.Install.InstallationID {
			return empty, FilePin{}, ErrConfigInvalid
		}
		seen[v.RegistrationID] = true
		for _, key := range v.ProjectKeys {
			if _, ok := selectedProjectContext(loaded.Install, key); !ok {
				return empty, FilePin{}, ErrConfigInvalid
			}
		}
		if v.RegistrationID == id {
			found = v
			pin = p
		}
	}
	if pin.Path == "" {
		return empty, FilePin{}, ErrLocalProvider
	}
	allowed := false
	for _, key := range found.ProjectKeys {
		if key == project.Key {
			allowed = true
		}
	}
	if !allowed {
		return empty, FilePin{}, ErrLocalProvider
	}
	return found, pin, nil
}

func (r *Runtime) OpenLocalProvider(ctx context.Context, id string) (*LocalProvider, error) {
	started := time.Now()
	registration, pin, err := r.localRegistration(ctx, id)
	if err != nil {
		return nil, err
	}
	expires := started.Add(time.Duration(registration.Limits.DeadlineMs) * time.Millisecond)
	bounded, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	endpoint, err := openLocalEndpoint(bounded, registration.Endpoint.SocketPath, registration.Endpoint.OwnerUID)
	if err != nil {
		return nil, err
	}
	p := &LocalProvider{runtime: r, pin: pin, registration: registration, endpoint: endpoint, expires: expires}
	p.observation = LocalSelectionObservation{RegistrationID: id, RegistrationSHA256: pin.SHA256, InstallationID: registration.InstallationID, ProjectContext: r.ProjectContext().Key, EndpointIdentity: "installed-path-observed-kernel-peer", CodeIdentity: "unchecked", PeerUID: endpoint.uid, PeerPID: endpoint.pid}
	if err = p.armLifetime(); err == nil {
		err = p.Recheck(bounded)
	}
	if err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

// Deadline is the installed operation deadline, including selection and connection.
func (p *LocalProvider) Deadline() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.expires
}

func (p *LocalProvider) Selection() LocalSelectionObservation {
	if p == nil {
		return LocalSelectionObservation{}
	}
	return p.observation
}

func (p *LocalProvider) Recheck(ctx context.Context) error {
	if p == nil {
		return ErrLocalProvider
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.lifetimeErrorLocked(); err != nil {
		return err
	}
	_, pin, err := p.runtime.localRegistration(ctx, p.registration.RegistrationID)
	if err != nil {
		return err
	}
	if pin != p.pin {
		return ErrPinMismatch
	}
	if err := p.endpoint.recheck(); err != nil {
		return err
	}
	return p.lifetimeErrorLocked()
}

// Limits is copied installed data, not a caller's connection authority.
func (p *LocalProvider) Limits() LocalReadLimits {
	if p == nil {
		return LocalReadLimits{}
	}
	return p.registration.Limits
}

type LocalReadLimits struct {
	FrameBytes  int `json:"frameBytes"`
	TotalBytes  int `json:"totalBytes"`
	Pages       int `json:"pages"`
	SourceBytes int `json:"sourceBytes"`
	DeadlineMs  int `json:"deadlineMs"`
}

// armLifetime installs the acquisition-relative ceiling before returning the carrier.
// Cancellation by a consumer closes the carrier; its timer needs no caller context.
func (p *LocalProvider) armLifetime() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.lifetimeErrorLocked(); err != nil {
		return err
	}
	if p.expires.IsZero() || p.timer != nil {
		return ErrLocalProvider
	}
	if err := p.endpoint.conn.SetDeadline(p.expires); err != nil {
		return err
	}
	p.timer = time.AfterFunc(time.Until(p.expires), func() { _ = p.Close() })
	return nil
}

// Expiry remains distinguishable after the timer has closed the descriptors.
func (p *LocalProvider) lifetimeErrorLocked() error {
	if !p.expires.IsZero() && !time.Now().Before(p.expires) {
		_ = p.closeLocked()
		return context.DeadlineExceeded
	}
	if p.closed || p.endpoint == nil {
		return ErrLocalProvider
	}
	return nil
}

func (p *LocalProvider) connection() (net.Conn, error) {
	if p == nil {
		return nil, ErrLocalProvider
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.lifetimeErrorLocked(); err != nil {
		return nil, err
	}
	return p.endpoint.conn, nil
}

func (p *LocalProvider) ioLifetimeError() error {
	if p == nil {
		return ErrLocalProvider
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lifetimeErrorLocked()
}

func (p *LocalProvider) Read(b []byte) (int, error) {
	c, err := p.connection()
	if err != nil {
		return 0, err
	}
	n, err := c.Read(b)
	if ended := p.ioLifetimeError(); ended != nil {
		return 0, ended
	}
	return n, err
}

func (p *LocalProvider) Write(b []byte) (int, error) {
	c, err := p.connection()
	if err != nil {
		return 0, err
	}
	n, err := c.Write(b)
	// Bytes may already have reached the peer, but expiry cannot report success.
	if ended := p.ioLifetimeError(); ended != nil {
		return n, ended
	}
	return n, err
}

func (p *LocalProvider) LocalAddr() net.Addr {
	c, err := p.connection()
	if err != nil {
		return nil
	}
	return c.LocalAddr()
}

func (p *LocalProvider) RemoteAddr() net.Addr {
	c, err := p.connection()
	if err != nil {
		return nil
	}
	return c.RemoteAddr()
}

func (p *LocalProvider) setDeadline(t time.Time, kind int) error {
	if p == nil {
		return ErrLocalProvider
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.lifetimeErrorLocked(); err != nil {
		return err
	}
	if t.IsZero() || t.After(p.expires) {
		t = p.expires
	}
	var err error
	switch kind {
	case 1:
		err = p.endpoint.conn.SetReadDeadline(t)
	case 2:
		err = p.endpoint.conn.SetWriteDeadline(t)
	default:
		err = p.endpoint.conn.SetDeadline(t)
	}
	if ended := p.lifetimeErrorLocked(); ended != nil {
		return ended
	}
	return err
}

func (p *LocalProvider) SetDeadline(t time.Time) error      { return p.setDeadline(t, 0) }
func (p *LocalProvider) SetReadDeadline(t time.Time) error  { return p.setDeadline(t, 1) }
func (p *LocalProvider) SetWriteDeadline(t time.Time) error { return p.setDeadline(t, 2) }

func (p *LocalProvider) closeLocked() error {
	if p.closed {
		return nil
	}
	p.closed = true
	if p.timer != nil {
		p.timer.Stop()
	}
	if p.endpoint == nil {
		return nil
	}
	return p.endpoint.close()
}

func (p *LocalProvider) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeLocked()
}

// ValidateLocalProviderDocument validates data only; it cannot establish a
// connection, installed selection, publisher identity or source authority.
func ValidateLocalProviderDocument(raw []byte) error {
	_, err := decodeLocalRegistration(raw)
	return err
}
