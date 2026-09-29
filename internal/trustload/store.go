package trustload

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

const (
	storedBundleAPIVersion = "tplaiter.dev/stored-bootstrap-bundle/v1"
	storeDBName            = "bootstrap.sqlite"
	pendingMarkerName      = "bootstrap.pending"
	activeMarkerName       = "bootstrap.active"
	maxCASBlobBytes        = 16 << 20
	maxRefreshBytes        = 64 << 20
	maxRefreshEvidence     = 1024
	maxGeneration          = 9007199254740991
)

var (
	ErrRefreshConflict = errors.New("trustload: TRUST_REFRESH_CONFLICT")
	ErrPending         = errors.New("trustload: TRUST_PENDING")
)

// StoredBundle is the closed local record retained in the trusted state store.
// Its references name raw SHA-256 evidence blobs; it carries no authority on
// its own and must be combined with a loaded accepted state and VerifyOSS.
type StoredBundle struct {
	APIVersion   string             `json:"apiVersion"`
	EnvelopeCAS  string             `json:"envelopeCAS"`
	ReceiptCAS   string             `json:"receiptCAS"`
	Transparency StoredTransparency `json:"transparency"`
}

type StoredTransparency struct {
	CheckpointCAS       string `json:"checkpointCAS"`
	InclusionProofCAS   string `json:"inclusionProofCAS"`
	ConsistencyProofCAS string `json:"consistencyProofCAS"`
}

func DecodeStoredBundle(raw []byte) (*StoredBundle, error) {
	if len(raw) == 0 || len(raw) > maxDocument {
		return nil, ErrConfigInvalid
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || len(object) != 4 {
		return nil, ErrConfigInvalid
	}
	for _, field := range []string{"apiVersion", "envelopeCAS", "receiptCAS", "transparency"} {
		if _, ok := object[field]; !ok {
			return nil, ErrConfigInvalid
		}
	}
	var transparency map[string]json.RawMessage
	if err := json.Unmarshal(object["transparency"], &transparency); err != nil || len(transparency) != 3 {
		return nil, ErrConfigInvalid
	}
	for _, field := range []string{"checkpointCAS", "inclusionProofCAS", "consistencyProofCAS"} {
		if _, ok := transparency[field]; !ok {
			return nil, ErrConfigInvalid
		}
	}
	var bundle StoredBundle
	if err := canonicaljson.DecodeStrict(raw, &bundle); err != nil || !bundle.Valid() {
		return nil, ErrConfigInvalid
	}
	return &bundle, nil
}

func (b StoredBundle) Valid() bool {
	return b.APIVersion == storedBundleAPIVersion && digest(b.EnvelopeCAS) && digest(b.ReceiptCAS) && digest(b.Transparency.CheckpointCAS) && digest(b.Transparency.InclusionProofCAS) && (b.Transparency.ConsistencyProofCAS == "" || digest(b.Transparency.ConsistencyProofCAS))
}

func (b StoredBundle) Digest() (string, error) {
	if !b.Valid() {
		return "", ErrConfigInvalid
	}
	return bootstrap.DomainDigest(storedBundleAPIVersion, b)
}

func (b StoredBundle) references() []string {
	refs := []string{b.EnvelopeCAS, b.ReceiptCAS, b.Transparency.CheckpointCAS, b.Transparency.InclusionProofCAS}
	if b.Transparency.ConsistencyProofCAS != "" {
		refs = append(refs, b.Transparency.ConsistencyProofCAS)
	}
	sort.Strings(refs)
	return refs
}

type installationProjection struct {
	installationID      string
	descriptorSHA256    string
	provisioningSHA256  string
	initialStateSHA256  string
	initialBundleSHA256 string
	descriptorJSON      []byte
	provisioningJSON    []byte
}

func projectInstallation(loaded *Loaded) (installationProjection, error) {
	if loaded == nil || loaded.Install.Profile != bootstrap.ProfileOSS || loaded.Install.OSS == nil {
		return installationProjection{}, ErrProtectedUnavailable
	}
	descriptor, err := bootstrap.DecodeDescriptorDocument(append([]byte(nil), loaded.DescriptorJSON...))
	if err != nil {
		return installationProjection{}, ErrProvenanceUnavailable
	}
	provisioning, err := bootstrap.DecodeProvisioningRecord(append([]byte(nil), loaded.ProvisioningJSON...))
	if err != nil || descriptor.Profile != bootstrap.ProfileOSS || descriptor.DescriptorSHA256 != loaded.Operator.DescriptorSHA256 || provisioning.Mode != "operator-pinned" || provisioning.DescriptorSHA256 != descriptor.DescriptorSHA256 {
		return installationProjection{}, ErrProvenanceUnavailable
	}
	if !digest(loaded.Install.OSS.InitialStateSHA256) {
		return installationProjection{}, ErrConfigInvalid
	}
	return installationProjection{
		installationID: loaded.Install.InstallationID, descriptorSHA256: descriptor.DescriptorSHA256,
		provisioningSHA256: provisioning.ProvisioningSHA256, initialStateSHA256: loaded.Install.OSS.InitialStateSHA256, initialBundleSHA256: loaded.Install.OSS.InitialBundleSHA256,
		descriptorJSON: clone(loaded.DescriptorJSON), provisioningJSON: clone(loaded.ProvisioningJSON),
	}, nil
}

// Store is an ordinary read-only view of one active installed OSS state. It is
// also the only ExternalAuthorityReader supplied to bootstrap.LoadExternal.
type Store struct {
	session *storeSession
	// db is the retained Conn, kept as an internal test observation surface;
	// it is never a database/sql pool and cannot replace the leased binding.
	db         *sql.Conn
	selection  LaunchSelection
	proj       installationProjection
	ownsLease  bool
	pending    bool // private same-EX pre-activation verification only
	markerName string
	marker     markerSnapshot
}

// markerSnapshot is the scalar identity captured from the authenticated
// marker inode. Store.Load rechecks it before publishing authority so a
// same-content inode replacement cannot reuse an existing Store.
type markerSnapshot struct {
	dev, ino uint64
	mode     uint32
	uid      uint32
	nlink    uint64
	size     int64
}

func (s markerSnapshot) equal(other markerSnapshot) bool { return s == other }

// VerifierFactory is supplied by the fixed composition root. It is never
// decoded from a bundle or installation file; its sole purpose is to bind a
// real bootstrap verifier to the immutable evidence view for this operation.
type VerifierFactory func(evidencecas.Reader) (*bootstrap.Verifier, error)

func (s *Store) Close() error {
	if s == nil || s.session == nil {
		return nil
	}
	var err error
	if s.session.binding != nil {
		err = s.session.binding.Close()
	}
	if err == nil && s.ownsLease && s.session.lease != nil {
		err = s.session.lease.Close()
	}
	s.session = nil
	return err
}

// OpenReadOnly performs no initialization, schema migration, journal recovery,
// or filesystem mutation. Missing/pending state fails closed.
func OpenReadOnly(ctx context.Context, selection LaunchSelection) (*Store, error) {
	loaded, err := Load(ctx, selection)
	if err != nil {
		return nil, err
	}
	return openReadOnlyLoaded(ctx, selection, loaded)
}

func openReadOnlyLoaded(ctx context.Context, selection LaunchSelection, loaded *Loaded) (*Store, error) {
	if ctx == nil {
		return nil, ErrAnchorMissing
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proj, err := projectInstallation(loaded)
	if err != nil {
		return nil, err
	}
	lease, err := openRootLease(ctx, loaded.Install.OSS.StorePath, storeRead)
	if err != nil {
		if errors.Is(err, ErrProvenanceUnavailable) {
			return nil, ErrAnchorMissing
		}
		return nil, err
	}
	current, err := Load(ctx, selection)
	if err != nil {
		_ = lease.Close()
		return nil, err
	}
	currentProj, err := projectInstallation(current)
	if err != nil || !sameProjection(proj, currentProj) {
		_ = lease.Close()
		return nil, ErrPinMismatch
	}
	if err := checkOrdinaryStoreState(ctx, lease, proj); err != nil {
		_ = lease.Close()
		return nil, err
	}
	binding, err := openSQLBinding(ctx, lease, storeRead)
	if err != nil {
		_ = lease.Close()
		return nil, err
	}
	_, marker, err := lease.readMarkerSnapshot(ctx, activeMarkerName, maxDocument)
	if err != nil {
		_ = binding.Close()
		_ = lease.Close()
		return nil, ErrAnchorMissing
	}
	s := &Store{session: &storeSession{lease: lease, binding: binding}, db: binding.conn, selection: selection, proj: proj, ownsLease: true, markerName: activeMarkerName, marker: marker}
	if err := s.checkInstallation(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func sameProjection(left, right installationProjection) bool {
	return left.installationID == right.installationID && left.descriptorSHA256 == right.descriptorSHA256 && left.provisioningSHA256 == right.provisioningSHA256 && left.initialStateSHA256 == right.initialStateSHA256 && left.initialBundleSHA256 == right.initialBundleSHA256 && bytes.Equal(left.descriptorJSON, right.descriptorJSON) && bytes.Equal(left.provisioningJSON, right.provisioningJSON)
}

// checkOrdinaryStoreState is deliberately repeated at every ordinary Store
// publication boundary.  It never performs recovery or mutation.
func checkOrdinaryStoreState(ctx context.Context, lease *rootLease, proj installationProjection) error {
	if lease == nil || !lease.valid() {
		return ErrAnchorMissing
	}
	pending, err := lease.markerExists(pendingMarkerName)
	if err != nil || pending {
		return ErrPending
	}
	active, err := lease.markerExists(activeMarkerName)
	if err != nil || !active {
		return ErrAnchorMissing
	}
	main, err := lease.hasLeaf(storeDBName)
	if err != nil || !main {
		return ErrAnchorMissing
	}
	if err := lease.pendingSidecar(); err != nil {
		return err
	}
	return checkMarker(ctx, lease, activeMarkerName, proj)
}

func checkPendingStoreState(ctx context.Context, lease *rootLease, proj installationProjection) error {
	if lease == nil || !lease.valid() {
		return ErrAnchorMissing
	}
	pending, err := lease.markerExists(pendingMarkerName)
	if err != nil || !pending {
		return ErrPending
	}
	active, err := lease.markerExists(activeMarkerName)
	if err != nil || active {
		return ErrPending
	}
	main, err := lease.hasLeaf(storeDBName)
	if err != nil || !main {
		return ErrAnchorMissing
	}
	if err := lease.pendingSidecar(); err != nil {
		return err
	}
	return checkMarker(ctx, lease, pendingMarkerName, proj)
}

type storeMarker struct {
	APIVersion          string `json:"apiVersion"`
	InstallationID      string `json:"installationID"`
	DescriptorSHA256    string `json:"descriptorSHA256"`
	ProvisioningSHA256  string `json:"provisioningSHA256"`
	InitialStateSHA256  string `json:"initialStateSHA256"`
	InitialBundleSHA256 string `json:"initialBundleSHA256"`
}

const storeMarkerAPIVersion = "tplaiter.dev/bootstrap-store-marker/v1"

func markerFor(p installationProjection, initialBundle string) storeMarker {
	return storeMarker{storeMarkerAPIVersion, p.installationID, p.descriptorSHA256, p.provisioningSHA256, p.initialStateSHA256, initialBundle}
}

func checkMarker(ctx context.Context, lease *rootLease, name string, p installationProjection) error {
	raw, err := lease.readMarker(ctx, name, maxDocument)
	if err != nil {
		return ErrAnchorMissing
	}
	var marker storeMarker
	if err := canonicaljson.DecodeStrict(raw, &marker); err != nil || marker.APIVersion != storeMarkerAPIVersion || marker.InstallationID != p.installationID || marker.DescriptorSHA256 != p.descriptorSHA256 || marker.ProvisioningSHA256 != p.provisioningSHA256 || marker.InitialStateSHA256 != p.initialStateSHA256 || marker.InitialBundleSHA256 != p.initialBundleSHA256 {
		return ErrProvenanceUnavailable
	}
	return nil
}

func (s *Store) checkInstallation(ctx context.Context) error {
	if s == nil || s.session == nil || s.session.binding == nil || s.session.binding.conn == nil {
		return ErrAnchorMissing
	}
	var id, descriptor, provisioning, initial string
	if err := s.session.binding.conn.QueryRowContext(ctx, `SELECT installationID, descriptorSHA256, provisioningSHA256, initialStateSHA256 FROM installation WHERE singleton=1`).Scan(&id, &descriptor, &provisioning, &initial); err != nil {
		return ErrProvenanceUnavailable
	}
	if id != s.proj.installationID || descriptor != s.proj.descriptorSHA256 || provisioning != s.proj.provisioningSHA256 || initial != s.proj.initialStateSHA256 {
		return ErrPinMismatch
	}
	if s.markerName == "" && s.session.lease != nil {
		name := activeMarkerName
		if s.pending {
			name = pendingMarkerName
		}
		_, marker, err := s.session.lease.readMarkerSnapshot(ctx, name, maxDocument)
		if err != nil {
			return ErrProvenanceUnavailable
		}
		s.markerName, s.marker = name, marker
	}
	return nil
}

// Load returns the authenticated semantic projections and selected accepted
// state. It never treats a database row as a source of expected pins.
func (s *Store) Load(ctx context.Context) (bootstrap.ProvisionedSnapshot, error) {
	if s == nil || s.session == nil || s.session.binding == nil || s.session.binding.conn == nil || ctx == nil {
		return bootstrap.ProvisionedSnapshot{}, ErrAnchorMissing
	}
	if err := ctx.Err(); err != nil {
		return bootstrap.ProvisionedSnapshot{}, err
	}
	loaded, err := Load(ctx, s.selection)
	if err != nil {
		return bootstrap.ProvisionedSnapshot{}, err
	}
	current, err := projectInstallation(loaded)
	stateErr := checkOrdinaryStoreState(ctx, s.session.lease, s.proj)
	if s.pending {
		stateErr = checkPendingStoreState(ctx, s.session.lease, s.proj)
	}
	if err != nil || !sameProjection(s.proj, current) || !s.session.lease.valid() || stateErr != nil {
		return bootstrap.ProvisionedSnapshot{}, ErrProvenanceUnavailable
	}
	if err := s.checkInstallation(ctx); err != nil {
		return bootstrap.ProvisionedSnapshot{}, err
	}
	if _, currentMarker, markerErr := s.session.lease.readMarkerSnapshot(ctx, s.markerName, maxDocument); markerErr != nil || !s.marker.equal(currentMarker) {
		return bootstrap.ProvisionedSnapshot{}, ErrProvenanceUnavailable
	}
	var stateDigest string
	var stateRaw []byte
	if err := s.session.binding.conn.QueryRowContext(ctx, `SELECT stateSHA256, stateJSON FROM accepted WHERE singleton=1`).Scan(&stateDigest, &stateRaw); err != nil {
		return bootstrap.ProvisionedSnapshot{}, ErrProvenanceUnavailable
	}
	state, err := bootstrap.DecodeOSSAcceptedState(append([]byte(nil), stateRaw...))
	if err != nil || state.StateSHA256 != stateDigest || state.DescriptorSHA256 != s.proj.descriptorSHA256 || state.ProvisioningSHA256 != s.proj.provisioningSHA256 {
		return bootstrap.ProvisionedSnapshot{}, ErrProvenanceUnavailable
	}
	return bootstrap.ProvisionedSnapshot{
		DescriptorJSON: clone(s.proj.descriptorJSON), ProvisioningJSON: clone(s.proj.provisioningJSON),
		ExpectedDescriptorSHA256: s.proj.descriptorSHA256, ExpectedProvisioningSHA256: s.proj.provisioningSHA256,
		OSSStateJSON: clone(stateRaw), ExpectedOSSStateSHA256: stateDigest, InitialOSSStateSHA256: s.proj.initialStateSHA256,
	}, nil
}

func (s *Store) currentBundle(ctx context.Context) (StoredBundle, []byte, error) {
	var raw []byte
	if s == nil || s.session == nil || s.session.binding == nil || s.session.binding.conn == nil || s.checkInstallation(ctx) != nil {
		return StoredBundle{}, nil, ErrProvenanceUnavailable
	}
	if err := s.session.binding.conn.QueryRowContext(ctx, `SELECT bundleJSON FROM accepted WHERE singleton=1`).Scan(&raw); err != nil {
		return StoredBundle{}, nil, ErrProvenanceUnavailable
	}
	bundle, err := DecodeStoredBundle(raw)
	if err != nil {
		return StoredBundle{}, nil, ErrProvenanceUnavailable
	}
	return *bundle, clone(raw), nil
}

// Read implements evidencecas.Reader. Every retained blob is re-hashed before
// return, so SQLite bytes cannot assert their own digest.
func (s *Store) Read(ctx context.Context, ref string) ([]byte, error) {
	if s == nil || s.session == nil || s.session.binding == nil || s.session.binding.conn == nil || ctx == nil || !digest(ref) || s.checkInstallation(ctx) != nil {
		return nil, ErrProvenanceUnavailable
	}
	var raw []byte
	if err := s.session.binding.conn.QueryRowContext(ctx, `SELECT bytes FROM blobs WHERE digest=?`, ref).Scan(&raw); err != nil {
		return nil, ErrProvenanceUnavailable
	}
	if len(raw) > maxCASBlobBytes || rawSHA256(raw) != ref {
		return nil, ErrProvenanceUnavailable
	}
	return clone(raw), nil
}

func bundleFromStored(ctx context.Context, reader interface {
	Read(context.Context, string) ([]byte, error)
}, stored StoredBundle,
) (bootstrap.Bundle, error) {
	envelope, err := reader.Read(ctx, stored.EnvelopeCAS)
	if err != nil {
		return bootstrap.Bundle{}, ErrProvenanceUnavailable
	}
	receipt, err := reader.Read(ctx, stored.ReceiptCAS)
	if err != nil {
		return bootstrap.Bundle{}, ErrProvenanceUnavailable
	}
	return bootstrap.Bundle{Envelope: envelope, Receipt: receipt, Transparency: bootstrap.TransparencyEvidence{CheckpointCAS: stored.Transparency.CheckpointCAS, InclusionProofCAS: stored.Transparency.InclusionProofCAS, ConsistencyProofCAS: stored.Transparency.ConsistencyProofCAS}}, nil
}

const storeSchema = `
CREATE TABLE installation (singleton INTEGER PRIMARY KEY CHECK(singleton=1), installationID TEXT NOT NULL, descriptorSHA256 TEXT NOT NULL, provisioningSHA256 TEXT NOT NULL, initialStateSHA256 TEXT NOT NULL);
CREATE TABLE blobs (digest TEXT PRIMARY KEY, bytes BLOB NOT NULL);
CREATE TABLE accepted (singleton INTEGER PRIMARY KEY CHECK(singleton=1), stateSHA256 TEXT NOT NULL, stateJSON BLOB NOT NULL, bundleJSON BLOB NOT NULL, generation INTEGER NOT NULL CHECK(generation >= 1 AND generation <= 9007199254740991));
CREATE TABLE transitions (nextStateSHA256 TEXT PRIMARY KEY, previousStateSHA256 TEXT NOT NULL, previousBundleJSON BLOB NOT NULL, nextBundleJSON BLOB NOT NULL, evidenceDigestsJSON BLOB NOT NULL);
`

func validateEvidence(evidence map[string][]byte, refs []string) error {
	if len(evidence) > maxRefreshEvidence {
		return ErrConfigInvalid
	}
	var total int
	for ref, raw := range evidence {
		if !digest(ref) || len(raw) == 0 || len(raw) > maxCASBlobBytes || rawSHA256(raw) != ref {
			return ErrConfigInvalid
		}
		total += len(raw)
		if total > maxRefreshBytes {
			return ErrConfigInvalid
		}
	}
	for _, ref := range refs {
		if _, ok := evidence[ref]; !ok {
			return ErrProvenanceUnavailable
		}
	}
	return nil
}

func markerBytes(marker storeMarker) ([]byte, error) {
	raw, err := json.Marshal(marker)
	if err != nil {
		return nil, ErrConfigInvalid
	}
	return raw, nil
}

func safeState(raw []byte, expected, descriptor, provisioning string) error {
	state, err := bootstrap.DecodeOSSAcceptedState(raw)
	if err != nil || state.StateSHA256 != expected || state.DescriptorSHA256 != descriptor || state.ProvisioningSHA256 != provisioning {
		return ErrProvenanceUnavailable
	}
	return nil
}

func canonicalRefs(refs []string) ([]byte, error) {
	sorted := append([]string(nil), refs...)
	sort.Strings(sorted)
	for i := range sorted {
		if !digest(sorted[i]) || (i > 0 && sorted[i] == sorted[i-1]) {
			return nil, ErrConfigInvalid
		}
	}
	return json.Marshal(sorted)
}

func beginImmediate(ctx context.Context, conn *sql.Conn) error {
	if conn == nil {
		return ErrProvenanceUnavailable
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return ErrRefreshConflict
	}
	return nil
}

func rollback(conn *sql.Conn) {
	if conn != nil {
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
	}
}
