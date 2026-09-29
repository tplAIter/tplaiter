package trustload

import (
	"context"
	"database/sql"
	"errors"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

// storeEnrollmentPhaseHook is a private test synchronization seam. It never
// returns data or approval and is nil in production; subprocess tests use it
// only to stop a child after a durable lifecycle boundary.
var (
	storeEnrollmentPhaseHook func(string)
	storeRefreshPhaseHook    func(string)
)

func observeStoreEnrollmentPhase(stage string) {
	if storeEnrollmentPhaseHook != nil {
		storeEnrollmentPhaseHook(stage)
	}
}

func observeStoreRefreshPhase(stage string) {
	if storeRefreshPhaseHook != nil {
		storeRefreshPhaseHook(stage)
	}
}

func Enroll(ctx context.Context, selection LaunchSelection, factory VerifierFactory, initialStateJSON, initialBundleJSON []byte, evidence map[string][]byte) error {
	if ctx == nil || factory == nil {
		return ErrAnchorMissing
	}
	loaded, err := Load(ctx, selection)
	if err != nil {
		return err
	}
	proj, err := projectInstallation(loaded)
	if err != nil {
		return err
	}
	if len(initialStateJSON) == 0 || len(initialStateJSON) > maxDocument || len(initialBundleJSON) == 0 || len(initialBundleJSON) > maxDocument {
		return ErrConfigInvalid
	}
	bundle, err := DecodeStoredBundle(initialBundleJSON)
	if err != nil {
		return err
	}
	bundleDigest, err := bundle.Digest()
	if err != nil || bundleDigest != loaded.Install.OSS.InitialBundleSHA256 {
		return ErrPinMismatch
	}
	if err := safeState(initialStateJSON, proj.initialStateSHA256, proj.descriptorSHA256, proj.provisioningSHA256); err != nil {
		return err
	}
	if err := validateEvidence(evidence, bundle.references()); err != nil {
		return err
	}
	lease, err := openRootLease(ctx, loaded.Install.OSS.StorePath, storeEnroll)
	if err != nil {
		return err
	}
	defer lease.Close()
	current, err := Load(ctx, selection)
	if err != nil {
		return err
	}
	currentProj, err := projectInstallation(current)
	if err != nil || !sameProjection(proj, currentProj) {
		return ErrPinMismatch
	}
	observeStoreEnrollmentPhase("root-created")
	markerRaw, err := markerBytes(markerFor(proj, bundleDigest))
	if err != nil {
		return err
	}
	if err := lease.writePendingMarker(ctx, markerRaw); err != nil {
		return err
	}
	observeStoreEnrollmentPhase("pending-synced")
	binding, err := openSQLBinding(ctx, lease, storeEnroll)
	if err != nil {
		return err
	}
	committed := false
	defer func() { //nolint:contextcheck // rollback must run even after ctx is cancelled
		if !committed {
			rollback(binding.conn)
		}
		_ = binding.Close()
	}()
	if _, err := binding.conn.ExecContext(ctx, storeSchema); err != nil {
		return ErrProvenanceUnavailable
	}
	if err := beginImmediate(ctx, binding.conn); err != nil {
		return err
	}
	if _, err := binding.conn.ExecContext(ctx, `INSERT INTO installation(singleton,installationID,descriptorSHA256,provisioningSHA256,initialStateSHA256) VALUES(1,?,?,?,?)`, proj.installationID, proj.descriptorSHA256, proj.provisioningSHA256, proj.initialStateSHA256); err != nil {
		return ErrProvenanceUnavailable
	}
	for ref, raw := range evidence {
		if _, err := binding.conn.ExecContext(ctx, `INSERT INTO blobs(digest,bytes) VALUES(?,?)`, ref, raw); err != nil {
			return ErrProvenanceUnavailable
		}
	}
	if _, err := binding.conn.ExecContext(ctx, `INSERT INTO accepted(singleton,stateSHA256,stateJSON,bundleJSON,generation) VALUES(1,?,?,?,1)`, proj.initialStateSHA256, initialStateJSON, initialBundleJSON); err != nil {
		return ErrProvenanceUnavailable
	}
	observeStoreEnrollmentPhase("sqlite-commit-before")
	if _, err := binding.conn.ExecContext(ctx, "COMMIT"); err != nil {
		return ErrProvenanceUnavailable
	}
	committed = true
	observeStoreEnrollmentPhase("sqlite-commit")
	if err := binding.Close(); err != nil {
		return ErrProvenanceUnavailable
	}
	observeStoreEnrollmentPhase("verification-before")
	if err := verifyUnderLease(ctx, lease, selection, proj, true, factory); err != nil {
		return ErrProvenanceUnavailable
	}
	observeStoreEnrollmentPhase("verification")
	if err := lease.activatePendingMarker(ctx, markerRaw); err != nil {
		return ErrProvenanceUnavailable
	}
	return nil
}

// borrowedStore is a private verification view held under an existing EX
// lease. It is never returned as an ordinary Store authority.
func borrowedStore(ctx context.Context, lease *rootLease, selection LaunchSelection, proj installationProjection, pending bool) (*Store, error) {
	binding, err := openSQLBinding(ctx, lease, storeRead)
	if err != nil {
		return nil, err
	}
	store := &Store{session: &storeSession{lease: lease, binding: binding}, db: binding.conn, selection: selection, proj: proj, pending: pending}
	if err := store.checkInstallation(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func verifyUnderLease(ctx context.Context, lease *rootLease, selection LaunchSelection, proj installationProjection, pending bool, factory VerifierFactory) error {
	if lease == nil || factory == nil || !lease.valid() {
		return ErrProvenanceUnavailable
	}
	store, err := borrowedStore(ctx, lease, selection, proj, pending)
	if err != nil {
		return err
	}
	defer store.Close()
	_, err = verifyCurrent(ctx, store, factory)
	return err
}

func verifyCurrent(ctx context.Context, store *Store, factory VerifierFactory) (*bootstrap.Authority, error) {
	if factory == nil {
		return nil, ErrAnchorMissing
	}
	ext, err := bootstrap.LoadExternal(ctx, store)
	if err != nil {
		return nil, err
	}
	stored, _, err := store.currentBundle(ctx)
	if err != nil {
		return nil, err
	}
	bundle, err := bundleFromStored(ctx, store, stored)
	if err != nil {
		return nil, err
	}
	verifier, err := factory(store)
	if err != nil || verifier == nil {
		return nil, ErrProvenanceUnavailable
	}
	return verifier.VerifyOSS(ctx, ext, bundle)
}

type overlayEvidence struct {
	base evidencecas.Reader
	add  map[string][]byte
}

func (r overlayEvidence) Read(ctx context.Context, digest string) ([]byte, error) {
	if raw, ok := r.add[digest]; ok {
		if len(raw) > maxCASBlobBytes || rawSHA256(raw) != digest {
			return nil, ErrProvenanceUnavailable
		}
		return clone(raw), nil
	}
	return r.base.Read(ctx, digest)
}

func Refresh(ctx context.Context, selection LaunchSelection, factory VerifierFactory, nextBundleJSON []byte, nextEvidence map[string][]byte) (*bootstrap.Authority, error) {
	if ctx == nil || factory == nil {
		return nil, ErrAnchorMissing
	}
	loaded, err := Load(ctx, selection)
	if err != nil {
		return nil, err
	}
	currentStore, err := openReadOnlyLoaded(ctx, selection, loaded)
	if err != nil {
		return nil, err
	}
	baselineRootDev, baselineRootIno := currentStore.session.lease.dev, currentStore.session.lease.ino
	baselineMarker := currentStore.marker
	currentAuthority, err := verifyCurrent(ctx, currentStore, factory)
	if err != nil {
		_ = currentStore.Close()
		return nil, ErrProvenanceUnavailable
	}
	_ = currentAuthority
	currentExternal, err := bootstrap.LoadExternal(ctx, currentStore)
	if err != nil {
		_ = currentStore.Close()
		return nil, ErrProvenanceUnavailable
	}
	currentStored, currentRaw, err := currentStore.currentBundle(ctx)
	if err != nil {
		_ = currentStore.Close()
		return nil, err
	}
	currentBundle, err := bundleFromStored(ctx, currentStore, currentStored)
	if err != nil {
		_ = currentStore.Close()
		return nil, err
	}
	nextStored, err := DecodeStoredBundle(nextBundleJSON)
	if err != nil || validateEvidenceSubset(nextEvidence) != nil {
		_ = currentStore.Close()
		return nil, ErrConfigInvalid
	}
	overlay := overlayEvidence{base: currentStore, add: cloneEvidence(nextEvidence)}
	for _, ref := range nextStored.references() {
		if _, err := overlay.Read(ctx, ref); err != nil {
			_ = currentStore.Close()
			return nil, ErrProvenanceUnavailable
		}
	}
	nextBundle, err := bundleFromStored(ctx, overlay, *nextStored)
	if err != nil {
		_ = currentStore.Close()
		return nil, err
	}
	verifier, err := factory(overlay)
	if err != nil || verifier == nil {
		_ = currentStore.Close()
		return nil, ErrProvenanceUnavailable
	}
	proposal, err := verifier.PrepareOSSRefresh(ctx, currentExternal, currentBundle, nextBundle)
	if closeErr := currentStore.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return nil, ErrProvenanceUnavailable
	}
	loaded, err = Load(ctx, selection)
	if err != nil {
		return nil, err
	}
	proj, err := projectInstallation(loaded)
	if err != nil || len(nextBundleJSON) > maxDocument || len(proposal.NextStateJSON()) > maxDocument {
		return nil, ErrConfigInvalid
	}
	nextState := proposal.NextStateJSON()
	if err := safeState(nextState, stateDigest(nextState), proj.descriptorSHA256, proj.provisioningSHA256); err != nil {
		return nil, err
	}
	lease, err := openRootLease(ctx, loaded.Install.OSS.StorePath, storeRefresh)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	if !refreshIdentityContinuous(ctx, lease, baselineRootDev, baselineRootIno, baselineMarker) {
		return nil, ErrProvenanceUnavailable
	}
	current, err := Load(ctx, selection)
	if err != nil {
		return nil, err
	}
	currentProj, err := projectInstallation(current)
	if err != nil || !sameProjection(proj, currentProj) {
		return nil, ErrPinMismatch
	}
	if err := checkOrdinaryStoreState(ctx, lease, proj); err != nil {
		return nil, err
	}
	binding, err := openSQLBinding(ctx, lease, storeRefresh)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() { //nolint:contextcheck // rollback must run even after ctx is cancelled
		if !committed {
			rollback(binding.conn)
		}
		_ = binding.Close()
	}()
	if err := beginImmediate(ctx, binding.conn); err != nil {
		return nil, err
	}
	observeStoreRefreshPhase("begin")
	var installationID, descriptor, provisioning, initial string
	if err := binding.conn.QueryRowContext(ctx, `SELECT installationID,descriptorSHA256,provisioningSHA256,initialStateSHA256 FROM installation WHERE singleton=1`).Scan(&installationID, &descriptor, &provisioning, &initial); err != nil || installationID != proj.installationID || descriptor != proj.descriptorSHA256 || provisioning != proj.provisioningSHA256 || initial != proj.initialStateSHA256 {
		return nil, ErrPinMismatch
	}
	var previousState string
	var generation int64
	if err := binding.conn.QueryRowContext(ctx, `SELECT stateSHA256,generation FROM accepted WHERE singleton=1`).Scan(&previousState, &generation); err != nil {
		return nil, ErrProvenanceUnavailable
	}
	if previousState != proposal.ExpectedStateSHA256() || generation < 1 || generation >= maxGeneration {
		return nil, ErrRefreshConflict
	}
	if err := insertEvidenceDirect(ctx, binding.conn, nextEvidence); err != nil {
		return nil, err
	}
	refs, err := canonicalRefs(nextStored.references())
	if err != nil {
		return nil, err
	}
	if _, err := binding.conn.ExecContext(ctx, `INSERT INTO transitions(nextStateSHA256,previousStateSHA256,previousBundleJSON,nextBundleJSON,evidenceDigestsJSON) VALUES(?,?,?,?,?)`, stateDigest(nextState), previousState, currentRaw, nextBundleJSON, refs); err != nil {
		return nil, ErrProvenanceUnavailable
	}
	if _, err := binding.conn.ExecContext(ctx, `UPDATE accepted SET stateSHA256=?,stateJSON=?,bundleJSON=?,generation=? WHERE singleton=1`, stateDigest(nextState), nextState, nextBundleJSON, generation+1); err != nil {
		return nil, ErrProvenanceUnavailable
	}
	observeStoreRefreshPhase("write")
	observeStoreRefreshPhase("commit-before")
	if _, err := binding.conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, ErrProvenanceUnavailable
	}
	committed = true
	observeStoreRefreshPhase("commit")
	if err := binding.Close(); err != nil {
		return nil, ErrProvenanceUnavailable
	}
	if err := checkOrdinaryStoreState(ctx, lease, proj); err != nil {
		return nil, err
	}
	if !refreshIdentityContinuous(ctx, lease, baselineRootDev, baselineRootIno, baselineMarker) {
		return nil, ErrProvenanceUnavailable
	}
	store, err := borrowedStore(ctx, lease, selection, proj, false)
	if err != nil {
		return nil, err
	}
	authority, verifyErr := verifyCurrent(ctx, store, factory)
	closeErr := store.Close()
	if verifyErr != nil || closeErr != nil {
		return nil, ErrProvenanceUnavailable
	}
	return authority, nil
}

// refreshIdentityContinuous binds the EX transaction and post-commit reader
// to the marker/root authenticated under the initial SH Store. A fresh Store
// must not silently recapture a replacement marker as its new baseline.
func refreshIdentityContinuous(ctx context.Context, lease *rootLease, dev, ino uint64, marker markerSnapshot) bool {
	if lease == nil || lease.dev != dev || lease.ino != ino || !lease.valid() {
		return false
	}
	_, current, err := lease.readMarkerSnapshot(ctx, activeMarkerName, maxDocument)
	return err == nil && marker.equal(current)
}

func cloneEvidence(in map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for ref, raw := range in {
		out[ref] = clone(raw)
	}
	return out
}

func validateEvidenceSubset(evidence map[string][]byte) error {
	if len(evidence) > maxRefreshEvidence {
		return ErrConfigInvalid
	}
	total := 0
	for ref, raw := range evidence {
		if !digest(ref) || len(raw) == 0 || len(raw) > maxCASBlobBytes || rawSHA256(raw) != ref {
			return ErrConfigInvalid
		}
		total += len(raw)
		if total > maxRefreshBytes {
			return ErrConfigInvalid
		}
	}
	return nil
}

func insertEvidenceDirect(ctx context.Context, conn *sql.Conn, evidence map[string][]byte) error {
	for ref, raw := range evidence {
		var previous []byte
		err := conn.QueryRowContext(ctx, `SELECT bytes FROM blobs WHERE digest=?`, ref).Scan(&previous)
		if errors.Is(err, sql.ErrNoRows) {
			if _, err = conn.ExecContext(ctx, `INSERT INTO blobs(digest,bytes) VALUES(?,?)`, ref, raw); err != nil {
				return ErrProvenanceUnavailable
			}
			continue
		}
		if err != nil || string(previous) != string(raw) {
			return ErrProvenanceUnavailable
		}
	}
	return nil
}

func stateDigest(raw []byte) string {
	state, err := bootstrap.DecodeOSSAcceptedState(raw)
	if err != nil {
		return ""
	}
	return state.StateSHA256
}

func RecoverState(ctx context.Context, selection LaunchSelection, factory VerifierFactory) error {
	if ctx == nil || factory == nil {
		return ErrAnchorMissing
	}
	loaded, err := Load(ctx, selection)
	if err != nil {
		return err
	}
	proj, err := projectInstallation(loaded)
	if err != nil {
		return err
	}
	lease, err := openRootLease(ctx, loaded.Install.OSS.StorePath, storeRecover)
	if err != nil {
		return err
	}
	defer lease.Close()
	current, err := Load(ctx, selection)
	if err != nil {
		return err
	}
	currentProj, err := projectInstallation(current)
	if err != nil || !sameProjection(proj, currentProj) {
		return ErrPinMismatch
	}
	pending, err := lease.markerExists(pendingMarkerName)
	if err != nil {
		return ErrPending
	}
	active, err := lease.markerExists(activeMarkerName)
	if err != nil || pending == active {
		return ErrPending
	}
	main, err := lease.hasLeaf(storeDBName)
	if err != nil || !main {
		return ErrPending
	}
	markerName := activeMarkerName
	if pending {
		markerName = pendingMarkerName
	}
	if err := checkMarker(ctx, lease, markerName, proj); err != nil {
		return err
	}
	if err := recoverStoreColdJournal(ctx, lease); err != nil {
		return err
	}
	if !pending {
		if err := verifyUnderLease(ctx, lease, selection, proj, false, factory); err != nil {
			return ErrProvenanceUnavailable
		}
		return nil
	}
	store, err := borrowedStore(ctx, lease, selection, proj, true)
	if err != nil {
		return err
	}
	var transitions int
	var state string
	queryErr := store.session.binding.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM transitions`).Scan(&transitions)
	if queryErr == nil {
		queryErr = store.session.binding.conn.QueryRowContext(ctx, `SELECT stateSHA256 FROM accepted WHERE singleton=1`).Scan(&state)
	}
	verifyErr := error(nil)
	if queryErr == nil && transitions == 0 && state == proj.initialStateSHA256 {
		_, verifyErr = verifyCurrent(ctx, store, factory)
	} else if queryErr == nil {
		verifyErr = ErrPending
	}
	closeErr := store.Close()
	if queryErr != nil || verifyErr != nil || closeErr != nil {
		return ErrPending
	}
	raw, err := markerBytes(markerFor(proj, proj.initialBundleSHA256))
	if err != nil {
		return err
	}
	return lease.activatePendingMarker(ctx, raw)
}
