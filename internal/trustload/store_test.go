package trustload

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

// exists is test-only compatibility for frozen helper regression fixtures.
func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

type bootstrapFixture struct {
	loaded     *Loaded
	selection  LaunchSelection
	load       *loadFixture
	stateJSON  []byte
	bundleJSON []byte
	evidence   map[string][]byte
	factory    VerifierFactory
}

func newBootstrapFixture(t *testing.T) bootstrapFixture {
	t.Helper()
	load := newLoadFixture(t)
	loaded, err := Load(context.Background(), load.selection)
	if err != nil {
		t.Fatal(err)
	}
	anchor := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	root := ed25519.NewKeyFromSeed([]byte("12345678901234567890123456789012"))
	evidence := map[string][]byte{}
	put := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		ref := evidencecas.Digest(raw)
		evidence[ref] = raw
		return ref
	}
	rootRaw := []byte(bootstrap.EncodePublicKey(root.Public().(ed25519.PublicKey)))
	rootRef := evidencecas.Digest(rootRaw)
	evidence[rootRef] = rootRaw
	envelope := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: "synthetic-authority", Sequence: 1, Validity: bootstrap.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(root.Public().(ed25519.PublicKey)), PublicKeyCAS: rootRef, Issuer: "publisher-1", Status: "active"}}, Threshold: 1, RevocationEpoch: 0, Revocations: []bootstrap.Revocation{}}
	envelope.PayloadSHA256, err = envelope.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := hex.DecodeString(envelope.PayloadSHA256[7:])
	if err != nil {
		t.Fatal(err)
	}
	sigRaw := []byte(bootstrap.EncodeSignature(ed25519.Sign(anchor, payload)))
	sigRef := evidencecas.Digest(sigRaw)
	evidence[sigRef] = sigRaw
	envelope.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchor.Public().(ed25519.PublicKey)), SignatureCAS: sigRef}}
	leaf := bootstrap.HashLeaf([]byte(envelope.PayloadSHA256))
	checkpointRef := put(bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: envelope.AuthorityID, TreeSize: 1, RootHash: "sha256:" + hex.EncodeToString(leaf[:])})
	inclusionRef := put(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 1, Hashes: []string{}})
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: envelope.AuthorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: envelope.PayloadSHA256, RevocationEpoch: 0, TreeSize: 1, CheckpointDigest: checkpointRef, PreviousReceiptDigest: ""}
	receipt.ReceiptDigest, err = receipt.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRef := evidencecas.Digest(envelopeRaw)
	evidence[envelopeRef] = envelopeRaw
	receiptRef := evidencecas.Digest(receiptRaw)
	evidence[receiptRef] = receiptRaw
	descriptor, err := bootstrap.DecodeDescriptorDocument(loaded.DescriptorJSON)
	if err != nil {
		t.Fatal(err)
	}
	provisioning, err := bootstrap.DecodeProvisioningRecord(loaded.ProvisioningJSON)
	if err != nil {
		t.Fatal(err)
	}
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: descriptor.DescriptorSHA256, ProvisioningSHA256: provisioning.ProvisioningSHA256, AuthorityID: envelope.AuthorityID, Sequence: envelope.Sequence, EnvelopePayloadSHA256: envelope.PayloadSHA256, RevocationEpoch: envelope.RevocationEpoch, ReceiptDigest: receipt.ReceiptDigest, TreeSize: receipt.TreeSize, CheckpointDigest: receipt.CheckpointDigest}
	state.StateSHA256 = state.ComputedSHA256()
	stateRaw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if state.StateSHA256 != loaded.Install.OSS.InitialStateSHA256 {
		loaded.Install.OSS.InitialStateSHA256 = state.StateSHA256
		// The loader fixture's RuntimeInstall is externally registered. Rebuild its
		// registration with the fixed semantic initial-state pin before loading it.
		load.install.OSS.InitialStateSHA256 = state.StateSHA256
		load.writeInstall(t)
		_, err = Load(context.Background(), load.selection)
		if err != nil {
			t.Fatal(err)
		}
	}
	bundle := StoredBundle{APIVersion: storedBundleAPIVersion, EnvelopeCAS: envelopeRef, ReceiptCAS: receiptRef, Transparency: StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: inclusionRef, ConsistencyProofCAS: ""}}
	bundleRaw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	load.install.OSS.InitialBundleSHA256 = bundleDigest
	load.writeInstall(t)
	loaded, err = Load(context.Background(), load.selection)
	if err != nil {
		t.Fatal(err)
	}
	factory := func(reader evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(reader, bootstrap.ClockFunc(func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }), nil, 0)
	}
	return bootstrapFixture{loaded: loaded, selection: load.selection, load: load, stateJSON: stateRaw, bundleJSON: bundleRaw, evidence: evidence, factory: factory}
}

func TestStoredBundleClosedWireAndDigest(t *testing.T) {
	fixture := newBootstrapFixture(t)
	bundle, err := DecodeStoredBundle(fixture.bundleJSON)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Digest(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"apiVersion":"tplaiter.dev/stored-bootstrap-bundle/v1"}`),
		[]byte(`{"apiVersion":"tplaiter.dev/stored-bootstrap-bundle/v1","envelopeCAS":"sha256:0000000000000000000000000000000000000000000000000000000000000000","receiptCAS":"sha256:0000000000000000000000000000000000000000000000000000000000000000","transparency":{},"extra":true}`),
	} {
		if _, err := DecodeStoredBundle(raw); err == nil {
			t.Fatal("accepted invalid stored bundle")
		}
	}
}

func TestEnrollReadOnlyExternalAndFixedPins(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	fixture := newBootstrapFixture(t)
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ext, err := bootstrap.LoadExternal(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	stored, _, err := store.currentBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := bundleFromStored(context.Background(), store, stored)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := fixture.factory(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyOSS(context.Background(), ext, candidate); err != nil {
		t.Fatalf("actual VerifyOSS = %v", err)
	}
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err == nil {
		t.Fatal("re-enrolled existing installation")
	}
	fixture.load.install.OSS.InitialStateSHA256 = rawSHA256([]byte("different fixed initial state"))
	fixture.load.writeInstall(t)
	fixture.selection = fixture.load.selection
	if _, err := OpenReadOnly(context.Background(), fixture.selection); err == nil {
		t.Fatal("accepted changed fixed initial pin")
	}
}

// TestOpenReadOnlySB09CompositionMatrix exercises production publication,
// rather than marker helpers: each hostile state must deny a usable Store.
func TestOpenReadOnlySB09CompositionMatrix(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, root string)
	}{
		{"missing-main", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, storeDBName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"both-markers", func(t *testing.T, root string) {
			raw, err := os.ReadFile(filepath.Join(root, activeMarkerName))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, pendingMarkerName), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"invalid-active", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, activeMarkerName), []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized-active", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, activeMarkerName), make([]byte, maxDocument+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-active", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, activeMarkerName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"pending-only", func(t *testing.T, root string) {
			raw, err := os.ReadFile(filepath.Join(root, activeMarkerName))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, pendingMarkerName), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, activeMarkerName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-active", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, activeMarkerName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("missing", filepath.Join(root, activeMarkerName)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
				t.Fatal(err)
			}
			root := fixture.loaded.Install.OSS.StorePath
			tc.mutate(t, root)
			if store, err := OpenReadOnly(context.Background(), fixture.selection); err == nil || store != nil {
				t.Fatalf("OpenReadOnly accepted hostile %s", tc.name)
			}
		})
	}
}

func TestStoreLoadSB09RechecksMarkerPublication(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	fixture := newBootstrapFixture(t)
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := fixture.loaded.Install.OSS.StorePath
	if err := os.WriteFile(filepath.Join(root, pendingMarkerName), []byte("substitution"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil {
		t.Fatal("Store.Load accepted pending substitution")
	}
}

func TestStoreLoadSB09RejectsValidMarkerAndRootReplacement(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, root string)
	}{
		{"valid-marker-replacement", func(t *testing.T, root string) {
			raw, err := os.ReadFile(filepath.Join(root, activeMarkerName))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(root, activeMarkerName), filepath.Join(root, activeMarkerName+".old")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, activeMarkerName), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"root-path-replacement", func(t *testing.T, root string) {
			if err := os.Rename(root, root+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
				t.Fatal(err)
			}
			store, err := OpenReadOnly(context.Background(), fixture.selection)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			tc.mutate(t, fixture.loaded.Install.OSS.StorePath)
			if _, err := store.Load(context.Background()); err == nil {
				t.Fatal("Store.Load accepted replacement")
			}
		})
	}
}

func rotateBundle(t *testing.T, fixture bootstrapFixture) ([]byte, map[string][]byte) {
	t.Helper()
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	current, _, err := store.currentBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	currentBundle, err := bundleFromStored(context.Background(), store, current)
	if err != nil {
		t.Fatal(err)
	}
	old, err := bootstrap.DecodeEnvelope(currentBundle.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	oldReceipt, err := bootstrap.DecodeReceipt(currentBundle.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := ed25519.NewKeyFromSeed([]byte("12345678901234567890123456789012"))
	newRoot := ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123"))
	added := map[string][]byte{}
	put := func(v any) string {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		ref := evidencecas.Digest(raw)
		added[ref] = raw
		return ref
	}
	pub := newRoot.Public().(ed25519.PublicKey)
	keyRaw := []byte(bootstrap.EncodePublicKey(pub))
	keyRef := evidencecas.Digest(keyRaw)
	added[keyRef] = keyRaw
	next := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: old.AuthorityID, Sequence: old.Sequence + 1, Validity: old.Validity, AllowedPolicyOrigins: old.AllowedPolicyOrigins, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(pub), PublicKeyCAS: keyRef, Issuer: "publisher-1", Status: "active"}}, Threshold: 1, RevocationEpoch: old.RevocationEpoch + 1, Revocations: []bootstrap.Revocation{}, Rotation: &bootstrap.Rotation{PreviousSequence: old.Sequence, OverlapUntil: "2026-12-01T00:00:00Z"}}
	next.PayloadSHA256, err = next.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := hex.DecodeString(next.PayloadSHA256[7:])
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []ed25519.PrivateKey{oldRoot, newRoot} {
		raw := []byte(bootstrap.EncodeSignature(ed25519.Sign(key, payload)))
		ref := evidencecas.Digest(raw)
		added[ref] = raw
		next.Signatures = append(next.Signatures, bootstrap.Signature{KeyFingerprint: bootstrap.Fingerprint(key.Public().(ed25519.PublicKey)), SignatureCAS: ref})
	}
	sort.Slice(next.Signatures, func(i, j int) bool { return next.Signatures[i].KeyFingerprint < next.Signatures[j].KeyFingerprint })
	oldLeaf, newLeaf := bootstrap.HashLeaf([]byte(old.PayloadSHA256)), bootstrap.HashLeaf([]byte(next.PayloadSHA256))
	root := bootstrap.HashChildren(oldLeaf, newLeaf)
	checkpointRef := put(bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: next.AuthorityID, TreeSize: 2, RootHash: "sha256:" + hex.EncodeToString(root[:])})
	inclusionRef := put(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 1, TreeSize: 2, Hashes: []string{"sha256:" + hex.EncodeToString(oldLeaf[:])}})
	consistencyRef := put(bootstrap.ConsistencyProof{APIVersion: bootstrap.ConsistencyAPIVersion, OldTreeSize: 1, NewTreeSize: 2, Hashes: []string{"sha256:" + hex.EncodeToString(newLeaf[:])}})
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: next.AuthorityID, HighestAcceptedSequence: next.Sequence, EnvelopePayloadSHA256: next.PayloadSHA256, RevocationEpoch: next.RevocationEpoch, TreeSize: 2, CheckpointDigest: checkpointRef, PreviousReceiptDigest: oldReceipt.ReceiptDigest}
	receipt.ReceiptDigest, err = receipt.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRef, receiptRef := evidencecas.Digest(envelopeRaw), evidencecas.Digest(receiptRaw)
	added[envelopeRef], added[receiptRef] = envelopeRaw, receiptRaw
	raw, err := json.Marshal(StoredBundle{APIVersion: storedBundleAPIVersion, EnvelopeCAS: envelopeRef, ReceiptCAS: receiptRef, Transparency: StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: inclusionRef, ConsistencyProofCAS: consistencyRef}})
	if err != nil {
		t.Fatal(err)
	}
	return raw, added
}

func TestRefreshCommitsOnlyPreparedStateAndReloads(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	fixture := newBootstrapFixture(t)
	if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
		t.Fatal(err)
	}
	nextBundle, nextEvidence := rotateBundle(t, fixture)
	authority, err := Refresh(context.Background(), fixture.selection, fixture.factory, nextBundle, nextEvidence)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if authority.Binding().ID != bootstrap.ProfileOSS {
		t.Fatal("refresh did not return reloaded OSS authority")
	}
	if _, err := Refresh(context.Background(), fixture.selection, fixture.factory, nextBundle, nextEvidence); err == nil {
		t.Fatal("replayed refresh accepted")
	}
	store, err := OpenReadOnly(context.Background(), fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var generations, transitions int
	if err := store.db.QueryRowContext(context.Background(), `SELECT generation FROM accepted WHERE singleton=1`).Scan(&generations); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM transitions`).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if generations != 2 || transitions != 1 {
		t.Fatalf("generation=%d transitions=%d", generations, transitions)
	}
}

func TestRecoverPendingEnrollmentOnly(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	fixture := newBootstrapFixture(t)
	failing := func(evidencecas.Reader) (*bootstrap.Verifier, error) {
		return nil, errors.New("injected verifier construction failure")
	}
	if err := Enroll(context.Background(), fixture.selection, failing, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err == nil {
		t.Fatal("injected enrollment failure accepted")
	}
	if _, err := OpenReadOnly(context.Background(), fixture.selection); !errors.Is(err, ErrPending) {
		t.Fatalf("ordinary pending read = %v", err)
	}
	if err := RecoverState(context.Background(), fixture.selection, fixture.factory); err != nil {
		t.Fatalf("RecoverState() = %v", err)
	}
	if _, err := OpenReadOnly(context.Background(), fixture.selection); err != nil {
		t.Fatalf("recovered reader = %v", err)
	}
}
