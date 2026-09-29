// Package ossinstall generates the operator-pinned OSS trust installation that
// a source build (`make install`) links into the tplaiter binary.
//
// The installing operator is the trust anchor: Generate creates a fresh
// Ed25519 anchor key, signs a single-authority trust-root envelope with it,
// records the envelope in a one-leaf transparency log, and discards every
// private key before it returns. The resulting documents are pinned by
// digest, from the leaf documents up to one installed-launch registration.
// Only the registration's absolute path and digest are then compiled into
// the binary through linker flags, so neither flags nor environment
// variables (HOME, XDG_*) ever participate in selecting trust material.
//
// See docs/adr/ADR-005-oss-install-registration.md for the design record.
package ossinstall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// RegistrationAPIVersion identifies the installed-launch registration
// document read by the binary at start-up.
const RegistrationAPIVersion = "tplaiter.dev/installed-launch-registration/v1"

// RegistrationFile is the registration's file name inside the install root.
const RegistrationFile = "registration.json"

// DefaultProjectKey is the project context key the registration selects.
const DefaultProjectKey = "default"

// DefaultValidity is how long the generated trust roots and execution policy
// stay valid. Re-running Generate with Rotate replaces an expired install.
const DefaultValidity = 5 * 365 * 24 * time.Hour

// Placeholder origins. The ".invalid" top-level domain is reserved (RFC 2606)
// and never resolves, so the default install trusts no real template source
// until the operator configures a publisher.
const (
	localPolicyOrigin    = "https://local.tplaiter.invalid/policy"
	localPredicate       = "https://local.tplaiter.invalid/predicate/template-source"
	unconfiguredOrigin   = "https://local.tplaiter.invalid/unconfigured"
	unconfiguredIssuer   = "local-unconfigured"
	publisherStatementV1 = "tplaiter-publisher-statement-v1"
	operatorPrincipal    = "principal:operator"
	publisherPrincipal   = "principal:publisher"
)

// Registration is the installed-launch registration document. The binary
// pins its raw SHA-256 at link time and trusts nothing else it cannot reach
// from these pins.
type Registration struct {
	APIVersion     string              `json:"apiVersion"`
	Profile        bootstrap.ProfileID `json:"profile"`
	RuntimeConfig  trustload.FilePin   `json:"runtimeConfig"`
	OperatorRecord trustload.FilePin   `json:"operatorRecord"`
	InstallationID string              `json:"installationID"`
	ProjectKey     string              `json:"projectKey"`
}

// DecodeRegistration strictly decodes a registration and rejects every
// profile other than OSS or organization; the development profile is never
// accepted in an installed launch.
func DecodeRegistration(raw []byte) (*Registration, error) {
	var r Registration
	if err := canonicaljson.DecodeStrict(raw, &r); err != nil {
		return nil, trustload.ErrConfigInvalid
	}
	if r.APIVersion != RegistrationAPIVersion || r.Profile == bootstrap.ProfileDevelopment || r.ProjectKey == "" {
		return nil, trustload.ErrConfigInvalid
	}
	return &r, nil
}

// Selection returns the launch selection carried by the registration.
func (r Registration) Selection() trustload.LaunchSelection {
	return trustload.LaunchSelection{Profile: r.Profile, RuntimeConfig: r.RuntimeConfig, OperatorRecord: r.OperatorRecord, InstallationID: r.InstallationID}
}

// Publisher is an operator-trusted template publisher. Its statements are
// accepted for SourceOrigin/TemplatePath when signed by PublicKeyBase64.
type Publisher struct {
	Issuer          string `json:"issuer"`
	PublicKeyBase64 string `json:"publicKeyBase64"`
	SourceOrigin    string `json:"sourceOrigin"`
	TemplatePath    string `json:"templatePath"`
	// ObjectRoot is an absolute directory of loose git objects for
	// SourceOrigin. When empty, Generate creates one inside the install root.
	ObjectRoot string `json:"objectRoot,omitempty"`
}

// Options control Generate.
type Options struct {
	// Root is the install root. It is created (mode 0700) when missing and
	// resolved to a symlink-free absolute path, because the loaders open
	// every path component with O_NOFOLLOW.
	Root string
	// Publishers lists trusted template publishers. When empty, a single
	// placeholder publisher over an unresolvable origin is generated and its
	// key discarded, so no real template source is trusted.
	Publishers []Publisher
	// Rotate discards an existing install root's documents and trust store
	// and generates a new installation.
	Rotate bool
	// Now and Validity bound the generated validity window. Zero values mean
	// time.Now and DefaultValidity.
	Now      time.Time
	Validity time.Duration
	// Rand supplies key and identifier entropy; nil means crypto/rand.
	Rand io.Reader
}

// Result describes the registration the binary must be linked against.
type Result struct {
	Root               string
	RegistrationPath   string
	RegistrationSHA256 string
	InstallationID     string
	// Reused is true when a valid existing installation was kept.
	Reused bool
}

// ErrInstallRootConflict is returned when the install root holds files that
// do not form a valid installation and Rotate was not requested.
var ErrInstallRootConflict = errors.New("ossinstall: install root exists but is not a valid installation (re-run with rotation to replace it)")

// ErrPublishersChanged is returned when publishers are requested for an
// install root that already holds a valid installation trusting a different
// publisher set and Rotate was not requested. Reusing the installation would
// silently drop the requested publishers, so Generate refuses instead
// (`make install TRUST_ROTATE=1` or `--rotate` replaces the installation).
var ErrPublishersChanged = errors.New("ossinstall: the existing installation trusts a different publisher set (re-run with rotation, TRUST_ROTATE=1, to replace it)")

// generatedEntries are the names Generate owns inside the install root.
var generatedEntries = []string{RegistrationFile, "config", "evidence", "objects", "scratch", "store", "projects"}

// Generate creates (or reuses) the operator-pinned OSS installation under
// options.Root and returns the registration pins for the linker.
func Generate(options Options) (Result, error) {
	if options.Root == "" || !filepath.IsAbs(options.Root) {
		return Result{}, errors.New("ossinstall: install root must be an absolute path")
	}
	if err := os.MkdirAll(options.Root, 0o700); err != nil {
		return Result{}, fmt.Errorf("ossinstall: create install root: %w", err)
	}
	root, err := filepath.EvalSymlinks(options.Root)
	if err != nil {
		return Result{}, fmt.Errorf("ossinstall: resolve install root: %w", err)
	}
	root = filepath.Clean(root)
	// Validate requested publishers before any reuse or rotation decision,
	// so an invalid request never replaces or silently keeps an install.
	var requested []publisherScope
	if len(options.Publishers) > 0 {
		if requested, err = normalizePublishers(options.Publishers); err != nil {
			return Result{}, err
		}
	}
	if options.Rotate {
		for _, name := range generatedEntries {
			if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
				return Result{}, fmt.Errorf("ossinstall: rotate: %w", err)
			}
		}
	} else if existing, ok, err := reuse(root, requested); err != nil {
		return Result{}, err
	} else if ok {
		return existing, nil
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	validity := options.Validity
	if validity <= 0 {
		validity = DefaultValidity
	}
	entropy := options.Rand
	if entropy == nil {
		entropy = rand.Reader
	}
	g := &generator{root: root, now: now.UTC().Truncate(time.Second), validity: validity, rand: entropy, evidence: map[string][]byte{}}
	return g.run(options.Publishers)
}

// reuse keeps an existing installation when its registration resolves to a
// complete, pin-consistent runtime configuration. When publishers are
// requested, the installation is kept only if it trusts exactly that set;
// otherwise ErrPublishersChanged is returned. With no requested publishers
// the existing installation is kept as it is.
func reuse(root string, requested []publisherScope) (Result, bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return Result{}, false, fmt.Errorf("ossinstall: read install root: %w", err)
	}
	if len(entries) == 0 {
		return Result{}, false, nil
	}
	path := filepath.Join(root, RegistrationFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return Result{}, false, ErrInstallRootConflict
	}
	registration, err := DecodeRegistration(raw)
	if err != nil {
		return Result{}, false, ErrInstallRootConflict
	}
	loaded, err := trustload.Load(context.Background(), registration.Selection())
	if err != nil || loaded.Install.OSS == nil || !strings.HasPrefix(registration.RuntimeConfig.Path, root+string(filepath.Separator)) {
		return Result{}, false, ErrInstallRootConflict
	}
	if len(requested) > 0 {
		match, err := trustsExactly(root, loaded, requested)
		if err != nil {
			return Result{}, false, err
		}
		if !match {
			return Result{}, false, ErrPublishersChanged
		}
	}
	return Result{Root: root, RegistrationPath: path, RegistrationSHA256: evidencecas.Digest(raw), InstallationID: registration.InstallationID, Reused: true}, true, nil
}

type generator struct {
	root     string
	now      time.Time
	validity time.Duration
	rand     io.Reader
	evidence map[string][]byte
}

func (g *generator) put(raw []byte) string {
	digest := evidencecas.Digest(raw)
	g.evidence[digest] = append([]byte(nil), raw...)
	return digest
}

func (g *generator) token(prefix string) (string, error) {
	var b [12]byte
	if _, err := io.ReadFull(g.rand, b[:]); err != nil {
		return "", fmt.Errorf("ossinstall: entropy: %w", err)
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func (g *generator) key() (ed25519.PrivateKey, error) {
	_, private, err := ed25519.GenerateKey(g.rand)
	if err != nil {
		return nil, fmt.Errorf("ossinstall: generate key: %w", err)
	}
	return private, nil
}

type publisherScope struct {
	Publisher
	key ed25519.PublicKey
}

func (g *generator) publishers(configured []Publisher) ([]publisherScope, error) {
	if len(configured) == 0 {
		// The placeholder key is discarded immediately: nothing can ever be
		// signed for the unresolvable placeholder origin.
		private, err := g.key()
		if err != nil {
			return nil, err
		}
		configured = []Publisher{{Issuer: unconfiguredIssuer, PublicKeyBase64: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), SourceOrigin: unconfiguredOrigin, TemplatePath: "."}}
	}
	return normalizePublishers(configured)
}

// normalizePublishers validates configured publishers and applies defaults.
func normalizePublishers(configured []Publisher) ([]publisherScope, error) {
	out := make([]publisherScope, 0, len(configured))
	for _, p := range configured {
		key, err := base64.StdEncoding.Strict().DecodeString(p.PublicKeyBase64)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ossinstall: publisher %q: invalid Ed25519 public key", p.Issuer)
		}
		if p.TemplatePath == "" {
			p.TemplatePath = "."
		}
		if p.ObjectRoot != "" && !filepath.IsAbs(p.ObjectRoot) {
			return nil, fmt.Errorf("ossinstall: publisher %q: object root must be absolute", p.Issuer)
		}
		out = append(out, publisherScope{Publisher: p, key: ed25519.PublicKey(key)})
	}
	return out, nil
}

func (g *generator) run(configured []Publisher) (Result, error) {
	publishers, err := g.publishers(configured)
	if err != nil {
		return Result{}, err
	}
	installationID, err := g.token("oss-")
	if err != nil {
		return Result{}, err
	}
	authorityID, err := g.token("local-authority-")
	if err != nil {
		return Result{}, err
	}
	anchor, err := g.key()
	if err != nil {
		return Result{}, err
	}
	anchorPublic := anchor.Public().(ed25519.PublicKey)
	window := bootstrap.Validity{NotBefore: g.now.Add(-time.Hour).Format(time.RFC3339), NotAfter: g.now.Add(g.validity).Format(time.RFC3339)}

	// Trust-root envelope: the publishers' keys, signed by the anchor.
	rootKeys := make([]bootstrap.RootKey, 0, len(publishers))
	seenKeys := map[string]bool{}
	for _, p := range publishers {
		fingerprint := bootstrap.Fingerprint(p.key)
		if seenKeys[fingerprint] {
			continue
		}
		seenKeys[fingerprint] = true
		rootKeys = append(rootKeys, bootstrap.RootKey{Fingerprint: fingerprint, PublicKeyCAS: g.put([]byte(bootstrap.EncodePublicKey(p.key))), Issuer: p.Issuer, Status: "active"})
	}
	sort.Slice(rootKeys, func(i, j int) bool { return rootKeys[i].Fingerprint < rootKeys[j].Fingerprint })
	envelope := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: authorityID, Sequence: 1, Validity: window, AllowedPolicyOrigins: []string{localPolicyOrigin}, RootKeys: rootKeys, Threshold: 1, Revocations: []bootstrap.Revocation{}}
	if envelope.PayloadSHA256, err = envelope.ComputePayloadSHA256(); err != nil {
		return Result{}, fmt.Errorf("ossinstall: envelope: %w", err)
	}
	payload, err := hex.DecodeString(strings.TrimPrefix(envelope.PayloadSHA256, "sha256:"))
	if err != nil {
		return Result{}, fmt.Errorf("ossinstall: envelope digest: %w", err)
	}
	envelope.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchorPublic), SignatureCAS: g.put([]byte(bootstrap.EncodeSignature(ed25519.Sign(anchor, payload))))}}
	// The anchor private key is not needed after this point; drop it so it
	// never reaches disk.
	for i := range anchor {
		anchor[i] = 0
	}
	envelopeRaw, err := marshal(envelope)
	if err != nil {
		return Result{}, err
	}
	envelopeRef := g.put(envelopeRaw)

	// One-leaf transparency log holding the envelope payload.
	leaf := bootstrap.HashLeaf([]byte(envelope.PayloadSHA256))
	checkpointRaw, err := marshal(bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: authorityID, TreeSize: 1, RootHash: "sha256:" + hex.EncodeToString(leaf[:])})
	if err != nil {
		return Result{}, err
	}
	checkpointRef := g.put(checkpointRaw)
	inclusionRaw, err := marshal(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 1, Hashes: []string{}})
	if err != nil {
		return Result{}, err
	}
	inclusionRef := g.put(inclusionRaw)
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: authorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: envelope.PayloadSHA256, TreeSize: 1, CheckpointDigest: checkpointRef}
	if receipt.ReceiptDigest, err = receipt.ComputeDigest(); err != nil {
		return Result{}, fmt.Errorf("ossinstall: receipt: %w", err)
	}
	receiptRaw, err := marshal(receipt)
	if err != nil {
		return Result{}, err
	}
	receiptRef := g.put(receiptRaw)

	// Descriptor, operator pin and provisioning record.
	scopes := make([]bootstrap.PublisherScope, 0, len(publishers))
	for _, p := range publishers {
		scopes = append(scopes, bootstrap.PublisherScope{PolicyOrigin: localPolicyOrigin, Issuer: p.Issuer, SourceOrigin: p.SourceOrigin, TemplatePath: p.TemplatePath, Predicate: localPredicate, Usage: "template-source"})
	}
	sort.Slice(scopes, func(i, j int) bool { return scopeKey(scopes[i]) < scopeKey(scopes[j]) })
	descriptor := bootstrap.DescriptorDocument{APIVersion: bootstrap.DescriptorAPIVersion, Profile: bootstrap.ProfileOSS, AuthorityID: authorityID, Anchors: []bootstrap.DescriptorAnchor{{Fingerprint: bootstrap.Fingerprint(anchorPublic), PublicKeyBase64: base64.StdEncoding.EncodeToString(anchorPublic)}}, Threshold: 1, AllowedPolicyOrigins: []string{localPolicyOrigin}, PublisherScopes: scopes}
	descriptor.DescriptorSHA256 = descriptor.ComputedSHA256()
	if err := descriptor.Validate(); err != nil {
		return Result{}, fmt.Errorf("ossinstall: descriptor: %w", err)
	}
	operatorRaw, err := marshal(trustload.OperatorPinRecord{APIVersion: trustload.OperatorPinRecordAPIVersion, Method: "operator-pinned", DescriptorSHA256: descriptor.DescriptorSHA256})
	if err != nil {
		return Result{}, err
	}
	// Evidence class "production": the keys and signatures are real and
	// were generated for this installation; nothing is a test fixture. The
	// "operator-pinned" mode records that the operator, not a release
	// publisher, is the anchor.
	provisioning := bootstrap.ProvisioningRecord{APIVersion: bootstrap.ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: descriptor.DescriptorSHA256, AuthenticationEvidenceSHA256: evidencecas.Digest(operatorRaw), EvidenceClass: bootstrap.EvidenceProduction}
	provisioning.ProvisioningSHA256 = provisioning.ComputedSHA256()
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: descriptor.DescriptorSHA256, ProvisioningSHA256: provisioning.ProvisioningSHA256, AuthorityID: authorityID, Sequence: 1, EnvelopePayloadSHA256: envelope.PayloadSHA256, ReceiptDigest: receipt.ReceiptDigest, TreeSize: 1, CheckpointDigest: checkpointRef}
	state.StateSHA256 = state.ComputedSHA256()

	// Execution policy: publishers map to one principal; no approvers, so
	// no template-derived action can be approved until the operator adds
	// an approver (see ADR-005).
	issuers := map[string]bool{}
	issuerPrincipals := []trustverify.IssuerPrincipal{}
	rules := make([]trustverify.SourceRule, 0, len(publishers))
	for _, p := range publishers {
		if !issuers[p.Issuer] {
			issuers[p.Issuer] = true
			issuerPrincipals = append(issuerPrincipals, trustverify.IssuerPrincipal{Issuer: p.Issuer, PrincipalID: publisherPrincipal})
		}
		rules = append(rules, trustverify.SourceRule{PolicyOrigin: localPolicyOrigin, Issuer: p.Issuer, Origin: p.SourceOrigin, TemplatePath: p.TemplatePath, Predicate: localPredicate, Format: publisherStatementV1})
	}
	sort.Slice(issuerPrincipals, func(i, j int) bool { return issuerPrincipals[i].Issuer < issuerPrincipals[j].Issuer })
	sort.Slice(rules, func(i, j int) bool { return ruleKey(rules[i]) < ruleKey(rules[j]) })
	policy := trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "local-oss-policy", Profile: string(bootstrap.ProfileOSS), MinimumProfile: string(bootstrap.ProfileOSS), Validity: trustverify.Validity{NotBefore: window.NotBefore, NotAfter: window.NotAfter}, Principals: []trustverify.Principal{{ID: operatorPrincipal}, {ID: publisherPrincipal}}, IssuerPrincipals: issuerPrincipals, SourceRules: rules, Approvers: []trustverify.Approver{}, AllowInvocationHuman: false, MaxTimeoutMillis: 120000}
	if policy.PolicySHA256, err = policy.ComputePolicySHA256(); err != nil {
		return Result{}, fmt.Errorf("ossinstall: policy: %w", err)
	}

	// Lay out the install root.
	dirs := map[string]string{"config": "config", "evidence": "evidence", "scratch": "scratch", "objects": "objects", "project": filepath.Join("projects", DefaultProjectKey)}
	for _, rel := range dirs {
		if err := os.MkdirAll(filepath.Join(g.root, rel), 0o700); err != nil {
			return Result{}, fmt.Errorf("ossinstall: create %s: %w", rel, err)
		}
	}
	config := filepath.Join(g.root, "config")
	documents := map[string]any{"descriptor.json": descriptor, "provisioning.json": provisioning, "policy.json": policy, "state.json": state}
	pins := map[string]trustload.FilePin{}
	for name, value := range documents {
		raw, err := marshal(value)
		if err != nil {
			return Result{}, err
		}
		if pins[name], err = writeDocument(filepath.Join(config, name), raw); err != nil {
			return Result{}, err
		}
	}
	if pins["operator.json"], err = writeDocument(filepath.Join(config, "operator.json"), operatorRaw); err != nil {
		return Result{}, err
	}
	bundle := trustload.StoredBundle{APIVersion: "tplaiter.dev/stored-bootstrap-bundle/v1", EnvelopeCAS: envelopeRef, ReceiptCAS: receiptRef, Transparency: trustload.StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: inclusionRef}}
	bundleRaw, err := marshal(bundle)
	if err != nil {
		return Result{}, err
	}
	bundleDigest, err := bundle.Digest()
	if err != nil {
		return Result{}, fmt.Errorf("ossinstall: bundle: %w", err)
	}
	if pins["bundle.json"], err = writeDocument(filepath.Join(config, "bundle.json"), bundleRaw); err != nil {
		return Result{}, err
	}
	for digest, raw := range g.evidence {
		if err := writeCAS(filepath.Join(g.root, "evidence"), digest, raw); err != nil {
			return Result{}, err
		}
	}
	origins := []trustload.ObjectOrigin{}
	seenOrigins := map[string]bool{}
	for i, p := range publishers {
		if seenOrigins[p.SourceOrigin] {
			continue
		}
		seenOrigins[p.SourceOrigin] = true
		objectRoot := p.ObjectRoot
		if objectRoot == "" {
			objectRoot = filepath.Join(g.root, "objects", fmt.Sprintf("origin-%d", i))
			if err := os.MkdirAll(objectRoot, 0o700); err != nil {
				return Result{}, fmt.Errorf("ossinstall: create object root: %w", err)
			}
		}
		origins = append(origins, trustload.ObjectOrigin{Origin: p.SourceOrigin, RootPath: objectRoot})
	}
	install := trustload.RuntimeInstall{
		APIVersion: trustload.RuntimeInstallAPIVersion, InstallationID: installationID,
		Profile: bootstrap.ProfileOSS, MinimumProfile: bootstrap.ProfileOSS,
		Descriptor: pins["descriptor.json"], Provisioning: pins["provisioning.json"],
		OperatorRecord: pins["operator.json"], ExecutionPolicy: pins["policy.json"],
		ProjectContexts: []trustload.ProjectContext{{Key: DefaultProjectKey, ProjectID: "local-" + DefaultProjectKey, SubmitterPrincipalID: operatorPrincipal, MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(g.root, dirs["project"])}},
		ObjectOrigins:   origins,
		EvidenceRoot:    filepath.Join(g.root, "evidence"), ScratchRoot: filepath.Join(g.root, "scratch"),
		OSS: &trustload.OSSInstall{StorePath: filepath.Join(g.root, "store"), InitialStatePath: pins["state.json"].Path, InitialStateSHA256: state.StateSHA256, InitialBundlePath: pins["bundle.json"].Path, InitialBundleSHA256: bundleDigest},
	}
	if err := install.Validate(); err != nil {
		return Result{}, fmt.Errorf("ossinstall: runtime install: %w", err)
	}
	installRaw, err := marshal(install)
	if err != nil {
		return Result{}, err
	}
	installDigest, err := install.Digest()
	if err != nil {
		return Result{}, fmt.Errorf("ossinstall: runtime install digest: %w", err)
	}
	installPath := filepath.Join(config, "runtime.json")
	if _, err := writeDocument(installPath, installRaw); err != nil {
		return Result{}, err
	}
	registration := Registration{APIVersion: RegistrationAPIVersion, Profile: bootstrap.ProfileOSS, RuntimeConfig: trustload.FilePin{Path: installPath, SHA256: installDigest}, OperatorRecord: install.OperatorRecord, InstallationID: installationID, ProjectKey: DefaultProjectKey}
	registrationRaw, err := marshal(registration)
	if err != nil {
		return Result{}, err
	}
	registrationPath := filepath.Join(g.root, RegistrationFile)
	pin, err := writeDocument(registrationPath, registrationRaw)
	if err != nil {
		return Result{}, err
	}
	if _, err := trustload.Load(context.Background(), registration.Selection()); err != nil {
		return Result{}, fmt.Errorf("ossinstall: generated installation does not load: %w", err)
	}
	return Result{Root: g.root, RegistrationPath: registrationPath, RegistrationSHA256: pin.SHA256, InstallationID: installationID}, nil
}

// expectedScopes returns the sorted publisher scope keys, the trust-root key
// set (fingerprint to issuer, first issuer per key wins) and the explicit
// object roots per source origin that run would generate for publishers.
func expectedScopes(publishers []publisherScope) ([]string, map[string]string, map[string]string) {
	scopes := make([]string, 0, len(publishers))
	keys := map[string]string{}
	objects := map[string]string{}
	for _, p := range publishers {
		scopes = append(scopes, scopeKey(bootstrap.PublisherScope{PolicyOrigin: localPolicyOrigin, Issuer: p.Issuer, SourceOrigin: p.SourceOrigin, TemplatePath: p.TemplatePath, Predicate: localPredicate, Usage: "template-source"}))
		fingerprint := bootstrap.Fingerprint(p.key)
		if _, ok := keys[fingerprint]; !ok {
			keys[fingerprint] = p.Issuer
		}
		if _, ok := objects[p.SourceOrigin]; !ok {
			objects[p.SourceOrigin] = p.ObjectRoot
		}
	}
	sort.Strings(scopes)
	return scopes, keys, objects
}

// trustsExactly reports whether a loaded installation trusts exactly the
// requested publishers: the same descriptor scopes, the same trust-root keys
// and the same explicit object roots.
func trustsExactly(root string, loaded *trustload.Loaded, requested []publisherScope) (bool, error) {
	wantScopes, wantKeys, wantObjects := expectedScopes(requested)

	descriptor, err := bootstrap.DecodeDescriptorDocument(loaded.DescriptorJSON)
	if err != nil {
		return false, ErrInstallRootConflict
	}
	haveScopes := make([]string, 0, len(descriptor.PublisherScopes))
	for _, s := range descriptor.PublisherScopes {
		haveScopes = append(haveScopes, scopeKey(s))
	}
	sort.Strings(haveScopes)
	if strings.Join(haveScopes, "\x01") != strings.Join(wantScopes, "\x01") {
		return false, nil
	}

	envelope, err := installedEnvelope(root, loaded)
	if err != nil {
		return false, err
	}
	if len(envelope.RootKeys) != len(wantKeys) {
		return false, nil
	}
	for _, k := range envelope.RootKeys {
		if issuer, ok := wantKeys[k.Fingerprint]; !ok || issuer != k.Issuer {
			return false, nil
		}
	}

	if len(loaded.Install.ObjectOrigins) != len(wantObjects) {
		return false, nil
	}
	generated := filepath.Join(root, "objects") + string(filepath.Separator)
	for _, o := range loaded.Install.ObjectOrigins {
		want, ok := wantObjects[o.Origin]
		if !ok {
			return false, nil
		}
		if want == "" && !strings.HasPrefix(o.RootPath, generated) || want != "" && filepath.Clean(want) != filepath.Clean(o.RootPath) {
			return false, nil
		}
	}
	return true, nil
}

// installedEnvelope reads the trust-root envelope the installation's initial
// bundle references from the install's evidence store and checks its digest.
func installedEnvelope(root string, loaded *trustload.Loaded) (*bootstrap.Envelope, error) {
	bundleRaw, err := os.ReadFile(loaded.Install.OSS.InitialBundlePath)
	if err != nil {
		return nil, ErrInstallRootConflict
	}
	bundle, err := trustload.DecodeStoredBundle(bundleRaw)
	if err != nil {
		return nil, ErrInstallRootConflict
	}
	x := strings.TrimPrefix(bundle.EnvelopeCAS, "sha256:")
	if _, hexErr := hex.DecodeString(x); hexErr != nil || len(x) != 64 || strings.ToLower(x) != x {
		return nil, ErrInstallRootConflict
	}
	evidenceRoot := filepath.Clean(loaded.Install.EvidenceRoot)
	if !strings.HasPrefix(evidenceRoot, root+string(filepath.Separator)) {
		return nil, ErrInstallRootConflict
	}
	// The path is confined: the evidence root lies inside the install root
	// and the digest was checked to be 64 lowercase hex characters.
	raw, err := os.ReadFile(filepath.Join(evidenceRoot, "sha256", x[:2], x[2:])) //nolint:gosec // G703: confined path, see above.
	if err != nil || evidencecas.Digest(raw) != bundle.EnvelopeCAS {
		return nil, ErrInstallRootConflict
	}
	envelope, err := bootstrap.DecodeEnvelope(raw)
	if err != nil {
		return nil, ErrInstallRootConflict
	}
	return envelope, nil
}

func scopeKey(s bootstrap.PublisherScope) string {
	return strings.Join([]string{s.PolicyOrigin, s.Issuer, s.SourceOrigin, s.TemplatePath, s.Predicate, s.Usage}, "\x00")
}

func ruleKey(r trustverify.SourceRule) string {
	return strings.Join([]string{r.PolicyOrigin, r.Issuer, r.Origin, r.TemplatePath, r.Predicate}, "\x00")
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("ossinstall: encode: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// writeDocument writes raw with mode 0600 through a temporary file and a
// rename, then returns its raw-content pin.
func writeDocument(path string, raw []byte) (trustload.FilePin, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return trustload.FilePin{}, fmt.Errorf("ossinstall: write %s: %w", filepath.Base(path), err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return trustload.FilePin{}, fmt.Errorf("ossinstall: write %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return trustload.FilePin{}, fmt.Errorf("ossinstall: write %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return trustload.FilePin{}, fmt.Errorf("ossinstall: write %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Close(); err != nil {
		return trustload.FilePin{}, fmt.Errorf("ossinstall: write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(name, path); err != nil {
		return trustload.FilePin{}, fmt.Errorf("ossinstall: write %s: %w", filepath.Base(path), err)
	}
	return trustload.FilePin{Path: path, SHA256: evidencecas.Digest(raw)}, nil
}

func writeCAS(root, digest string, raw []byte) error {
	x := strings.TrimPrefix(digest, "sha256:")
	dir := filepath.Join(root, "sha256", x[:2])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ossinstall: evidence: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, x[2:]), raw, 0o600); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("ossinstall: evidence: %w", err)
	}
	return nil
}
