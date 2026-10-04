package ossinstall

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Git's SHA-1 object format.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	SourcePackageAPIVersion     = "tplaiter.dev/initial-source-package/v1"
	MaxSourcePackageInputBytes  = 96 << 20
	MaxProjectContextInputBytes = 1 << 20
)

// SourcePackage contains public evidence only. Objects are uncompressed Git
// frames (kind SP size NUL data), JSON base64 encoded. No package field enrolls
// a key, chooses a reader root, or supplies an independent checkpoint.
type SourcePackage struct {
	APIVersion     string            `json:"apiVersion"`
	Statement      json.RawMessage   `json:"statement"`
	Signature      string            `json:"signature"`
	KeyFingerprint string            `json:"keyFingerprint"`
	Objects        map[string][]byte `json:"objects"`
}

var ErrEnrollmentChanged = errors.New("ossinstall: initial enrollment contract differs; choose a fresh install root (no store reset)")

func DecodeSourcePackages(raw []byte) ([]SourcePackage, error) {
	var v []SourcePackage
	if len(raw) == 0 || len(raw) > MaxSourcePackageInputBytes {
		return nil, errors.New("ossinstall: source input size limit")
	}
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, err
	}
	if len(v) == 0 || len(v) > 32 {
		return nil, errors.New("ossinstall: expected 1..32 source packages")
	}
	return v, nil
}

func DecodeProjectContexts(raw []byte) ([]trustload.ProjectContext, error) {
	var v []trustload.ProjectContext
	if len(raw) == 0 || len(raw) > MaxProjectContextInputBytes {
		return nil, errors.New("ossinstall: project input size limit")
	}
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, err
	}
	if len(v) == 0 || len(v) > 32 {
		return nil, errors.New("ossinstall: expected 1..32 project contexts")
	}
	return v, nil
}

type packageObjects struct {
	origin  string
	objects map[string]trustverify.GitObject
	used    map[string]bool
}

func (r *packageObjects) ReadObject(ctx context.Context, origin trustverify.SourceOrigin, id trustverify.ObjectID) (trustverify.GitObject, error) {
	if err := ctx.Err(); err != nil {
		return trustverify.GitObject{}, err
	}
	o, ok := r.objects[string(id)]
	if string(origin) != r.origin || !ok {
		return trustverify.GitObject{}, errors.New("ossinstall: object missing")
	}
	r.used[string(id)] = true
	return o, nil
}

func rawObject(id string, raw []byte) (trustverify.GitObject, error) {
	bad := errors.New("ossinstall: malformed raw Git object or identity mismatch")
	if (len(id) != 40 && len(id) != 64) || strings.ToLower(id) != id {
		return trustverify.GitObject{}, bad
	}
	if _, err := hex.DecodeString(id); err != nil {
		return trustverify.GitObject{}, bad
	}
	i := bytes.IndexByte(raw, 0)
	if i < 1 || i > 64 {
		return trustverify.GitObject{}, bad
	}
	parts := strings.Split(string(raw[:i]), " ")
	if len(parts) != 2 {
		return trustverify.GitObject{}, bad
	}
	data := raw[i+1:]
	if parts[1] != strconv.Itoa(len(data)) {
		return trustverify.GitObject{}, bad
	}
	switch parts[0] {
	case "commit", "tree":
		if len(data) > 1<<20 {
			return trustverify.GitObject{}, bad
		}
	case "blob":
		if len(data) > 16<<20 {
			return trustverify.GitObject{}, bad
		}
	default:
		return trustverify.GitObject{}, bad
	}
	var got string
	if len(id) == 40 {
		h := sha1.Sum(raw) //nolint:gosec // Rehashing the existing Git SHA-1 object format.
		got = hex.EncodeToString(h[:])
	} else {
		h := sha256.Sum256(raw)
		got = hex.EncodeToString(h[:])
	}
	if id != got {
		return trustverify.GitObject{}, bad
	}
	return trustverify.GitObject{Kind: parts[0], Data: data}, nil
}

func validatePackagesWithContext(ctx context.Context, packages []SourcePackage, publishers []publisherScope) error {
	if packages != nil && len(packages) == 0 || len(packages) > 32 {
		return errors.New("ossinstall: package count limit")
	}
	total := 0
	seen := map[string]bool{}
	for _, p := range packages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p.APIVersion != SourcePackageAPIVersion || len(p.Statement) > 1<<20 || len(p.Signature) > 128 || len(p.Objects) == 0 || len(p.Objects) > 8192 {
			return errors.New("ossinstall: invalid source package bounds")
		}
		statement, err := bootstrap.DecodePublisherStatement(p.Statement)
		if err != nil {
			return err
		}
		identity := statement.Subject.Origin + "\x00" + statement.Subject.TemplatePath + "\x00" + statement.Subject.Commit
		if seen[identity] {
			return errors.New("ossinstall: duplicate source selection")
		}
		seen[identity] = true
		approved := false
		for _, pub := range publishers {
			if statement.Issuer == pub.Issuer && statement.Subject.Origin == pub.SourceOrigin && statement.Subject.TemplatePath == pub.TemplatePath && p.KeyFingerprint == bootstrap.Fingerprint(pub.key) && statement.PolicyOrigin == localPolicyOrigin && statement.Predicate == localPredicate && statement.Usage == "template-source" {
				approved = true
			}
		}
		if !approved {
			return errors.New("ossinstall: publisher scope not approved")
		}
		reader := &packageObjects{origin: statement.Subject.Origin, objects: map[string]trustverify.GitObject{}, used: map[string]bool{}}
		for id, raw := range p.Objects {
			if err := ctx.Err(); err != nil {
				return err
			}
			total += len(raw)
			if total > 64<<20 {
				return errors.New("ossinstall: aggregate object byte limit")
			}
			o, err := rawObject(id, raw)
			if err != nil {
				return err
			}
			reader.objects[id] = o
		}
		snapshot, err := trustverify.VerifySource(ctx, reader, statementSubject(statement))
		if err != nil {
			return err
		}
		if len(reader.used) != len(p.Objects) {
			return errors.New("ossinstall: package contains objects outside the selected closure")
		}
		if err := validateNativeSnapshot(snapshot); err != nil {
			return err
		}
	}
	return nil
}

func validateNativeSnapshot(snapshot *trustverify.SourceSnapshot) error {
	manifestRaw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return errors.New("ossinstall: manifest missing")
	}
	if _, err := operationtrust.DecodeNativeContract(snapshot.ContractBytes(), manifestRaw); err != nil {
		return err
	}
	if err := validateManifestShape(manifestRaw); err != nil {
		return err
	}
	tpl, err := manifest.ParseTemplate(manifestRaw)
	if err != nil {
		return err
	}
	if err := tpl.Validate(); err != nil {
		return err
	}
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || len(tpl.Generators) != 0 || len(tpl.Commands) != 0 {
		return errors.New("ossinstall: initial enrollment supports action-free native templates only")
	}
	return nil
}

func statementSubject(s *bootstrap.PublisherStatement) trustverify.Subject {
	return trustverify.Subject{Origin: s.Subject.Origin, TemplatePath: s.Subject.TemplatePath, RequestedRef: s.Subject.Commit, Commit: s.Subject.Commit, TreeSHA256: s.Subject.TreeSHA256, ContractSHA256: s.Subject.ContractSHA256}
}

// canonicalProjectRoot binds an existing no-follow directory or a single
// absent leaf beneath an existing no-follow directory. It never creates content.
func canonicalProjectRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || path == string(filepath.Separator) {
		return errors.New("ossinstall: project root must be canonical and absolute")
	}
	parent := path
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		parent = filepath.Dir(path)
	} else if err != nil {
		return err
	}
	for p := parent; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("ossinstall: project root requires a no-follow existing parent")
		}
		if p == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}

func validateProjects(root string, projects []trustload.ProjectContext, pubs []publisherScope) error {
	if projects == nil {
		return nil
	}
	if len(projects) == 0 || len(projects) > 32 {
		return errors.New("ossinstall: expected 1..32 project contexts")
	}
	keys, ids := map[string]bool{}, map[string]bool{}
	token := func(s string) bool {
		if len(s) == 0 || len(s) > 256 {
			return false
		}
		for _, c := range s {
			valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.:", c)
			if !valid {
				return false
			}
		}
		return true
	}
	for i, p := range projects {
		if !token(p.Key) || !token(p.ProjectID) || keys[p.Key] || ids[p.ProjectID] || p.MinimumProfile != bootstrap.ProfileOSS || (p.SubmitterPrincipalID != operatorPrincipal && p.SubmitterPrincipalID != publisherPrincipal) {
			return errors.New("ossinstall: invalid project identity, submitter or minimum profile")
		}
		keys[p.Key], ids[p.ProjectID] = true, true
		if err := canonicalProjectRoot(p.RootPath); err != nil {
			return err
		}
		if overlaps(root, p.RootPath) {
			return errors.New("ossinstall: project overlaps installation")
		}
		for _, pub := range pubs {
			if pub.ObjectRoot != "" && overlaps(pub.ObjectRoot, p.RootPath) {
				return errors.New("ossinstall: project overlaps object root")
			}
		}
		for _, prev := range projects[:i] {
			if overlaps(prev.RootPath, p.RootPath) {
				return errors.New("ossinstall: ambiguous project roots")
			}
		}
	}
	return nil
}

type enrollmentContract struct {
	APIVersion           string `json:"apiVersion"`
	Digest               string `json:"digest"`
	LocalPublisherSHA256 string `json:"localPublisherSHA256,omitempty"`
}

func contractFor(o Options) (enrollmentContract, error) {
	return contractForWithContext(context.Background(), o)
}

func contractForWithContext(ctx context.Context, o Options) (enrollmentContract, error) {
	// Source/context sets are order-independent; the selected default key is explicit.
	sources := []string{}
	for _, p := range o.SourcePackages {
		if err := ctx.Err(); err != nil {
			return enrollmentContract{}, err
		}
		d, err := bootstrap.DomainDigest(SourcePackageAPIVersion, struct {
			Package      SourcePackage `json:"package"`
			StatementCAS string        `json:"statementCAS"`
		}{p, evidencecas.Digest(p.Statement)})
		if err != nil {
			return enrollmentContract{}, err
		}
		sources = append(sources, d)
	}
	sort.Strings(sources)
	projects := append([]trustload.ProjectContext(nil), o.ProjectContexts...)
	sort.Slice(projects, func(i, j int) bool { return projects[i].Key < projects[j].Key })
	defaultKey := DefaultProjectKey
	if len(o.ProjectContexts) > 0 {
		defaultKey = o.ProjectContexts[0].Key
	}
	d, err := bootstrap.DomainDigest("tplaiter.dev/initial-enrollment-contract/v1", struct {
		LocalPublisherSHA256 string                     `json:"localPublisherSHA256,omitempty"`
		DefaultProjectKey    string                     `json:"defaultProjectKey"`
		Sources              []string                   `json:"sources"`
		Projects             []trustload.ProjectContext `json:"projects"`
	}{localRecordDigest(o.localRecord), defaultKey, sources, projects})
	return enrollmentContract{APIVersion: "tplaiter.dev/initial-enrollment-contract/v1", Digest: d, LocalPublisherSHA256: localRecordDigest(o.localRecord)}, err
}

func generateEnrollment(ctx context.Context, o Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !filepath.IsAbs(o.Root) || filepath.Clean(o.Root) != o.Root {
		return Result{}, errors.New("ossinstall: canonical absolute install root required")
	}
	// The existing parent must be canonical: never normalize a symlink into trust.
	if err := canonicalProjectRoot(o.Root); err != nil {
		return Result{}, err
	}
	pubs, err := normalizePublishers(o.Publishers)
	if err != nil {
		return Result{}, err
	}
	for _, pub := range pubs {
		if pub.ObjectRoot != "" {
			return Result{}, errors.New("ossinstall: initial enrollment uses generated fixed object roots only")
		}
	}
	if err := validatePackagesWithContext(ctx, o.SourcePackages, pubs); err != nil {
		return Result{}, err
	}
	if err := validateProjects(o.Root, o.ProjectContexts, pubs); err != nil {
		return Result{}, err
	}
	contract, err := contractForWithContext(ctx, o)
	if err != nil {
		return Result{}, err
	}
	if _, err := os.Stat(o.Root); err == nil {
		if o.LocalSources != nil {
			return Result{}, ErrInstallRootForeign
		}
		empty, err := checkOwnership(o.Root)
		if err != nil {
			return Result{}, err
		}
		if empty {
			return Result{}, ErrInstallRootForeign
		}
		if !empty {
			if o.Rotate {
				return Result{}, ErrEnrollmentChanged
			}
			result, ok, err := reuseWithContext(ctx, o.Root, pubs)
			if errors.Is(err, ErrPublishersChanged) || errors.Is(err, ErrInstallRootConflict) {
				return Result{}, ErrEnrollmentChanged
			}
			if err != nil {
				return Result{}, err
			}
			if !ok {
				return Result{}, ErrInstallRootConflict
			}
			raw, err := readConfined(o.Root, filepath.Join("config", "enrollment.json"))
			var old enrollmentContract
			regRaw, regErr := readConfined(o.Root, RegistrationFile)
			reg, decodeErr := DecodeRegistration(regRaw)
			if err != nil || regErr != nil || decodeErr != nil || reg.InitialEnrollmentSHA256 != contract.Digest || canonicaljson.DecodeStrict(raw, &old) != nil || old != contract {
				return Result{}, ErrEnrollmentChanged
			}
			if err := verifyRetainedPackagesWithContext(ctx, loadedInstallWithContext(ctx, result), o.SourcePackages); err != nil {
				return Result{}, err
			}
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			result.SelectionsPath = filepath.Join(o.Root, "config", "source-selections.json")
			return result, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(o.Root), ".tplaiter-initial-")
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := writeOwnershipMarker(stage); err != nil {
		return Result{}, err
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	validity := o.Validity
	if validity <= 0 {
		validity = DefaultValidity
	}
	entropy := o.Rand
	if entropy == nil {
		entropy = defaultEntropy()
	}
	g := &generator{ctx: ctx, root: o.Root, disk: stage, contractDigest: contract.Digest, sources: o.SourcePackages, projects: o.ProjectContexts, now: now.UTC().Truncate(time.Second), validity: validity, rand: entropy, evidence: map[string][]byte{}}
	result, err := g.run(ctx, o.Publishers)
	if err != nil {
		return Result{}, err
	}
	raw, err := marshal(contract)
	if err != nil {
		return Result{}, err
	}
	if _, err := g.writeDocument(filepath.Join(o.Root, "config", "enrollment.json"), raw); err != nil {
		return Result{}, err
	}
	if o.localRecord != nil {
		if _, err := g.writeDocument(filepath.Join(o.Root, "config", "local-publisher.json"), o.localRecord); err != nil {
			return Result{}, err
		}
	}
	// Recheck vacancy and project parent constraints at the publication boundary.
	if err := validateProjects(o.Root, o.ProjectContexts, pubs); err != nil {
		return Result{}, err
	}
	committed, err := publishInstallationWithContext(ctx, stage, o.Root, func() error { return validateProjects(o.Root, o.ProjectContexts, pubs) })
	if !committed {
		if err != nil {
			return Result{}, err
		}
		return Result{}, errors.New("ossinstall: publication did not commit")
	}
	result.PublicationState = "committed"
	if err != nil {
		result.PublicationState = "committed-unconfirmed"
		return result, &PublicationCommittedError{Cause: err}
	}
	// Rename has committed. Detach cancellation only here: the published tree
	// must be synced/reauthenticated even when the caller cancels after commit.
	// Keep context values and bound finalization independently to 30 seconds.
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if publicationFinalizationHook != nil {
		if err := publicationFinalizationHook(); err != nil {
			result.PublicationState = "committed-unconfirmed"
			return result, &PublicationCommittedError{Cause: err}
		}
	}
	if _, err := trustload.Load(finalCtx, mustSelection(result)); err != nil {
		result.PublicationState = "committed-unconfirmed"
		return result, &PublicationCommittedError{Cause: err}
	}
	return result, nil
}

func mustSelection(r Result) trustload.LaunchSelection {
	raw, err := readConfined(r.Root, RegistrationFile)
	if err != nil {
		return trustload.LaunchSelection{}
	}
	reg, err := DecodeRegistration(raw)
	if err != nil {
		return trustload.LaunchSelection{}
	}
	return reg.Selection()
}

func (g *generator) path(path string) string {
	if g.disk == "" {
		return path
	}
	rel, _ := filepath.Rel(g.root, path)
	return filepath.Join(g.disk, rel)
}

func (g *generator) writeDocument(path string, raw []byte) (trustload.FilePin, error) {
	if err := g.context().Err(); err != nil {
		return trustload.FilePin{}, err
	}
	pin, err := writeDocument(g.path(path), raw)
	pin.Path = path
	return pin, err
}

type enrollmentEvidence map[string][]byte

func (r enrollmentEvidence) Read(ctx context.Context, ref string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, ok := r[ref]
	if !ok || evidencecas.Digest(b) != ref {
		return nil, bootstrap.ErrEvidenceMissing
	}
	return append([]byte(nil), b...), nil
}

type enrollmentExternal struct{ snapshot bootstrap.ProvisionedSnapshot }

func (r enrollmentExternal) Load(context.Context) (bootstrap.ProvisionedSnapshot, error) {
	return r.snapshot, nil
}

func (g *generator) verifyEnrollment(ctx context.Context, d bootstrap.DescriptorDocument, p bootstrap.ProvisioningRecord, s bootstrap.OSSAcceptedState, envelope, receipt []byte, checkpoint string, proofs []string) error {
	draw, err := marshal(d)
	if err != nil {
		return err
	}
	praw, err := marshal(p)
	if err != nil {
		return err
	}
	sraw, err := marshal(s)
	if err != nil {
		return err
	}
	ext, err := bootstrap.LoadExternal(ctx, enrollmentExternal{bootstrap.ProvisionedSnapshot{DescriptorJSON: draw, ProvisioningJSON: praw, ExpectedDescriptorSHA256: d.DescriptorSHA256, ExpectedProvisioningSHA256: p.ProvisioningSHA256, OSSStateJSON: sraw, ExpectedOSSStateSHA256: s.StateSHA256, InitialOSSStateSHA256: s.StateSHA256}})
	if err != nil {
		return err
	}
	verifier, err := bootstrap.NewVerifier(enrollmentEvidence(g.evidence), bootstrap.ClockFunc(func() time.Time { return g.now }), nil, 0)
	if err != nil {
		return err
	}
	authority, err := verifier.VerifyOSS(ctx, ext, bootstrap.Bundle{Envelope: envelope, Receipt: receipt, Transparency: bootstrap.TransparencyEvidence{CheckpointCAS: checkpoint, InclusionProofCAS: proofs[0]}})
	if err != nil {
		return err
	}
	for i, source := range g.sources {
		statement, err := bootstrap.DecodePublisherStatement(source.Statement)
		if err != nil {
			return err
		}
		refs := bootstrap.PublisherEvidence{StatementCAS: g.put(source.Statement), SignatureCAS: g.put([]byte(source.Signature)), KeyFingerprint: source.KeyFingerprint}
		expected := bootstrap.PublisherExpectation{PolicyOrigin: localPolicyOrigin, Issuer: statement.Issuer, Predicate: localPredicate, Usage: "template-source", Subject: statement.Subject}
		if _, err := verifier.VerifyPublisherClaim(ctx, authority, expected, refs); err != nil {
			return err
		}
		if err := bootstrap.VerifyArtifactTransparency(ctx, authority, enrollmentEvidence(g.evidence), refs.StatementCAS, bootstrap.TransparencyEvidence{CheckpointCAS: checkpoint, InclusionProofCAS: proofs[i+1]}); err != nil {
			return err
		}
		g.selections = append(g.selections, operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: operationtrust.SelectionSubject{Origin: statement.Subject.Origin, TemplatePath: statement.Subject.TemplatePath, RequestedRef: statement.Subject.Commit, Commit: statement.Subject.Commit, TreeSHA256: statement.Subject.TreeSHA256, ContractSHA256: statement.Subject.ContractSHA256}, Evidence: operationtrust.SelectionEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: refs.StatementCAS, SignatureCAS: refs.SignatureCAS, KeyFingerprint: refs.KeyFingerprint, CheckpointCAS: checkpoint, InclusionProofCAS: proofs[i+1]}, Dependencies: []string{}})
	}
	return nil
}

func (g *generator) publishSources(origins []trustload.ObjectOrigin) error {
	for _, source := range g.sources {
		statement, err := bootstrap.DecodePublisherStatement(source.Statement)
		if err != nil {
			return err
		}
		root := ""
		for _, origin := range origins {
			if origin.Origin == statement.Subject.Origin {
				root = g.path(origin.RootPath)
			}
		}
		if root == "" {
			return errors.New("ossinstall: fixed object origin missing")
		}
		for id, raw := range source.Objects {
			if err := g.context().Err(); err != nil {
				return err
			}
			if err := publishImmutable(root, id, raw); err != nil {
				return err
			}
		}
	}
	if g.selections == nil {
		g.selections = []operationtrust.SourceSelection{}
	}
	raw, err := marshal(g.selections)
	if err != nil {
		return err
	}
	_, err = g.writeDocument(filepath.Join(g.root, "config", "source-selections.json"), raw)
	return err
}

// RFC 6962 split-at-largest-power-of-two tree, using the existing verifier's
// leaf/hash domains. Proofs are bottom-up and bind the leaf's exact CAS text.
func (g *generator) checkpoint(authority string, leaves []string) (string, []string, error) {
	hashes := make([]bootstrap.MerkleHash, len(leaves))
	for i, l := range leaves {
		hashes[i] = bootstrap.HashLeaf([]byte(l))
	}
	root := merkleRoot(hashes)
	raw, err := marshal(bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: authority, TreeSize: uint64(len(leaves)), RootHash: hashText(root)})
	if err != nil {
		return "", nil, err
	}
	cp := g.put(raw)
	proofs := make([]string, len(leaves))
	for i := range leaves {
		v := []string{}
		for _, h := range merkleProof(hashes, i) {
			v = append(v, hashText(h))
		}
		raw, err := marshal(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: uint64(i), TreeSize: uint64(len(leaves)), Hashes: v})
		if err != nil {
			return "", nil, err
		}
		proofs[i] = g.put(raw)
	}
	return cp, proofs, nil
}
func hashText(h bootstrap.MerkleHash) string { return "sha256:" + hex.EncodeToString(h[:]) }
func merkleSplit(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func merkleRoot(h []bootstrap.MerkleHash) bootstrap.MerkleHash {
	if len(h) == 1 {
		return h[0]
	}
	k := merkleSplit(len(h))
	return bootstrap.HashChildren(merkleRoot(h[:k]), merkleRoot(h[k:]))
}

func merkleProof(h []bootstrap.MerkleHash, i int) []bootstrap.MerkleHash {
	if len(h) == 1 {
		return nil
	}
	k := merkleSplit(len(h))
	if i < k {
		return append(merkleProof(h[:k], i), merkleRoot(h[k:]))
	}
	return append(merkleProof(h[k:], i-k), merkleRoot(h[:k]))
}

func loadedInstallWithContext(ctx context.Context, result Result) *trustload.RuntimeInstall {
	loaded, err := trustload.Load(ctx, mustSelection(result))
	if err != nil {
		return nil
	}
	return &loaded.Install
}

func verifyRetainedPackagesWithContext(ctx context.Context, install *trustload.RuntimeInstall, packages []SourcePackage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if install == nil {
		return ErrInstallRootConflict
	}
	for _, p := range packages {
		statement, err := bootstrap.DecodePublisherStatement(p.Statement)
		if err != nil {
			return err
		}
		root := ""
		for _, origin := range install.ObjectOrigins {
			if origin.Origin == statement.Subject.Origin {
				root = origin.RootPath
			}
		}
		if root == "" {
			return ErrInstallRootConflict
		}
		for id, raw := range p.Objects {
			if err := ctx.Err(); err != nil {
				return err
			}
			previous, err := readConfined(root, id)
			if err != nil || !bytes.Equal(previous, raw) {
				return ErrInstallRootConflict
			}
		}
		for _, raw := range [][]byte{p.Statement, []byte(p.Signature)} {
			digest := evidencecas.Digest(raw)
			x := strings.TrimPrefix(digest, "sha256:")
			previous, err := readConfined(install.EvidenceRoot, filepath.Join("sha256", x[:2], x[2:]))
			if err != nil || !bytes.Equal(previous, raw) {
				return ErrInstallRootConflict
			}
		}
	}
	return nil
}

// Match the native adapter's closed YAML shape before the existing manifest
// parser: a single document, no aliases/anchors, merges or case-folded keys.
func validateManifestShape(raw []byte) error {
	bad := errors.New("ossinstall: unsupported native manifest shape")
	if len(raw) == 0 || len(raw) > 1<<20 {
		return bad
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var node yaml.Node
	if err := dec.Decode(&node); err != nil || len(node.Content) != 1 {
		return bad
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return bad
	}
	nodes := 0
	var walk func(*yaml.Node, int) error
	walk = func(n *yaml.Node, depth int) error {
		nodes++
		if nodes > 8192 || depth > 64 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" {
			return bad
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				key := n.Content[i]
				fold := strings.ToLower(key.Value)
				if key.Kind != yaml.ScalarNode || key.Value == "<<" || seen[fold] {
					return bad
				}
				seen[fold] = true
			}
		}
		for _, child := range n.Content {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(node.Content[0], 0)
}
