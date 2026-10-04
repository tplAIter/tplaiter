package ossinstall

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	MaxLocalSourceInputBytes   = 64 << 10
	LocalPublicationAPIVersion = "tplaiter.dev/local-operator-source-publication/v1"
)

// LocalPublication records operator attestation of captured bytes, not upstream
// authorship, ownership, or fetching provenance. It contains no input locator.
type LocalPublication struct {
	APIVersion     string                    `json:"apiVersion"`
	Mode           string                    `json:"mode"`
	Issuer         string                    `json:"issuer"`
	KeyFingerprint string                    `json:"keyFingerprint"`
	Subject        bootstrap.SubjectIdentity `json:"subject"`
	PolicyOrigin   string                    `json:"policyOrigin"`
	Predicate      string                    `json:"predicate"`
	Usage          string                    `json:"usage"`
}

func DecodeLocalSources(raw []byte) ([]sourcepackage.CaptureInput, error) {
	if len(raw) == 0 || len(raw) > MaxLocalSourceInputBytes {
		return nil, errors.New("ossinstall: local source input size limit")
	}
	var inputs []sourcepackage.CaptureInput
	if err := canonicaljson.DecodeStrict(raw, &inputs); err != nil {
		return nil, err
	}
	if len(inputs) != 1 {
		return nil, errors.New("ossinstall: exactly one explicitly approved local source required")
	}
	if err := inputs[0].Validate(); err != nil {
		return nil, err
	}
	return inputs, nil
}

func eraseKey(key ed25519.PrivateKey) {
	for i := range key {
		key[i] = 0
	}
}

func localRecordDigest(raw []byte) string {
	if raw == nil {
		return ""
	}
	return evidencecas.Digest(raw)
}

func generateLocal(ctx context.Context, o Options) (Result, error) {
	if len(o.LocalSources) != 1 || o.SourcePackages != nil || o.Publishers != nil || o.Rotate || len(o.ProjectContexts) == 0 {
		return Result{}, errors.New("ossinstall: local sources require one source, explicit contexts, no external publishers/packages and no rotation")
	}
	if !filepath.IsAbs(o.Root) || filepath.Clean(o.Root) != o.Root {
		return Result{}, errors.New("ossinstall: canonical absolute install root required")
	}
	if err := canonicalProjectRoot(o.Root); err != nil {
		return Result{}, err
	}
	if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return Result{}, err
		}
		return Result{}, ErrInstallRootForeign
	}
	for _, p := range o.ProjectContexts {
		if p.SubmitterPrincipalID != operatorPrincipal {
			return Result{}, errors.New("ossinstall: local project submitter must be operator")
		}
	}
	if err := validateProjects(o.Root, o.ProjectContexts, nil); err != nil {
		return Result{}, err
	}
	capture, err := sourcepackage.Capture(ctx, o.LocalSources[0])
	if err != nil {
		return Result{}, err
	}
	// Validate the native raw-manifest pin, empty dependencies, and current action
	// restrictions before generating any signing key. This reuses strict verification.
	reader := &packageObjects{origin: capture.Subject.Origin, objects: map[string]trustverify.GitObject{}, used: map[string]bool{}}
	for id, raw := range capture.Objects {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		obj, err := rawObject(id, raw)
		if err != nil {
			return Result{}, err
		}
		reader.objects[id] = obj
	}
	snapshot, err := trustverify.VerifySource(ctx, reader, capture.Subject)
	if err != nil {
		return Result{}, err
	}
	if err := validateNativeSnapshot(snapshot); err != nil {
		return Result{}, err
	}
	if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
		return Result{}, ErrInstallRootForeign
	}
	// Validate exactly the importer's canonical statement subject and fixed scope
	// before source-key entropy. The issuer's syntax is checked using the reserved
	// local prefix; the fingerprint suffix is filled only after key generation.
	s := capture.Subject
	subject := bootstrap.SubjectIdentity{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: localPolicyOrigin, Issuer: "local-operator", Predicate: localPredicate, Usage: "template-source", Subject: subject}
	preflight, err := marshal(statement)
	if err != nil {
		return Result{}, err
	}
	if _, err := bootstrap.DecodePublisherStatement(preflight); err != nil {
		return Result{}, err
	}
	entropy := o.Rand
	if entropy == nil {
		entropy = defaultEntropy()
	}
	g := &generator{ctx: ctx, rand: entropy}
	key, err := g.key()
	if err != nil {
		return Result{}, err
	}
	defer eraseKey(key)
	public := key.Public().(ed25519.PublicKey)
	fingerprint := bootstrap.Fingerprint(public)
	issuer := "local-operator-" + strings.TrimPrefix(fingerprint, "sha256:")
	statement.Issuer = issuer
	raw, err := marshal(statement)
	if err != nil {
		return Result{}, err
	}
	digest, err := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	if err != nil {
		return Result{}, err
	}
	message, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil || len(message) != 32 {
		return Result{}, errors.New("ossinstall: invalid statement digest")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	signature := bootstrap.EncodeSignature(ed25519.Sign(key, message))
	eraseKey(key)
	o.Publishers = []Publisher{{Issuer: issuer, PublicKeyBase64: base64.StdEncoding.EncodeToString(public), SourceOrigin: s.Origin, TemplatePath: s.TemplatePath}}
	o.SourcePackages = []SourcePackage{{APIVersion: SourcePackageAPIVersion, Statement: raw, Signature: signature, KeyFingerprint: fingerprint, Objects: capture.Objects}}
	o.localRecord, err = marshal(LocalPublication{APIVersion: LocalPublicationAPIVersion, Mode: "local-operator", Issuer: issuer, KeyFingerprint: fingerprint, Subject: subject, PolicyOrigin: localPolicyOrigin, Predicate: localPredicate, Usage: "template-source"})
	if err != nil {
		return Result{}, err
	}
	return generateEnrollment(ctx, o)
}
