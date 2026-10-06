// Package operationtrust contains the deliberately narrow, no-side-effect
// preparation boundary used by trusted new/update composition.
package operationtrust

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextwire"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	NativeContractAPIVersion  = "tplaiter.dev/native-template-contract/v1"
	NativeContractKind        = "NativeTemplate"
	SourceSelectionAPIVersion = "tplaiter.dev/source-selection-input/v1"
)

var ErrSourceAdapterUnsupported = contextwire.ErrNativeUnsupported

// NativeContract is the complete T5 compatibility closure. It intentionally
// cannot describe portable dependencies or modifiers.
type NativeContract = contextwire.NativeContract

// SourceSelection is untrusted transport data. Verification happens only when
// its conversion is passed to Runtime.VerifySubject.
type SourceSelection struct {
	APIVersion   string            `json:"apiVersion"`
	Subject      SelectionSubject  `json:"subject"`
	Evidence     SelectionEvidence `json:"evidence"`
	Dependencies []string          `json:"dependencies"`
}

type SelectionSubject struct {
	Origin         string `json:"origin"`
	TemplatePath   string `json:"templatePath"`
	RequestedRef   string `json:"requestedRef"`
	Commit         string `json:"commit"`
	TreeSHA256     string `json:"treeSHA256"`
	ContractSHA256 string `json:"contractSHA256"`
}
type SelectionEvidence struct {
	Format            string `json:"format"`
	StatementCAS      string `json:"statementCAS"`
	SignatureCAS      string `json:"signatureCAS"`
	KeyFingerprint    string `json:"keyFingerprint"`
	CheckpointCAS     string `json:"checkpointCAS"`
	InclusionProofCAS string `json:"inclusionProofCAS"`
}

// DecodeNativeContract rejects every field outside the fixed, native-only
// wire. manifestRaw must be the bytes read from a verified snapshot.
func DecodeNativeContract(raw, manifestRaw []byte) (*NativeContract, error) {
	return contextwire.DecodeNativeContract(raw, manifestRaw)
}

// DecodeSourceSelection accepts only the bounded, closed native T5 input.
func DecodeSourceSelection(raw []byte) (*SourceSelection, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrSourceAdapterUnsupported
	}
	var v SourceSelection
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, ErrSourceAdapterUnsupported
	}
	if v.APIVersion != SourceSelectionAPIVersion || v.Dependencies == nil || len(v.Dependencies) != 0 ||
		v.Subject.Origin == "" || v.Subject.TemplatePath == "" || v.Subject.RequestedRef == "" ||
		v.Subject.Commit == "" || v.Subject.TreeSHA256 == "" || v.Subject.ContractSHA256 == "" ||
		v.Subject.RequestedRef != v.Subject.Commit || v.Evidence.Format == "" ||
		v.Evidence.StatementCAS == "" || v.Evidence.SignatureCAS == "" || v.Evidence.KeyFingerprint == "" ||
		v.Evidence.CheckpointCAS == "" || v.Evidence.InclusionProofCAS == "" {
		return nil, ErrSourceAdapterUnsupported
	}
	return &v, nil
}

func (v SourceSelection) TrustSubject() trustverify.Subject {
	return trustverify.Subject{Origin: v.Subject.Origin, TemplatePath: v.Subject.TemplatePath, RequestedRef: v.Subject.RequestedRef, Commit: v.Subject.Commit, TreeSHA256: v.Subject.TreeSHA256, ContractSHA256: v.Subject.ContractSHA256}
}

func (v SourceSelection) EvidenceRefs() trustverify.EvidenceRefs {
	return trustverify.EvidenceRefs{Format: v.Evidence.Format, StatementCAS: v.Evidence.StatementCAS, SignatureCAS: v.Evidence.SignatureCAS, KeyFingerprint: v.Evidence.KeyFingerprint, CheckpointCAS: v.Evidence.CheckpointCAS, InclusionProofCAS: v.Evidence.InclusionProofCAS}
}

func rawDigest(raw []byte) string {
	s := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(s[:])
}

func requireNativeContract(contract, manifest []byte) (*NativeContract, error) { //nolint:unparam // callers use the error only today; the parsed contract is the result
	v, err := DecodeNativeContract(contract, manifest)
	if err != nil {
		return nil, fmt.Errorf("%w", ErrSourceAdapterUnsupported)
	}
	if err := validateNativeManifest(manifest); err != nil {
		return nil, fmt.Errorf("%w", ErrSourceAdapterUnsupported)
	}
	return v, nil
}

// validateNativeManifest adds the portable native-adapter restrictions before
// the existing strict manifest parser: exactly one document, no aliases or
// merge keys, no duplicate keys, and no case-folded collisions.
func validateNativeManifest(raw []byte) error {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	var node yaml.Node
	if err := dec.Decode(&node); err != nil || len(node.Content) != 1 {
		return errors.New("native manifest shape")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("native manifest has multiple documents")
	}
	if err := validateYAMLNode(node.Content[0]); err != nil {
		return err
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		return err
	}
	return tpl.Validate()
}

func validateYAMLNode(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.Anchor != "" || node.Tag == "!!merge" {
		return errors.New("native manifest aliases unsupported")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]struct{}{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Value == "<<" {
				return errors.New("native manifest merge unsupported")
			}
			folded := strings.ToLower(key.Value)
			if _, ok := seen[folded]; ok {
				return errors.New("native manifest duplicate key")
			}
			seen[folded] = struct{}{}
			if err := validateYAMLNode(node.Content[i+1]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validateYAMLNode(child); err != nil {
			return err
		}
	}
	return nil
}
