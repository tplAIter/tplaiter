package contextsource

import (
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/contextwire"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"regexp"
	"strings"
)

const NativeContextContractAPIVersion = contextwire.NativeContextContractAPIVersion
const ContextSourceSelectionAPIVersion = "tplaiter.dev/source-selection-input/v2"
const MaxContextSources = contextwire.MaxContextSources

type ContextDependency = contextwire.ContextDependency
type NativeContextContract = contextwire.NativeContextContract

var contextDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var contextCommitRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
var errContextSources = contextwire.ErrSources
var errContextSourceLimit = contextwire.ErrSourceLimit

func decodeContextWire(raw []byte, dst any, limit int) error {
	return contextwire.DecodeRequired(raw, dst, limit)
}

// ContextSourceProof is untrusted evidence transport, not an admitted resolution.
type ContextSourceProof struct {
	Subject  operationtrust.SelectionSubject  `json:"subject"`
	Evidence operationtrust.SelectionEvidence `json:"evidence"`
}
type ContextSourceSelection struct {
	APIVersion string               `json:"apiVersion"`
	Root       ContextSourceProof   `json:"root"`
	Sources    []ContextSourceProof `json:"sources"`
}

func contextProof(p ContextSourceProof) error {
	s, e := p.Subject, p.Evidence
	if s.Origin == "" || len(s.Origin) > 4096 || strings.ContainsAny(s.Origin, "\x00\r\n") || !contextTemplatePath(s.TemplatePath) || !contextCommitRE.MatchString(s.Commit) || s.RequestedRef != s.Commit || !contextDigestRE.MatchString(s.TreeSHA256) || !contextDigestRE.MatchString(s.ContractSHA256) || e.Format != bootstrap.PublisherStatementAPIVersion {
		return errContextSources
	}
	for _, d := range []string{e.StatementCAS, e.SignatureCAS, e.KeyFingerprint, e.CheckpointCAS, e.InclusionProofCAS} {
		if !contextDigestRE.MatchString(d) {
			return errContextSources
		}
	}
	return nil
}
func contextTemplatePath(p string) bool { return p == "." || contextResourcePath(p) }
func contextSubject(p ContextSourceProof) trustverify.Subject {
	s := p.Subject
	return trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}
func contextEvidence(p ContextSourceProof) trustverify.EvidenceRefs {
	e := p.Evidence
	return trustverify.EvidenceRefs{Format: e.Format, StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint, CheckpointCAS: e.CheckpointCAS, InclusionProofCAS: e.InclusionProofCAS}
}
func contextSubjectKey(s trustverify.Subject) string {
	return s.Origin + "\x00" + s.TemplatePath + "\x00" + s.Commit
}
func DecodeSourceSelectionV2(raw []byte) (ContextSourceSelection, error) {
	var v ContextSourceSelection
	if decodeContextWire(raw, &v, 1<<20) != nil || v.APIVersion != ContextSourceSelectionAPIVersion || len(v.Sources) > MaxContextSources-1 {
		return v, errContextSources
	}
	if e := contextProof(v.Root); e != nil {
		return v, e
	}
	seen := map[string]bool{contextSubjectKey(contextSubject(v.Root)): true}
	for _, p := range v.Sources {
		if contextProof(p) != nil {
			return v, errContextSources
		}
		k := contextSubjectKey(contextSubject(p))
		if seen[k] {
			return v, errContextSources
		}
		seen[k] = true
	}
	return v, nil
}

func DecodeNativeContextContractV2(raw, manifest []byte) (NativeContextContract, error) {
	return contextwire.DecodeNativeContextContractV2(raw, manifest)
}
