// Package templatediscovery ranks immutable descriptive data. It has no source
// reader, trust verifier, execution capability, or installation authority.
package templatediscovery

import "errors"

const APIVersion = "tplaiter.dev/template-discovery/v1"
const MinBytes = 2048

var ErrInput = errors.New("DISCOVERY_INPUT_INVALID")

type Kind string

const (
	KindTemplate Kind = "template"
	KindBlock    Kind = "installable-block"
	KindContext  Kind = "context"
	KindRecipe   Kind = "documentation-recipe"
	KindFixture  Kind = "test-fixture"
	KindSkill    Kind = "skill"
	KindUnknown  Kind = "unknown"
)

type Readiness string

const (
	Ready        Readiness = "ready"
	Experimental Readiness = "experimental"
	Planned      Readiness = "planned"
	Deprecated   Readiness = "deprecated"
	Unknown      Readiness = "unknown"
)

func (k Kind) Valid() bool {
	switch k {
	case KindTemplate, KindBlock, KindContext, KindRecipe, KindFixture, KindSkill, KindUnknown:
		return true
	}
	return false
}
func (r Readiness) Valid() bool {
	switch r {
	case Ready, Experimental, Planned, Deprecated, Unknown:
		return true
	}
	return false
}

// SourcePin is an immutable data reference, never evidence of authority.
// owner-supplied means the caller owns admission; this package does not verify it.
type SourcePin struct {
	Qualification  string `json:"qualification"`
	Repo           string `json:"repo,omitempty"`
	Path           string `json:"path,omitempty"`
	Commit         string `json:"commit,omitempty"`
	ManifestSHA256 string `json:"manifestSHA256,omitempty"`
	SourceID       string `json:"sourceID,omitempty"`
	Revision       string `json:"revision,omitempty"`
	ContentSHA256  string `json:"contentSHA256,omitempty"`
}
type Provenance struct {
	CatalogSource  string `json:"catalogSource"`
	Provider       string `json:"provider"`
	ContractSHA256 string `json:"contractSHA256"`
	ExportID       string `json:"exportID"`
	Domain         string `json:"domain"`
	ContentSHA256  string `json:"contentSHA256"`
}
type Reference struct {
	ID                string      `json:"id"`
	SourcePin         SourcePin   `json:"sourcePin"`
	CandidateKind     Kind        `json:"candidateKind"`
	Readiness         Readiness   `json:"readiness"`
	DeclarationStatus string      `json:"declarationStatus"`
	Availability      string      `json:"availability"`
	Provenance        *Provenance `json:"provenance"`
}
type Candidate struct {
	ID             string              `json:"id"`
	MetadataSHA256 string              `json:"metadataSHA256"`
	SourcePin      SourcePin           `json:"sourcePin"`
	Name           string              `json:"name"`
	Version        string              `json:"version"`
	Description    string              `json:"description"`
	Labels         map[string][]string `json:"labels"`
	CandidateKind  Kind                `json:"candidateKind"`
	Readiness      Readiness           `json:"readiness"`
	Blocks         []Reference         `json:"blocks"`
	Skills         []Reference         `json:"skills"`
}
type FactEvidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type ProjectFacts struct {
	Status     string         `json:"status"`
	Language   string         `json:"language"`
	Frameworks []string       `json:"frameworks"`
	Template   string         `json:"template"`
	Evidence   []FactEvidence `json:"evidence"`
}
type Query struct {
	Task          string       `json:"task"`
	Language      string       `json:"language"`
	Framework     string       `json:"framework"`
	Labels        []string     `json:"labels"`
	Facts         ProjectFacts `json:"facts"`
	MaxCandidates int          `json:"maxCandidates"`
	MaxResults    int          `json:"maxResults"`
	MaxBytes      int          `json:"maxBytes"`
}
type MatchReason struct {
	Field string `json:"field"`
	Token string `json:"token"`
	Value string `json:"value"`
}
type ReadOnlyCall struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}
type Suggestion struct {
	ID                   string         `json:"id"`
	MetadataSHA256       string         `json:"metadataSHA256"`
	SourcePin            SourcePin      `json:"sourcePin"`
	Name                 string         `json:"name"`
	Description          string         `json:"description"`
	DescriptionTruncated bool           `json:"descriptionTruncated"`
	Version              string         `json:"version"`
	CandidateKind        Kind           `json:"candidateKind"`
	Readiness            Readiness      `json:"readiness"`
	Score                int            `json:"score"`
	Reasons              []MatchReason  `json:"reasons"`
	Blocks               []Reference    `json:"blocks"`
	Skills               []Reference    `json:"skills"`
	NextToolCalls        []ReadOnlyCall `json:"nextToolCalls"`
}
type Diagnostic struct {
	Code        string `json:"code"`
	CandidateID string `json:"candidateID"`
	Field       string `json:"field"`
}
type Budget struct {
	MaxCandidates int  `json:"maxCandidates"`
	MaxResults    int  `json:"maxResults"`
	MaxBytes      int  `json:"maxBytes"`
	Considered    int  `json:"considered"`
	Emitted       int  `json:"emitted"`
	Bytes         int  `json:"bytes"`
	Truncated     bool `json:"truncated"`
}
type Result struct {
	APIVersion    string       `json:"apiVersion"`
	Qualification string       `json:"qualification"`
	Facts         ProjectFacts `json:"facts"`
	Suggestions   []Suggestion `json:"suggestions"`
	Diagnostics   []Diagnostic `json:"diagnostics"`
	Budget        Budget       `json:"budget"`
}
