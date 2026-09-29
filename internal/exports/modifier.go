// Package exports contains the pure authoring and composition contracts.
package exports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

type Modifier struct {
	APIVersion      string               `json:"apiVersion"`
	Kind            string               `json:"kind"`
	Metadata        Metadata             `json:"metadata"`
	Compatibility   Compatibility        `json:"compatibility"`
	Sources         []SourcePin          `json:"sources"`
	SelfSource      string               `json:"selfSource"`
	Requires        Requires             `json:"requires"`
	Provides        []ProvidedCapability `json:"provides"`
	Conflicts       []Capability         `json:"conflicts"`
	Replaces        []Replacement        `json:"replaces"`
	Bindings        []Binding            `json:"bindings"`
	Rules           []Operation          `json:"rules"`
	ToolConstraints []ToolConstraint     `json:"toolConstraints"`
	Renames         []Rename             `json:"renames"`
}

type Metadata struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}
type Compatibility struct {
	MinimumCLI  string   `json:"minimumCLI"`
	PortableAPI string   `json:"portableAPI"`
	Runtimes    []string `json:"runtimes"`
	Layouts     []string `json:"layouts"`
}
type SourcePin struct {
	Alias           string `json:"alias"`
	ProviderID      string `json:"providerId"`
	Origin          string `json:"origin"`
	TemplatePath    string `json:"templatePath"`
	RequestedRef    string `json:"requestedRef"`
	TreeDigest      string `json:"treeDigest"`
	ContentDigest   string `json:"contentDigest"`
	ContractDigest  string `json:"contractDigest"`
	EvidenceDigest  string `json:"evidenceDigest"`
	CommitAlgorithm string `json:"commitAlgorithm"`
	Commit          string `json:"commit"`
}
type Requires struct {
	Exports      []ExportRequirement `json:"exports"`
	Capabilities []Capability        `json:"capabilities"`
}
type ExportRequirement struct {
	Selector        string `json:"selector"`
	ContractDigest  string `json:"contractDigest"`
	CompatibleRange string `json:"compatibleRange"`
}
type Capability struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type ProvidedCapability struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	RuleID string `json:"ruleId"`
}
type Replacement struct {
	Name         string `json:"name"`
	Value        string `json:"value"`
	ProviderRule string `json:"providerRule"`
	WithRule     string `json:"withRule"`
}
type Binding struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}
type Operation struct {
	ID              string   `json:"id"`
	Op              string   `json:"op"`
	Before          []string `json:"before"`
	After           []string `json:"after"`
	Target          string   `json:"target,omitempty"`
	ExpectedDigest  string   `json:"expectedDigest,omitempty"`
	ExpectedVersion string   `json:"expectedVersion,omitempty"`
	Export          string   `json:"export,omitempty"`
}
type ToolConstraint struct {
	ID              string `json:"id"`
	CompatibleRange string `json:"compatibleRange"`
	OptionsDigest   string `json:"optionsDigest"`
}
type Rename struct {
	Path                   string `json:"path"`
	OldBlockID             string `json:"oldBlockId"`
	NewBlockID             string `json:"newBlockId"`
	ExpectedBaselineDigest string `json:"expectedBaselineDigest"`
	ExpectedSourceDigest   string `json:"expectedSourceDigest"`
}

// Parse decodes one strict JSON modifier document and runs semantic validation.
func Parse(data []byte) (Modifier, error) {
	normalized, err := normalizeDocument(data)
	if err != nil {
		return Modifier{}, err
	}
	if err := validateRequiredShape(normalized); err != nil {
		return Modifier{}, err
	}
	var m Modifier
	if err := canonicaljson.DecodeStrict(normalized, &m); err != nil {
		return Modifier{}, err
	}
	if err := Validate(m); err != nil {
		return Modifier{}, err
	}
	return m, nil
}

var (
	tokenRE    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
	aliasRE    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)
	digestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	semverRE   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	selectorRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}\.(block|skill|approach|package)\.[A-Za-z][A-Za-z0-9_-]{0,127}$`)
)

func Validate(m Modifier) error {
	if m.APIVersion != "tplaiter.dev/modifier/v1" || m.Kind != "Modifier" {
		return errors.New("modifier: unsupported apiVersion or kind")
	}
	if !tokenRE.MatchString(m.Metadata.ID) || !strictSemver(m.Metadata.Version) {
		return errors.New("modifier: invalid metadata")
	}
	if !strictSemver(m.Compatibility.MinimumCLI) || m.Compatibility.PortableAPI != "tplaiter.dev/portable/v1" || len(m.Compatibility.Runtimes) == 0 || len(m.Compatibility.Layouts) == 0 {
		return errors.New("modifier: invalid compatibility")
	}
	if len(m.Sources) == 0 || len(m.Rules) == 0 || m.Requires.Exports == nil || m.Requires.Capabilities == nil || m.Provides == nil || m.Conflicts == nil || m.Replaces == nil || m.Bindings == nil || m.ToolConstraints == nil || m.Renames == nil {
		return errors.New("modifier: missing required collection")
	}
	seenAlias := map[string]bool{}
	seenIdentity := map[string]bool{}
	for _, s := range m.Sources {
		if err := validateSource(s); err != nil {
			return err
		}
		if !aliasRE.MatchString(s.Alias) || seenAlias[s.Alias] {
			return fmt.Errorf("modifier: duplicate source alias %q", s.Alias)
		}
		seenAlias[s.Alias] = true
		id := s.Origin + "\x00" + s.TemplatePath
		if seenIdentity[id] {
			return fmt.Errorf("modifier: duplicate source identity %q", id)
		}
		seenIdentity[id] = true
	}
	if err := validateModifierCollections(m); err != nil {
		return err
	}
	if !aliasRE.MatchString(m.SelfSource) || !seenAlias[m.SelfSource] {
		return errors.New("modifier: invalid selfSource")
	}
	for _, c := range append(append([]Capability{}, m.Requires.Capabilities...), m.Conflicts...) {
		if !tokenRE.MatchString(c.Name) || !tokenRE.MatchString(c.Value) {
			return errors.New("modifier: invalid capability")
		}
	}
	seenOps := map[string]bool{}
	for _, op := range m.Rules {
		if op.Before == nil || op.After == nil {
			return errors.New("modifier: operation edges are required")
		}
		if err := validateOperation(op); err != nil {
			return err
		}
		if op.Export != "" && !sourceAlias(m, strings.Split(op.Export, ".")[0]) {
			return errors.New("modifier: operation references unknown source")
		}
		if seenOps[op.ID] {
			return fmt.Errorf("modifier: duplicate operation %q", op.ID)
		}
		seenOps[op.ID] = true
	}
	for _, b := range m.Bindings {
		if !aliasRE.MatchString(b.Name) || len(b.Value) == 0 || bytes.Equal(bytes.TrimSpace(b.Value), []byte("null")) {
			return fmt.Errorf("modifier: invalid binding %q", b.Name)
		}
		if _, err := bindingScalar(b); err != nil {
			return fmt.Errorf("modifier: binding %q: %w", b.Name, err)
		}
	}
	return nil
}

func validateSource(s SourcePin) error {
	if !aliasRE.MatchString(s.Alias) || !tokenRE.MatchString(s.ProviderID) || s.Origin == "" || s.TemplatePath == "" || s.RequestedRef == "" || !digestRE.MatchString(s.TreeDigest) || !digestRE.MatchString(s.ContentDigest) || !digestRE.MatchString(s.ContractDigest) || !digestRE.MatchString(s.EvidenceDigest) {
		return fmt.Errorf("modifier: invalid source pin %q", s.Alias)
	}
	if runeLen(s.Origin) > 1024 || runeLen(s.TemplatePath) > 1024 || runeLen(s.RequestedRef) > 1024 {
		return errors.New("modifier: source string limit exceeded")
	}
	if s.CommitAlgorithm != "sha1" && s.CommitAlgorithm != "sha256" {
		return errors.New("modifier: invalid commit algorithm")
	}
	n := 40
	if s.CommitAlgorithm == "sha256" {
		n = 64
	}
	if len(s.Commit) != n || strings.Trim(s.Commit, "0123456789abcdef") != "" {
		return errors.New("modifier: invalid commit")
	}
	if err := validateRelativePath(s.TemplatePath, true); err != nil {
		return err
	}
	if strings.Contains(s.Origin, "@") || strings.Contains(s.Origin, "?") {
		return errors.New("modifier: unsafe origin")
	}
	return nil
}

func validateOperation(op Operation) error {
	if !tokenRE.MatchString(op.ID) || op.Op == "" || (op.Export != "" && !aliasRE.MatchString(strings.Split(op.Export, ".")[0])) {
		return fmt.Errorf("modifier: invalid operation %q", op.ID)
	}
	if len(op.Before) > 256 || len(op.After) > 256 || !uniqueStrings(op.Before) || !uniqueStrings(op.After) {
		return errors.New("modifier: invalid operation edges")
	}
	for _, id := range append(append([]string{}, op.Before...), op.After...) {
		if !tokenRE.MatchString(id) {
			return errors.New("modifier: invalid operation edge")
		}
	}
	switch op.Op {
	case "add":
		if op.Target != "" || op.ExpectedDigest != "" || op.ExpectedVersion != "" || !selectorRE.MatchString(op.Export) {
			return errors.New("modifier: invalid add")
		}
	case "replace":
		if !tokenRE.MatchString(op.Target) || !digestRE.MatchString(op.ExpectedDigest) || (op.ExpectedVersion != "" && !strictSemver(op.ExpectedVersion)) || !selectorRE.MatchString(op.Export) {
			return errors.New("modifier: invalid replace")
		}
	case "remove":
		if !tokenRE.MatchString(op.Target) || !digestRE.MatchString(op.ExpectedDigest) || (op.ExpectedVersion != "" && !strictSemver(op.ExpectedVersion)) || op.Export != "" {
			return errors.New("modifier: invalid remove")
		}
	default:
		return fmt.Errorf("modifier: unknown operation %q", op.Op)
	}
	return nil
}

func sortedStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}
