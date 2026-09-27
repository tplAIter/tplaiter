package exports

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
)

const (
	CatalogAPIVersion     = "tplaiter.dev/export-catalog/v1"
	SelectionAPIVersion   = "tplaiter.dev/export-selection/v1"
	ExportGraphAPIVersion = "tplaiter.dev/export-graph/v1"
	maxCatalogWireBytes   = 1 << 20
	maxResolverCatalogs   = 1024
	maxExportRequires     = 4096
	maxWireStringBytes    = 4096
	maxExportVersionBytes = 1024
	maxRangeRunes         = 1024
)

var exportAliasRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)
var exportTokenRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
var exportDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type ScalarParameter struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}
type Catalog struct {
	APIVersion     string        `json:"apiVersion"`
	Provider       string        `json:"provider"`
	Source         string        `json:"source"`
	ContractDigest string        `json:"contractDigest"`
	Exports        []ExportEntry `json:"exports"`
}
type ExportEntry struct {
	ID            string              `json:"id"`
	Domain        string              `json:"domain"`
	Name          string              `json:"name"`
	Version       string              `json:"version"`
	ContentDigest string              `json:"contentDigest"`
	Parameters    []ScalarParameter   `json:"parameters"`
	ToolDigest    string              `json:"toolDigest"`
	Requires      []ExportRequirement `json:"requires"`
}
type Selection struct {
	APIVersion string            `json:"apiVersion"`
	Selector   string            `json:"selector"`
	Bindings   []ScalarParameter `json:"bindings"`
}

func ParseCatalog(raw []byte) (Catalog, error) {
	var v Catalog
	if len(raw) > maxCatalogWireBytes {
		return v, fmt.Errorf("exports: catalog byte limit")
	}
	if err := decodeClosed(raw, []string{"apiVersion", "provider", "source", "contractDigest", "exports"}, &v); err != nil {
		return v, err
	}
	if err := v.Validate(); err != nil {
		return v, err
	}
	return v, nil
}
func ParseSelection(raw []byte) (Selection, error) {
	var v Selection
	if err := decodeClosed(raw, []string{"apiVersion", "selector", "bindings"}, &v); err != nil {
		return v, err
	}
	if err := v.Validate(); err != nil {
		return v, err
	}
	return v, nil
}
func decodeClosed(raw []byte, fields []string, dst any) error {
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if len(m) != len(fields) {
		return fmt.Errorf("exports: unknown or missing field")
	}
	for _, f := range fields {
		if _, ok := m[f]; !ok {
			return fmt.Errorf("exports: missing field %s", f)
		}
	}
	return canonicaljson.DecodeStrict(raw, dst)
}
func (c Catalog) Validate() error {
	if c.APIVersion != CatalogAPIVersion || !exportTokenRE.MatchString(c.Provider) || !exportDigestRE.MatchString(c.Source) || !exportDigestRE.MatchString(c.ContractDigest) || c.Exports == nil || len(c.Exports) > 4096 {
		return fmt.Errorf("exports: invalid catalog")
	}
	seen := map[string]bool{}
	for _, e := range c.Exports {
		if err := e.Validate(); err != nil {
			return err
		}
		if seen[e.ID] {
			return fmt.Errorf("exports: duplicate id %s", e.ID)
		}
		seen[e.ID] = true
	}
	if !sort.SliceIsSorted(c.Exports, func(i, j int) bool { return eKey(c.Exports[i]) < eKey(c.Exports[j]) }) {
		return fmt.Errorf("exports: exports must be sorted")
	}
	return nil
}
func (e ExportEntry) Validate() error {
	if !exportTokenRE.MatchString(e.ID) || !exportAliasRE.MatchString(e.Name) || len(e.Version) == 0 || len(e.Version) > maxExportVersionBytes || !strictSemver(e.Version) || !domainRankOK(e.Domain) || !exportDigestRE.MatchString(e.ContentDigest) || !exportDigestRE.MatchString(e.ToolDigest) || e.Requires == nil || len(e.Requires) > maxExportRequires || e.Parameters == nil {
		return fmt.Errorf("exports: invalid entry %s", e.ID)
	}
	if err := validateParams(e.Parameters); err != nil {
		return err
	}
	prev := ""
	for _, r := range e.Requires {
		if !selectorRE.MatchString(r.Selector) || len(r.Selector) > maxWireStringBytes || !exportDigestRE.MatchString(r.ContractDigest) || r.CompatibleRange == "" || !utf8.ValidString(r.CompatibleRange) || utf8.RuneCountInString(r.CompatibleRange) > maxRangeRunes || r.Selector <= prev {
			return fmt.Errorf("exports: invalid requirements")
		}
		prev = r.Selector
	}
	return nil
}
func (s Selection) Validate() error {
	if s.APIVersion != SelectionAPIVersion || !selectorRE.MatchString(s.Selector) || s.Bindings == nil {
		return fmt.Errorf("exports: invalid selection")
	}
	return validateParams(s.Bindings)
}
func validateParams(ps []ScalarParameter) error {
	if len(ps) > 256 {
		return fmt.Errorf("exports: parameter limit")
	}
	prev := ""
	for _, p := range ps {
		if !exportAliasRE.MatchString(p.Name) || p.Name <= prev || !scalar(p.Value) {
			return fmt.Errorf("exports: invalid parameters")
		}
		prev = p.Name
	}
	return nil
}
func scalar(raw json.RawMessage) bool {
	return deps.ValidateScalarParameter(raw) == nil
}
func eKey(e ExportEntry) string {
	return fmt.Sprintf("%03d", domainRank(e.Domain)) + "\x00" + e.Name + "\x00" + e.ID
}
func domainRankOK(s string) bool {
	switch s {
	case "block", "skill", "approach", "package":
		return true
	}
	return false
}
func domainRank(s string) int {
	switch s {
	case "block":
		return 0
	case "skill":
		return 1
	case "approach":
		return 2
	default:
		return 3
	}
}
func parameterDigest(ps []ScalarParameter) (string, error) {
	b, err := canonicaljson.Canonical(ps)
	if err != nil {
		return "", err
	}
	return hashDomain("tplaiter/source-parameters/v1", b), nil
}

type catalogEntryIdentity struct {
	Source          string              `json:"source"`
	Provider        string              `json:"provider"`
	Entry           ExportEntry         `json:"entry"`
	ParameterSHA256 string              `json:"parameterSHA256"`
	Requires        []ExportRequirement `json:"requires"`
}

func CatalogEntryIdentity(c Catalog, e ExportEntry) (string, error) {
	p, err := parameterDigest(e.Parameters)
	if err != nil {
		return "", err
	}
	clean := e
	clean.Requires = nil
	req := append([]ExportRequirement(nil), e.Requires...)
	sort.Slice(req, func(i, j int) bool { return req[i].Selector < req[j].Selector })
	return domainDigest("tplaiter/export-entry/v1", catalogEntryIdentity{
		Source:          c.Source,
		Provider:        c.Provider,
		Entry:           clean,
		ParameterSHA256: p,
		Requires:        req,
	})
}

func SelectionBindingsIdentity(s Selection) (string, error) {
	return domainDigest("tplaiter/export-bindings/v1", s.Bindings)
}

func domainDigest(domain string, v any) (string, error) {
	b, err := canonicaljson.Canonical(v)
	if err != nil {
		return "", err
	}
	return hashDomain(domain, b), nil
}
func hashDomain(domain string, b []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
