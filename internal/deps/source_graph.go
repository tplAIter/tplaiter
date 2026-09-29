// Package deps builds a closed, content-addressed graph of pinned template
// sources. It is deliberately pure: graph construction neither resolves refs
// nor reads a provider.
package deps

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const (
	SourceRootMissing         = "SOURCE_ROOT_MISSING"
	SourceCycle               = "SOURCE_CYCLE"
	SourceConflict            = "SOURCE_CONFLICT"
	SourceInvalid             = "SOURCE_INVALID"
	SourceLimit               = "SOURCE_LIMIT"
	SourceSnapshotUnavailable = "SOURCE_SNAPSHOT_UNAVAILABLE"
	SourceEvidenceMismatch    = "SOURCE_EVIDENCE_MISMATCH"
	SourceContentMismatch     = "SOURCE_CONTENT_MISMATCH"
	SourceClosureInput        = "SOURCE_CLOSURE_INPUT"
	SourceDependencyMissing   = "SOURCE_DEPENDENCY_MISSING"

	maxSourceNodes    = 1024
	maxSourceEdges    = 4096
	maxSourceParams   = 256
	maxSourceDepth    = 128
	maxSourceString   = 4096
	sourceParamDomain = "tplaiter/source-parameters/v1"
	sourceNodeDomain  = "tplaiter/source-node/v1"
	sourceGraphDomain = "tplaiter/source-graph/v1"
)

type SourceClosureStatus string

const (
	SourceClosurePresent SourceClosureStatus = "SOURCE_CLOSURE_PRESENT"
	SourceOptionalEmpty  SourceClosureStatus = "SOURCE_OPTIONAL_EMPTY"
)

type SourceGraphInput struct {
	Root              *PinnedSource
	DependencyClosure *SourceDependencyClosure
}
type (
	SourceDependencyClosure struct{ Pins []PinnedSource }
	SourceGraphResult       struct {
		Graph         SourceGraph
		ClosureStatus SourceClosureStatus
	}
)

// Parameter is a scalar input retained in the immutable source identity.
// Value is raw only at the wire boundary; Validate canonicalizes and checks it.
type Parameter struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

// PinnedSource is the complete closed source wire. Alias and RequestedRef are
// retained provenance, not immutable source identity.
type PinnedSource struct {
	APIVersion      string      `json:"apiVersion"`
	Alias           string      `json:"alias"`
	ProviderID      string      `json:"providerID"`
	Origin          string      `json:"origin"`
	TemplatePath    string      `json:"templatePath"`
	RequestedRef    string      `json:"requestedRef"`
	CommitAlgorithm string      `json:"commitAlgorithm"`
	Commit          string      `json:"commit"`
	TreeDigest      string      `json:"treeDigest"`
	ContentDigest   string      `json:"contentDigest"`
	ContractDigest  string      `json:"contractDigest"`
	EvidenceDigest  string      `json:"evidenceDigest"`
	Parameters      []Parameter `json:"parameters"`
	Dependencies    []string    `json:"dependencies"`
}

// SourceNodeIdentity is intentionally smaller than PinnedSource. The omitted
// alias, requestedRef, apiVersion and dependencies are provenance or topology,
// not source material identity.
type SourceNodeIdentity struct {
	Commit          string `json:"commit"`
	CommitAlgorithm string `json:"commitAlgorithm"`
	ContentDigest   string `json:"contentDigest"`
	ContractDigest  string `json:"contractDigest"`
	EvidenceDigest  string `json:"evidenceDigest"`
	Origin          string `json:"origin"`
	ParameterSHA256 string `json:"parameterSHA256"`
	ProviderID      string `json:"providerID"`
	TemplatePath    string `json:"templatePath"`
	TreeDigest      string `json:"treeDigest"`
}

type SourceProvenance struct {
	Alias        string `json:"alias"`
	RequestedRef string `json:"requestedRef"`
}

type SourceNode struct {
	Key        string             `json:"key"`
	Identity   SourceNodeIdentity `json:"identity"`
	Provenance []SourceProvenance `json:"provenance"`
}

// SourceEdge points from dependency to consumer.
type SourceEdge struct {
	Dependency string `json:"dependency"`
	Consumer   string `json:"consumer"`
}

type SourceGraph struct {
	Nodes  []SourceNode `json:"nodes"`
	Edges  []SourceEdge `json:"edges"`
	Digest string       `json:"digest"`
}

// Error retains only deterministic diagnostic values. Chains are alias paths
// from a root to the conflicting source, or node-key paths for a cycle.
type Error struct {
	Code   string
	Detail string
	Chains [][]string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "deps: " + e.Code
	}
	return "deps: " + e.Code + ": " + e.Detail
}

func sourceError(code, detail string) error { return &Error{Code: code, Detail: detail} }

// DecodePinnedSource decodes the closed source wire and enforces required
// fields before the graph builder sees it.
func DecodePinnedSource(raw []byte) (PinnedSource, error) {
	var p PinnedSource
	if err := requirePinnedSourceFields(raw); err != nil {
		return p, err
	}
	if err := canonicaljson.DecodeStrict(raw, &p); err != nil {
		return p, fmt.Errorf("deps: strict pinned source: %w", err)
	}
	if err := validatePinnedSource(p); err != nil {
		return p, err
	}
	return p, nil
}

func requirePinnedSourceFields(raw []byte) error {
	// Canonicalize first gives duplicate names, invalid UTF-8 and nested nulls
	// the same rejection behavior as every other strict wire decoder.
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return fmt.Errorf("deps: strict pinned source: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("deps: strict pinned source: %w", err)
	}
	required := []string{"apiVersion", "alias", "providerID", "origin", "templatePath", "requestedRef", "commitAlgorithm", "commit", "treeDigest", "contentDigest", "contractDigest", "evidenceDigest", "parameters", "dependencies"}
	if len(fields) != len(required) {
		return sourceError(SourceInvalid, "unknown or missing pinned source field")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return sourceError(SourceInvalid, "missing pinned source field "+name)
		}
	}
	return nil
}

// BuildSourceGraph validates every pin, merges equal immutable identities, and
// returns a canonical DAG. A nil or empty list is a missing root; a source with
// an explicit empty dependencies array is a valid leaf root.
func BuildSourceGraph(inputs []PinnedSource) (*SourceGraph, error) {
	if len(inputs) == 0 {
		return nil, sourceError(SourceRootMissing, "no pinned root")
	}
	if len(inputs) > maxSourceNodes {
		return nil, sourceError(SourceLimit, "node limit exceeded")
	}
	byAlias := make(map[string]PinnedSource, len(inputs))
	keys := make(map[string]string, len(inputs))
	identities := make(map[string]SourceNodeIdentity, len(inputs))
	for _, p := range inputs {
		if err := validatePinnedSource(p); err != nil {
			return nil, err
		}
		if _, exists := byAlias[p.Alias]; exists {
			return nil, sourceError(SourceInvalid, "duplicate alias "+p.Alias)
		}
		identity, err := sourceIdentity(p)
		if err != nil {
			return nil, err
		}
		key, err := sourceNodeKey(identity)
		if err != nil {
			return nil, err
		}
		byAlias[p.Alias], keys[p.Alias], identities[p.Alias] = p, key, identity
	}

	// A provider locator identifies one source instance. Different immutable
	// material for that locator is a conflict even when aliases differ.
	locator := make(map[string]string, len(inputs))
	locatorAlias := make(map[string]string, len(inputs))
	for _, p := range inputs {
		loc := p.Origin + "\x00" + p.TemplatePath
		if prior, exists := locator[loc]; exists && prior != keys[p.Alias] {
			return nil, &Error{Code: SourceConflict, Detail: "immutable pins differ for " + p.Origin + "/" + p.TemplatePath, Chains: [][]string{sourceChain(locatorAlias[loc], byAlias), sourceChain(p.Alias, byAlias)}}
		}
		locator[loc], locatorAlias[loc] = keys[p.Alias], p.Alias
	}

	nodeMap := make(map[string]*SourceNode, len(inputs))
	for _, p := range inputs {
		key := keys[p.Alias]
		n := nodeMap[key]
		if n == nil {
			n = &SourceNode{Key: key, Identity: identities[p.Alias]}
			nodeMap[key] = n
		}
		n.Provenance = append(n.Provenance, SourceProvenance{Alias: p.Alias, RequestedRef: p.RequestedRef})
	}

	edgeSet := make(map[string]SourceEdge)
	for _, p := range inputs {
		for _, alias := range p.Dependencies {
			if alias == p.Alias {
				return nil, sourceError(SourceInvalid, "self dependency "+alias)
			}
			if _, ok := byAlias[alias]; !ok {
				return nil, sourceError(SourceInvalid, "unknown dependency "+alias)
			}
			e := SourceEdge{Dependency: keys[alias], Consumer: keys[p.Alias]}
			edgeSet[e.Dependency+"\x00"+e.Consumer] = e
		}
	}
	if len(edgeSet) > maxSourceEdges {
		return nil, sourceError(SourceLimit, "edge limit exceeded")
	}
	nodes := make([]SourceNode, 0, len(nodeMap))
	for _, n := range nodeMap {
		sort.Slice(n.Provenance, func(i, j int) bool {
			if n.Provenance[i].Alias == n.Provenance[j].Alias {
				return n.Provenance[i].RequestedRef < n.Provenance[j].RequestedRef
			}
			return n.Provenance[i].Alias < n.Provenance[j].Alias
		})
		nodes = append(nodes, *n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Key < nodes[j].Key })
	edges := make([]SourceEdge, 0, len(edgeSet))
	for _, e := range edgeSet {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Dependency == edges[j].Dependency {
			return edges[i].Consumer < edges[j].Consumer
		}
		return edges[i].Dependency < edges[j].Dependency
	})
	if err := validateDAG(nodes, edges); err != nil {
		return nil, err
	}
	digest, err := sourceGraphDigest(nodes, edges)
	if err != nil {
		return nil, err
	}
	return &SourceGraph{Nodes: nodes, Edges: edges, Digest: digest}, nil
}

func BuildSourceGraphWithContext(input SourceGraphInput) (SourceGraphResult, error) {
	if input.Root == nil {
		return SourceGraphResult{}, sourceError(SourceRootMissing, "missing root")
	}
	if err := validatePinnedSource(*input.Root); err != nil {
		return SourceGraphResult{}, err
	}
	if input.DependencyClosure == nil {
		if len(input.Root.Dependencies) != 0 {
			return SourceGraphResult{}, sourceError(SourceDependencyMissing, "root dependency closure absent")
		}
		g, err := BuildSourceGraph([]PinnedSource{*input.Root})
		if err != nil {
			return SourceGraphResult{}, err
		}
		return SourceGraphResult{Graph: cloneSourceGraph(*g), ClosureStatus: SourceOptionalEmpty}, nil
	}
	if input.DependencyClosure.Pins == nil {
		return SourceGraphResult{}, sourceError(SourceClosureInput, "nil closure pins")
	}
	pins := make([]PinnedSource, 0, 1+len(input.DependencyClosure.Pins))
	pins = append(pins, *input.Root)
	pins = append(pins, input.DependencyClosure.Pins...)
	if len(pins) > maxSourceNodes {
		return SourceGraphResult{}, sourceError(SourceLimit, "node limit exceeded")
	}
	for _, p := range pins[1:] {
		if err := validatePinnedSource(p); err != nil {
			return SourceGraphResult{}, err
		}
	}
	aliases := map[string]bool{}
	for _, p := range pins {
		aliases[p.Alias] = true
	}
	for _, p := range pins {
		for _, d := range p.Dependencies {
			if !aliases[d] {
				return SourceGraphResult{}, sourceError(SourceDependencyMissing, "declared dependency missing")
			}
		}
	}
	g, err := BuildSourceGraph(pins)
	if err != nil {
		return SourceGraphResult{}, err
	}
	return SourceGraphResult{Graph: cloneSourceGraph(*g), ClosureStatus: SourceClosurePresent}, nil
}

func cloneSourceGraph(g SourceGraph) SourceGraph {
	out := SourceGraph{Digest: g.Digest, Nodes: make([]SourceNode, len(g.Nodes)), Edges: append([]SourceEdge(nil), g.Edges...)}
	for i, n := range g.Nodes {
		out.Nodes[i] = n
		out.Nodes[i].Provenance = append([]SourceProvenance(nil), n.Provenance...)
	}
	return out
}

// ValidateSourceGraph replays the immutable node keys, closed edge set, and
// graph digest before a downstream catalog binds itself to a graph node.
func ValidateSourceGraph(g *SourceGraph) error {
	if g == nil || len(g.Nodes) == 0 || len(g.Nodes) > maxSourceNodes || len(g.Edges) > maxSourceEdges || !validDigest(g.Digest) {
		return sourceError(SourceInvalid, "invalid source graph")
	}
	nodes := append([]SourceNode(nil), g.Nodes...)
	if !sort.SliceIsSorted(nodes, func(i, j int) bool { return nodes[i].Key < nodes[j].Key }) {
		return sourceError(SourceInvalid, "source graph nodes not sorted")
	}
	seen := map[string]bool{}
	aliases := map[string]bool{}
	for i := range nodes {
		key, err := sourceNodeKey(nodes[i].Identity)
		if err != nil || validateSourceNodeIdentity(nodes[i].Identity) != nil || key != nodes[i].Key || seen[key] || len(nodes[i].Provenance) == 0 {
			return sourceError(SourceInvalid, "source graph node mismatch")
		}
		seen[key] = true
		for j, p := range nodes[i].Provenance {
			if !validAlias(p.Alias) || aliases[p.Alias] || p.RequestedRef == "" || len(p.RequestedRef) > maxSourceString || !utf8.ValidString(p.RequestedRef) || strings.ContainsAny(p.RequestedRef, "\x00\r\n") || (j > 0 && (nodes[i].Provenance[j-1].Alias > p.Alias || nodes[i].Provenance[j-1].Alias == p.Alias && nodes[i].Provenance[j-1].RequestedRef >= p.RequestedRef)) {
				return sourceError(SourceInvalid, "source graph provenance mismatch")
			}
			aliases[p.Alias] = true
		}
	}
	edges := append([]SourceEdge{}, g.Edges...)
	if !sort.SliceIsSorted(edges, func(i, j int) bool {
		if edges[i].Dependency == edges[j].Dependency {
			return edges[i].Consumer < edges[j].Consumer
		}
		return edges[i].Dependency < edges[j].Dependency
	}) {
		return sourceError(SourceInvalid, "source graph edges not sorted")
	}
	for i, e := range edges {
		if !seen[e.Dependency] || !seen[e.Consumer] {
			return sourceError(SourceInvalid, "source graph edge mismatch")
		}
		if i > 0 && edges[i-1] == e {
			return sourceError(SourceInvalid, "source graph duplicate edge")
		}
	}
	if err := validateDAG(nodes, edges); err != nil {
		return err
	}
	d, err := sourceGraphDigest(nodes, edges)
	if err != nil || d != g.Digest {
		return sourceError(SourceInvalid, "source graph digest mismatch")
	}
	return nil
}

func sourceChain(alias string, byAlias map[string]PinnedSource) []string {
	seen := map[string]bool{}
	var visit func(string) []string
	visit = func(a string) []string {
		if seen[a] {
			return []string{a}
		}
		seen[a] = true
		p := byAlias[a]
		if len(p.Dependencies) == 0 {
			return []string{a}
		}
		deps := append([]string(nil), p.Dependencies...)
		sort.Strings(deps)
		return append(visit(deps[0]), a)
	}
	return visit(alias)
}

func validateDAG(nodes []SourceNode, edges []SourceEdge) error {
	adj := make(map[string][]string, len(nodes))
	for _, n := range nodes {
		adj[n.Key] = nil
	}
	for _, e := range edges {
		adj[e.Dependency] = append(adj[e.Dependency], e.Consumer)
	}
	for k := range adj {
		sort.Strings(adj[k])
	}
	state := make(map[string]uint8, len(nodes))
	stack := make([]string, 0, maxSourceDepth)
	var walk func(string) error
	walk = func(k string) error {
		if len(stack) >= maxSourceDepth {
			return sourceError(SourceLimit, "dependency depth exceeded")
		}
		state[k] = 1
		stack = append(stack, k)
		for _, next := range adj[k] {
			switch state[next] {
			case 1:
				start := 0
				for stack[start] != next {
					start++
				}
				chain := append([]string(nil), stack[start:]...)
				chain = append(chain, next)
				return &Error{Code: SourceCycle, Detail: "closed dependency cycle", Chains: [][]string{chain}}
			case 0:
				if err := walk(next); err != nil {
					return err
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[k] = 2
		return nil
	}
	for _, n := range nodes {
		if state[n.Key] == 0 {
			if err := walk(n.Key); err != nil {
				return err
			}
		}
	}
	depths := make(map[string]int, len(nodes))
	var longest func(string) (int, error)
	longest = func(key string) (int, error) {
		if d, ok := depths[key]; ok {
			return d, nil
		}
		best := 1
		for _, next := range adj[key] {
			d, err := longest(next)
			if err != nil {
				return 0, err
			}
			if d+1 > best {
				best = d + 1
			}
		}
		if best > maxSourceDepth {
			return 0, sourceError(SourceLimit, "dependency depth exceeded")
		}
		depths[key] = best
		return best, nil
	}
	for _, n := range nodes {
		if _, err := longest(n.Key); err != nil {
			return err
		}
	}
	return nil
}

func sourceIdentity(p PinnedSource) (SourceNodeIdentity, error) {
	params, err := parameterDigest(p.Parameters)
	if err != nil {
		return SourceNodeIdentity{}, err
	}
	return SourceNodeIdentity{Commit: p.Commit, CommitAlgorithm: p.CommitAlgorithm, ContentDigest: p.ContentDigest, ContractDigest: p.ContractDigest, EvidenceDigest: p.EvidenceDigest, Origin: p.Origin, ParameterSHA256: params, ProviderID: p.ProviderID, TemplatePath: p.TemplatePath, TreeDigest: p.TreeDigest}, nil
}

func validateSourceNodeIdentity(identity SourceNodeIdentity) error {
	if !validProviderID(identity.ProviderID) || !validTemplatePath(identity.TemplatePath) || (identity.CommitAlgorithm != "sha1" && identity.CommitAlgorithm != "sha256") || !isLowerHex(identity.Commit, map[string]int{"sha1": 40, "sha256": 64}[identity.CommitAlgorithm]) {
		return sourceError(SourceInvalid, "invalid source graph identity")
	}
	if err := validateOrigin(identity.Origin); err != nil {
		return err
	}
	for _, d := range []string{identity.TreeDigest, identity.ContentDigest, identity.ContractDigest, identity.EvidenceDigest, identity.ParameterSHA256} {
		if !validDigest(d) {
			return sourceError(SourceInvalid, "invalid source graph identity digest")
		}
	}
	return nil
}

func sourceNodeKey(identity SourceNodeIdentity) (string, error) {
	return framedDigest(sourceNodeDomain, identity)
}

func parameterDigest(parameters []Parameter) (string, error) {
	values := make([]struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	}, len(parameters))
	for i, p := range parameters {
		values[i] = struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		}{p.Name, p.Value}
	}
	return framedDigest(sourceParamDomain, values)
}

func sourceGraphDigest(nodes []SourceNode, edges []SourceEdge) (string, error) {
	keys := make([]string, len(nodes))
	for i := range nodes {
		keys[i] = nodes[i].Key
	}
	return framedDigest(sourceGraphDomain, struct {
		Edges []SourceEdge `json:"edges"`
		Nodes []string     `json:"nodes"`
	}{Edges: edges, Nodes: keys})
}

func framedDigest(domain string, value any) (string, error) {
	b, err := canonicaljson.Canonical(value)
	if err != nil {
		return "", fmt.Errorf("deps: canonical identity: %w", err)
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func validatePinnedSource(p PinnedSource) error {
	if p.APIVersion != "tplaiter.dev/pinned-source/v1" {
		return sourceError(SourceInvalid, "unsupported apiVersion")
	}
	for _, pair := range []struct{ name, value string }{{"alias", p.Alias}, {"providerID", p.ProviderID}, {"origin", p.Origin}, {"templatePath", p.TemplatePath}, {"requestedRef", p.RequestedRef}, {"commitAlgorithm", p.CommitAlgorithm}, {"commit", p.Commit}, {"treeDigest", p.TreeDigest}, {"contentDigest", p.ContentDigest}, {"contractDigest", p.ContractDigest}, {"evidenceDigest", p.EvidenceDigest}} {
		if pair.value == "" || len(pair.value) > maxSourceString || !utf8.ValidString(pair.value) {
			return sourceError(SourceInvalid, "invalid "+pair.name)
		}
	}
	if !validAlias(p.Alias) || !validProviderID(p.ProviderID) {
		return sourceError(SourceInvalid, "invalid alias or providerID")
	}
	if err := validateOrigin(p.Origin); err != nil {
		return err
	}
	if !validTemplatePath(p.TemplatePath) {
		return sourceError(SourceInvalid, "invalid templatePath")
	}
	if strings.ContainsAny(p.RequestedRef, "\x00\r\n") {
		return sourceError(SourceInvalid, "invalid requestedRef")
	}
	if (p.CommitAlgorithm != "sha1" && p.CommitAlgorithm != "sha256") || !isLowerHex(p.Commit, map[string]int{"sha1": 40, "sha256": 64}[p.CommitAlgorithm]) {
		return sourceError(SourceInvalid, "invalid commit")
	}
	for _, d := range []string{p.TreeDigest, p.ContentDigest, p.ContractDigest, p.EvidenceDigest} {
		if !validDigest(d) {
			return sourceError(SourceInvalid, "invalid sha256 digest")
		}
	}
	if p.Parameters == nil || len(p.Parameters) > maxSourceParams {
		return sourceError(SourceInvalid, "invalid parameters")
	}
	for i, param := range p.Parameters {
		if !validAlias(param.Name) || len(param.Value) == 0 {
			return sourceError(SourceInvalid, "invalid parameter")
		}
		if i > 0 && p.Parameters[i-1].Name >= param.Name {
			return sourceError(SourceInvalid, "parameters must be sorted and unique")
		}
		if err := validScalar(param.Value); err != nil {
			return err
		}
	}
	if p.Dependencies == nil || len(p.Dependencies) > maxSourceNodes {
		return sourceError(SourceInvalid, "invalid dependencies")
	}
	for i, dep := range p.Dependencies {
		if !validAlias(dep) || (i > 0 && p.Dependencies[i-1] >= dep) {
			return sourceError(SourceInvalid, "dependencies must be sorted and unique")
		}
	}
	return nil
}

func validScalar(raw []byte) error {
	// Decode the original RawMessage before canonicalization. Canonical JSON
	// intentionally normalizes -0, decimal, and exponent spellings, but those
	// spellings are forbidden at this typed wire boundary.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return sourceError(SourceInvalid, "invalid parameter scalar")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return sourceError(SourceInvalid, "invalid parameter scalar")
	}
	switch x := v.(type) {
	case string, bool:
		_, err := canonicaljson.Canonicalize(raw)
		if err != nil {
			return sourceError(SourceInvalid, "invalid parameter scalar")
		}
		return nil
	case json.Number:
		lexeme := x.String()
		if !strictSafeInteger(lexeme) {
			return sourceError(SourceInvalid, "parameter integer required")
		}
		if _, err := canonicaljson.Canonicalize(raw); err != nil {
			return sourceError(SourceInvalid, "invalid parameter scalar")
		}
		return nil
	default:
		return sourceError(SourceInvalid, "parameter scalar required")
	}
}

// ValidateScalarParameter validates the closed scalar facet shared by P08
// source and export wires. It preserves the original JSON number lexeme until
// after the integer-safety decision.
func ValidateScalarParameter(raw []byte) error { return validScalar(raw) }

func strictSafeInteger(lexeme string) bool {
	if lexeme == "" || lexeme == "-0" {
		return false
	}
	start := 0
	if lexeme[0] == '-' {
		if len(lexeme) == 1 || lexeme[1] == '0' {
			return false
		}
		start = 1
	} else if lexeme[0] == '0' && len(lexeme) != 1 {
		return false
	}
	for _, r := range lexeme[start:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(lexeme, 10, 64)
	return err == nil && n >= -(1<<53)+1 && n <= (1<<53)-1
}

func validateOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "ssh") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(origin, "@") || strings.Contains(origin, "\\") {
		return sourceError(SourceInvalid, "invalid origin")
	}
	if u.Path != "" && path.Clean(u.Path) != u.Path {
		return sourceError(SourceInvalid, "unnormalized origin")
	}
	return nil
}

func validTemplatePath(v string) bool {
	return v == "." || (!strings.HasPrefix(v, "/") && !strings.Contains(v, "\\") && path.Clean(v) == v && !strings.HasPrefix(v, "../") && v != "..")
}

func validAlias(v string) bool {
	if len(v) == 0 || len(v) > 128 || !isASCIIAlpha(v[0]) {
		return false
	}
	// Iterate bytes, not runes: every byte of a multi-byte UTF-8 sequence is
	// >= 0x80 and therefore rejected, whereas byte(rune) would truncate a
	// non-ASCII rune such as U+0141 to an ASCII letter.
	for i := 1; i < len(v); i++ {
		r := v[i]
		if !isASCIIAlpha(r) && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func validProviderID(v string) bool {
	if len(v) == 0 || len(v) > 128 || !isASCIIAlpha(v[0]) {
		return false
	}
	for i := 1; i < len(v); i++ {
		r := v[i]
		if !isASCIIAlpha(r) && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}
func isASCIIAlpha(v byte) bool { return v >= 'A' && v <= 'Z' || v >= 'a' && v <= 'z' }
func validDigest(v string) bool {
	return strings.HasPrefix(v, "sha256:") && isLowerHex(v[len("sha256:"):], 64)
}

func isLowerHex(v string, n int) bool {
	if len(v) != n {
		return false
	}
	for _, r := range v {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
