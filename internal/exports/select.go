package exports

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/deps"
)

type SelectedExport struct {
	Source                string            `json:"source"`
	Provider              string            `json:"provider"`
	ID                    string            `json:"id"`
	Domain                string            `json:"domain"`
	Name                  string            `json:"name"`
	Version               string            `json:"version"`
	ContentDigest         string            `json:"contentDigest"`
	ContractDigest        string            `json:"contractDigest"`
	Parameters            []ScalarParameter `json:"parameters"`
	BindingSHA256         string            `json:"bindingSHA256"`
	SourceParameterSHA256 string            `json:"sourceParameterSHA256"`
	ToolDigest            string            `json:"toolDigest"`
	Chains                [][]string        `json:"chains"`
}
type ExportGraph struct {
	Selected []SelectedExport `json:"selected"`
	Edges    []ExportEdge     `json:"edges"`
	Digest   string           `json:"digest"`
}
type ExportEdge struct {
	Dependency string `json:"dependency"`
	Consumer   string `json:"consumer"`
}

type selectedExportIdentity struct {
	Source                 string `json:"source"`
	Provider               string `json:"provider"`
	ID                     string `json:"id"`
	Version                string `json:"version"`
	ContentDigest          string `json:"contentDigest"`
	ContractDigest         string `json:"contractDigest"`
	SourceParameterSHA256  string `json:"sourceParameterSHA256"`
	EntryParameterSHA256   string `json:"entryParameterSHA256"`
	SelectionBindingSHA256 string `json:"selectionBindingSHA256"`
	ToolDigest             string `json:"toolDigest"`
}

type exportGraphIdentity struct {
	Selected []SelectedExport `json:"selected"`
	Edges    []ExportEdge     `json:"edges"`
}

// SelectedExportIdentity returns the stable identity of one resolved export.
// SourceParameterSHA256 is projected from the actual bound SourceGraph node;
// a node key is intentionally not substituted for that identity member.
func SelectedExportIdentity(s SelectedExport) (string, error) {
	ep, err := parameterDigest(s.Parameters)
	if err != nil {
		return "", err
	}
	return domainDigest("tplaiter/selected-export/v1", selectedExportIdentity{
		Source:                 s.Source,
		Provider:               s.Provider,
		ID:                     s.ID,
		Version:                s.Version,
		ContentDigest:          s.ContentDigest,
		ContractDigest:         s.ContractDigest,
		SourceParameterSHA256:  s.SourceParameterSHA256,
		EntryParameterSHA256:   ep,
		SelectionBindingSHA256: s.BindingSHA256,
		ToolDigest:             s.ToolDigest,
	})
}

// ExportGraphDigest hashes the canonical, sorted selected records and edges.
// The returned digest is over the graph preimage and never includes itself.
func ExportGraphDigest(selected []SelectedExport, edges []ExportEdge) (string, error) {
	ss := append([]SelectedExport(nil), selected...)
	ee := append([]ExportEdge(nil), edges...)
	sort.Slice(ss, func(i, j int) bool { return selectedKey(ss[i]) < selectedKey(ss[j]) })
	sort.Slice(ee, func(i, j int) bool {
		if ee[i].Dependency != ee[j].Dependency {
			return ee[i].Dependency < ee[j].Dependency
		}
		return ee[i].Consumer < ee[j].Consumer
	})
	return domainDigest("tplaiter/export-graph/v1", exportGraphIdentity{Selected: ss, Edges: ee})
}

func selectedKey(s SelectedExport) string {
	return s.Source + "\x00" + s.Provider + "\x00" + fmt.Sprintf("%03d", domainRank(s.Domain)) + "\x00" + s.Name + "\x00" + s.ID
}

type selectKey struct {
	catalog               Catalog
	entry                 ExportEntry
	alias                 string
	sourceParameterSHA256 string
	chains                [][]string
	depth                 int
}

const maxExportDependencyDepth = 128

// ResolveSelection performs provider-scoped, dependency-closed selection. It
// only validates and returns immutable records; it never materializes or runs.
func ResolveSelection(selection Selection, sources *deps.SourceGraph, catalogs []Catalog) (ExportGraph, error) {
	if err := selection.Validate(); err != nil {
		return ExportGraph{}, err
	}
	if sources == nil || len(sources.Nodes) == 0 || len(catalogs) > maxResolverCatalogs {
		return ExportGraph{}, fmt.Errorf("EXPORT_SOURCE: missing or excessive source graph")
	}
	if err := deps.ValidateSourceGraph(sources); err != nil {
		return ExportGraph{}, fmt.Errorf("EXPORT_SOURCE: invalid source graph")
	}
	alias, domain, name := splitSelector(selection.Selector)
	if alias == "" {
		return ExportGraph{}, fmt.Errorf("EXPORT_SELECTOR: invalid selector")
	}
	bySource := map[string]deps.SourceNode{}
	byAlias := map[string]deps.SourceNode{}
	for _, node := range sources.Nodes {
		if node.Key == "" || node.Identity.ProviderID == "" || !exportDigestRE.MatchString(node.Identity.ContractDigest) || !exportDigestRE.MatchString(node.Identity.ParameterSHA256) {
			return ExportGraph{}, fmt.Errorf("EXPORT_SOURCE: invalid graph node")
		}
		if _, exists := bySource[node.Key]; exists {
			return ExportGraph{}, fmt.Errorf("EXPORT_SOURCE: duplicate graph node")
		}
		bySource[node.Key] = node
		for _, provenance := range node.Provenance {
			if _, exists := byAlias[provenance.Alias]; exists {
				return ExportGraph{}, fmt.Errorf("EXPORT_SOURCE: duplicate alias %s", provenance.Alias)
			}
			byAlias[provenance.Alias] = node
		}
	}
	bySourceCatalog := map[string]Catalog{}
	for _, c := range catalogs {
		if err := c.Validate(); err != nil {
			return ExportGraph{}, err
		}
		node, ok := bySource[c.Source]
		if !ok || node.Identity.ContractDigest != c.ContractDigest || node.Identity.ProviderID != c.Provider {
			return ExportGraph{}, fmt.Errorf("EXPORT_SOURCE: catalog source or contract mismatch")
		}
		if _, ok := bySourceCatalog[c.Source]; ok {
			return ExportGraph{}, fmt.Errorf("EXPORT_SOURCE: duplicate catalog source")
		}
		bySourceCatalog[c.Source] = c
	}
	rootNode, ok := byAlias[alias]
	if !ok {
		return ExportGraph{}, fmt.Errorf("EXPORT_PROVIDER: unknown provider %s", alias)
	}
	root, ok := bySourceCatalog[rootNode.Key]
	if !ok {
		return ExportGraph{}, fmt.Errorf("EXPORT_SOURCE: missing catalog for %s", alias)
	}
	selected := map[string]selectKey{}
	edges := map[string]ExportEdge{}
	visiting := map[string]bool{}
	var visit func(string, Catalog, string, string, string, []string) (string, error)
	visit = func(currentAlias string, cat Catalog, sel, dom, n string, chain []string) (string, error) {
		if len(chain) >= maxExportDependencyDepth {
			return "", fmt.Errorf("EXPORT_LIMIT: dependency depth exceeded")
		}
		key := ""
		var ent *ExportEntry
		for i := range cat.Exports {
			if cat.Exports[i].Domain == dom && cat.Exports[i].Name == n {
				if ent != nil {
					return "", fmt.Errorf("EXPORT_AMBIGUOUS: %s", sel)
				}
				ent = &cat.Exports[i]
			}
		}
		if ent == nil {
			return "", fmt.Errorf("EXPORT_MISSING: %s", sel)
		}
		key = selectNodeKey(cat.Source, cat.Provider, *ent)
		if visiting[key] {
			return "", fmt.Errorf("EXPORT_CYCLE: %s", strings.Join(append(chain, currentAlias), " -> "))
		}
		if prior, ok := selected[key]; ok {
			prior.chains = append(prior.chains, append([]string(nil), append(chain, currentAlias)...))
			selected[key] = prior
			return key, nil
		}
		visiting[key] = true
		defer delete(visiting, key)
		for _, req := range ent.Requires {
			ra, rd, rn := splitSelector(req.Selector)
			node, ok := byAlias[ra]
			if !ok {
				return "", fmt.Errorf("EXPORT_PROVIDER: unknown provider %s", ra)
			}
			rc, ok := bySourceCatalog[node.Key]
			if !ok {
				return "", fmt.Errorf("EXPORT_SOURCE: missing catalog for %s", ra)
			}
			required, err := findExportEntry(rc, rd, rn, req.Selector)
			if err != nil {
				return "", err
			}
			if req.ContractDigest != rc.ContractDigest {
				return "", fmt.Errorf("EXPORT_FACT_MISMATCH: contract digest")
			}
			if !versionMatches(required.Version, req.CompatibleRange) {
				return "", fmt.Errorf("EXPORT_FACT_MISMATCH: version")
			}
			dep, err := visit(ra, rc, req.Selector, rd, rn, append(chain, currentAlias))
			if err != nil {
				return "", err
			}
			edges[dep+"\x00"+key] = ExportEdge{Dependency: dep, Consumer: key}
		}
		if sel == selection.Selector && !reflect.DeepEqual(ent.Parameters, selection.Bindings) {
			return "", fmt.Errorf("EXPORT_BINDING: parameter mismatch for %s", sel)
		}
		node := bySource[cat.Source]
		selected[key] = selectKey{catalog: cat, entry: *ent, alias: currentAlias, sourceParameterSHA256: node.Identity.ParameterSHA256, chains: [][]string{append([]string(nil), append(chain, currentAlias)...)}}
		if len(selected) > 4096 {
			return "", fmt.Errorf("EXPORT_LIMIT: selected export limit")
		}
		return key, nil
	}
	if _, err := visit(alias, root, selection.Selector, domain, name, nil); err != nil {
		return ExportGraph{}, err
	}
	items := make([]selectKey, 0, len(selected))
	for _, x := range selected {
		items = append(items, x)
	}
	if err := assignPrerequisiteDepths(items, edges); err != nil {
		return ExportGraph{}, err
	}
	items, err := orderReadySelectKeys(items, edges)
	if err != nil {
		return ExportGraph{}, err
	}
	out := ExportGraph{Edges: make([]ExportEdge, 0, len(edges))}
	for _, x := range items {
		bd, _ := parameterDigest(selection.Bindings)
		sort.Slice(x.chains, func(i, j int) bool { return strings.Join(x.chains[i], "\x00") < strings.Join(x.chains[j], "\x00") })
		out.Selected = append(out.Selected, SelectedExport{Source: x.catalog.Source, Provider: x.catalog.Provider, ID: x.entry.ID, Domain: x.entry.Domain, Name: x.entry.Name, Version: x.entry.Version, ContentDigest: x.entry.ContentDigest, ContractDigest: x.catalog.ContractDigest, Parameters: x.entry.Parameters, BindingSHA256: bd, SourceParameterSHA256: x.sourceParameterSHA256, ToolDigest: x.entry.ToolDigest, Chains: cloneChains(x.chains)})
	}
	for _, e := range edges {
		out.Edges = append(out.Edges, e)
	}
	sort.Slice(out.Edges, func(i, j int) bool {
		if out.Edges[i].Dependency != out.Edges[j].Dependency {
			return out.Edges[i].Dependency < out.Edges[j].Dependency
		}
		return out.Edges[i].Consumer < out.Edges[j].Consumer
	})
	out.Digest, err = ExportGraphDigest(out.Selected, out.Edges)
	if err != nil {
		return ExportGraph{}, err
	}
	return out, nil
}

func findExportEntry(c Catalog, domain, name, selector string) (*ExportEntry, error) {
	var found *ExportEntry
	for i := range c.Exports {
		if c.Exports[i].Domain == domain && c.Exports[i].Name == name {
			if found != nil {
				return nil, fmt.Errorf("EXPORT_AMBIGUOUS: %s", selector)
			}
			found = &c.Exports[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("EXPORT_MISSING: %s", selector)
	}
	return found, nil
}

func assignPrerequisiteDepths(items []selectKey, edges map[string]ExportEdge) error {
	byKey := make(map[string]*selectKey, len(items))
	incoming := map[string][]string{}
	for i := range items {
		byKey[selectNodeKey(items[i].catalog.Source, items[i].catalog.Provider, items[i].entry)] = &items[i]
	}
	for _, e := range edges {
		incoming[e.Consumer] = append(incoming[e.Consumer], e.Dependency)
	}
	state := map[string]uint8{}
	var depth func(string) (int, error)
	depth = func(k string) (int, error) {
		if state[k] == 1 {
			return 0, fmt.Errorf("EXPORT_CYCLE: selected export graph")
		}
		if state[k] == 2 {
			return byKey[k].depth, nil
		}
		state[k] = 1
		best := 0
		for _, dep := range incoming[k] {
			d, e := depth(dep)
			if e != nil {
				return 0, e
			}
			if d+1 > best {
				best = d + 1
			}
		}
		state[k] = 2
		byKey[k].depth = best
		return best, nil
	}
	for k := range byKey {
		if _, err := depth(k); err != nil {
			return err
		}
	}
	for i := range items {
		items[i].depth = byKey[selectNodeKey(items[i].catalog.Source, items[i].catalog.Provider, items[i].entry)].depth
	}
	return nil
}

// orderReadySelectKeys is the production Kahn ready-node ordering helper.
// The ready key is deliberately component-wise: depth, provider alias, fixed
// domain rank, export name, then provider-local export ID.
func orderReadySelectKeys(items []selectKey, edges map[string]ExportEdge) ([]selectKey, error) {
	byKey := make(map[string]selectKey, len(items))
	indegree := make(map[string]int, len(items))
	adj := make(map[string][]string, len(items))
	for _, item := range items {
		key := selectNodeKey(item.catalog.Source, item.catalog.Provider, item.entry)
		byKey[key] = item
		indegree[key] = 0
	}
	for _, edge := range edges {
		if _, ok := byKey[edge.Dependency]; !ok {
			return nil, fmt.Errorf("EXPORT_GRAPH: unknown dependency %s", edge.Dependency)
		}
		if _, ok := byKey[edge.Consumer]; !ok {
			return nil, fmt.Errorf("EXPORT_GRAPH: unknown consumer %s", edge.Consumer)
		}
		adj[edge.Dependency] = append(adj[edge.Dependency], edge.Consumer)
		indegree[edge.Consumer]++
	}
	ready := make([]selectKey, 0, len(items))
	for key, item := range byKey {
		if indegree[key] == 0 {
			ready = append(ready, item)
		}
	}
	ordered := make([]selectKey, 0, len(items))
	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool { return readySelectLess(ready[i], ready[j]) })
		item := ready[0]
		ready = ready[1:]
		ordered = append(ordered, item)
		key := selectNodeKey(item.catalog.Source, item.catalog.Provider, item.entry)
		for _, consumer := range adj[key] {
			indegree[consumer]--
			if indegree[consumer] == 0 {
				ready = append(ready, byKey[consumer])
			}
		}
	}
	if len(ordered) != len(items) {
		return nil, fmt.Errorf("EXPORT_CYCLE: selected export graph")
	}
	return ordered, nil
}

func readySelectLess(a, b selectKey) bool {
	if a.depth != b.depth {
		return a.depth < b.depth
	}
	if a.alias != b.alias {
		return a.alias < b.alias
	}
	if domainRank(a.entry.Domain) != domainRank(b.entry.Domain) {
		return domainRank(a.entry.Domain) < domainRank(b.entry.Domain)
	}
	if a.entry.Name != b.entry.Name {
		return a.entry.Name < b.entry.Name
	}
	return a.entry.ID < b.entry.ID
}

func selectNodeKey(source, provider string, entry ExportEntry) string {
	return source + "\x00" + provider + "\x00" + entry.Domain + "\x00" + entry.ID
}

func cloneChains(in [][]string) [][]string {
	out := make([][]string, len(in))
	for i := range in {
		out[i] = append([]string(nil), in[i]...)
	}
	return out
}

func splitSelector(s string) (string, string, string) {
	p := strings.Split(s, ".")
	if len(p) != 3 {
		return "", "", ""
	}
	return p[0], p[1], p[2]
}
