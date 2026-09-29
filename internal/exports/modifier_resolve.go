package exports

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

type Rule struct {
	ID           string
	Digest       string
	Version      string
	Provider     string
	Capabilities []Capability
	Sources      []SourcePin
	Export       string
	Bindings     []Binding
	Tools        []ToolConstraint
	ExportFacts  map[string]ExportFact
	ToolFacts    map[string]ToolFact
	Requirements Requires
	Operation    Operation
}
type RuleSet struct {
	Rules      []Rule
	Required   []Capability
	Tombstones []Tombstone
	Exports    map[string]ExportFact
	Tools      map[string]ToolFact
}
type (
	ExportFact struct{ ContractDigest, Version string }
	ToolFact   struct{ Version, OptionsDigest string }
	Tombstone  struct {
		ID, Digest, Provider, Version, ReplacedBy, Reason string
		Chain                                             []string
		Capabilities                                      []Capability
	}
)

type Composition struct {
	Rules      []Rule
	Tombstones []Tombstone
	Ordered    []Operation
	Digest     string
}

// ResolveModifiers deterministically applies validated modifiers to an
// in-memory ruleset. It performs no I/O, execution, caching, or mutation of
// its arguments.
func ResolveModifiers(base RuleSet, modifiers []Modifier) (Composition, error) {
	active := map[string]Rule{}
	retired := map[string]Tombstone{}
	for _, t := range base.Tombstones {
		if t.ID == "" || retired[t.ID].ID != "" {
			return Composition{}, errors.New("RULE_TOMBSTONE: invalid prior tombstone")
		}
		retired[t.ID] = cloneTombstone(t)
	}
	for _, r := range base.Rules {
		if r.ID == "" || active[r.ID].ID != "" {
			return Composition{}, fmt.Errorf("RULE_TARGET: duplicate base rule %q", r.ID)
		}
		if _, exists := retired[r.ID]; exists {
			return Composition{}, fmt.Errorf("RULE_TOMBSTONE: active base reuses retired id %q", r.ID)
		}
		active[r.ID] = cloneRule(r)
	}
	ops := make([]operationRef, 0)
	for mi, m := range modifiers {
		if err := Validate(m); err != nil {
			return Composition{}, err
		}
		if err := validateModifierCollections(m); err != nil {
			return Composition{}, err
		}
		if err := validateExternalFacts(base, m); err != nil {
			return Composition{}, err
		}
		for _, op := range m.Rules {
			ops = append(ops, operationRef{m: m, op: op, index: mi})
		}
	}
	ordered, err := orderOperations(ops)
	if err != nil {
		return Composition{}, err
	}
	tomb := make([]Tombstone, 0, len(base.Tombstones)+len(ops))
	for _, t := range base.Tombstones {
		tomb = append(tomb, cloneTombstone(t))
	}
	for _, ref := range ordered {
		op := ref.op
		switch op.Op {
		case "add":
			if _, ok := active[op.ID]; ok {
				return Composition{}, fmt.Errorf("RULE_TARGET: add reuses active id %q", op.ID)
			}
			if _, ok := retired[op.ID]; ok {
				return Composition{}, fmt.Errorf("RULE_TOMBSTONE: add reuses retired id %q", op.ID)
			}
			rule, err := ruleFor(ref, base)
			if err != nil {
				return Composition{}, err
			}
			active[op.ID] = rule
		case "replace":
			target, ok := active[op.Target]
			if !ok {
				return Composition{}, fmt.Errorf("RULE_TARGET: missing target %q", op.Target)
			}
			if target.Digest != op.ExpectedDigest {
				return Composition{}, fmt.Errorf("RULE_PRECONDITION: digest mismatch for %q", op.Target)
			}
			if op.ExpectedVersion != "" && target.Version != op.ExpectedVersion {
				return Composition{}, fmt.Errorf("RULE_PRECONDITION: version mismatch for %q", op.Target)
			}
			if _, ok := active[op.ID]; ok {
				return Composition{}, fmt.Errorf("RULE_TARGET: replacement id exists %q", op.ID)
			}
			if _, ok := retired[op.ID]; ok {
				return Composition{}, fmt.Errorf("RULE_TOMBSTONE: replacement reuses retired id %q", op.ID)
			}
			delete(active, op.Target)
			rule, err := ruleFor(ref, base)
			if err != nil {
				return Composition{}, err
			}
			active[op.ID] = rule
			t := Tombstone{ID: target.ID, Digest: target.Digest, Provider: target.Provider, Version: target.Version, ReplacedBy: op.ID, Reason: "replace", Chain: []string{op.ID}, Capabilities: append([]Capability(nil), target.Capabilities...)}
			tomb = append(tomb, t)
			retired[t.ID] = t
		case "remove":
			target, ok := active[op.Target]
			if !ok {
				return Composition{}, fmt.Errorf("RULE_TARGET: missing target %q", op.Target)
			}
			if target.Digest != op.ExpectedDigest {
				return Composition{}, fmt.Errorf("RULE_PRECONDITION: digest mismatch for %q", op.Target)
			}
			if op.ExpectedVersion != "" && target.Version != op.ExpectedVersion {
				return Composition{}, fmt.Errorf("RULE_PRECONDITION: version mismatch for %q", op.Target)
			}
			delete(active, op.Target)
			t := Tombstone{ID: target.ID, Digest: target.Digest, Provider: target.Provider, Version: target.Version, Reason: "remove", Chain: []string{op.ID}, Capabilities: append([]Capability(nil), target.Capabilities...)}
			tomb = append(tomb, t)
			retired[t.ID] = t
		}
	}
	if err := validateConstraints(active, tomb, base.Required, modifiers); err != nil {
		return Composition{}, err
	}
	rules := make([]Rule, 0, len(active))
	for _, r := range active {
		r.Capabilities = append([]Capability(nil), r.Capabilities...)
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	sort.Slice(tomb, func(i, j int) bool { return tomb[i].ID < tomb[j].ID })
	orderedOps := toOps(ordered)
	digest, err := compositionDigest(base, modifiers, rules, tomb, orderedOps)
	if err != nil {
		return Composition{}, err
	}
	return Composition{Rules: rules, Tombstones: tomb, Ordered: orderedOps, Digest: digest}, nil
}

func cloneTombstone(t Tombstone) Tombstone {
	t.Chain = cloneStrings(t.Chain)
	t.Capabilities = cloneCapabilities(t.Capabilities)
	return t
}

func validateExternalFacts(base RuleSet, m Modifier) error {
	for _, r := range m.Requires.Exports {
		if base.Exports == nil {
			return fmt.Errorf("EXPORT_FACT_UNSUPPORTED: %s", r.Selector)
		}
		fact, ok := base.Exports[r.Selector]
		if !ok || fact.ContractDigest != r.ContractDigest {
			return fmt.Errorf("EXPORT_FACT_MISMATCH: %s", r.Selector)
		}
		if fact.Version == "" {
			return fmt.Errorf("EXPORT_FACT_UNSUPPORTED: version %s", r.Selector)
		}
		if !versionMatches(fact.Version, r.CompatibleRange) {
			return fmt.Errorf("EXPORT_FACT_MISMATCH: version %s", r.Selector)
		}
	}
	for _, r := range m.ToolConstraints {
		fact, ok := base.Tools[r.ID]
		if !ok {
			return fmt.Errorf("TOOL_CONSTRAINT_UNSUPPORTED: %s", r.ID)
		}
		if fact.Version == "" {
			return fmt.Errorf("TOOL_CONSTRAINT_UNSUPPORTED: version %s", r.ID)
		}
		if fact.OptionsDigest != r.OptionsDigest || !versionMatches(fact.Version, r.CompatibleRange) {
			return fmt.Errorf("TOOL_CONSTRAINT_MISMATCH: %s", r.ID)
		}
	}
	return nil
}

func versionMatches(version, constraint string) bool {
	if !strictSemver(version) {
		return false
	}
	if constraint == "*" {
		return true
	}
	parts := strings.Fields(constraint)
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		op := ""
		for _, x := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(p, x) {
				op = x
				p = strings.TrimPrefix(p, x)
				break
			}
		}
		if op == "" || !strictSemver(p) {
			return false
		}
		cmp := compareSemver(version, p)
		if (op == ">=" && cmp < 0) || (op == "<=" && cmp > 0) || (op == ">" && cmp <= 0) || (op == "<" && cmp >= 0) || (op == "=" && cmp != 0) {
			return false
		}
	}
	return true
}

func compareSemver(a, b string) int {
	coreAndPre := func(s string) (core, pre []string) {
		withoutBuild := strings.SplitN(s, "+", 2)[0]
		parts := strings.SplitN(withoutBuild, "-", 2)
		core = strings.Split(parts[0], ".")
		if len(parts) == 2 {
			pre = strings.Split(parts[1], ".")
		}
		return core, pre
	}
	aa, ap := coreAndPre(a)
	bb, bp := coreAndPre(b)
	for i := range aa {
		if cmp := compareDecimalIdentifier(aa[i], bb[i]); cmp != 0 {
			return cmp
		}
	}
	if len(ap) == 0 || len(bp) == 0 {
		if len(ap) == len(bp) {
			return 0
		}
		if len(ap) == 0 {
			return 1 // A release has higher precedence than a prerelease.
		}
		return -1
	}
	for i := 0; i < len(ap) && i < len(bp); i++ {
		if ap[i] == bp[i] {
			continue
		}
		aNumeric, bNumeric := allDigits(ap[i]), allDigits(bp[i])
		switch {
		case aNumeric && bNumeric:
			return compareDecimalIdentifier(ap[i], bp[i])
		case aNumeric:
			return -1 // Numeric prerelease identifiers sort before nonnumeric ones.
		case bNumeric:
			return 1
		case ap[i] < bp[i]:
			return -1
		default:
			return 1
		}
	}
	if len(ap) < len(bp) {
		return -1
	}
	if len(ap) > len(bp) {
		return 1
	}
	return 0
}

// compareDecimalIdentifier compares nonempty decimal strings without parsing
// them into a machine integer. strictSemver has already rejected leading zero
// numeric identifiers where SemVer forbids them.
func compareDecimalIdentifier(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

type operationRef struct {
	m     Modifier
	op    Operation
	index int
}

func orderOperations(in []operationRef) ([]operationRef, error) {
	ids := map[string]int{}
	for i, r := range in {
		if _, ok := ids[r.op.ID]; ok {
			return nil, fmt.Errorf("RULE_ORDER: duplicate operation %q", r.op.ID)
		}
		ids[r.op.ID] = i
	}
	targets := map[string]int{}
	adj := make([]map[int]bool, len(in))
	indeg := make([]int, len(in))
	for i := range adj {
		adj[i] = map[int]bool{}
	}
	for i, r := range in {
		if r.op.Op == "replace" || r.op.Op == "remove" {
			if prior, ok := targets[r.op.Target]; ok && prior != i {
				return nil, fmt.Errorf("RULE_TARGET: concurrent target %q", r.op.Target)
			}
			targets[r.op.Target] = i
		}
		for _, id := range r.op.Before {
			j, ok := ids[id]
			if !ok {
				return nil, fmt.Errorf("RULE_ORDER: unknown before %q", id)
			}
			if i == j {
				return nil, fmt.Errorf("RULE_ORDER: self edge %q", id)
			}
			adj[i][j] = true
		}
		for _, id := range r.op.After {
			j, ok := ids[id]
			if !ok {
				return nil, fmt.Errorf("RULE_ORDER: unknown after %q", id)
			}
			if i == j {
				return nil, fmt.Errorf("RULE_ORDER: self edge %q", id)
			}
			adj[j][i] = true
		}
		if producer, ok := ids[r.op.Target]; ok && (r.op.Op == "replace" || r.op.Op == "remove") {
			if producer == i {
				return nil, fmt.Errorf("RULE_ORDER: self target %q", r.op.Target)
			}
			adj[producer][i] = true
		}
	}
	for i := range adj {
		for j := range adj[i] {
			indeg[j]++
		}
	}
	result := make([]operationRef, 0, len(in))
	for len(result) < len(in) {
		ready := []int{}
		for i, d := range indeg {
			if d == 0 {
				ready = append(ready, i)
			}
		}
		if len(ready) == 0 {
			return nil, fmt.Errorf("RULE_ORDER: cycle %s", strings.Join(closedCyclePath(adj, indeg, in), " -> "))
		}
		sort.Slice(ready, func(a, b int) bool { return operationKey(in[ready[a]]) < operationKey(in[ready[b]]) })
		for _, i := range ready {
			indeg[i] = -1
			result = append(result, in[i])
			for j := range adj[i] {
				indeg[j]--
			}
		}
	}
	return result, nil
}

func closedCyclePath(adj []map[int]bool, indeg []int, in []operationRef) []string {
	state := make([]uint8, len(in))
	stack := []int{}
	position := map[int]int{}
	var visit func(int) []string
	visit = func(node int) []string {
		state[node] = 1
		position[node] = len(stack)
		stack = append(stack, node)
		next := make([]int, 0, len(adj[node]))
		for child := range adj[node] {
			if indeg[child] >= 0 {
				next = append(next, child)
			}
		}
		sort.Slice(next, func(i, j int) bool { return in[next[i]].op.ID < in[next[j]].op.ID })
		for _, child := range next {
			if state[child] == 1 {
				path := []string{}
				for _, item := range stack[position[child]:] {
					path = append(path, in[item].op.ID)
				}
				return append(path, in[child].op.ID)
			}
			if state[child] == 0 {
				if path := visit(child); path != nil {
					return path
				}
			}
		}
		delete(position, node)
		stack = stack[:len(stack)-1]
		state[node] = 2
		return nil
	}
	starts := []int{}
	for i, d := range indeg {
		if d >= 0 {
			starts = append(starts, i)
		}
	}
	sort.Slice(starts, func(i, j int) bool { return in[starts[i]].op.ID < in[starts[j]].op.ID })
	for _, start := range starts {
		if state[start] == 0 {
			if path := visit(start); path != nil {
				return path
			}
		}
	}
	return []string{"unknown", "unknown"}
}

func operationKey(r operationRef) string {
	return r.m.SelfSource + "\x00" + r.op.Export + "\x00" + r.op.ID
}

func toOps(in []operationRef) []Operation {
	out := make([]Operation, len(in))
	for i, r := range in {
		out[i] = normalizedOperation(r.op)
	}
	return out
}

func ruleFor(r operationRef, base RuleSet) (Rule, error) {
	caps := []Capability{}
	for _, p := range r.m.Provides {
		if p.RuleID == r.op.ID {
			caps = append(caps, Capability{p.Name, p.Value})
		}
	}
	context := normalizedModifier(r.m)
	// A rule binds its own operation, not every operation in the same modifier:
	// otherwise a successor's expectedDigest would make its producer identity
	// self-referential. compositionDigest binds the complete operation set.
	context.Rules = []Operation{}
	exportFacts, toolFacts := selectedFacts(base, r.m)
	identity := struct {
		APIVersion  string                `json:"apiVersion"`
		Modifier    Modifier              `json:"modifier"`
		Operation   Operation             `json:"operation"`
		ExportFacts map[string]ExportFact `json:"exportFacts"`
		ToolFacts   map[string]ToolFact   `json:"toolFacts"`
	}{"tplaiter.dev/composition-input/v1", context, normalizedOperation(r.op), exportFacts, toolFacts}
	digest, err := canonicalDigest("tplaiter.dev/composition-input/v1", identity)
	if err != nil {
		return Rule{}, fmt.Errorf("RULE_IDENTITY: %w", err)
	}
	return Rule{
		ID: r.op.ID, Digest: digest, Version: r.m.Metadata.Version, Provider: r.m.SelfSource,
		Capabilities: cloneCapabilities(caps), Sources: cloneSources(context.Sources), Export: r.op.Export,
		Bindings: cloneBindings(context.Bindings), Tools: cloneTools(context.ToolConstraints),
		ExportFacts: cloneExportFacts(exportFacts), ToolFacts: cloneToolFacts(toolFacts),
		Requirements: cloneRequires(context.Requires), Operation: normalizedOperation(r.op),
	}, nil
}

func selectedFacts(base RuleSet, m Modifier) (map[string]ExportFact, map[string]ToolFact) {
	exports := make(map[string]ExportFact, len(m.Requires.Exports))
	for _, r := range m.Requires.Exports {
		exports[r.Selector] = base.Exports[r.Selector]
	}
	tools := make(map[string]ToolFact, len(m.ToolConstraints))
	for _, r := range m.ToolConstraints {
		tools[r.ID] = base.Tools[r.ID]
	}
	return exports, tools
}

func cloneRule(r Rule) Rule {
	r.Capabilities = cloneCapabilities(r.Capabilities)
	r.Sources = cloneSources(r.Sources)
	r.Bindings = cloneBindings(r.Bindings)
	r.Tools = cloneTools(r.Tools)
	r.ExportFacts = cloneExportFacts(r.ExportFacts)
	r.ToolFacts = cloneToolFacts(r.ToolFacts)
	r.Requirements = cloneRequires(r.Requirements)
	r.Operation = cloneOperation(r.Operation)
	return r
}

func validateConstraints(active map[string]Rule, tomb []Tombstone, required []Capability, mods []Modifier) error {
	counts := map[string]int{}
	values := map[string]map[string]int{}
	for _, r := range active {
		for _, c := range r.Capabilities {
			counts[c.Name]++
			if values[c.Name] == nil {
				values[c.Name] = map[string]int{}
			}
			values[c.Name][c.Value]++
		}
	}
	allRequired := append([]Capability(nil), required...)
	for _, m := range mods {
		allRequired = append(allRequired, m.Requires.Capabilities...)
	}
	for _, name := range []string{"runtime", "router"} {
		if counts[name] > 1 {
			return fmt.Errorf("CAPABILITY_PROVIDER: %s has multiple providers", name)
		}
	}
	for _, c := range allRequired {
		if counts[c.Name] != 1 || values[c.Name][c.Value] != 1 {
			return fmt.Errorf("CAPABILITY_PROVIDER: %s=%s requires exactly one provider", c.Name, c.Value)
		}
	}
	for _, m := range mods {
		for _, c := range m.Conflicts {
			if values[c.Name][c.Value] > 0 {
				return fmt.Errorf("CAPABILITY_CONFLICT: %s=%s", c.Name, c.Value)
			}
		}
		for _, r := range m.Replaces {
			var old *Tombstone
			for i := range tomb {
				if tomb[i].ID == r.ProviderRule {
					old = &tomb[i]
					break
				}
			}
			next, ok := active[r.WithRule]
			if old == nil || !ok || next.Provider != m.SelfSource || !hasCapability(old.Capabilities, r.Name, r.Value) || !hasCapabilityName(next.Capabilities, r.Name) {
				return fmt.Errorf("REPLACEMENT_INVALID: %s", r.ProviderRule)
			}
		}
	}
	return nil
}

func hasCapability(values []Capability, name, value string) bool {
	for _, v := range values {
		if v.Name == name && v.Value == value {
			return true
		}
	}
	return false
}

func hasCapabilityName(values []Capability, name string) bool {
	for _, v := range values {
		if v.Name == name {
			return true
		}
	}
	return false
}

func cloneOperation(op Operation) Operation {
	op.Before = cloneStrings(op.Before)
	op.After = cloneStrings(op.After)
	return op
}

// normalizedOperation copies an operation and canonicalizes its dependency
// edge sets. It deliberately leaves the enclosing operation sequence alone:
// that sequence is the solver's normative DAG order.
func normalizedOperation(op Operation) Operation {
	op = cloneOperation(op)
	op.Before = sortedStrings(op.Before)
	op.After = sortedStrings(op.After)
	return op
}

func cloneSources(in []SourcePin) []SourcePin {
	out := make([]SourcePin, len(in))
	copy(out, in)
	return out
}

func cloneBindings(in []Binding) []Binding {
	out := make([]Binding, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Value = append([]byte(nil), in[i].Value...)
	}
	return out
}

func cloneTools(in []ToolConstraint) []ToolConstraint {
	out := make([]ToolConstraint, len(in))
	copy(out, in)
	return out
}

func cloneExportFacts(in map[string]ExportFact) map[string]ExportFact {
	out := make(map[string]ExportFact, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneToolFacts(in map[string]ToolFact) map[string]ToolFact {
	out := make(map[string]ToolFact, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRequires(in Requires) Requires {
	exports := make([]ExportRequirement, len(in.Exports))
	capabilities := make([]Capability, len(in.Capabilities))
	copy(exports, in.Exports)
	copy(capabilities, in.Capabilities)
	return Requires{Exports: exports, Capabilities: capabilities}
}

func cloneCapabilities(in []Capability) []Capability {
	out := make([]Capability, len(in))
	copy(out, in)
	return out
}

func cloneStrings(in []string) []string { out := make([]string, len(in)); copy(out, in); return out }

func cloneProvided(in []ProvidedCapability) []ProvidedCapability {
	out := make([]ProvidedCapability, len(in))
	copy(out, in)
	return out
}

func cloneReplacements(in []Replacement) []Replacement {
	out := make([]Replacement, len(in))
	copy(out, in)
	return out
}

func cloneRenames(in []Rename) []Rename { out := make([]Rename, len(in)); copy(out, in); return out }

// normalizedModifier materializes the order-independent authoring sets before
// identity hashing. Rule edges retain their order only through the separately
// hashed, normative Ordered operation sequence.
func normalizedModifier(in Modifier) Modifier {
	m := in
	m.Compatibility.Runtimes = sortedStrings(in.Compatibility.Runtimes)
	m.Compatibility.Layouts = sortedStrings(in.Compatibility.Layouts)
	m.Sources = cloneSources(in.Sources)
	sort.Slice(m.Sources, func(i, j int) bool { return sourceKey(m.Sources[i]) < sourceKey(m.Sources[j]) })
	m.Requires = cloneRequires(in.Requires)
	sort.Slice(m.Requires.Exports, func(i, j int) bool {
		return exportRequirementKey(m.Requires.Exports[i]) < exportRequirementKey(m.Requires.Exports[j])
	})
	sort.Slice(m.Requires.Capabilities, func(i, j int) bool {
		return capabilityKey(m.Requires.Capabilities[i]) < capabilityKey(m.Requires.Capabilities[j])
	})
	m.Provides = cloneProvided(in.Provides)
	sort.Slice(m.Provides, func(i, j int) bool { return providedKey(m.Provides[i]) < providedKey(m.Provides[j]) })
	m.Conflicts = cloneCapabilities(in.Conflicts)
	sort.Slice(m.Conflicts, func(i, j int) bool { return capabilityKey(m.Conflicts[i]) < capabilityKey(m.Conflicts[j]) })
	m.Replaces = cloneReplacements(in.Replaces)
	sort.Slice(m.Replaces, func(i, j int) bool { return replacementKey(m.Replaces[i]) < replacementKey(m.Replaces[j]) })
	m.Bindings = cloneBindings(in.Bindings)
	sort.Slice(m.Bindings, func(i, j int) bool { return m.Bindings[i].Name < m.Bindings[j].Name })
	m.ToolConstraints = cloneTools(in.ToolConstraints)
	sort.Slice(m.ToolConstraints, func(i, j int) bool { return toolKey(m.ToolConstraints[i]) < toolKey(m.ToolConstraints[j]) })
	m.Renames = cloneRenames(in.Renames)
	sort.Slice(m.Renames, func(i, j int) bool { return renameKey(m.Renames[i]) < renameKey(m.Renames[j]) })
	m.Rules = make([]Operation, len(in.Rules))
	for i := range in.Rules {
		m.Rules[i] = normalizedOperation(in.Rules[i])
	}
	sort.Slice(m.Rules, func(i, j int) bool { return m.Rules[i].ID < m.Rules[j].ID })
	return m
}
func sourceKey(s SourcePin) string { return s.Origin + "\x00" + s.TemplatePath + "\x00" + s.Alias }
func exportRequirementKey(r ExportRequirement) string {
	return r.Selector + "\x00" + r.ContractDigest + "\x00" + r.CompatibleRange
}
func capabilityKey(c Capability) string       { return c.Name + "\x00" + c.Value }
func providedKey(c ProvidedCapability) string { return c.Name + "\x00" + c.Value + "\x00" + c.RuleID }

func replacementKey(r Replacement) string {
	return r.Name + "\x00" + r.Value + "\x00" + r.ProviderRule + "\x00" + r.WithRule
}

func toolKey(t ToolConstraint) string {
	return t.ID + "\x00" + t.CompatibleRange + "\x00" + t.OptionsDigest
}
func renameKey(r Rename) string { return r.Path + "\x00" + r.OldBlockID + "\x00" + r.NewBlockID }

func compositionDigest(base RuleSet, modifiers []Modifier, rules []Rule, tombstones []Tombstone, ordered []Operation) (string, error) {
	normalizedModifiers := make([]Modifier, len(modifiers))
	for i := range modifiers {
		normalizedModifiers[i] = normalizedModifier(modifiers[i])
	}
	sort.Slice(normalizedModifiers, func(i, j int) bool {
		left, _ := canonicaljson.Canonical(normalizedModifiers[i])
		right, _ := canonicaljson.Canonical(normalizedModifiers[j])
		return string(left) < string(right)
	})
	baseCopy := cloneRuleSet(base)
	sort.Slice(baseCopy.Rules, func(i, j int) bool { return baseCopy.Rules[i].ID < baseCopy.Rules[j].ID })
	sort.Slice(baseCopy.Tombstones, func(i, j int) bool { return baseCopy.Tombstones[i].ID < baseCopy.Tombstones[j].ID })
	sort.Slice(baseCopy.Required, func(i, j int) bool { return capabilityKey(baseCopy.Required[i]) < capabilityKey(baseCopy.Required[j]) })
	payload := struct {
		APIVersion string      `json:"apiVersion"`
		Base       RuleSet     `json:"base"`
		Modifiers  []Modifier  `json:"modifiers"`
		Rules      []Rule      `json:"rules"`
		Tombstones []Tombstone `json:"tombstones"`
		Ordered    []Operation `json:"ordered"`
	}{"tplaiter.dev/composition-graph/v1", baseCopy, normalizedModifiers, normalizedRules(rules), cloneTombstones(tombstones), normalizedOperations(ordered)}
	return canonicalDigest("tplaiter.dev/composition-graph/v1", payload)
}

func canonicalDigest(domain string, payload any) (string, error) {
	b, err := canonicaljson.Canonical(payload)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(append([]byte(domain+"\x00"), b...))
	return "sha256:" + hex.EncodeToString(s[:]), nil
}

func cloneRules(in []Rule) []Rule {
	out := make([]Rule, len(in))
	for i := range in {
		out[i] = cloneRule(in[i])
	}
	return out
}

func cloneTombstones(in []Tombstone) []Tombstone {
	out := make([]Tombstone, len(in))
	for i := range in {
		out[i] = cloneTombstone(in[i])
	}
	return out
}

func normalizedOperations(in []Operation) []Operation {
	out := make([]Operation, len(in))
	for i := range in {
		out[i] = normalizedOperation(in[i])
	}
	return out
}

func normalizedRules(in []Rule) []Rule {
	out := cloneRules(in)
	for i := range out {
		out[i].Operation = normalizedOperation(out[i].Operation)
	}
	return out
}

func cloneRuleSet(in RuleSet) RuleSet {
	out := in
	out.Rules = cloneRules(in.Rules)
	out.Required = cloneCapabilities(in.Required)
	out.Tombstones = cloneTombstones(in.Tombstones)
	if in.Exports != nil {
		out.Exports = make(map[string]ExportFact, len(in.Exports))
		for k, v := range in.Exports {
			out.Exports[k] = v
		}
	}
	if in.Tools != nil {
		out.Tools = make(map[string]ToolFact, len(in.Tools))
		for k, v := range in.Tools {
			out.Tools[k] = v
		}
	}
	return out
}
